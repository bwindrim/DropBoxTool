#!/usr/bin/env python3
"""Read-only Dropbox integrity auditing. All persistent writes target the catalogue."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time
import unicodedata

BLOCK = 4 * 1024 * 1024
LOG = logging.getLogger(__name__)


def content_hash(path, *, dir_fd=None):
    """Hash a stable regular file without following a final symbolic link."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise OSError('not a regular file')
        digest = hashlib.sha256()
        while True:
            block = source.read(BLOCK)
            if not block:
                break
            digest.update(hashlib.sha256(block).digest())
        after = os.fstat(source.fileno())
        current = os.stat(path, follow_symlinks=False, dir_fd=dir_fd)
        signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if signature(before) != signature(after) or signature(after) != signature(current):
            raise OSError('file changed during hashing')
        return digest.hexdigest(), after


def connect(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.executescript('''
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY,mode TEXT,started REAL,finished REAL,status TEXT,error TEXT);
    CREATE TABLE IF NOT EXISTS entries(scan INTEGER,side TEXT,path TEXT,kind TEXT,size INTEGER,mtime TEXT,hash TEXT,file_id TEXT,verified REAL,error TEXT,norm TEXT,PRIMARY KEY(scan,side,path));
    CREATE INDEX IF NOT EXISTS entry_hash ON entries(scan,side,hash);
    CREATE INDEX IF NOT EXISTS entry_norm ON entries(scan,side,norm);
    CREATE TABLE IF NOT EXISTS scan_options(scan INTEGER PRIMARY KEY,ignore_hidden INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS comparison_sources(scan INTEGER PRIMARY KEY,local_scan INTEGER NOT NULL,remote_scan INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS remote_events(scan INTEGER,file_id TEXT,old_path TEXT,new_path TEXT,event TEXT);
    CREATE TABLE IF NOT EXISTS cache(path TEXT PRIMARY KEY,size INTEGER,mtime TEXT,hash TEXT,verified REAL);
    CREATE TABLE IF NOT EXISTS issues(scan INTEGER,category TEXT,path TEXT,other TEXT,detail TEXT,is_new INTEGER);
    CREATE INDEX IF NOT EXISTS issue_lookup ON issues(scan,category,path,other);
    ''')
    return db


def setting(db, key, default=None):
    row = db.execute('SELECT value FROM config WHERE key=?', (key,)).fetchone()
    return row[0] if row else default


def put(db, key, value):
    db.execute('INSERT OR REPLACE INTO config VALUES (?,?)', (key, str(value)))


def normalized(path):
    return unicodedata.normalize('NFC', path).casefold()


def entry(db, scan, side, path, kind, size=None, mtime=None, hash=None,
          file_id=None, verified=None, error=None):
    db.execute('INSERT OR REPLACE INTO entries VALUES (?,?,?,?,?,?,?,?,?,?,?)',
               (scan, side, path, kind, size, mtime, hash, file_id, verified, error, normalized(path)))


def ignores_hidden(db, scan):
    row = db.execute('SELECT ignore_hidden FROM scan_options WHERE scan=?', (scan,)).fetchone()
    return bool(row and row[0])


def local_scan(db, scan, root, full=False, ignore_hidden=False):
    db.execute('INSERT OR REPLACE INTO scan_options VALUES (?,?)', (scan, int(ignore_hidden)))
    db.commit()
    errors = 0
    def traversal_error(exc):
        nonlocal errors
        errors += 1
        path = os.path.relpath(exc.filename or root, root)
        entry(db, scan, 'local', path, 'unknown', error=str(exc))
        db.commit()

    # fwalk pins parent directory descriptors, avoiding traversal through replaced links.
    count = 0
    for directory, directories, files, directory_fd in os.fwalk(root, follow_symlinks=False, onerror=traversal_error):
        visible_files = [name for name in files if not (ignore_hidden and name.startswith('.'))]
        for name in directories + visible_files:
            relative = Path(directory, name).relative_to(root).as_posix()
            try:
                s = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISDIR(s.st_mode):
                    entry(db, scan, 'local', relative, 'folder')
                elif stat.S_ISREG(s.st_mode):
                    old = db.execute('SELECT * FROM cache WHERE path=?', (relative,)).fetchone()
                    if not full and old and old['size'] == s.st_size and old['mtime'] == str(s.st_mtime_ns):
                        digest, verified = old['hash'], old['verified']
                    else:
                        digest, s = content_hash(name, dir_fd=directory_fd)
                        verified = time.time()
                        db.execute('INSERT OR REPLACE INTO cache VALUES (?,?,?,?,?)',
                                   (relative, s.st_size, str(s.st_mtime_ns), digest, verified))
                    entry(db, scan, 'local', relative, 'file', s.st_size, str(s.st_mtime_ns), digest, verified=verified)
                else:
                    raise OSError('symbolic link or special file excluded')
            except OSError as exc:
                errors += 1
                entry(db, scan, 'local', relative, 'unknown', error=str(exc))
            count += 1
            if count % 100 == 0:
                db.commit()
                LOG.info('Local scan: %s entries; latest %s', count, relative)
        db.commit()
    return errors


def request(call, *args, **kwargs):
    from dropbox.exceptions import RateLimitError, InternalServerError
    from requests.exceptions import RequestException
    for attempt in range(4):
        try:
            return call(*args, **kwargs)
        except (RateLimitError, InternalServerError, RequestException) as exc:
            if attempt == 3:
                raise
            delay = max(1, getattr(exc, 'backoff', None) or 2 ** attempt)
            if delay > 60:
                raise RuntimeError('Rate limit requires a longer wait; retry this scan later') from None
            LOG.warning('Retrying metadata request in %ss', delay)
            time.sleep(delay)


def remote_scan(db, scan, client, root, fresh=False):
    from dropbox.files import FileMetadata, FolderMetadata, DeletedMetadata
    previous = setting(db, 'remote_scan')
    cursor = None if fresh else setting(db, 'cursor')
    # The entire remote snapshot and its cursor are one transaction.
    with db:
        if cursor and previous:
            db.execute("INSERT INTO entries SELECT ?,side,path,kind,size,mtime,hash,file_id,verified,error,norm FROM entries WHERE scan=? AND side='remote'", (scan, previous))
            result = request(client.files_list_folder_continue, cursor)
        else:
            result = request(client.files_list_folder, root, recursive=True, include_deleted=True, include_non_downloadable_files=True)
        while True:
            for item in result.entries:
                display = item.path_display
                if not isinstance(display, str) or not display.startswith('/'):
                    raise ValueError('Dropbox returned metadata without an absolute display path')
                # Compare components, not string offsets: Unicode normalization and
                # case folding can change the length of a root's spelling.
                parts = display[1:].split('/')
                prefix = root.strip('/').split('/') if root.strip('/') else []
                if (any(part in ('', '.', '..') for part in parts)
                        or len(parts) < len(prefix)
                        or [normalized(p) for p in parts[:len(prefix)]] != [normalized(p) for p in prefix]):
                    raise ValueError(f'Dropbox returned a path outside the configured root: {display!r} (root {root!r})')
                relative = parts[len(prefix):]
                if not relative:
                    # A listing may include metadata for the selected folder itself.
                    # It is not a descendant, and must not enter the relative catalogue.
                    if isinstance(item, FolderMetadata):
                        continue
                    raise ValueError(f'Dropbox returned non-folder metadata for the configured root: {display!r}')
                path = '/'.join(relative)
                if isinstance(item, (DeletedMetadata, FileMetadata)):
                    # Prefix comparison avoids SQL LIKE wildcard interpretation of filenames.
                    db.execute("DELETE FROM entries WHERE scan=? AND side='remote' AND (norm=? OR substr(norm,1,?)=?)", (scan, normalized(path), len(normalized(path)) + 1, normalized(path) + '/'))
                if isinstance(item, DeletedMetadata):
                    continue
                kind = 'folder' if isinstance(item, FolderMetadata) else 'file'
                # Dropbox's namespace is case insensitive; retain its exact display spelling.
                db.execute("DELETE FROM entries WHERE scan=? AND side='remote' AND norm=?", (scan, normalized(path)))
                entry(db, scan, 'remote', path, kind, getattr(item, 'size', None),
                      str(getattr(item, 'server_modified', '')), getattr(item, 'content_hash', None),
                      getattr(item, 'id', None), error=('Dropbox did not supply a content hash' if kind == 'file' and not getattr(item, 'content_hash', None) else None))
            LOG.info('Received Dropbox metadata page')
            if not result.has_more:
                break
            result = request(client.files_list_folder_continue, result.cursor)
        if previous:
            db.execute("""INSERT INTO remote_events
                SELECT ?,old.file_id,old.path,new.path,
                CASE WHEN new.path IS NULL THEN 'removed' WHEN old.path<>new.path THEN 'moved' ELSE 'modified' END
                FROM entries old LEFT JOIN entries new ON new.scan=? AND new.side='remote' AND new.file_id=old.file_id
                WHERE old.scan=? AND old.side='remote' AND old.file_id IS NOT NULL
                AND (new.path IS NULL OR old.path<>new.path OR old.hash IS NOT new.hash)""", (scan, scan, previous))
        put(db, 'cursor', result.cursor)
        put(db, 'remote_scan', scan)


def compare(db, scan, *, commit=True):
    previous = setting(db, 'comparison_scan', '0')
    def issue(category, path, other='', detail=''):
        exists = db.execute('SELECT 1 FROM issues WHERE scan=? AND category=? AND path=? AND other=?', (previous, category, path, other)).fetchone()
        db.execute('INSERT INTO issues VALUES (?,?,?,?,?,?)', (scan, category, path, other, detail, int(not exists)))
    identical = 0
    for side in ('local', 'remote'):
        for row in db.execute('SELECT norm FROM entries WHERE scan=? AND side=? GROUP BY norm HAVING count(*)>1', (scan, side)):
            for item in db.execute('SELECT path FROM entries WHERE scan=? AND side=? AND norm=?', (scan, side, row[0])):
                issue('path_collision', item[0], detail=side)
    for local in db.execute("SELECT * FROM entries WHERE scan=? AND side='local'", (scan,)):
        remote = db.execute("SELECT * FROM entries WHERE scan=? AND side='remote' AND path=?", (scan, local['path'])).fetchone()
        if local['error'] or (remote and remote['error']):
            issue('unverified', local['path'], detail=local['error'] or remote['error'])
        elif not remote:
            issue('directory_mismatch' if local['kind'] == 'folder' else 'missing_remotely', local['path'], detail='missing remotely')
            if local['hash']:
                matches = db.execute("SELECT path FROM entries WHERE scan=? AND side='remote' AND hash=? AND path<>? LIMIT 21", (scan, local['hash'], local['path'])).fetchall()
                for match in matches[:20]:
                    issue('possible_rename', local['path'], match[0], 'same content; candidate, not proof of a move')
        elif local['kind'] != remote['kind']:
            issue('directory_mismatch', local['path'], detail='file/folder type differs')
        elif local['kind'] == 'file':
            if local['size'] != remote['size']:
                issue('size_mismatch', local['path'], detail=f"local={local['size']} remote={remote['size']}")
            if local['hash'] != remote['hash']:
                issue('content_mismatch', local['path'])
            else:
                identical += 1
    for remote in db.execute("SELECT r.* FROM entries r WHERE scan=? AND side='remote' AND NOT EXISTS (SELECT 1 FROM entries l WHERE l.scan=r.scan AND l.side='local' AND l.path=r.path)", (scan,)):
        issue('unverified' if remote['error'] else 'directory_mismatch' if remote['kind'] == 'folder' else 'extra_remotely', remote['path'], detail=remote['error'] or 'extra remotely')
    baseline_changes(db, scan, issue)
    put(db, 'comparison_scan', scan)
    put(db, 'identical', identical)
    if commit:
        db.commit()
    return identical


def baseline_changes(db, scan, issue):
    baseline = setting(db, 'baseline_scan')
    ignore_hidden = ignores_hidden(db, scan)
    if baseline:
        for old in db.execute("SELECT * FROM entries WHERE scan=? AND side='local'", (baseline,)):
            if ignore_hidden and old['kind'] != 'folder' and old['path'].rsplit('/', 1)[-1].startswith('.'):
                continue
            now = db.execute("SELECT * FROM entries WHERE scan=? AND side='local' AND path=?", (scan, old['path'])).fetchone()
            if now is None or (old['kind'], old['hash']) != (now['kind'], now['hash']):
                issue('local_baseline_changed', old['path'], detail='removed' if now is None else 'modified or unverified')
    else:
        put(db, 'baseline_scan', scan)


def offline_compare(db):
    """Compare saved snapshots atomically, without consulting either directory tree."""
    local = db.execute("SELECT id FROM scans WHERE status='complete' AND mode IN ('local','initial','quick','full') ORDER BY id DESC LIMIT 1").fetchone()
    remote = setting(db, 'remote_scan')
    if local is None:
        raise ValueError('No completed local catalogue available; run local first')
    if remote is None or db.execute('SELECT 1 FROM scans WHERE id=?', (remote,)).fetchone() is None:
        raise ValueError('No trusted remote catalogue available; run initial or quick first')
    local_id, remote_id = local[0], int(remote)
    # Copies preserve historical report behavior and use SQLite disk-backed storage.
    # Include empty successful catalogues: entry counts do not indicate completeness.
    with db:
        scan = db.execute('INSERT INTO scans(mode,started,status) VALUES (?,?,?)', ('compare', time.time(), 'running')).lastrowid
        for side, source in (('local', local_id), ('remote', remote_id)):
            db.execute('INSERT INTO entries SELECT ?,side,path,kind,size,mtime,hash,file_id,verified,error,norm FROM entries WHERE scan=? AND side=?', (scan, source, side))
        db.execute('INSERT INTO comparison_sources VALUES (?,?,?)', (scan, local_id, remote_id))
        db.execute('INSERT INTO scan_options VALUES (?,?)', (scan, int(ignores_hidden(db, local_id))))
        compare(db, scan, commit=False)
        incomplete = db.execute("SELECT 1 FROM issues WHERE scan=? AND category='unverified'", (scan,)).fetchone()
        db.execute('UPDATE scans SET finished=?,status=? WHERE id=?', (time.time(), 'incomplete' if incomplete else 'complete', scan))
    return scan


def safe_output(path, root, database):
    root = root.resolve()
    resolved = Path(path).expanduser().resolve()
    if resolved == root or root in resolved.parents:
        raise ValueError('Catalogue and reports must be outside the local backup')
    if resolved == database:
        raise ValueError('Report must not overwrite the catalogue')
    return resolved


def report(db, scan, csv_path=None, json_path=None, *,
           csv_omit_remote_only=False, csv_omit_baseline_changes=False):
    summary = {side: dict(db.execute("SELECT count(*) AS files,coalesce(sum(size),0) AS bytes FROM entries WHERE scan=? AND side=? AND kind='file'", (scan, side)).fetchone()) for side in ('local', 'remote')}
    summary['discrepancies'] = dict(db.execute('SELECT category,count(*) FROM issues WHERE scan=? GROUP BY category', (scan,)))
    summary['identical'] = db.execute("SELECT count(*) FROM entries l JOIN entries r ON l.scan=r.scan AND l.path=r.path WHERE l.scan=? AND l.side='local' AND r.side='remote' AND l.kind='file' AND l.hash=r.hash AND l.error IS NULL AND r.error IS NULL", (scan,)).fetchone()[0]
    row = db.execute('SELECT * FROM scans WHERE id=?', (scan,)).fetchone()
    summary['scan'] = dict(row)
    summary['ignore_hidden_local_files'] = ignores_hidden(db, scan)
    sources = db.execute('SELECT local_scan,remote_scan FROM comparison_sources WHERE scan=?', (scan,)).fetchone()
    if sources:
        summary['sources'] = {
            side: dict(db.execute('SELECT id,mode,started,finished,status FROM scans WHERE id=?', (sources[side + '_scan'],)).fetchone())
            for side in ('local', 'remote')
        }
        summary['remote_state_note'] = 'Saved Dropbox metadata only; Dropbox has not been contacted.'
    summary['comparison_performed'] = row['mode'] != 'local'
    if row['mode'] == 'local':
        summary['remote'] = None
        summary['identical'] = None
    summary['duration_seconds'] = round((row['finished'] or time.time()) - row['started'], 2)
    print(json.dumps(summary, indent=2))
    fields = ['category', 'path', 'other', 'detail', 'is_new']
    if csv_path:
        with open(csv_path, 'x', newline='', encoding='utf-8') as target:
            writer = csv.writer(target)
            writer.writerow(fields)
            conditions = ['i.scan=?']
            if csv_omit_remote_only:
                conditions.append("""NOT (
                    EXISTS (SELECT 1 FROM entries r WHERE r.scan=i.scan AND r.side='remote' AND r.path=i.path)
                    AND NOT EXISTS (SELECT 1 FROM entries l WHERE l.scan=i.scan AND l.side='local' AND l.path=i.path)
                )""")
            if csv_omit_baseline_changes:
                conditions.append("i.category<>'local_baseline_changed'")
            query = ('SELECT i.category,i.path,i.other,i.detail,i.is_new FROM issues i WHERE '
                     + ' AND '.join(conditions) + ' ORDER BY i.category,i.path')
            writer.writerows(db.execute(query, (scan,)))
    if json_path:
        with open(json_path, 'x', encoding='utf-8') as target:
            target.write('{"summary":' + json.dumps(summary) + ',"issues":[')
            separator = ''
            for issue in db.execute('SELECT category,path,other,detail,is_new FROM issues WHERE scan=?', (scan,)):
                target.write(separator + json.dumps(dict(issue)))
                separator = ','
            target.write(']}\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', required=True, type=Path)
    parser.add_argument('-v', '--verbose', action='store_true')
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init')
    init.add_argument('--local-root', required=True, type=Path)
    init.add_argument('--dropbox-root', required=True)
    for name in ('initial', 'quick', 'full', 'local', 'compare', 'report'):
        command = sub.add_parser(name)
        command.add_argument('--csv')
        command.add_argument('--json')
        command.add_argument('--csv-omit-remote-only', action='store_true',
                             help='Omit CSV rows for paths present only in the remote catalogue')
        command.add_argument('--csv-omit-baseline-changes', action='store_true',
                             help='Omit local_baseline_changed rows from CSV')
        if name == 'report':
            command.add_argument('--scan', type=int, help='Include failed scan diagnostics by scan ID')
        if name in ('local', 'initial', 'quick', 'full'):
            command.add_argument('--ignore-hidden', action='store_true', help="Skip local files whose names begin with '.'; still traverse hidden directories")
        if name == 'local':
            command.add_argument('--full', action='store_true', help='Rehash every local file')
        if name not in ('local', 'compare', 'report'):
            command.add_argument('--rebuild-remote', action='store_true')
    sub.add_parser('history')
    args = parser.parse_args(argv)
    csv_options = {
        'csv_omit_remote_only': getattr(args, 'csv_omit_remote_only', False),
        'csv_omit_baseline_changes': getattr(args, 'csv_omit_baseline_changes', False),
    }
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    db = None
    scan = None
    lock = None
    try:
        database = args.db.expanduser().resolve()
        if args.command == 'init':
            root = args.local_root.expanduser().resolve(strict=True)
            if not root.is_dir():
                raise ValueError('Local root must be a directory')
            safe_output(database, root, Path('/__not_a_report__'))
        elif not database.exists():
            raise ValueError('Catalogue does not exist; run init first')
        import fcntl
        lock = open(str(database) + '.lock', 'a')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Another auditor is using this catalogue') from None
        db = connect(database)
        if args.command == 'init':
            if setting(db, 'local_root'):
                raise ValueError('Catalogue already initialized; use a new database for different roots')
            remote = args.dropbox_root.rstrip('/')
            if remote and (not remote.startswith('/') or any(p in ('.', '..', '') for p in remote[1:].split('/'))):
                raise ValueError('Dropbox root must be / or an absolute Dropbox folder path')
            put(db, 'local_root', root)
            put(db, 'root_identity', f'{root.stat().st_dev}:{root.stat().st_ino}')
            put(db, 'dropbox_root', remote)
            db.commit()
            print('Catalogue initialized. Roots are pinned; credentials are read from the environment.')
            return 0
        root = Path(setting(db, 'local_root'))
        csv_path = safe_output(args.csv, root, database) if getattr(args, 'csv', None) else None
        json_path = safe_output(args.json, root, database) if getattr(args, 'json', None) else None
        if args.command == 'history':
            for row in db.execute('SELECT * FROM scans ORDER BY id'):
                print(json.dumps(dict(row)))
            return 0
        if args.command == 'report':
            scan_id = args.scan or setting(db, 'comparison_scan') or setting(db, 'local_scan')
            if not scan_id:
                raise ValueError('No completed local scan or comparison available')
            status = db.execute('SELECT status FROM scans WHERE id=?', (scan_id,)).fetchone()
            if status is None:
                raise ValueError('Unknown scan ID')
            report(db, scan_id, csv_path, json_path, **csv_options)
            for error in db.execute('SELECT side,path,error FROM entries WHERE scan=? AND error IS NOT NULL', (scan_id,)):
                print(json.dumps(dict(error)))
            return 2 if status[0] != 'complete' else int(db.execute('SELECT 1 FROM issues WHERE scan=? LIMIT 1', (scan_id,)).fetchone() is not None)
        if args.command == 'compare':
            scan = offline_compare(db)
            report(db, scan, csv_path, json_path, **csv_options)
            status = db.execute('SELECT status FROM scans WHERE id=?', (scan,)).fetchone()[0]
            return 2 if status != 'complete' else int(db.execute('SELECT 1 FROM issues WHERE scan=? LIMIT 1', (scan,)).fetchone() is not None)
        s = root.stat()
        if f'{s.st_dev}:{s.st_ino}' != setting(db, 'root_identity'):
            raise ValueError('Local root identity changed; check that the correct disk is mounted')
        if args.command == 'initial' and setting(db, 'comparison_scan'):
            raise ValueError('Initial scan already completed; use quick or full')
        if args.command == 'local':
            db.execute("UPDATE scans SET status='interrupted',finished=? WHERE status='running'", (time.time(),))
            scan = db.execute('INSERT INTO scans(mode,started,status) VALUES (?,?,?)', ('local', time.time(), 'running')).lastrowid
            db.commit()
            errors = local_scan(db, scan, root, args.full, ignore_hidden=args.ignore_hidden)
            previous = setting(db, 'local_scan', '0')

            def local_issue(category, path, other='', detail=''):
                exists = db.execute('SELECT 1 FROM issues WHERE scan=? AND category=? AND path=? AND other=?', (previous, category, path, other)).fetchone()
                db.execute('INSERT INTO issues VALUES (?,?,?,?,?,?)', (scan, category, path, other, detail, int(not exists)))

            for row in db.execute("SELECT path,error FROM entries WHERE scan=? AND side='local' AND error IS NOT NULL", (scan,)):
                local_issue('unverified', row['path'], detail=row['error'])
            # A partial traversal must never establish a baseline or imply removals.
            if not errors:
                baseline_changes(db, scan, local_issue)
                put(db, 'local_scan', scan)
            db.execute('UPDATE scans SET finished=?,status=? WHERE id=?', (time.time(), 'incomplete' if errors else 'complete', scan))
            db.commit()
            report(db, scan, csv_path, json_path, **csv_options)
            return 2 if errors else int(db.execute('SELECT 1 FROM issues WHERE scan=? LIMIT 1', (scan,)).fetchone() is not None)
        import dropbox
        token = os.getenv('DROPBOX_ACCESS_TOKEN')
        refresh = os.getenv('DROPBOX_REFRESH_TOKEN')
        if not token and not refresh:
            raise ValueError('Set DROPBOX_ACCESS_TOKEN or DROPBOX_REFRESH_TOKEN and DROPBOX_APP_KEY')
        if refresh and not os.getenv('DROPBOX_APP_KEY'):
            raise ValueError('DROPBOX_APP_KEY is required with a refresh token')
        client = dropbox.Dropbox(oauth2_access_token=token, oauth2_refresh_token=refresh,
                                 app_key=os.getenv('DROPBOX_APP_KEY'), app_secret=os.getenv('DROPBOX_APP_SECRET'), timeout=30)
        # A prior running scan was interrupted. Its cache remains usable, but never its snapshot.
        db.execute("UPDATE scans SET status='interrupted',finished=? WHERE status='running'", (time.time(),))
        scan = db.execute('INSERT INTO scans(mode,started,status) VALUES (?,?,?)', (args.command, time.time(), 'running')).lastrowid
        db.commit()
        errors = local_scan(db, scan, root, args.command == 'full', ignore_hidden=args.ignore_hidden)
        if errors:
            raise RuntimeError('Local scan incomplete; trusted comparison retained. Inspect entries.error for this scan.')
        remote_scan(db, scan, client, setting(db, 'dropbox_root'), args.command != 'quick' or args.rebuild_remote)
        compare(db, scan)
        incomplete = db.execute("SELECT 1 FROM issues WHERE scan=? AND category='unverified'", (scan,)).fetchone()
        db.execute('UPDATE scans SET finished=?,status=? WHERE id=?', (time.time(), 'incomplete' if incomplete else 'complete', scan))
        db.commit()
        report(db, scan, csv_path, json_path, **csv_options)
        return 2 if incomplete else int(db.execute('SELECT 1 FROM issues WHERE scan=? LIMIT 1', (scan,)).fetchone() is not None)
    except (Exception, KeyboardInterrupt) as exc:
        if db is not None and scan is not None:
            db.rollback()
            # Do not log SDK exceptions: they can include request details or credentials.
            db.execute('UPDATE scans SET finished=?,status=?,error=? WHERE id=?', (time.time(), 'incomplete', type(exc).__name__, scan))
            db.commit()
        print(f'Error: {exc if isinstance(exc, (ValueError, RuntimeError, OSError)) else type(exc).__name__}. Scan incomplete; retry or use --rebuild-remote for an invalid cursor.', file=sys.stderr)
        return 2
    finally:
        if db is not None:
            db.close()
        if lock is not None:
            lock.close()


if __name__ == '__main__':
    sys.exit(main())
