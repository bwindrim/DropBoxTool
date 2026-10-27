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
from collections.abc import Callable, Sequence
from typing import Any, Protocol, TYPE_CHECKING, TypeVar, Union, overload

if TYPE_CHECKING:
    from dropbox import Dropbox

# Configuration values store scan IDs as text; SQLite accepts either form.
ScanId = Union[int, str]
FilePath = Union[str, os.PathLike[str]]
Result = TypeVar('Result')


class IssueReporter(Protocol):
    """Callback interface for recording a discrepancy and its optional diagnostics."""
    def __call__(self, category: str, path: str, other: str = '', detail: str = '') -> None:
        """Record one category/path discrepancy, optionally naming a related path."""
        ...

BLOCK = 4 * 1024 * 1024
LOG = logging.getLogger(__name__)


def content_hash(path: FilePath, *, dir_fd: int | None = None) -> tuple[str, os.stat_result]:
    """Return a Dropbox content hash and the verified file metadata.

    Read the regular file in 4 MiB blocks without following its final symlink.
    For a relative path, dir_fd pins the parent directory. Raise OSError for
    read failures, unsupported file types, or detected changes during hashing.
    An empty file returns the SHA-256 digest of an empty digest sequence.
    """
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
        def signature(s: os.stat_result) -> tuple[int, int, int, int, int]:
            """Select the identity and timestamps used to detect replacement or mutation."""
            return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns
        if signature(before) != signature(after) or signature(after) != signature(current):
            raise OSError('file changed during hashing')
        return digest.hexdigest(), after


def connect(path: FilePath) -> sqlite3.Connection:
    """Open or create a SQLite catalogue and initialize its tables and indexes.

    Enable WAL journaling and named-row access. The caller owns the returned
    connection and must close it; no backup files or Dropbox data are changed.
    """
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


@overload
def setting(db: sqlite3.Connection, key: str, default: str) -> str: ...


@overload
def setting(db: sqlite3.Connection, key: str, default: None = None) -> str | None: ...


def setting(db: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    """Return a stored configuration string, or default when the key is absent."""
    row = db.execute('SELECT value FROM config WHERE key=?', (key,)).fetchone()
    return row[0] if row else default


def required_setting(db: sqlite3.Connection, key: str) -> str:
    """Return a configuration string, raising ValueError if the key is absent."""
    value = setting(db, key)
    if value is None:
        raise ValueError(f'Catalogue is missing {key}; initialize a new database')
    return value


def put(db: sqlite3.Connection, key: str, value: str | int | Path) -> None:
    """Store a configuration value as text without committing the transaction."""
    db.execute('INSERT OR REPLACE INTO config VALUES (?,?)', (key, str(value)))


def normalized(path: str) -> str:
    """Return an NFC-normalized, case-folded key for path diagnostics and lookup.

    This key does not replace the original spelling stored in the catalogue.
    """
    return unicodedata.normalize('NFC', path).casefold()


def entry(db: sqlite3.Connection, scan: ScanId, side: str, path: str, kind: str,
          size: int | None = None, mtime: str | None = None, hash: str | None = None,
          file_id: str | None = None, verified: float | None = None,
          error: str | None = None) -> None:
    """Insert or replace one path in a scan's local or remote catalogue.

    Paths are relative to the configured root. Metadata may be absent for
    folders or unverified entries; error records why verification failed.
    The caller controls transaction commits.
    """
    db.execute('INSERT OR REPLACE INTO entries VALUES (?,?,?,?,?,?,?,?,?,?,?)',
               (scan, side, path, kind, size, mtime, hash, file_id, verified, error, normalized(path)))


def ignores_hidden(db: sqlite3.Connection, scan: ScanId) -> bool:
    """Return whether this scan excluded local dotfiles; older scans default to false."""
    row = db.execute('SELECT ignore_hidden FROM scan_options WHERE scan=?', (scan,)).fetchone()
    return bool(row and row[0])


def local_scan(db: sqlite3.Connection, scan: ScanId, root: Path,
               full: bool = False, ignore_hidden: bool = False) -> int:
    """Catalogue root without following symlinks and return the number of errors.

    Reuse hashes when size and nanosecond mtime match the cache unless full
    is true. With ignore_hidden, omit dotfiles while still traversing hidden
    directories. Record unreadable or unstable entries as errors, and commit
    progress every 100 entries and at directory boundaries for restartability.
    The caller determines scan completion and whether to establish a baseline.
    """
    db.execute('INSERT OR REPLACE INTO scan_options VALUES (?,?)', (scan, int(ignore_hidden)))
    db.commit()
    errors = 0
    def traversal_error(exc: OSError) -> None:
        """Persist a directory traversal failure so unseen children are not treated as deleted."""
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


def request(call: Callable[..., Result], *args: Any, **kwargs: Any) -> Result:
    """Call a Dropbox metadata operation with at most four attempts.

    Forward arguments and return the operation's result. Retry rate limits,
    server failures and network errors with bounded delays. Propagate other
    errors immediately, and raise RuntimeError when a backoff exceeds 60 seconds.
    """
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
    raise AssertionError('Retry loop exhausted without returning or raising')


def remote_scan(db: sqlite3.Connection, scan: ScanId, client: Dropbox,
                root: str, fresh: bool = False) -> None:
    """Save a complete Dropbox metadata snapshot and its cursor in one transaction.

    Apply paginated changes to the previous trusted snapshot, or list root
    recursively when fresh is true or no cursor exists. Process deletion
    subtrees and retain ID-based move/modification history. Failures roll back
    the new snapshot and cursor, preserving the trusted catalogue. Only
    metadata endpoints are called; file contents are never transferred.
    """
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


def compare(db: sqlite3.Connection, scan: ScanId, *, commit: bool = True) -> int:
    """Record discrepancies for the two catalogues belonging to scan.

    Return the number of same-path files with matching hashes. Retain exact
    path spellings, report normalization collisions and rename candidates,
    and check the pinned local baseline. Update the latest comparison pointer.
    Set commit to false when the caller owns the surrounding transaction;
    this function expects a new scan and does not clear existing issues.
    """
    previous = setting(db, 'comparison_scan', '0')
    def issue(category: str, path: str, other: str = '', detail: str = '') -> None:
        """Record a discrepancy and whether it was absent from the previous comparison."""
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


def baseline_changes(db: sqlite3.Connection, scan: ScanId, issue: IssueReporter) -> None:
    """Report local removals and content/type changes through issue.

    Compare scan with the first successful local baseline, skipping dotfiles
    when this scan excludes them. If no baseline exists, pin scan instead.
    Call only after a complete local traversal; the caller commits changes.
    """
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


def offline_compare(db: sqlite3.Connection) -> int:
    """Return a new comparison ID using saved local and remote catalogues.

    Select the latest completed local scan and the trusted remote snapshot,
    raising ValueError if either is unavailable. Copy their entries, preserve
    source IDs and local filtering options, and save discrepancies atomically.
    Neither tree is scanned, and remote state is only as recent as its source
    snapshot. Existing baseline, cache and Dropbox cursor are preserved.
    """
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
        if scan is None:
            raise RuntimeError('SQLite did not return an ID for the new scan')
        for side, source in (('local', local_id), ('remote', remote_id)):
            db.execute('INSERT INTO entries SELECT ?,side,path,kind,size,mtime,hash,file_id,verified,error,norm FROM entries WHERE scan=? AND side=?', (scan, source, side))
        db.execute('INSERT INTO comparison_sources VALUES (?,?,?)', (scan, local_id, remote_id))
        db.execute('INSERT INTO scan_options VALUES (?,?)', (scan, int(ignores_hidden(db, local_id))))
        compare(db, scan, commit=False)
        incomplete = db.execute("SELECT 1 FROM issues WHERE scan=? AND category='unverified'", (scan,)).fetchone()
        db.execute('UPDATE scans SET finished=?,status=? WHERE id=?', (time.time(), 'incomplete' if incomplete else 'complete', scan))
    return scan


def safe_output(path: FilePath, root: Path, database: Path) -> Path:
    """Resolve an output path and reject destinations inside the backup or at the database.

    Raise ValueError for rejected paths. This validates the destination only;
    report creation separately refuses to overwrite an existing file.
    """
    root = root.resolve()
    resolved = Path(path).expanduser().resolve()
    if resolved == root or root in resolved.parents:
        raise ValueError('Catalogue and reports must be outside the local backup')
    if resolved == database:
        raise ValueError('Report must not overwrite the catalogue')
    return resolved


def report(db: sqlite3.Connection, scan: ScanId, csv_path: FilePath | None = None,
           json_path: FilePath | None = None, *, csv_omit_remote_only: bool = False,
           csv_omit_baseline_changes: bool = False) -> None:
    """Print a saved scan summary and optionally create CSV and JSON reports.

    CSV options omit remote-only paths or local baseline changes from CSV
    rows alone; summaries, JSON and stored issues remain unchanged. Files are
    created exclusively, raising FileExistsError rather than overwriting.
    Offline comparison summaries include source scan IDs and timestamps.
    """
    summary: dict[str, Any] = {side: dict(db.execute("SELECT count(*) AS files,coalesce(sum(size),0) AS bytes FROM entries WHERE scan=? AND side=? AND kind='file'", (scan, side)).fetchone()) for side in ('local', 'remote')}
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


def duplicates_report(db: sqlite3.Connection, csv_path: FilePath | None = None,
                      json_path: FilePath | None = None, *,
                      directories: Sequence[str] = ()) -> int:
    """Report duplicate content in the last trusted remote snapshot, entirely offline."""
    source = setting(db, 'remote_scan')
    if source is None:
        raise ValueError('No saved remote catalogue; run initial or full first')
    row = db.execute('SELECT id,mode,started,finished,status FROM scans WHERE id=?', (source,)).fetchone()
    if row is None:
        raise ValueError('Saved remote catalogue refers to an unknown scan')
    roots: list[str] = []
    for directory in directories:
        directory = directory.strip('/')
        if directory and any(part in ('', '.', '..') for part in directory.split('/')):
            raise ValueError('Subdirectories must not contain empty, . or .. components')
        if directory and not db.execute(
            "SELECT 1 FROM entries WHERE scan=? AND side='remote' AND kind='folder' AND norm=?",
            (source, normalized(directory)),
        ).fetchone():
            raise ValueError(f'Subdirectory not found in saved remote catalogue: {directory!r}')
        roots.append(directory)
    # Match literal directory boundaries; SQL LIKE would treat % and _ as wildcards.
    scope = "scan=? AND side='remote' AND kind='file'"
    parameters: list[Any] = [source]
    if roots and '' not in roots:
        scope += ' AND (' + ' OR '.join('substr(norm,1,?)=?' for _ in roots) + ')'
        for directory in roots:
            prefix = normalized(directory) + '/'
            parameters.extend((len(prefix), prefix))
    groups = []
    valid = scope + " AND error IS NULL AND hash IS NOT NULL AND hash<>'' AND size IS NOT NULL AND size>=0"
    for size, digest, count in db.execute(
        'SELECT size,hash,count(*) FROM entries WHERE ' + valid +
        ' GROUP BY size,hash HAVING count(*)>1 ORDER BY size DESC,hash', parameters
    ):
        files = [dict(item) for item in db.execute(
            'SELECT path,file_id FROM entries WHERE ' + valid + ' AND size=? AND hash=? ORDER BY path',
            [*parameters, size, digest])]
        groups.append({'content_hash': digest, 'size': size, 'copies': count,
                       'redundant_bytes': size * (count - 1), 'files': files})
    unverified = [dict(item) for item in db.execute(
        'SELECT path,error FROM entries WHERE ' + scope +
        " AND (error IS NOT NULL OR hash IS NULL OR hash='' OR size IS NULL OR size<0) ORDER BY path", parameters)]
    summary = {
        'source': dict(row), 'dropbox_root': required_setting(db, 'dropbox_root') or '/',
        'subdirectories': roots or ['/'],
        'remote_state_note': 'Saved Dropbox metadata only; Dropbox has not been contacted. Paths are relative to dropbox_root.',
        'files_scanned': db.execute('SELECT count(*) FROM entries WHERE ' + scope, parameters).fetchone()[0],
        'duplicate_groups': len(groups), 'duplicate_files': sum(g['copies'] for g in groups),
        'redundant_copies': sum(g['copies'] - 1 for g in groups),
        'redundant_bytes': sum(g['redundant_bytes'] for g in groups),
        'unverified_files': len(unverified), 'complete': not unverified,
    }
    result = {'summary': summary, 'groups': groups, 'unverified': unverified}
    if csv_path:
        with open(csv_path, 'x', newline='', encoding='utf-8') as target:
            writer = csv.writer(target)
            writer.writerow(['group', 'content_hash', 'size', 'copies', 'file_id', 'path'])
            for number, group in enumerate(groups, 1):
                for item in group['files']:
                    writer.writerow([number, group['content_hash'], group['size'], group['copies'], item['file_id'], item['path']])
    if json_path:
        with open(json_path, 'x', encoding='utf-8') as target:
            json.dump(result, target, indent=2)
            target.write('\n')
    print(json.dumps(result, indent=2))
    return 2 if unverified else int(bool(groups))


def build_parser() -> argparse.ArgumentParser:
    """Build command help for setup, scanning, updates and saved reports."""
    formatter = argparse.RawDescriptionHelpFormatter
    parser = argparse.ArgumentParser(
        description=(
            'Verify a local backup against Dropbox using content hashes and saved SQLite catalogues.\n'
            'Reads local files and Dropbox metadata only; never synchronizes or repairs files.'
        ),
        formatter_class=formatter,
        epilog='''Typical workflow (global options go BEFORE the command):
  1. Configure independent roots; no scanning or Dropbox credentials needed:
     python3 dropbox_audit.py --db audit.sqlite init --local-root /Volumes/Backup/Photos --dropbox-root /Photos
  2. Scan the local backup without contacting Dropbox (optional before initial):
     python3 dropbox_audit.py --db audit.sqlite -v local --ignore-hidden
  3. Fetch Dropbox metadata and perform the first comparison:
     export DROPBOX_ACCESS_TOKEN='your-token'
     python3 dropbox_audit.py --db audit.sqlite -v initial --ignore-hidden --csv initial.csv
  4. Update both catalogues and compare after later changes:
     python3 dropbox_audit.py --db audit.sqlite -v quick --ignore-hidden --csv update.csv
  5. Or rescan only locally, then compare against SAVED Dropbox metadata:
     python3 dropbox_audit.py --db audit.sqlite local --ignore-hidden
     python3 dropbox_audit.py --db audit.sqlite compare --csv offline.csv

Command names: local/initial/full perform scans; quick performs incremental updates.
There are no separate commands named "scan" or "update".
Use COMMAND --help for its options and more examples.

Authentication (initial, quick, full only):
  Set DROPBOX_ACCESS_TOKEN, or DROPBOX_REFRESH_TOKEN with DROPBOX_APP_KEY
  (and DROPBOX_APP_SECRET for confidential apps). Required OAuth scope:
  files.metadata.read. Secrets are read from the environment, never stored in SQLite.

Safety and results:
  Keep the database and reports outside the local backup. Reports must use new
  filenames; existing files are never overwritten. The first successful local
  catalogue pins the baseline; later scans retain historical records.
  Exit codes: 0 = match/success, 1 = discrepancies, 2 = incomplete/error.
  CSV filters do not change saved discrepancies, summary counts or exit codes.''',
    )
    parser.add_argument('--db', required=True, type=Path, metavar='DATABASE',
                        help='SQLite catalogue path; init creates it, other commands require it to exist. Keep outside the backup.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Log local scan progress, Dropbox metadata pages and retries. Place before the command.')
    sub = parser.add_subparsers(dest='command', required=True, title='commands', metavar='COMMAND')
    init = sub.add_parser(
        'init', help='Create a catalogue and pin the local and Dropbox roots; do not scan.',
        description='Create a new SQLite catalogue and record the two independent roots.\n'
                    'Does not read file contents or contact Dropbox. Existing catalogues cannot be reinitialized.',
        formatter_class=formatter,
        epilog='''Example:
  python3 dropbox_audit.py --db audit.sqlite init --local-root /Volumes/Backup/Photos --dropbox-root /Photos

The local root must exist. Its device/inode identity is pinned to detect a
changed mount on later scans. Use / as the Dropbox account root, or an absolute
folder path in the app's accessible namespace. Use a new database to change roots.''',
    )
    init.add_argument('--local-root', required=True, type=Path, metavar='DIRECTORY',
                      help='Existing authoritative local backup directory, scanned recursively.')
    init.add_argument('--dropbox-root', required=True, metavar='DROPBOX_PATH',
                      help='Corresponding Dropbox folder, e.g. /Photos; use / for the account root. Independent of local path.')
    descriptions = {
        'initial': (
            'Build the first Dropbox catalogue and compare with the local backup.',
            'Rescan local metadata, reusing unchanged cached hashes, and fetch a fresh complete\n'
            'Dropbox listing. Compare the catalogues and save discrepancies. Requires OAuth\n'
            'credentials. Run once before using quick; an earlier local-only scan is optional.',
            'python3 dropbox_audit.py --db audit.sqlite -v initial --ignore-hidden --csv initial.csv',
        ),
        'quick': (
            'Update local hashes and saved Dropbox metadata, then compare.',
            'Rescan local metadata and rehash only files whose size or mtime changed.\n'
            'Apply Dropbox updates using the saved cursor (fresh listing if none exists),\n'
            'then compare. Requires OAuth credentials and contacts Dropbox. Edits preserving\n'
            'size and mtime may be missed; use full periodically.',
            'python3 dropbox_audit.py --db audit.sqlite -v quick --ignore-hidden --csv update.csv',
        ),
        'full': (
            'Rehash every local file and rebuild Dropbox metadata, then compare.',
            'Perform a full integrity verification: recalculate every local content hash,\n'
            'regardless of cached metadata, and fetch a fresh complete Dropbox listing.\n'
            'Requires OAuth credentials. May take hours on large backups; file contents\n'
            'are read locally only, never downloaded from Dropbox.',
            'python3 dropbox_audit.py --db audit.sqlite -v full --csv full-check.csv',
        ),
        'local': (
            'Scan and hash the local backup without contacting Dropbox.',
            'Build a new local catalogue, reusing hashes when size and mtime are unchanged.\n'
            'No Dropbox credentials required. The first successful scan pins the local\n'
            'baseline; later scans report removals and content/type changes against it.\n'
            'Retry this command after interruption to reuse committed hash progress.',
            'python3 dropbox_audit.py --db audit.sqlite -v local --ignore-hidden\n'
            '  python3 dropbox_audit.py --db audit.sqlite -v local --full --json local-check.json',
        ),
        'compare': (
            'Compare saved local and remote catalogues entirely offline.',
            'Compare the latest completed local scan with the last trusted remote snapshot\n'
            'in this database. Neither tree is rescanned; no credentials or mounted backup\n'
            'are required. Dropbox findings reflect the SAVED remote state, not its live\n'
            'state. Save a new comparison with source scan IDs and timestamps.',
            'python3 dropbox_audit.py --db audit.sqlite compare --csv offline.csv\n'
            '  python3 dropbox_audit.py --db audit.sqlite compare --csv focused.csv --csv-omit-remote-only --csv-omit-baseline-changes',
        ),
        'report': (
            'Display or export an existing scan result without comparing again.',
            'Display the latest saved comparison, or the latest successful local-only scan\n'
            'if no comparison exists. Use --scan to select an older or incomplete scan\n'
            'and inspect its errors. Does not scan files, contact Dropbox or recompute\n'
            'discrepancies. Returns the selected scan result\'s exit code.',
            'python3 dropbox_audit.py --db audit.sqlite report --csv saved-report.csv\n'
            '  python3 dropbox_audit.py --db audit.sqlite report --scan 2 --json scan-2.json',
        ),
    }
    for name, (brief, description, example) in descriptions.items():
        command = sub.add_parser(name, help=brief, description=description,
                                 formatter_class=formatter,
                                 epilog='Examples:\n  ' + example + '\n\n'
                                        'Report paths must be outside the backup and must not already exist.\n'
                                        'Exit codes: 0 = match/success, 1 = discrepancies, 2 = incomplete/error.')
        command.add_argument('--csv', metavar='FILE',
                             help='Create a detailed UTF-8 discrepancy CSV. Matching files appear only in summary counts.')
        command.add_argument('--json', metavar='FILE',
                             help='Create a JSON summary and all discrepancies, unaffected by CSV filters.')
        command.add_argument('--csv-omit-remote-only', action='store_true',
                             help='Omit CSV rows for paths present only remotely, including extra files/directories and remote-only unverified entries. Does not change counts or exit codes.')
        command.add_argument('--csv-omit-baseline-changes', action='store_true',
                             help='Omit local_baseline_changed rows from CSV only; other discrepancies for the same path remain.')
        if name == 'report':
            command.add_argument('--scan', type=int, metavar='ID',
                                 help='Select a saved scan ID from history, including incomplete scans, instead of the default result.')
        if name in ('local', 'initial', 'quick', 'full'):
            command.add_argument('--ignore-hidden', action='store_true',
                                 help="Skip local files whose names start with '.', including ._ files. Still traverse hidden directories. Pass on every scan where desired; remote-only dotfiles may still be reported.")
        if name == 'local':
            command.add_argument('--full', action='store_true',
                                 help='Rehash all local files regardless of cached size/mtime. Does not contact Dropbox.')
        if name in ('initial', 'quick', 'full'):
            command.add_argument('--rebuild-remote', action='store_true',
                                 help='Ignore the saved cursor and fetch a fresh complete remote listing (use after cursor expiry). Already implicit in initial and full; trusted state survives listing failure.')
    duplicates = sub.add_parser(
        'duplicates', help='Find duplicate files in the saved remote catalogue, offline.',
        description='Group files by size and content hash in the last trusted remote snapshot.\n'
                    'No Dropbox credentials or mounted backup are required. No catalogue data is changed.',
        formatter_class=formatter,
        epilog='Example:\n  python3 dropbox_audit.py --db audit.sqlite duplicates --csv duplicates.csv\n\n'
               'Paths are relative to the configured Dropbox root. Reports require new filenames\n'
               'outside the backup. Exit: 0 = no duplicates, 1 = duplicates, 2 = incomplete/error.',
    )
    duplicates.add_argument('--csv', metavar='FILE', help='Create a CSV with one row per duplicate member.')
    duplicates.add_argument('directories', nargs='*', metavar='SUBDIRECTORY',
                            help='Restrict to these saved folders and descendants, relative to the configured Dropbox root (optional leading slash). Default: entire saved tree.')
    duplicates.add_argument('--json', metavar='FILE', help='Create a full JSON duplicate report, including unverified paths.')
    sub.add_parser(
        'history', help='List scan IDs, modes, timestamps and completion status.',
        description='Print saved scan history as one JSON object per scan.\n'
                    'Use an ID with report --scan ID to inspect its saved result or errors.',
        formatter_class=formatter,
        epilog='Example:\n  python3 dropbox_audit.py --db audit.sqlite history\n'
               '  python3 dropbox_audit.py --db audit.sqlite report --scan 2\n\n'
               'Does not scan files or contact Dropbox. Returns 0 on success, 2 on error.',
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse CLI arguments, execute the selected operation and return its exit code.

    Return 0 for a successful match or local scan, 1 for discrepancies, and
    2 for incomplete scans or operational errors. Use a catalogue lock to
    prevent concurrent writers. Scanning commands validate the mounted root;
    offline compare and report require no backup mount or Dropbox credentials.
    Record scan failures without exposing SDK request details or credentials.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    csv_options: dict[str, bool] = {
        'csv_omit_remote_only': getattr(args, 'csv_omit_remote_only', False),
        'csv_omit_baseline_changes': getattr(args, 'csv_omit_baseline_changes', False),
    }
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    db: sqlite3.Connection | None = None
    scan: int | None = None
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
        root = Path(required_setting(db, 'local_root'))
        csv_path = safe_output(args.csv, root, database) if getattr(args, 'csv', None) else None
        json_path = safe_output(args.json, root, database) if getattr(args, 'json', None) else None
        if args.command == 'history':
            for row in db.execute('SELECT * FROM scans ORDER BY id'):
                print(json.dumps(dict(row)))
            return 0
        if args.command == 'duplicates':
            return duplicates_report(db, csv_path, json_path, directories=args.directories)
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
            if scan is None:
                raise RuntimeError('SQLite did not return an ID for the new scan')
            db.commit()
            errors = local_scan(db, scan, root, args.full, ignore_hidden=args.ignore_hidden)
            previous = setting(db, 'local_scan', '0')

            def local_issue(category: str, path: str, other: str = '', detail: str = '') -> None:
                """Record a local discrepancy, marking novelty against the preceding local scan."""
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
        if scan is None:
            raise RuntimeError('SQLite did not return an ID for the new scan')
        db.commit()
        errors = local_scan(db, scan, root, args.command == 'full', ignore_hidden=args.ignore_hidden)
        if errors:
            raise RuntimeError('Local scan incomplete; trusted comparison retained. Inspect entries.error for this scan.')
        remote_scan(db, scan, client, required_setting(db, 'dropbox_root'), args.command != 'quick' or args.rebuild_remote)
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
