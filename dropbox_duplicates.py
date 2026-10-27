#!/usr/bin/env python3
"""Find duplicate remote files using metadata, without downloading or modifying files."""
from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from collections.abc import Sequence
from typing import Any

import dropbox
from dropbox.exceptions import AuthError
from dropbox.files import FileMetadata
from dropbox_audit import request


def normalize_roots(paths: Sequence[str]) -> list[str]:
    """Normalize paths and eliminate overlapping selections, case insensitively."""
    roots = []
    for path in paths or ['/']:
        path = '/' + path.strip('/')
        if any(part in ('.', '..') for part in path.split('/')) or '//' in path:
            raise ValueError('Folder paths must not contain empty, . or .. components')
        roots.append(path.rstrip('/'))
    selected: list[str] = []
    for root in sorted(set(roots), key=lambda value: (len(value), value)):
        if not any(not parent or root.lower() == parent.lower() or
                   root.lower().startswith(parent.lower() + '/') for parent in selected):
            selected.append(root)
    return selected


def scan(client: Any, roots: Sequence[str], db: sqlite3.Connection) -> dict[str, Any]:
    """Catalogue recursive listings on disk, deduplicate IDs and group content."""
    db.execute('CREATE TABLE files (id TEXT PRIMARY KEY, path TEXT NOT NULL, size INTEGER NOT NULL, hash TEXT)')
    for root in roots:
        page = request(client.files_list_folder, root, recursive=True,
                       include_deleted=False, include_non_downloadable_files=True)
        while True:
            for item in page.entries:
                if isinstance(item, FileMetadata):
                    if not item.id or not item.path_display:
                        raise ValueError('Dropbox returned a file without an ID or path')
                    db.execute('INSERT OR REPLACE INTO files VALUES (?,?,?,?)',
                               (item.id, item.path_display, item.size, item.content_hash or None))
            db.commit()
            logging.info('Scanned metadata page under %s', root or '/')
            if not page.has_more:
                break
            page = request(client.files_list_folder_continue, page.cursor)
    db.execute('CREATE INDEX content ON files(size,hash)')
    groups = []
    for size, digest, count in db.execute(
        'SELECT size,hash,count(*) FROM files WHERE hash IS NOT NULL '
        'GROUP BY size,hash HAVING count(*)>1 ORDER BY size DESC,hash'
    ):
        files = [{'id': file_id, 'path': path} for file_id, path in db.execute(
            'SELECT id,path FROM files WHERE size=? AND hash=? ORDER BY path', (size, digest))]
        groups.append({'content_hash': digest, 'size': size, 'copies': count,
                       'redundant_bytes': size * (count - 1), 'files': files})
    unverified = [path for (path,) in db.execute('SELECT path FROM files WHERE hash IS NULL ORDER BY path')]
    return {'summary': {'roots': [root or '/' for root in roots],
                        'files_scanned': db.execute('SELECT count(*) FROM files').fetchone()[0],
                        'duplicate_groups': len(groups),
                        'duplicate_files': sum(group['copies'] for group in groups),
                        'redundant_copies': sum(group['copies'] - 1 for group in groups),
                        'redundant_bytes': sum(group['redundant_bytes'] for group in groups),
                        'unverified_files': len(unverified), 'complete': not unverified},
            'groups': groups, 'unverified': unverified}


def positive_timeout(value: str) -> float:
    timeout = float(value)
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError('timeout must be finite and greater than zero')
    return timeout


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        'Requires files.metadata.read. Set DROPBOX_ACCESS_TOKEN, or DROPBOX_REFRESH_TOKEN '
        'with DROPBOX_APP_KEY (and DROPBOX_APP_SECRET for confidential apps). '
        'Exit: 0 no duplicates, 1 duplicates found, 2 incomplete/error.'))
    parser.add_argument('directories', nargs='*', help='Folders to scan recursively; default: entire accessible tree')
    parser.add_argument('--json', type=Path, help='Also save full JSON report to a new file')
    parser.add_argument('--csv', type=Path, help='Also save duplicate members as CSV to a new file')
    parser.add_argument('--timeout', type=positive_timeout, default=30, help='Network timeout in seconds (default: 30)')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    try:
        roots = normalize_roots(args.directories)
        for path in (args.json, args.csv):
            if path is not None and path.exists():
                raise ValueError('Report already exists; choose a new output filename')
        if args.json is not None and args.csv is not None and args.json.resolve() == args.csv.resolve():
            raise ValueError('JSON and CSV reports must use different paths')
        token, refresh = os.getenv('DROPBOX_ACCESS_TOKEN'), os.getenv('DROPBOX_REFRESH_TOKEN')
        if not token and not refresh:
            raise ValueError('Set DROPBOX_ACCESS_TOKEN or DROPBOX_REFRESH_TOKEN with DROPBOX_APP_KEY')
        if refresh and not os.getenv('DROPBOX_APP_KEY'):
            raise ValueError('DROPBOX_APP_KEY is required with a refresh token')
        with dropbox.Dropbox(oauth2_access_token=token, oauth2_refresh_token=refresh,
                             app_key=os.getenv('DROPBOX_APP_KEY'), app_secret=os.getenv('DROPBOX_APP_SECRET'),
                             timeout=args.timeout) as client:
            with tempfile.TemporaryDirectory(prefix='dropbox-duplicates-') as directory:
                db = sqlite3.connect(str(Path(directory) / 'files.sqlite'))
                try:
                    result = scan(client, roots, db)
                finally:
                    db.close()
        if args.json:
            with args.json.open('x', encoding='utf-8') as output:
                json.dump(result, output, ensure_ascii=True, indent=2)
                output.write('\n')
        if args.csv:
            with args.csv.open('x', encoding='utf-8', newline='') as output:
                writer = csv.writer(output)
                writer.writerow(['group', 'content_hash', 'size', 'copies', 'id', 'path'])
                for number, group in enumerate(result['groups'], 1):
                    for item in group['files']:
                        writer.writerow([number, group['content_hash'], group['size'], group['copies'], item['id'], item['path']])
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 2 if result['unverified'] else int(bool(result['groups']))
    except AuthError:
        print(
            'Error: Dropbox authentication failed. The access token may have expired, '
            'been revoked, or be invalid. Set DROPBOX_ACCESS_TOKEN to a new access token, '
            'or configure DROPBOX_REFRESH_TOKEN and DROPBOX_APP_KEY '
            '(plus DROPBOX_APP_SECRET for confidential apps) for automatic renewal. '
            'Refresh credentials are optional when using a valid access token. Scan incomplete.',
            file=sys.stderr,
        )
        return 2
    except (Exception, KeyboardInterrupt) as exc:
        # SDK exception strings can contain request details or credentials.
        diagnostic = str(exc) if isinstance(exc, (ValueError, OSError, RuntimeError)) else type(exc).__name__
        print(f'Error: {diagnostic}. Scan incomplete.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
