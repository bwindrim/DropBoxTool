import contextlib
from datetime import datetime
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from dropbox.files import FileMetadata, FolderMetadata
from dropbox.exceptions import AuthError
import dropbox_duplicates as duplicates


def file(path, digest='a' * 64, size=3, identity=None):
    return FileMetadata(name=path.rsplit('/', 1)[-1], id=identity or 'id:' + path,
                        client_modified=datetime(2026, 1, 1), server_modified=datetime(2026, 1, 1),
                        rev='123456789', size=size, path_display=path, content_hash=digest)


def page(entries, more=False):
    return SimpleNamespace(entries=entries, has_more=more, cursor='cursor')


class DuplicateTests(unittest.TestCase):
    def test_roots(self):
        self.assertEqual(duplicates.normalize_roots([]), [''])
        self.assertEqual(duplicates.normalize_roots(['/Photos/a', 'Photos/', '/photos', '/Other']), ['/Other', '/Photos'])
        self.assertEqual(duplicates.normalize_roots(['/Photos', '/']), [''])
        for root in ['/a/../b', '/a//b']:
            with self.assertRaises(ValueError):
                duplicates.normalize_roots([root])

    def test_pagination_cross_root_duplicates_and_unique_ids(self):
        client = MagicMock()
        a = file('/one/a')
        client.files_list_folder.side_effect = [page([a, FolderMetadata(name='folder', id='id:folder')], True),
                                               page([file('/two/b'), a, file('/two/c', size=4)])]
        client.files_list_folder_continue.return_value = page([file('/one/empty', size=0), file('/one/empty2', size=0)])
        with sqlite3.connect(':memory:') as db:
            result = duplicates.scan(client, ['/one', '/two'], db)
        self.assertEqual(result['summary']['files_scanned'], 5)
        self.assertEqual(result['summary']['duplicate_groups'], 2)
        self.assertEqual(result['summary']['redundant_bytes'], 3)
        self.assertEqual(result['groups'][0]['copies'], 2)
        client.files_list_folder_continue.assert_called_once_with('cursor')
        self.assertTrue(client.files_list_folder.call_args.kwargs['recursive'])

    def test_cli_exports_and_unverified(self):
        client = MagicMock()
        client.__enter__.return_value = client
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'DROPBOX_ACCESS_TOKEN': 'fake'}), patch('dropbox.Dropbox', return_value=client):
            client.files_list_folder.return_value = page([file('/a'), file('/b')])
            target = Path(directory) / 'result.json'
            csv = Path(directory) / 'result.csv'
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(duplicates.main(['--json', str(target), '--csv', str(csv)]), 1)
            self.assertEqual(json.loads(target.read_text())['summary']['redundant_copies'], 1)
            self.assertIn('/b', csv.read_text())
            client.files_list_folder.return_value = page([file('/unknown', digest=None)])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(duplicates.main([]), 2)
            client.files_list_folder.return_value = page([])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(duplicates.main([]), 0)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(duplicates.main(['--json', str(target)]), 2)

    def test_auth_failure_explains_credentials_without_exposing_secrets(self):
        client = MagicMock()
        client.__enter__.return_value = client
        client.files_list_folder.side_effect = AuthError('request-id', 'secret-token')
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {'DROPBOX_ACCESS_TOKEN': 'fake'}), patch('dropbox.Dropbox', return_value=client), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(duplicates.main([]), 2)
        self.assertEqual(out.getvalue(), '')
        self.assertIn('may have expired', err.getvalue())
        self.assertIn('DROPBOX_ACCESS_TOKEN', err.getvalue())
        self.assertIn('Refresh credentials are optional', err.getvalue())
        self.assertNotIn('secret-token', err.getvalue())

    def test_failure_emits_no_success_report_or_secret(self):
        client = MagicMock()
        client.__enter__.return_value = client
        client.files_list_folder.return_value = page([file('/a')], True)
        client.files_list_folder_continue.side_effect = Exception('secret-token')
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {'DROPBOX_ACCESS_TOKEN': 'fake'}), patch('dropbox.Dropbox', return_value=client), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(duplicates.main([]), 2)
        self.assertEqual(out.getvalue(), '')
        self.assertNotIn('secret-token', err.getvalue())


if __name__ == '__main__':
    unittest.main()
