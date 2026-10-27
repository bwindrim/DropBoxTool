import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

import dropbox_audit as audit
from dropbox.files import FileMetadata, FolderMetadata, DeletedMetadata


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'backup'
        self.root.mkdir()
        self.db = audit.connect(Path(self.temp.name) / 'catalogue.db')
        self.addCleanup(self.db.close)

    def test_hash_boundaries(self):
        for length in (0, 1, audit.BLOCK - 1, audit.BLOCK, audit.BLOCK + 1, 2 * audit.BLOCK):
            data = b'x' * length
            path = self.root / 'file'
            path.write_bytes(data)
            expected = hashlib.sha256(b''.join(hashlib.sha256(data[i:i + audit.BLOCK]).digest() for i in range(0, length, audit.BLOCK))).hexdigest()
            self.assertEqual(audit.content_hash(path)[0], expected)

    def test_changing_file(self):
        path = self.root / 'file'
        path.write_bytes(b'hello')
        real_stat = os.stat
        def changed(*args, **kwargs):
            path.write_bytes(b'changed')
            return real_stat(*args, **kwargs)
        with patch.object(audit.os, 'stat', side_effect=changed):
            with self.assertRaisesRegex(OSError, 'changed'):
                audit.content_hash(path)

    def test_cache_recovery_and_full(self):
        (self.root / 'a').write_text('a')
        audit.local_scan(self.db, 1, self.root)
        with patch.object(audit, 'content_hash', side_effect=AssertionError('cache not used')):
            audit.local_scan(self.db, 2, self.root)
        with patch.object(audit, 'content_hash', wraps=audit.content_hash) as hashed:
            audit.local_scan(self.db, 3, self.root, full=True)
            self.assertEqual(hashed.call_count, 1)

    def test_symlink_and_unreadable(self):
        (self.root / 'link').symlink_to('/etc/passwd')
        self.assertEqual(audit.local_scan(self.db, 1, self.root), 1)
        with patch.object(audit.os, 'fwalk', side_effect=lambda *a, **k: (k['onerror'](PermissionError('denied')) or iter(()))):
            self.assertEqual(audit.local_scan(self.db, 2, self.root), 1)

    def populate(self, side, path, digest='abc', kind='file', scan=1):
        audit.entry(self.db, scan, side, path, kind, size=3, hash=digest if kind == 'file' else None)

    def test_comparison(self):
        for side in ('local', 'remote'):
            self.populate(side, 'same')
        self.populate('local', 'missing')
        self.populate('remote', 'extra', 'other')
        self.populate('local', 'modified', 'old')
        self.populate('remote', 'modified', 'new')
        self.populate('remote', 'renamed')
        self.populate('local', 'empty', kind='folder')
        self.assertEqual(audit.compare(self.db, 1), 1)
        categories = {r[0] for r in self.db.execute('SELECT category FROM issues')}
        self.assertTrue({'missing_remotely', 'extra_remotely', 'content_mismatch', 'possible_rename', 'directory_mismatch'} <= categories)

    def test_collision(self):
        self.populate('local', 'A')
        self.populate('local', 'a')
        audit.compare(self.db, 1)
        self.assertEqual(self.db.execute("SELECT count(*) FROM issues WHERE category='path_collision'").fetchone()[0], 2)

    def test_historical_and_baseline(self):
        self.populate('local', 'gone')
        audit.compare(self.db, 1)
        self.populate('local', 'gone', scan=2)
        audit.compare(self.db, 2)
        self.assertEqual(self.db.execute("SELECT is_new FROM issues WHERE scan=2 AND category='missing_remotely'").fetchone()[0], 0)
        audit.compare(self.db, 3)
        self.assertEqual(self.db.execute("SELECT category FROM issues WHERE scan=3").fetchone()[0], 'local_baseline_changed')

    def file(self, path):
        return FileMetadata(name=path.split('/')[-1], id='id:' + path, client_modified=__import__('datetime').datetime(2020, 1, 1), server_modified=__import__('datetime').datetime(2020, 1, 1), rev='123456789', size=1, path_display=path, content_hash='a' * 64)

    def page(self, entries, cursor, more=False):
        return SimpleNamespace(entries=entries, cursor=cursor, has_more=more)

    def test_pagination_failure_atomicity_and_deletion(self):
        client = Mock()
        client.files_list_folder.return_value = self.page([FolderMetadata(name='dir', id='id:dir', path_display='/base/dir'), self.file('/base/dir/a')], 'p1', True)
        client.files_list_folder_continue.return_value = self.page([self.file('/base/b')], 'p2')
        audit.remote_scan(self.db, 1, client, '/base')
        self.assertEqual(audit.setting(self.db, 'cursor'), 'p2')
        client.files_list_folder_continue.side_effect = [self.page([DeletedMetadata(name='dir', path_display='/base/dir')], 'p3', True), RuntimeError('offline')]
        with self.assertRaises(RuntimeError):
            audit.remote_scan(self.db, 2, client, '/base')
        self.assertEqual(audit.setting(self.db, 'cursor'), 'p2')
        self.assertEqual(self.db.execute('SELECT count(*) FROM entries WHERE scan=2').fetchone()[0], 0)
        client.files_list_folder_continue.side_effect = None
        client.files_list_folder_continue.return_value = self.page([DeletedMetadata(name='dir', path_display='/base/dir')], 'p4')
        audit.remote_scan(self.db, 3, client, '/base')
        self.assertEqual([r[0] for r in self.db.execute('SELECT path FROM entries WHERE scan=3')], ['b'])

    def test_cli_end_to_end_and_history(self):
        import contextlib
        import io
        database = str(Path(self.temp.name) / 'cli.db')
        (self.root / 'a').write_bytes(b'x')
        metadata = self.file('/base/a')
        metadata.content_hash = audit.content_hash(self.root / 'a')[0]
        client = Mock()
        client.files_list_folder.return_value = self.page([metadata], 'c1')
        client.files_list_folder_continue.return_value = self.page([], 'c2')
        with contextlib.redirect_stdout(io.StringIO()), patch.dict(os.environ, {'DROPBOX_ACCESS_TOKEN': 'fake'}), patch('dropbox.Dropbox', return_value=client):
            self.assertEqual(audit.main(['--db', database, 'init', '--local-root', str(self.root), '--dropbox-root', '/base']), 0)
            self.assertEqual(audit.main(['--db', database, 'initial']), 0)
            self.assertEqual(audit.main(['--db', database, 'quick']), 0)
            self.assertEqual(audit.main(['--db', database, 'report']), 0)
            (self.root / 'a').write_bytes(b'changed')
            self.assertEqual(audit.main(['--db', database, 'quick']), 1)

    def test_local_only_workflow(self):
        import contextlib
        import io
        database = str(Path(self.temp.name) / 'local.db')
        (self.root / 'a').write_bytes(b'x')
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.dict(os.environ, {}, clear=True), patch('dropbox.Dropbox', side_effect=AssertionError('Dropbox accessed')):
            self.assertEqual(audit.main(['--db', database, 'init', '--local-root', str(self.root), '--dropbox-root', '/base']), 0)
            csv_path = str(Path(self.temp.name) / 'local.csv')
            json_path = str(Path(self.temp.name) / 'local.json')
            self.assertEqual(audit.main(['--db', database, 'local', '--csv', csv_path, '--json', json_path]), 0)
            with patch.object(audit, 'content_hash', side_effect=AssertionError('cache not used')):
                self.assertEqual(audit.main(['--db', database, 'local']), 0)
            with patch.object(audit, 'content_hash', wraps=audit.content_hash) as hashed:
                self.assertEqual(audit.main(['--db', database, 'local', '--full']), 0)
                self.assertEqual(hashed.call_count, 1)
            self.assertEqual(audit.main(['--db', database, 'report', '--scan', '1']), 0)
            self.assertEqual(audit.main(['--db', database, 'report']), 0)
            (self.root / 'a').unlink()
            self.assertEqual(audit.main(['--db', database, 'local']), 1)
        import json
        saved = json.loads(Path(json_path).read_text())
        self.assertFalse(saved['summary']['comparison_performed'])
        self.assertIsNone(saved['summary']['remote'])
        self.assertEqual(saved['summary']['local']['files'], 1)
        db = audit.connect(database)
        self.addCleanup(db.close)
        self.assertEqual(audit.setting(db, 'baseline_scan'), '1')
        self.assertIsNone(audit.setting(db, 'comparison_scan'))
        self.assertIsNone(audit.setting(db, 'cursor'))
        self.assertEqual(db.execute("SELECT count(*) FROM entries WHERE side='remote'").fetchone()[0], 0)
        self.assertEqual(db.execute("SELECT category FROM issues WHERE scan=4").fetchone()[0], 'local_baseline_changed')
        # A local baseline must not prevent the later first Dropbox comparison.
        metadata = self.file('/base/a')
        client = Mock()
        client.files_list_folder.return_value = self.page([metadata], 'cursor')
        with contextlib.redirect_stdout(io.StringIO()), patch.dict(os.environ, {'DROPBOX_ACCESS_TOKEN': 'fake'}), patch('dropbox.Dropbox', return_value=client):
            self.assertEqual(audit.main(['--db', database, 'initial']), 1)
            client.files_list_folder.assert_called_once()

    def test_incomplete_local_scan_keeps_baseline_and_cursor(self):
        import contextlib
        import io
        database = str(Path(self.temp.name) / 'incomplete.db')
        (self.root / 'a').write_bytes(b'x')
        with contextlib.redirect_stdout(io.StringIO()), patch('dropbox.Dropbox', side_effect=AssertionError('Dropbox accessed')):
            self.assertEqual(audit.main(['--db', database, 'init', '--local-root', str(self.root), '--dropbox-root', '/base']), 0)
            with patch.object(audit, 'content_hash', side_effect=OSError('unreadable')):
                self.assertEqual(audit.main(['--db', database, 'local']), 2)
            db = audit.connect(database)
            self.assertIsNone(audit.setting(db, 'baseline_scan'))
            self.assertIsNone(audit.setting(db, 'local_scan'))
            self.assertEqual(db.execute('SELECT category FROM issues').fetchone()[0], 'unverified')
            audit.put(db, 'cursor', 'trusted')
            db.commit()
            db.close()
            self.assertEqual(audit.main(['--db', database, 'local']), 0)
            with patch.object(audit, 'content_hash', side_effect=KeyboardInterrupt):
                self.assertEqual(audit.main(['--db', database, 'local', '--full']), 2)
            db = audit.connect(database)
            self.assertEqual(audit.setting(db, 'baseline_scan'), '2')
            self.assertEqual(audit.setting(db, 'local_scan'), '2')
            self.assertEqual(audit.setting(db, 'cursor'), 'trusted')
            self.assertEqual(db.execute('SELECT status FROM scans WHERE id=3').fetchone()[0], 'incomplete')
            db.close()

    def test_remote_root_metadata_on_later_page(self):
        client = Mock()
        client.files_list_folder.return_value = self.page([self.file('/Photos/a')], 'p1', True)
        client.files_list_folder_continue.side_effect = [
            self.page([self.file('/Photos/b')], 'p2', True),
            self.page([FolderMetadata(name='Photos', id='id:root', path_display='/photos'), self.file('/Photos/c')], 'p3'),
        ]
        audit.remote_scan(self.db, 1, client, '/Photos')
        self.assertEqual([r[0] for r in self.db.execute('SELECT path FROM entries ORDER BY path')], ['a', 'b', 'c'])
        self.assertEqual(audit.setting(self.db, 'cursor'), 'p3')

    def test_remote_path_validation_and_unicode_root(self):
        client = Mock()
        client.files_list_folder.return_value = self.page([self.file('/Cafe\u0301/a')], 'ok')
        audit.remote_scan(self.db, 1, client, '/Caf\u00e9')
        self.assertEqual(self.db.execute('SELECT path FROM entries WHERE scan=1').fetchone()[0], 'a')
        for path in ('/PhotosOther/a', '/Elsewhere/a', '/Photos/../a'):
            client.files_list_folder.return_value = self.page([self.file(path)], 'bad')
            with self.assertRaisesRegex(ValueError, 'outside the configured root') as caught:
                audit.remote_scan(self.db, 2, client, '/Photos', fresh=True)
            self.assertIn(repr(path), str(caught.exception))
            self.assertEqual(audit.setting(self.db, 'cursor'), 'ok')
            self.assertEqual(self.db.execute('SELECT count(*) FROM entries WHERE scan=2').fetchone()[0], 0)
        client.files_list_folder.return_value = self.page([DeletedMetadata(name='Photos', path_display='/Photos')], 'deleted')
        with self.assertRaisesRegex(ValueError, 'non-folder metadata'):
            audit.remote_scan(self.db, 2, client, '/Photos', fresh=True)

    def test_offline_compare_latest_local_and_saved_remote(self):
        import contextlib
        import io
        import json
        database = str(Path(self.temp.name) / 'offline.db')
        (self.root / 'a').write_bytes(b'x')
        metadata = self.file('/base/a')
        metadata.content_hash = audit.content_hash(self.root / 'a')[0]
        client = Mock()
        client.files_list_folder.return_value = self.page([metadata], 'trusted-cursor')
        with contextlib.redirect_stdout(io.StringIO()), patch.dict(os.environ, {'DROPBOX_ACCESS_TOKEN': 'fake'}), patch('dropbox.Dropbox', return_value=client):
            self.assertEqual(audit.main(['--db', database, 'init', '--local-root', str(self.root), '--dropbox-root', '/base']), 0)
            self.assertEqual(audit.main(['--db', database, 'initial']), 0)
            (self.root / 'a').write_bytes(b'changed')
            self.assertEqual(audit.main(['--db', database, 'local']), 1)
        # Simulate a disconnected backup disk. Offline comparison must still work.
        self.root.rename(Path(self.temp.name) / 'unmounted')
        json_path = str(Path(self.temp.name) / 'offline.json')
        csv_path = str(Path(self.temp.name) / 'offline.csv')
        with contextlib.redirect_stdout(io.StringIO()), patch.dict(os.environ, {}, clear=True), patch('dropbox.Dropbox', side_effect=AssertionError('Dropbox accessed')), patch.object(audit, 'local_scan', side_effect=AssertionError('local scanned')), patch.object(audit, 'remote_scan', side_effect=AssertionError('remote scanned')):
            self.assertEqual(audit.main(['--db', database, 'compare', '--json', json_path, '--csv', csv_path]), 1)
            self.assertEqual(audit.main(['--db', database, 'compare']), 1)
            self.assertEqual(audit.main(['--db', database, 'report']), 1)
        saved = json.loads(Path(json_path).read_text())
        self.assertEqual(saved['summary']['sources']['local']['id'], 2)
        self.assertEqual(saved['summary']['sources']['remote']['id'], 1)
        self.assertEqual(saved['summary']['discrepancies']['content_mismatch'], 1)
        self.assertIn('content_mismatch', Path(csv_path).read_text())
        db = audit.connect(database)
        self.addCleanup(db.close)
        self.assertEqual(audit.setting(db, 'cursor'), 'trusted-cursor')
        self.assertEqual(audit.setting(db, 'remote_scan'), '1')
        self.assertEqual(audit.setting(db, 'baseline_scan'), '1')
        self.assertEqual(audit.setting(db, 'local_scan'), '2')
        self.assertEqual(db.execute("SELECT is_new FROM issues WHERE scan=4 AND category='content_mismatch'").fetchone()[0], 0)

    def test_offline_compare_missing_and_empty_catalogues(self):
        with self.assertRaisesRegex(ValueError, 'local catalogue'):
            audit.offline_compare(self.db)
        self.db.execute("INSERT INTO scans VALUES (1,'local',1,2,'complete',NULL)")
        with self.assertRaisesRegex(ValueError, 'remote catalogue'):
            audit.offline_compare(self.db)
        self.db.execute("INSERT INTO scans VALUES (2,'initial',2,3,'complete',NULL)")
        audit.put(self.db, 'remote_scan', 2)
        # Newer incomplete local data must not be used.
        self.db.execute("INSERT INTO scans VALUES (3,'local',3,4,'incomplete',NULL)")
        self.populate('local', 'partial', scan=3)
        self.db.commit()
        scan = audit.offline_compare(self.db)
        self.assertEqual(tuple(self.db.execute('SELECT local_scan,remote_scan FROM comparison_sources WHERE scan=?', (scan,)).fetchone()), (2, 2))
        self.assertEqual(self.db.execute('SELECT count(*) FROM issues WHERE scan=?', (scan,)).fetchone()[0], 0)
        self.assertEqual(self.db.execute('SELECT status FROM scans WHERE id=?', (scan,)).fetchone()[0], 'complete')

    def test_offline_compare_atomicity_and_unverified_remote(self):
        self.db.execute("INSERT INTO scans VALUES (1,'initial',1,2,'incomplete',NULL)")
        self.db.execute("INSERT INTO scans VALUES (2,'local',2,3,'complete',NULL)")
        self.populate('local', 'a', scan=2)
        audit.entry(self.db, 1, 'remote', 'a', 'file', size=3, error='no hash')
        audit.put(self.db, 'remote_scan', 1)
        self.db.commit()
        with patch.object(audit, 'compare', side_effect=RuntimeError('interrupted')):
            with self.assertRaises(RuntimeError):
                audit.offline_compare(self.db)
        self.assertEqual(self.db.execute('SELECT count(*) FROM scans').fetchone()[0], 2)
        self.assertIsNone(audit.setting(self.db, 'comparison_scan'))
        scan = audit.offline_compare(self.db)
        self.assertEqual(self.db.execute('SELECT status FROM scans WHERE id=?', (scan,)).fetchone()[0], 'incomplete')
        self.assertEqual(self.db.execute('SELECT category FROM issues WHERE scan=?', (scan,)).fetchone()[0], 'unverified')

    def test_ignore_hidden_files_preserves_directories_and_cache(self):
        (self.root / '.hidden-dir').mkdir()
        (self.root / '.hidden-dir' / 'visible').write_text('keep')
        (self.root / '.hidden-dir' / '.hidden').write_text('skip')
        (self.root / '.dotfile').write_text('skip')
        (self.root / 'visible').write_text('keep')
        audit.local_scan(self.db, 1, self.root)
        audit.put(self.db, 'baseline_scan', 1)
        self.db.commit()
        with patch.object(audit, 'content_hash', side_effect=AssertionError('cache should be reused')):
            self.assertEqual(audit.local_scan(self.db, 2, self.root, ignore_hidden=True), 0)
        paths = {row[0] for row in self.db.execute('SELECT path FROM entries WHERE scan=2')}
        self.assertEqual(paths, {'.hidden-dir', '.hidden-dir/visible', 'visible'})
        issues = []
        audit.baseline_changes(self.db, 2, lambda *args, **kwargs: issues.append((args, kwargs)))
        self.assertEqual(issues, [])
        self.assertTrue(audit.ignores_hidden(self.db, 2))
        self.assertEqual(self.db.execute('SELECT count(*) FROM cache').fetchone()[0], 4)
        # Removing an actual hidden directory is still a baseline change.
        self.db.execute("DELETE FROM entries WHERE scan=2 AND path='.hidden-dir'")
        audit.baseline_changes(self.db, 2, lambda *args, **kwargs: issues.append((args, kwargs)))
        self.assertEqual(issues[0][0], ('local_baseline_changed', '.hidden-dir'))

    def test_ignore_hidden_cli_and_offline_compare(self):
        import contextlib
        import io
        import json
        database = str(Path(self.temp.name) / 'hidden.db')
        (self.root / '.dotfile').write_text('skip')
        (self.root / 'visible').write_text('keep')
        with contextlib.redirect_stdout(io.StringIO()), patch('dropbox.Dropbox', side_effect=AssertionError('Dropbox accessed')):
            self.assertEqual(audit.main(['--db', database, 'init', '--local-root', str(self.root), '--dropbox-root', '/base']), 0)
            self.assertEqual(audit.main(['--db', database, 'local']), 0)
            self.assertEqual(audit.main(['--db', database, 'local', '--ignore-hidden']), 0)
        db = audit.connect(database)
        self.addCleanup(db.close)
        db.execute("INSERT INTO scans VALUES (3,'initial',1,2,'complete',NULL)")
        # Emulate an older trusted remote snapshot with just the visible file.
        db.execute("INSERT INTO entries SELECT 3,'remote',path,kind,size,mtime,hash,file_id,verified,error,norm FROM entries WHERE scan=2 AND path='visible'")
        db.execute("UPDATE scans SET status='incomplete' WHERE id=3")
        audit.put(db, 'remote_scan', 3)
        db.commit()
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch('dropbox.Dropbox', side_effect=AssertionError('Dropbox accessed')):
            self.assertEqual(audit.main(['--db', database, 'compare']), 0)
        self.assertTrue(json.loads(output.getvalue())['ignore_hidden_local_files'])
        self.assertTrue(audit.ignores_hidden(db, 4))
        self.assertEqual(db.execute("SELECT count(*) FROM issues WHERE scan=4").fetchone()[0], 0)
        # The default remains inclusive on subsequent scans.
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(audit.main(['--db', database, 'local']), 0)
        self.assertFalse(audit.ignores_hidden(db, 5))
        self.assertIsNotNone(db.execute("SELECT 1 FROM entries WHERE scan=5 AND path='.dotfile'").fetchone())

    def test_remote_move_id_history(self):
        client = Mock()
        original = self.file('/base/a')
        client.files_list_folder.return_value = self.page([original], 'c1')
        audit.remote_scan(self.db, 1, client, '/base')
        moved = self.file('/base/b')
        moved.id = original.id
        client.files_list_folder_continue.return_value = self.page([DeletedMetadata(name='a', path_display='/base/a'), moved], 'c2')
        audit.remote_scan(self.db, 2, client, '/base')
        event = self.db.execute('SELECT old_path,new_path,event FROM remote_events').fetchone()
        self.assertEqual(tuple(event), ('a', 'b', 'moved'))

    def test_csv_filters_are_independent_and_do_not_change_results(self):
        import contextlib
        import csv
        import io
        import json
        import itertools
        audit.put(self.db, 'local_root', self.root)
        self.db.execute("INSERT INTO scans VALUES (1,'local',1,2,'complete',NULL)")
        self.db.execute("INSERT INTO scans VALUES (2,'compare',2,3,'complete',NULL)")
        self.populate('local', 'removed', scan=1)
        audit.put(self.db, 'baseline_scan', 1)
        self.populate('local', 'missing', scan=2)
        self.populate('remote', 'extra', scan=2)
        self.populate('remote', 'extra-dir', kind='folder', scan=2)
        audit.entry(self.db, 2, 'remote', 'remote-unverified', 'file', error='no hash')
        self.populate('local', 'missing-dir', kind='folder', scan=2)
        self.populate('local', 'type-diff', kind='folder', scan=2)
        self.populate('remote', 'type-diff', scan=2)
        audit.compare(self.db, 2)
        original_count = self.db.execute('SELECT count(*) FROM issues WHERE scan=2').fetchone()[0]
        database = str(Path(self.temp.name) / 'catalogue.db')
        for omit_remote, omit_baseline in itertools.product((False, True), repeat=2):
            tag = f'{omit_remote}-{omit_baseline}'
            csv_path = Path(self.temp.name) / (tag + '.csv')
            json_path = Path(self.temp.name) / (tag + '.json')
            args = ['--db', database, 'report', '--scan', '2', '--csv', str(csv_path), '--json', str(json_path)]
            if omit_remote:
                args.append('--csv-omit-remote-only')
            if omit_baseline:
                args.append('--csv-omit-baseline-changes')
            with contextlib.redirect_stdout(io.StringIO()), patch.object(audit, 'local_scan', side_effect=AssertionError('scan called')):
                self.assertEqual(audit.main(args), 1)
            with csv_path.open(newline='') as source:
                rows = list(csv.DictReader(source))
            paths = {row['path'] for row in rows}
            for path in ('extra', 'extra-dir', 'remote-unverified'):
                self.assertEqual(path in paths, not omit_remote)
            self.assertEqual('removed' in paths, not omit_baseline)
            self.assertTrue({'missing', 'missing-dir', 'type-diff'} <= paths)
            saved = json.loads(json_path.read_text())
            self.assertEqual(len(saved['issues']), original_count)
            self.assertEqual(saved['summary']['discrepancies']['extra_remotely'], 1)
            self.assertEqual(self.db.execute('SELECT count(*) FROM issues WHERE scan=2').fetchone()[0], original_count)

    def test_duplicates_offline_reports_and_preserves_catalogue(self):
        import contextlib
        import csv
        import io
        import json
        audit.put(self.db, 'local_root', self.root)
        audit.put(self.db, 'dropbox_root', '/Photos')
        # Overall scan status may be incomplete despite a trusted remote snapshot.
        self.db.execute("INSERT INTO scans VALUES (1,'initial',1,2,'incomplete',NULL)")
        audit.put(self.db, 'remote_scan', 1)
        audit.put(self.db, 'cursor', 'trusted')
        for path, size, digest in [('a', 3, 'hash'), ('nested/b', 3, 'hash'),
                                   ('different-size', 4, 'hash'), ('empty', 0, 'empty-hash'),
                                   ('empty-copy', 0, 'empty-hash')]:
            audit.entry(self.db, 1, 'remote', path, 'file', size=size, hash=digest, file_id='id:' + path)
        audit.entry(self.db, 1, 'remote', 'folder', 'folder')
        audit.entry(self.db, 1, 'local', 'local-only', 'file', size=3, hash='hash')
        # A newer untrusted snapshot must not be used.
        audit.entry(self.db, 2, 'remote', 'untrusted', 'file', size=3, hash='hash')
        self.db.commit()
        before = list(self.db.iterdump())
        json_path = Path(self.temp.name) / 'duplicates.json'
        csv_path = Path(self.temp.name) / 'duplicates.csv'
        database = str(Path(self.temp.name) / 'catalogue.db')
        self.root.rename(Path(self.temp.name) / 'unmounted')
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.dict(os.environ, {}, clear=True), patch('dropbox.Dropbox', side_effect=AssertionError('Dropbox accessed')), patch.object(audit, 'local_scan', side_effect=AssertionError('local scanned')):
            self.assertEqual(audit.main(['--db', database, 'duplicates', '--json', str(json_path), '--csv', str(csv_path)]), 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result, json.loads(json_path.read_text()))
        self.assertEqual(result['summary']['source']['id'], 1)
        self.assertEqual(result['summary']['dropbox_root'], '/Photos')
        self.assertEqual(result['summary']['files_scanned'], 5)
        self.assertEqual(result['summary']['duplicate_groups'], 2)
        self.assertEqual(result['summary']['redundant_bytes'], 3)
        with csv_path.open(newline='') as source:
            self.assertEqual(len(list(csv.DictReader(source))), 4)
        self.assertEqual(list(self.db.iterdump()), before)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(audit.main(['--db', database, 'duplicates', '--json', str(json_path)]), 2)

    def test_duplicates_missing_empty_and_unverified(self):
        import contextlib
        import io
        import json
        with self.assertRaisesRegex(ValueError, 'No saved remote catalogue'):
            audit.duplicates_report(self.db)
        audit.put(self.db, 'remote_scan', 1)
        audit.put(self.db, 'dropbox_root', '')
        self.db.execute("INSERT INTO scans VALUES (1,'full',1,2,'complete',NULL)")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(audit.duplicates_report(self.db), 0)
        audit.entry(self.db, 1, 'remote', 'no-hash', 'file', size=3)
        audit.entry(self.db, 1, 'remote', 'bad', 'file', size=3, hash='hash', error='unverified')
        audit.entry(self.db, 1, 'remote', 'good', 'file', size=3, hash='hash')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(audit.duplicates_report(self.db), 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result['summary']['unverified_files'], 2)
        self.assertFalse(result['summary']['complete'])
        self.assertEqual(result['groups'], [])

    def test_duplicates_subdirectories_scope_counts_and_boundaries(self):
        import contextlib
        import io
        import json
        audit.put(self.db, 'remote_scan', 1)
        audit.put(self.db, 'dropbox_root', '/Photos')
        self.db.execute("INSERT INTO scans VALUES (1,'full',1,2,'complete',NULL)")
        for directory in ('A', 'A/nested', 'B', 'A_other', 'wild%_'):
            audit.entry(self.db, 1, 'remote', directory, 'folder')
        for path in ('A/one', 'A/nested/two', 'B/three', 'A_other/four', 'wild%_/five'):
            audit.entry(self.db, 1, 'remote', path, 'file', size=3, hash='same')
        audit.entry(self.db, 1, 'remote', 'B/unknown', 'file', size=3)
        def run(directories):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = audit.duplicates_report(self.db, directories=directories)
            return code, json.loads(output.getvalue())
        code, result = run(['a', '/A/nested/'])
        self.assertEqual(code, 1)
        self.assertEqual(result['summary']['files_scanned'], 2)
        self.assertEqual(result['summary']['redundant_bytes'], 3)
        self.assertEqual({f['path'] for f in result['groups'][0]['files']}, {'A/one', 'A/nested/two'})
        code, result = run(['A/nested', 'B'])
        self.assertEqual(code, 2)
        self.assertEqual(result['summary']['files_scanned'], 3)
        self.assertEqual(result['summary']['duplicate_files'], 2)
        self.assertEqual(result['unverified'][0]['path'], 'B/unknown')
        code, result = run(['wild%_'])
        self.assertEqual(code, 0)
        self.assertEqual(result['summary']['files_scanned'], 1)
        for directory in ('missing', 'A/one', 'A/../B', 'A//nested'):
            with self.assertRaises(ValueError):
                run([directory])
        self.assertEqual(run(['/'])[1]['summary']['files_scanned'], 6)
        args = audit.build_parser().parse_args(['--db', 'audit.sqlite', 'duplicates', 'A', 'B', '--csv', 'out.csv'])
        self.assertEqual(args.directories, ['A', 'B'])

    def test_safe_output(self):
        with self.assertRaises(ValueError):
            audit.safe_output(self.root / 'db', self.root, Path('/other'))


if __name__ == '__main__':
    unittest.main()
