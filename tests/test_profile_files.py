"""Check local source paths and native format hints from an explicit selection."""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


FIXTURES = Path(__file__).resolve().parent / 'fixtures'
ROOT = FIXTURES.parents[1]


class ProfileFileTests(unittest.TestCase):
    def test_file_journal_discovery_preserves_a_literal_directory_name(self):
        from src.techexpert import profile_files

        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp) / 'Orders'
            base.mkdir()
            (base / '1Cv8.1CD').touch()
            request = dict(items=[dict(id='selected', kind='file_jr', path=str(base) + ' ')])
            row, = profile_files.inspect(request)['items']
            self.assertEqual(row['status'], 'unsupported_path' if os.name == 'nt' else 'not_found')

    def test_file_infobase_suggests_only_a_checked_journal_under_its_root(self):
        from src.techexpert import profile_files

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = root / 'Orders'
            base.mkdir()
            (base / '1Cv8.1CD').write_bytes(b'private infobase bytes')
            journal = base / '1Cv8Log'
            shutil.copytree(FIXTURES / 'native-jr', journal)
            request = dict(items=[dict(id='orders', kind='file_jr', path=str(base)),
                                  dict(id='missing', kind='file_jr', path=str(root / 'Missing'))])
            with patch.object(profile_files, '_peek', wraps=profile_files._peek) as peek:
                found, missing = profile_files.inspect(request)['items']
                self.assertTrue(peek.call_args_list)
                self.assertTrue(all(call.args[0].parent == journal for call in peek.call_args_list))
            self.assertEqual(found['status'], 'header_seen')
            self.assertEqual(found['format'], 'jr_sequential')
            self.assertEqual(found['candidate_path'], str(journal))
            self.assertFalse(found['coverage_verified'])
            self.assertEqual(missing['status'], 'not_found')
            self.assertIsNone(missing['candidate_path'])
            self.assertNotIn('private infobase bytes', json.dumps(found))
            self.assertEqual(found['version_status'], 'unknown')
            (journal / '1Cv8.lgf').write_bytes(b'wrong dictionary')
            blocked = profile_files.inspect(request)['items'][0]
            self.assertEqual(blocked['status'], 'header_unrecognized')
            self.assertIsNone(blocked['candidate_path'])

    def test_configured_paths_keep_format_location_and_snapshot_requirements_distinct(self):
        from src.techexpert import profile_files

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sqlite = root / '1Cv8.lgd'
            with sqlite3.connect(sqlite) as database:
                database.execute('create table example (name text)')
            database.close()
            (root / '1Cv8.lgd-wal').write_bytes(b'not read')
            tj = root / 'tech' / 'rphost_1'
            tj.mkdir(parents=True)
            shutil.copyfile(FIXTURES / 'native-tj' / 'folders-minute.txt', tj / '26111610.log')
            request = dict(items=[
                dict(id='jw', kind='jr', path=str(sqlite)),
                dict(id='tj', kind='tj', path=str(tj.parent)),
                dict(id='away', kind='tj', path='//file.invalid/shared/tj'),
                dict(id='git', kind='source', path='https://git.invalid/project', source_kind='git'),
            ])
            result = profile_files.inspect(request)
            states = {row['id']: row for row in result['items']}
            self.assertEqual(states['jw']['status'], 'snapshot_required')
            self.assertEqual(states['jw']['format'], 'jr_sqlite')
            self.assertEqual(states['tj']['status'], 'header_seen')
            self.assertEqual(states['tj']['format'], 'tj_minute')
            self.assertEqual(states['away']['status'], 'separate_access_required')
            self.assertEqual(states['git']['status'], 'separate_access_required')
            self.assertFalse(result['collection_started'])

    def test_source_selection_skips_unselected_modes_and_remote_settings(self):
        from src.techexpert import profile_files

        chosen = profile_files.from_bases([
            dict(id='local', mode='file', connection='D:/Orders'),
            dict(id='server', mode='server', connection='Srvr=host;Ref=Orders'),
            dict(id='unknown', mode='unknown', connection=''),
            dict(id='missing-address', mode='file', connection=''),
        ])
        self.assertEqual(chosen, dict(items=[dict(id='local', kind='file_jr', path='D:/Orders')]))

    def test_find_journals_resolves_saved_and_explicit_resource_profiles(self):
        from src.techexpert import profile_resources, profiles

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = root / 'state'
            profile = profile_resources.upgrade_profile(dict(schema_version=1, name='File infobase', bases=[
                dict(id='a', name='Orders', mode='file', connection=str(root / 'missing'))], sources=[]))
            profiles.save_profile(state, profile, expected_revision=0)
            choice = root / 'profile.json'
            choice.write_text(json.dumps(profile), encoding='utf-8')
            legacy = root / 'legacy.json'
            legacy.write_text(json.dumps(dict(schema_version=1, name='Legacy infobase', bases=[
                dict(id='a', name='Orders', mode='file', connection='File="' + str(root / 'missing') + '";')],
                sources=[])), encoding='utf-8')
            command = [sys.executable, '-B', '-X', 'utf8', str(ROOT / 'techexpert.py'), '--state-dir', str(state),
                       'profile-files', '--find-journals']
            for extra in ([], [str(choice)], [str(legacy)]):
                completed = subprocess.run(command + extra, capture_output=True, timeout=30)
                self.assertEqual(completed.returncode, 0, completed.stdout)
                row, = json.loads(completed.stdout)['data']['items']
                self.assertEqual((row['id'], row['status']), ('a', 'not_found'))
            self.assertEqual(profiles.load_profile(state)['revision'], 1)
