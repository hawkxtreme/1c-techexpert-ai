import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def profile():
    return dict(schema_version=1, name='Local', bases=[dict(id='a', name='IB', mode='file', connection='D:/IB')],
                sources=[dict(id='tj-a', type='tj', path='D:/logs', host='host-a', base_ids=['a'])])


class ProfileTests(unittest.TestCase):
    def test_cli_reads_the_requested_profile_revision(self):
        from src.techexpert.profiles import save_profile

        with tempfile.TemporaryDirectory() as temp:
            first = save_profile(temp, profile(), expected_revision=0)
            current = save_profile(temp, dict(profile(), name='Another environment'), expected_revision=1)
            cli = Path(__file__).resolve().parents[1] / 'techexpert.py'
            command = [sys.executable, str(cli), '--state-dir', temp, 'profile']
            result = subprocess.run(command + ['--revision', str(first['revision']), '--resolved'],
                                    capture_output=True, check=True, timeout=10)
            self.assertEqual(json.loads(result.stdout)['view'], first)
            result = subprocess.run(command, capture_output=True, check=True, timeout=10)
            self.assertEqual(json.loads(result.stdout), current)

    def test_profile_save_uses_expected_revision_without_overwriting_another_context(self):
        from src.techexpert.profiles import save_profile,load_profile
        import inspect
        self.assertIn('expected_revision',inspect.signature(save_profile).parameters,'CLI profile save needs a stale-writer guard')
        with tempfile.TemporaryDirectory() as temp:
            a=save_profile(temp,profile(),expected_revision=0)
            b=dict(profile(),name='Other context');saved=save_profile(temp,b,expected_revision=a['revision'])
            with self.assertRaisesRegex(ValueError,'changed|revision'):save_profile(temp,profile(),expected_revision=a['revision'])
            self.assertEqual(load_profile(temp)['name'],'Other context');self.assertEqual(load_profile(temp)['revision'],saved['revision'])
    def test_local_preflight_does_not_probe_network_directories(self):
        from src.techexpert.profiles import check_profile
        for address in (r'\\network-review.invalid\logs', '//network-review.invalid/logs'):
            value=profile();value['sources'][0]['path']=address
            with self.subTest(address=address):
                with patch.object(Path,'is_dir',side_effect=AssertionError('network metadata probe')):
                    result=check_profile(value)
                self.assertEqual(result['sources'][0]['status'],'requires_explicit_path_check')
                self.assertFalse(result['connected'])

    def test_sql_database_map_rejects_connection_strings_before_saving(self):
        from src.techexpert.profiles import save_profile
        for database in ('postgresql://reader:synthetic-secret@db/ib','password=synthetic-secret','ib;Password=synthetic-secret'):
            value=profile();value['bases'][0]['mode']='server'
            value['sources'][0].update(type='sql',path='',settings={'databases':{'a':database}})
            with self.subTest(database=database), tempfile.TemporaryDirectory() as temp:
                with self.assertRaises(ValueError):save_profile(Path(temp),value)
                self.assertFalse((Path(temp)/'profiles').exists())

    def test_collector_preset_is_saved_without_execution_and_edits_survive_reload(self):
        from src.techexpert.profiles import save_profile,load_profile
        value=profile();value['sources'][0].update(type='os',path='',host='')
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            first=save_profile(root,value)
            settings=first['sources'][0]['settings']
            self.assertEqual((settings['duration_seconds'],settings['interval_seconds']),(300,1))
            first['sources'][0]['settings']['duration_seconds']=120
            save_profile(root,first)
            self.assertEqual(load_profile(root)['sources'][0]['settings']['duration_seconds'],120)
            self.assertFalse((root/'artifacts').exists())

    def test_ras_is_server_only_and_private_settings_do_not_store_passwords(self):
        from src.techexpert.profiles import validate_profile
        value=profile();value['sources'][0].update(type='rac',path='localhost:2545')
        with self.assertRaises(ValueError):validate_profile(value)
        value['bases'][0]['mode']='server'
        self.assertEqual(validate_profile(value)['sources'][0]['type'],'rac')
        value['sources'][0]['settings']={'password':'secret'}
        with self.assertRaises(ValueError):validate_profile(value)

    def test_revision_and_independent_paths(self):
        from src.techexpert.profiles import save_profile, load_profile
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp)
            original = profile()
            first = save_profile(state, original)
            second = save_profile(state, original)
            self.assertEqual(first['revision'], 1)
            self.assertEqual(second['revision'], 2)
            self.assertEqual(load_profile(state)['sources'][0]['path'], 'D:/logs')
            self.assertTrue((state / 'profiles' / '1.json').exists())

    def test_file_database_rejects_sql(self):
        from src.techexpert.profiles import save_profile
        value = profile()
        value['sources'][0]['type'] = 'sql'
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
            save_profile(Path(temp), value)

    def test_sources_reject_archives_and_jr_xml(self):
        from src.techexpert.profiles import save_profile
        for kind, path in [('jr', 'D:/jr.xml'), ('source', 'D:/src.zip')]:
            value = profile()
            value['sources'][0].update(type=kind, path=path)
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
                save_profile(Path(temp), value)

    def test_no_passwords_in_profiles(self):
        from src.techexpert.profiles import save_profile
        value = profile()
        value['bases'][0]['connection'] = 'Srvr=host;Usr=user;Pwd=secret;'
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
            save_profile(Path(temp), value)

    def test_shared_server_can_link_two_server_databases(self):
        from src.techexpert.profiles import save_profile
        value = profile()
        value['bases'][0]['mode'] = 'server'
        value['bases'].append(dict(id='b', name='Second', mode='server', connection='srv/db2'))
        value['sources'][0].update(type='sql', base_ids=['a', 'b'])
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(len(save_profile(Path(temp), value)['sources']), 1)

    def test_starter_file_server_url_and_no_shared_traversal(self):
        from src.techexpert.profiles import read_starter
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'ibases.v8i'
            p.write_text('[File IB]\nConnect=File="D:\\IB";\n[Server IB]\nConnect=Srvr="host";Ref="db";Usr="u";Pwd="secret";\n[Web IB]\nConnect=WS="https://example.test/base?token=secret";\n[Common]\nCommonInfoBases=\\\\other\\shared.v8i\n', encoding='utf-8-sig')
            result = read_starter(p)
            self.assertEqual([x['mode'] for x in result], ['file', 'server', 'unknown'])
            self.assertNotIn('secret', str(result))
            self.assertNotIn('shared', str(result))

    def test_ipv6_publication_url_preserved(self):
        from src.techexpert.profiles import read_starter
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'ibases.v8i'
            p.write_text('[IPv6]\nConnect=WS="https://[2001:db8::1]:8080/base";\n', encoding='utf-8')
            self.assertEqual(read_starter(p)[0]['connection'], 'https://[2001:db8::1]:8080/base')

    def test_oversized_profile_does_not_replace_saved_profile(self):
        from src.techexpert.profiles import save_profile, load_profile
        value = dict(schema_version=1,name='Large',bases=[dict(id=str(i)+'a'*75,name='a'*120,mode='server',connection='x'*2048) for i in range(100)],sources=[])
        ids = [base['id'] for base in value['bases']]
        value['sources'] = [dict(id=str(i),type='sql',path='x'*2048,host='x'*256,base_ids=ids) for i in range(100)]
        with tempfile.TemporaryDirectory() as temp:
            original = save_profile(Path(temp), profile())
            with self.assertRaises(ValueError):
                save_profile(Path(temp), value)
            self.assertEqual(load_profile(Path(temp))['revision'], original['revision'])


if __name__ == '__main__':
    unittest.main()
