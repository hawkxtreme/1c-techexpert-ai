import tempfile
import unittest
from pathlib import Path


def profile():
    return dict(schema_version=1, name='Local', bases=[dict(id='a', name='IB', mode='file', connection='D:/IB')],
                sources=[dict(id='tj-a', type='tj', path='D:/logs', host='host-a', base_ids=['a'])])


class ProfileTests(unittest.TestCase):
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
