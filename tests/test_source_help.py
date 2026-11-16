import importlib
import importlib.util
import unittest

class SourceHelpTests(unittest.TestCase):
    def test_each_source_explains_purpose_expected_input_and_os_preparation(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.source_help'),'bundled source preparation help is missing')
        api=importlib.import_module('src.techexpert.source_help')
        help=api.catalogue()
        self.assertEqual(set(help['sources']),{'tj','jr','source','sql','os','rac'})
        for kind,item in help['sources'].items():
            with self.subTest(kind=kind):
                for key in ('purpose','expected_format','example','rights','agent_actions'):self.assertTrue(item[key])
                self.assertTrue(item['windows_steps']);self.assertTrue(item['linux_steps'])
        self.assertIn('logcfg.xml',help['sources']['tj']['expected_format'])
        self.assertIn('1Cv8.lgf',help['sources']['jr']['expected_format'])
        self.assertIn('XML',help['sources']['jr']['excluded_inputs'])
        self.assertIn('сут',help['sources']['os']['long_observation'])

    def test_source_export_help_distinguishes_planning_copy_and_explicit_native_step(self):
        api=importlib.import_module('src.techexpert.source_help')
        help=api.catalogue()['sources']['source'].get('export_help')
        self.assertIsNotNone(help,'obtaining sources is missing from the setup helper')
        self.assertTrue(help['title']);self.assertTrue(help['request_in_chat']);self.assertGreaterEqual(len(help['steps']),3)
        text=' '.join(help['steps'])+' '+help['scope']
        self.assertIn('копи',text);self.assertIn('отдельн',text);self.assertIn('Windows',text)

if __name__=='__main__':unittest.main()
