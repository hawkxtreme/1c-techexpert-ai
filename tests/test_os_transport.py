import importlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


class OsTransportTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.os_metrics'), 'OS transport/import adapter is missing')
        self.api=importlib.import_module('src.techexpert.os_metrics')

    def test_transport_validates_hosts_and_never_enables_services(self):
        request=self.api.validate_request(dict(transport='ssh',host='reader@node.example',duration_seconds=5,interval_seconds=1))
        argv=self.api.ssh_command(request)
        self.assertIn('StrictHostKeyChecking=yes',argv)
        self.assertIn('BatchMode=yes',argv)
        self.assertIn('reader@node.example',argv)
        self.assertNotIn('sudo',' '.join(argv))
        for host in ('-ProxyCommand=x','host; touch /x','u@host\n','https://host','a$(whoami)'):
            with self.assertRaises(ValueError):self.api.validate_request(dict(transport='ssh',host=host))
        with self.assertRaises(ValueError):self.api.validate_request(dict(transport='winrm',host='host',password='secret'))
        with self.assertRaises(ValueError):self.api.validate_request(dict(transport='ssh',host='host',port=True))

    def test_ssh_uses_explicit_identity_and_known_hosts_without_disabling_verification(self):
        r=self.api.validate_request(dict(transport='ssh',host='reader@localhost',identity_file='D:/lab/id',known_hosts_file='D:/lab/known_hosts'))
        command=self.api.ssh_command(r)
        self.assertIn('-i',command)
        self.assertIn('D:/lab/id',command)
        self.assertIn('UserKnownHostsFile="D:/lab/known_hosts"',command)
        self.assertIn('StrictHostKeyChecking=yes',command)
        with self.assertRaises(ValueError):self.api.validate_request(dict(transport='ssh',host='node',identity_file='key\nProxyCommand=bad'))

    def test_current_windows_import_is_private_and_integrity_checked(self):
        import json
        document=dict(schema_version=1,profile='os-metrics-v1',node='test',role='onec',scope='host',
                      plan=dict(duration_seconds=1,interval_seconds=1,max_bytes=8388608),status='cancelled',
                      samples=[dict(elapsed_seconds=0,metrics=[])])
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'capture.json';source.write_text(json.dumps(document),encoding='utf-8')
            report=self.api.import_os(root/'state',source)
            self.assertEqual(report['result']['collection_status'],'cancelled')
            self.assertEqual(report['result']['coverage_status'],'incomplete')
            source.unlink()
            from src.techexpert.artifacts import load_artifact
            self.assertEqual(load_artifact(root/'state',report['artifact_id']),report)


if __name__=='__main__':unittest.main()
