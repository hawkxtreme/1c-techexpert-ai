import importlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


class RacTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.rac'), 'read-only RAC adapter is missing')
        self.api=importlib.import_module('src.techexpert.rac')

    def test_parse_scoped_rows_preserves_colons_quotes_and_unknown_values(self):
        text='infobase : 123\nname : "Test: IB"\ndescr : "quoted \\"value\\""\n\ninfobase : 456\nname : Other\n'
        rows=self.api.parse_rows(text)
        self.assertEqual(rows[0]['name'],'Test: IB')
        self.assertEqual(rows[1]['infobase'],'456')
        with self.assertRaises(ValueError):self.api.parse_rows('name : A\nname : B\n')
        with self.assertRaises(ValueError):self.api.parse_rows('unparsed error\n')

    def test_catalogue_cannot_execute_mutations_or_inject_options(self):
        client=self.api.RacClient('localhost:2545',docker_container='lab')
        cluster='01234567-1234-1234-1234-0123456789ab'
        command=client.command('infobases',cluster=cluster)
        self.assertEqual(command[-1],'localhost:2545')
        self.assertIn('--cluster='+cluster,command)
        self.assertIn('timeout',command)
        for operation in ('drop','terminate','create','update','sessions --terminate'):
            with self.assertRaises(ValueError):client.command(operation,cluster=cluster)
        with self.assertRaises(ValueError):client.command('sessions')
        with self.assertRaises(ValueError):client.command('sessions',cluster='--cluster-pwd=secret')
        for endpoint in ('-h','localhost:0','localhost:65536','localhost;whoami','https://user:pwd@host'):
            with self.assertRaises(ValueError):self.api.RacClient(endpoint)

    def test_collect_keeps_raw_evidence_and_does_not_promote_current_snapshot_to_history(self):
        class FakeClient(self.api.RacClient):
            def execute(self,operation,cluster=None):
                self.command(operation,cluster=cluster)
                return 'cluster : 01234567-1234-1234-1234-0123456789ab\nhost : localhost\nport : 2541\n'
        with tempfile.TemporaryDirectory() as temp:
            report=self.api.collect_rac(Path(temp),FakeClient('localhost:2545'),'clusters')
            self.assertEqual(report['result']['temporal_scope'],'current_snapshot_only')
            self.assertEqual(report['result']['rows'][0]['host'],'localhost')
            self.assertFalse(report['result']['historical_identity_established'])
            from src.techexpert.artifacts import load_artifact
            self.assertEqual(load_artifact(Path(temp),report['artifact_id']),report)


if __name__=='__main__':unittest.main()
