"""Sealed named outputs remain evidence, with old artifact paths unchanged."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from src.techexpert import artifacts, source_changes
from src.techexpert.inputs import InputError


class ArtifactFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)

    def save(self, names=None):
        return artifacts.save_artifact(self.state, 'logcfg_proposal', {}, [('supplied', b'<config/>')], {}, source_names=names)

    def test_old_default_stays_schema1_and_bin(self):
        report = self.save()
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(artifacts.source_path(artifacts.artifact_folder(self.state, report['artifact_id']), report['sources'][0]).name, 's1.bin')
        self.assertEqual(artifacts.load_artifact(self.state, report['artifact_id']), report)

    def test_named_xml_is_actual_sealed_source_and_can_be_compared(self):
        report = self.save(['logcfg.xml'])
        self.assertEqual(report['schema_version'], 2)
        evidence = artifacts.artifact_evidence(self.state, report['artifact_id'], 's1')
        self.assertEqual(Path(evidence['file_path']).name, 'logcfg.xml')
        self.assertEqual(Path(evidence['file_path']).read_bytes(), b'<config/>')
        other = self.save()
        ref = lambda r: dict(kind='artifact', id=r['artifact_id'], source_id='s1')
        self.assertEqual(source_changes.compare(self.state, before=ref(report), after=ref(other))['byte_relation'], 'identical')
        Path(evidence['file_path']).write_bytes(b'changed')
        with self.assertRaises(InputError): artifacts.load_artifact(self.state, report['artifact_id'])

    def test_unsafe_names_and_case_collisions_are_rejected_before_creating_artifact(self):
        for name in ('../logcfg.xml', 'a/b.xml', 'a\\b.xml', 'CON.xml', 'aux.bin', 'foo.xml.', 'foo.txt', 'C:foo.xml', 'x'*130+'.xml'):
            with self.subTest(name=name), self.assertRaises(InputError): self.save([name])
        with self.assertRaises(InputError):
            artifacts.save_artifact(self.state, 'example', {}, [('a', b''), ('b', b'')], {}, source_names=['a.xml', 'A.xml'])
        self.assertFalse((self.state/'artifacts').exists())

    def test_resealed_path_traversal_metadata_is_rejected(self):
        report = self.save(['logcfg.xml'])
        folder = artifacts.artifact_folder(self.state, report['artifact_id'])
        report['sources'][0]['file_name'] = '../request.json'
        artifacts.write_json(folder/'report.json', report)
        receipt = json.loads((folder/'receipt.json').read_text(encoding='utf-8'))
        receipt['report_sha256'] = hashlib.sha256((folder/'report.json').read_bytes()).hexdigest()
        artifacts.write_json(folder/'receipt.json', receipt)
        with self.assertRaises(InputError): artifacts.load_artifact(self.state, report['artifact_id'])

    def test_schema_accepts_legacy_sealed_evidence_replay_without_injecting_new_path(self):
        from src.techexpert import capabilities,operations,operation_state as fs
        report=self.save()
        request=dict(schema_version=1,operation_key='legacy-evidence',executor_id='fixture',operation='artifact.evidence',
            arguments=dict(artifact_id=report['artifact_id'],source_id='s1'))
        first=operations.run(self.state,request)
        self.assertEqual(first['status'],'succeeded',first)
        folder=fs.folder(self.state,first['run_id'])
        # Compatibility fixture:0.27 sealed data did not contain file_path.
        old=fs.read(folder/'output.json');old['data'].pop('file_path')
        fs.write(folder/'output.json',old)
        receipt=fs.read(folder/'output-receipt.json');receipt['sha256']=fs.digest(old)
        fs.write(folder/'output-receipt.json',receipt)
        replay=operations.run(self.state,request)
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['data'],old['data'])
        schema=capabilities.ROUTES['artifact.evidence']['data_schema']
        self.assertLessEqual(set(schema['required']),replay['data'].keys(),'Current advertised schema rejects old sealed evidence replay')
        self.assertEqual(schema['properties']['file_path']['type'],'string')
