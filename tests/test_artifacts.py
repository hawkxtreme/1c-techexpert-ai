import importlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.artifacts'), 'immutable artifact storage is missing')
        self.api = importlib.import_module('src.techexpert.artifacts')

    def test_apdex_cli_keeps_snapshot_and_explicit_selection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root/'measurements.json'; state = root/'state'
            source.write_text(json.dumps([dict(id='1', operation='post', started_at='2026-11-16T06:00:00Z',
                                               duration_seconds=3, success=True)]), encoding='utf-8')
            run = subprocess.run([sys.executable, str(ROOT/'techexpert.py'), '--state-dir', str(state),
                                  'apdex', str(source), '--target', '2', '--operation', 'post'],
                                 capture_output=True, encoding='utf-8', timeout=15)
            self.assertEqual(run.returncode, 0, run.stdout+run.stderr)
            artifact = json.loads(run.stdout)
            self.assertEqual(artifact['result']['score'], .5)
            self.assertEqual(artifact['kind'], 'apdex')
            source.write_text('replaced', encoding='utf-8')
            resumed = self.api.load_artifact(state, artifact['artifact_id'])
            self.assertEqual(resumed, artifact)
            proof = self.api.artifact_evidence(state, artifact['artifact_id'], 's1')
            self.assertIn('duration_seconds', proof['text'])
            self.assertTrue(proof['integrity_verified'])

    def test_corrupt_snapshot_and_path_traversal_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            report=self.api.save_artifact(root, 'test', {'a': 1}, [('input', b'evidence')], {'value': 2})
            (root/'artifacts'/report['artifact_id']/'sources/s1.bin').write_bytes(b'corrupt')
            with self.assertRaises(ValueError):self.api.load_artifact(root,report['artifact_id'])
            with self.assertRaises(ValueError):self.api.load_artifact(root,'../escape')

    def test_unserializable_report_or_oversized_request_does_not_create_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for request,result in (({}, {'score': float('nan')}), ({'blob': 'x'*1048577}, {})):
                with self.assertRaises(ValueError):self.api.save_artifact(root,'apdex',request,[],result)
            self.assertFalse((root/'artifacts').exists())


if __name__=='__main__':unittest.main()
