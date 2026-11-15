import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class StorageTests(unittest.TestCase):
    def test_snapshot_survives_original_change_and_resumes(self):
        from src.techexpert.storage import investigate, load_case, read_evidence
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case = json.loads((ROOT / 'examples/sc01/case.json').read_text(encoding='utf-8'))
            source = root / 'events.jsonl'
            source.write_bytes((ROOT / 'examples/sc01/events.jsonl').read_bytes())
            case['sources'][0]['path'] = str(source)
            manifest = root / 'case.json'
            manifest.write_text(json.dumps(case), encoding='utf-8')
            result = investigate(manifest, root / 'state')
            source.write_text('changed', encoding='utf-8')
            loaded = load_case(root / 'state', result['case_id'])
            self.assertEqual(loaded['durations_seconds']['total'], 2700)
            proof = read_evidence(root / 'state', result['case_id'], 's1:1')
            self.assertEqual(json.loads(proof['text'])['kind'], 'queued')
            self.assertTrue(proof['integrity_verified'])

    def test_snapshot_corruption_detected(self):
        from src.techexpert.storage import investigate, read_evidence
        from src.techexpert.inputs import InputError
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp)
            result = investigate(ROOT / 'examples/sc01/case.json', state)
            snapshot = state / 'cases' / result['case_id'] / 'sources' / 's1.bin'
            snapshot.write_bytes(b'corrupt')
            with self.assertRaises(InputError):
                read_evidence(state, result['case_id'], 's1:1')

    def test_state_does_not_accept_path_traversal(self):
        from src.techexpert.storage import load_case
        from src.techexpert.inputs import InputError
        with self.assertRaises(InputError):
            load_case(Path(tempfile.gettempdir()), '../outside')

    def test_new_analysis_keeps_previous_case(self):
        from src.techexpert.storage import investigate, load_case
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp)
            first = investigate(ROOT / 'examples/sc01/case.json', state)
            second = investigate(ROOT / 'examples/sc01/case.json', state)
            self.assertNotEqual(first['case_id'], second['case_id'])
            self.assertEqual(load_case(state, first['case_id'])['case_id'], first['case_id'])


class CLITests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / 'techexpert.py'), *args], cwd=ROOT,
                              capture_output=True, text=True, encoding='utf-8', timeout=15)

    def test_demo_and_resume_and_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self.run_cli('--state-dir', temp, 'demo')
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['origin'], 'synthetic')
            self.assertEqual(report['durations_seconds']['queue'], 240)
            self.assertEqual(report['baseline']['status'], 'user_reported_not_measured')
            show = self.run_cli('--state-dir', temp, 'show', report['case_id'])
            self.assertEqual(show.returncode, 0, show.stderr)
            self.assertEqual(json.loads(show.stdout)['case_id'], report['case_id'])
            proof = self.run_cli('--state-dir', temp, 'evidence', report['case_id'], 's1:2')
            self.assertEqual(proof.returncode, 0, proof.stderr)
            self.assertIn('started', json.loads(proof.stdout)['text'])

    def test_missing_input_is_structured_error(self):
        result = self.run_cli('analyze', 'does-not-exist.json')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['status'], 'error')

    def test_doctor_does_not_need_database(self):
        result = self.run_cli('doctor')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertTrue(data['ai_harness_required'])
        self.assertEqual(data['capabilities']['native_jr'], 'not_implemented')

    def test_saved_gui_profile_returns_to_same_agent(self):
        from src.techexpert.profiles import save_profile
        from test_profiles import profile
        with tempfile.TemporaryDirectory() as temp:
            save_profile(Path(temp), profile())
            result = self.run_cli('--state-dir', temp, 'profile')
            self.assertEqual(result.returncode, 0, result.stderr)
            loaded = json.loads(result.stdout)
            self.assertEqual(loaded['revision'], 1)
            self.assertEqual(loaded['sources'][0]['path'], 'D:/logs')
            self.assertEqual(loaded['capability_status'], 'configured_not_connected')


if __name__ == '__main__':
    unittest.main()
