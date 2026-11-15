import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from test_sc01 import records, event, SCOPE


class EvidenceRegressions(unittest.TestCase):
    def test_invalid_duplicate_boundary_cannot_disappear(self):
        from src.techexpert.analysis import analyze_events
        rows = records() + [event('started', 'unknown')]
        result = analyze_events(rows, SCOPE)
        self.assertIsNone(result['durations_seconds']['execution'])

    def test_unavailable_source_has_distinct_identity(self):
        from src.techexpert.inputs import load_manifest
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'valid.jsonl'
            source.write_text(json.dumps(records()[0]), encoding='utf-8')
            manifest = root / 'case.json'
            manifest.write_text(json.dumps(dict(schema=1,scenario='SC-01',origin='synthetic',selection=SCOPE,
                sources=[dict(path='missing.jsonl',format='normalized-events-v1'), dict(path='valid.jsonl',format='normalized-events-v1')])), encoding='utf-8')
            result = load_manifest(manifest)
            self.assertNotEqual(result['limitations'][0]['source'], result['sources'][0]['id'])

    def test_unknown_event_type_does_not_crash(self):
        from src.techexpert.analysis import analyze_events
        rows = records() + [event('unrecognized', '2026-11-15T09:10:00+03:00')]
        result = analyze_events(rows, SCOPE)
        self.assertEqual(result['durations_seconds']['execution'], 2460)

    def test_malformed_records_count_toward_limit(self):
        from src.techexpert.inputs import load_manifest
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'bad.jsonl').write_text('!\n' * 12, encoding='utf-8')
            manifest = root / 'case.json'
            manifest.write_text(json.dumps(dict(schema=1,scenario='SC-01',origin='synthetic',selection=SCOPE,
                sources=[dict(path='bad.jsonl',format='normalized-events-v1')])), encoding='utf-8')
            with patch('src.techexpert.inputs.MAX_EVENTS', 5):
                result = load_manifest(manifest)
            self.assertTrue(any(x['code']=='record_limit' for x in result['limitations']))
            self.assertLessEqual(len(result['limitations']), 6)

    def test_invalid_input_details_stay_bounded_and_case_resumes(self):
        from src.techexpert.storage import investigate, load_case
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'bad.jsonl').write_text('!\n' * 1600, encoding='utf-8')
            manifest = root / 'case.json'
            manifest.write_text(json.dumps(dict(schema=1,scenario='SC-01',origin='synthetic',selection=SCOPE,
                sources=[dict(path='bad.jsonl',format='normalized-events-v1')])), encoding='utf-8')
            result = investigate(manifest, root / 'state')
            self.assertLessEqual(len(result['limitations']), 501)
            self.assertEqual(load_case(root / 'state', result['case_id'])['case_id'], result['case_id'])

    def test_unbounded_timestamp_is_rejected(self):
        from src.techexpert.analysis import analyze_events
        rows = records()
        rows[1]['timestamp'] = '2026-11-15T09:04:00.' + '1' * 1000 + '+03:00'
        result = analyze_events(rows, SCOPE)
        self.assertIsNone(result['durations_seconds']['execution'])

    def test_report_size_failure_does_not_create_successful_case(self):
        from src.techexpert.storage import investigate
        from src.techexpert.inputs import InputError
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp)
            root = Path(__file__).resolve().parents[1]
            with patch('src.techexpert.storage.MAX_REPORT_BYTES', 1, create=True):
                with self.assertRaises(InputError):
                    investigate(root / 'examples/sc01/case.json', state)
            self.assertFalse((state / 'cases').exists())


if __name__ == '__main__':
    unittest.main()
