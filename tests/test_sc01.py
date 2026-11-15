import copy
import json
import tempfile
import unittest
from pathlib import Path


SCOPE = dict(database='demo-ib', node='server-a', process='rphost-1', epoch='boot-1', run='job-42')


def event(kind, timestamp, **extra):
    return dict(kind=kind, timestamp=timestamp, scope=dict(SCOPE), **extra)


def records():
    return [event('queued', '2026-11-15T09:00:00+03:00'),
            event('started', '2026-11-15T09:04:00+03:00'),
            event('finished', '2026-11-15T09:45:00+03:00')]


class SC01Tests(unittest.TestCase):
    def analyze(self, rows, **kwargs):
        from src.techexpert.analysis import analyze_events
        return analyze_events(rows, SCOPE, **kwargs)

    def test_original_queue_execution_total(self):
        result = self.analyze(records())
        self.assertEqual(result['durations_seconds'], dict(queue=240, execution=2460, total=2700))
        self.assertEqual(result['cause_state'], 'insufficient_data')
        self.assertTrue(result['requires_ai_interpretation'])

    def test_missing_queue_keeps_execution(self):
        result = self.analyze(records()[1:])
        self.assertIsNone(result['durations_seconds']['queue'])
        self.assertEqual(result['durations_seconds']['execution'], 2460)

    def test_missing_finish_does_not_invent_duration(self):
        result = self.analyze(records()[:2])
        self.assertEqual(result['durations_seconds']['queue'], 240)
        self.assertIsNone(result['durations_seconds']['execution'])

    def test_other_database_run_process_epoch_are_not_joined(self):
        for key in SCOPE:
            rows = records()
            rows[-1]['scope'][key] = 'different'
            with self.subTest(key=key):
                self.assertIsNone(self.analyze(rows)['durations_seconds']['execution'])

    def test_two_start_events_are_ambiguous(self):
        rows = records() + [event('started', '2026-11-15T09:05:00+03:00')]
        result = self.analyze(rows)
        self.assertIsNone(result['durations_seconds']['execution'])
        self.assertTrue(any(x['code'] == 'ambiguous_milestone' for x in result['limitations']))

    def test_negative_intervals_are_unknown(self):
        rows = records()
        rows[2]['timestamp'] = '2026-11-15T09:03:00+03:00'
        self.assertIsNone(self.analyze(rows)['durations_seconds']['execution'])

    def test_timezone_required(self):
        rows = records()
        rows[1]['timestamp'] = '2026-11-15T09:04:00'
        result = self.analyze(rows)
        self.assertIsNone(result['durations_seconds']['execution'])
        self.assertTrue(result['limitations'])

    def test_waits_union_and_clipping_not_sum(self):
        rows = records() + [
            event('wait', '2026-11-15T09:05:00+03:00', end='2026-11-15T09:25:00+03:00', reason='lock'),
            event('wait', '2026-11-15T09:20:00+03:00', end='2026-11-15T09:50:00+03:00', reason='lock')]
        result = self.analyze(rows)
        self.assertEqual(result['wait_seconds'], 2400)
        self.assertNotEqual(result['cause_state'], 'confirmed')

    def test_wait_without_full_run_does_not_claim_percentage(self):
        rows = records()[1:2] + [event('wait', '2026-11-15T09:05:00+03:00', end='2026-11-15T09:25:00+03:00')]
        result = self.analyze(rows)
        self.assertIsNone(result['wait_fraction_of_execution'])

    def test_unknown_event_is_not_a_job_boundary(self):
        rows = [event('CALL', '2026-11-15T09:45:00+03:00', duration_us=2460000000)]
        result = self.analyze(rows)
        self.assertIsNone(result['durations_seconds']['execution'])

    def test_incomplete_scope_is_not_linked(self):
        rows = records()
        del rows[-1]['scope']['epoch']
        self.assertIsNone(self.analyze(rows)['durations_seconds']['execution'])


class InputTests(unittest.TestCase):
    def test_jsonl_provenance_errors_and_dedup_file(self):
        from src.techexpert.inputs import load_manifest
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'events.jsonl'
            source.write_text('\n'.join(json.dumps(r) for r in records()) + '\nBROKEN\n', encoding='utf-8')
            manifest = root / 'case.json'
            manifest.write_text(json.dumps(dict(schema=1, scenario='SC-01', origin='synthetic', selection=SCOPE,
                sources=[dict(path=str(source), format='normalized-events-v1'), dict(path=str(source), format='normalized-events-v1')])) , encoding='utf-8')
            bundle = load_manifest(manifest)
            self.assertEqual(len(bundle['events']), 3)
            self.assertEqual(len(bundle['sources']), 1)
            self.assertEqual(bundle['events'][0]['evidence']['line'], 1)
            self.assertTrue(bundle['limitations'])
            self.assertEqual(bundle['events'][0]['evidence']['sha256'], bundle['sources'][0]['sha256'])

    def test_manifest_rejects_unknown_schema(self):
        from src.techexpert.inputs import load_manifest, InputError
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'case.json'
            p.write_text('{"schema":9}', encoding='utf-8')
            with self.assertRaises(InputError):
                load_manifest(p)

    def test_input_limit_before_read(self):
        from src.techexpert.inputs import read_snapshot, InputError
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'large.jsonl'
            p.write_bytes(b'x' * 100)
            with self.assertRaises(InputError):
                read_snapshot(p, max_bytes=10)


if __name__ == '__main__':
    unittest.main()
