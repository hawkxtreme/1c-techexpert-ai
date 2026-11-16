"""Public boundary tests use synthetic adversarial fixtures, not a platform claim."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_job_correlation import documents, events, JOB
from src.techexpert.inputs import InputError
from src.techexpert.storage import investigate, load_case, read_evidence, list_native_events

ROOT = Path(__file__).resolve().parents[1]


def manifest(root, *, missing_exit=False):
    docs = documents()[:2] if missing_exit else documents()
    sources = []
    for doc in docs:
        path = root / (doc['role'] + '.json')
        path.write_text(json.dumps(doc['data'], indent=2), encoding='utf-8')
        sources.append(dict(path=str(path), format='1c-job-runtime-v1', role=doc['role'],
                            platform_version='8.3.27.1989', platform_utc_offset='+03:00'))
    lines = []
    for row in events():
        props = ','.join(k + "='" + v.replace("'", "''") + "'" for k, v in row['properties'].items())
        lines.append(f"{row['timestamp_utc'].removesuffix('+00:00')}-{row['duration_us']},{row['event']},1,{props}\n")
    log = root / 'native.txt'
    log.write_bytes(''.join(lines).encode('utf-8'))
    sources.append(dict(path=str(log), format='1c-tj-text-v1', platform_version='8.3.27.1989',
                        encoding='utf-8', placement='plain', timestamp_format='iso', utc_offset='+00:00'))
    path = root / 'manifest.json'
    path.write_text(json.dumps(dict(schema=1, scenario='SC-01', origin='synthetic',
        correlation_profile='1c-file-job-markers-v1', selection=dict(run=JOB), sources=sources)), encoding='utf-8')
    return path


class JobStorageTests(unittest.TestCase):
    def test_job_execution_precision_and_link_survive_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = investigate(manifest(root), root/'state')
            self.assertEqual(report['durations_seconds'], dict(queue=None, execution=2, total=None))
            self.assertEqual(report['job_correlation']['native_link']['status'], 'established')
            metric = next(m for m in report['metrics'] if m['name']=='execution')
            self.assertEqual(metric['precision_seconds'], 1)
            self.assertEqual(metric['bounds_seconds'], [1, 3])
            self.assertEqual(report['cause_state'], 'insufficient_data')
            self.assertEqual(report['selection'], {'run':JOB})
            self.assertEqual(load_case(root/'state', report['case_id']), report)
            self.assertFalse(report['native_1c_compatibility_verified'])

    def test_runtime_evidence_is_whole_immutable_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = investigate(manifest(root), root/'state')
            (root/'controller.json').write_text('changed', encoding='utf-8')
            proof = read_evidence(root/'state', report['case_id'], 's1:1')
            self.assertEqual(json.loads(proof['text'])['job_uuid'], JOB)
            self.assertEqual(proof['byte_start'], 0)
            self.assertGreater(proof['end_line'], 1)
            self.assertTrue(proof['integrity_verified'])
            with self.assertRaises(InputError):
                read_evidence(root/'state', report['case_id'], 's1:2')

    def test_linked_page_uses_snapshot_and_excludes_other_thread_and_outside_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = investigate(manifest(root), root/'state')
            (root/'native.txt').write_text('changed', encoding='utf-8')
            page = list_native_events(root/'state', report['case_id'], linked_run=True, limit=1)
            self.assertEqual(page['matched_count'], 3)
            self.assertEqual(page['job_correlation'], 'established')
            self.assertEqual(page['next_offset'], 1)
            calls = list_native_events(root/'state', report['case_id'], linked_run=True, event='CALL')
            self.assertEqual(calls['matched_count'], 1)
            self.assertEqual(calls['records'][0]['properties']['OSThread'], '222')
            (root/'state/cases'/report['case_id']/'sources/s4.bin').write_bytes(b'corrupted')
            with self.assertRaises(InputError):
                list_native_events(root/'state', report['case_id'], linked_run=True)

    def test_unproven_link_returns_empty_not_all_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = investigate(manifest(root, missing_exit=True), root/'state')
            page = list_native_events(root/'state', report['case_id'], linked_run=True)
            self.assertEqual(page['matched_count'], 0)
            self.assertEqual(page['job_correlation'], 'not_established')
            self.assertEqual(page['records'], [])
            self.assertGreater(list_native_events(root/'state', report['case_id'])['matched_count'], 0)

    def test_cli_linked_run_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = investigate(manifest(root), root/'state')
            call = subprocess.run([sys.executable, str(ROOT/'techexpert.py'), '--state-dir', str(root/'state'),
                'events', report['case_id'], '--linked-run', '--limit', '1'], capture_output=True,
                encoding='utf-8', timeout=15)
            self.assertEqual(call.returncode, 0, call.stdout+call.stderr)
            self.assertEqual(json.loads(call.stdout)['matched_count'], 3)

    def test_unparsed_session_switch_blocks_native_link_but_not_platform_dates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = manifest(root)
            log = root/'native.txt'
            data = log.read_bytes()
            bad = b'2026-11-16T05:55:36.999999-0,SESN,1,process=1cv8,OSThread=222,Nmb=3,ID=bad,Func=Start,malformed\n'
            data = data.replace(b'2026-11-16T05:55:37.000000-', bad+b'2026-11-16T05:55:37.000000-')
            log.write_bytes(data)
            report = investigate(path, root/'state')
            self.assertEqual(report['job_correlation']['native_link']['status'], 'not_established')
            self.assertEqual(report['job_correlation']['native_link']['linked_count'], 0)
            self.assertEqual(report['durations_seconds']['execution'], 2)
            self.assertEqual(list_native_events(root/'state', report['case_id'], linked_run=True)['matched_count'], 0)

    def test_parse_gap_after_session_does_not_erase_verified_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = manifest(root)
            with (root/'native.txt').open('ab') as stream:
                stream.write(b'malformed after known session\n')
            report = investigate(path, root/'state')
            self.assertEqual(report['job_correlation']['native_link']['status'], 'established')

    def test_runtime_snapshot_tampering_blocks_linked_query(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = investigate(manifest(root), root/'state')
            (root/'state/cases'/report['case_id']/'sources/s1.bin').write_bytes(b'changed')
            with self.assertRaises(InputError):
                list_native_events(root/'state', report['case_id'], linked_run=True)

    def test_many_retained_ambiguous_nonidentity_fields_are_not_unread_bytes(self):
        for extra_invalid in (False,True):
            with self.subTest(extra_invalid=extra_invalid), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);path=manifest(root);log=root/'native.txt'
                row=b'2026-11-16T05:55:37.100000-1,SDBL,1,process=1cv8,OSThread=222,Func=Transaction,Func=CommitTransaction\n'
                additions=row*240+(b'bad unread session transition\n' if extra_invalid else b'')
                log.write_bytes(log.read_bytes().replace(b'2026-11-16T05:55:37.500000-',additions+b'2026-11-16T05:55:37.500000-'))
                report=investigate(path,root/'state')
                expected='not_established' if extra_invalid else 'established'
                self.assertEqual(report['job_correlation']['native_link']['status'],expected)
                if not extra_invalid:
                    self.assertEqual(list_native_events(root/'state',report['case_id'],linked_run=True)['matched_count'],243)


if __name__ == '__main__':
    unittest.main()
