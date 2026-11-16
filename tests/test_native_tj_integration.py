import json
import tempfile
import unittest
import subprocess
import sys
from pathlib import Path

from src.techexpert.inputs import InputError, load_manifest
from src.techexpert.storage import investigate, read_evidence, load_case


SCOPE = dict(database='orders', node='node-a', process='rphost-42', epoch='boot-a', run='job-42')
NATIVE = ('45:00.000001-2460000000,CALL,1,process=rphost,p:processName=orders,'
          'SessionID=12,Context="Загрузка, заказов\nВторая строка"\n')


def native_spec(path):
    return dict(path=str(path), format='1c-tj-text-v1', platform_version='8.3.27.1989',
                encoding='utf-8', placement='folders', timestamp_format='minute', rotation_hours=1,
                file_hour='2026-11-15T09:00:00+03:00',
                context=dict(node='node-a', process='rphost-42', epoch='boot-a'))


def write_manifest(root, sources):
    path = root / 'case.json'
    path.write_text(json.dumps(dict(schema=1, scenario='SC-01', origin='provided', selection=SCOPE,
        symptom='Загрузка заказов 45 минут вместо пяти', reported_normal_seconds=300,
        sources=sources)), encoding='utf-8')
    return path


class NativeIntegrationTests(unittest.TestCase):
    def test_native_call_is_observation_not_whole_background_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / '26111509.log'
            log.write_text(NATIVE, encoding='utf-8')
            result = investigate(write_manifest(root, [native_spec(log)]), root / 'state')
            self.assertEqual(result['input_contract'], '1c-tj-text-v1')
            self.assertEqual(result['durations_seconds'], dict(queue=None, execution=None, total=None))
            self.assertEqual(result['cause_state'], 'insufficient_data')
            observed = result['native_observations']
            self.assertEqual(observed['event_count'], 1)
            self.assertEqual(observed['by_event'], {'CALL': 1})
            self.assertEqual(observed['longest_events'][0]['duration_us'], 2460000000)
            self.assertEqual(observed['job_correlation'], 'not_established')
            self.assertEqual(result['sources'][0]['parse_status'], 'parsed')
            self.assertEqual(load_case(root / 'state', result['case_id'])['case_id'], result['case_id'])

    def test_native_multiline_evidence_uses_original_snapshot_and_byte_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / '26111509.log'
            data = b'\xef\xbb\xbf' + NATIVE.replace('\n', '\r\n').encode('utf-8')
            log.write_bytes(data)
            result = investigate(write_manifest(root, [native_spec(log)]), root / 'state')
            log.write_bytes(b'rotated/truncated')
            proof = read_evidence(root / 'state', result['case_id'], 's1:1')
            self.assertIn('Вторая строка', proof['text'])
            self.assertEqual(proof['end_line'], 2)
            self.assertEqual(proof['byte_end'], len(data))
            self.assertTrue(proof['integrity_verified'])
            self.assertTrue(proof['untrusted_source_content'])
            with self.assertRaises(InputError):
                read_evidence(root / 'state', result['case_id'], 's1:2')

    def test_mixed_native_and_explicit_milestones_still_requires_correlation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / '26111509.log'
            log.write_text(NATIVE, encoding='utf-8')
            norm = root / 'events.jsonl'
            norm.write_text('\n'.join(json.dumps(dict(kind=k, timestamp=t, scope=SCOPE)) for k, t in
                [('started', '2026-11-15T09:04:00+03:00'), ('finished', '2026-11-15T09:45:00+03:00')]), encoding='utf-8')
            result = investigate(write_manifest(root, [native_spec(log),dict(path=str(norm),format='normalized-events-v1')]),root/'state')
            self.assertEqual(result['durations_seconds']['execution'], 2460)
            self.assertIsNone(result['durations_seconds']['queue'])
            self.assertEqual(result['native_observations']['job_correlation'], 'not_established')
            self.assertEqual(result['native_observations']['longest_events'][0]['evidence']['id'], 's1:1')

    def test_same_file_conflicting_profiles_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / 'renamed.txt'
            log.write_text(NATIVE, encoding='utf-8')
            one = native_spec(log)
            two = dict(one, file_hour='2026-11-15T10:00:00+03:00')
            with self.assertRaisesRegex(ValueError, 'conflicting'):
                load_manifest(write_manifest(root, [one,two]))

    def test_empty_and_invalid_native_files_have_distinct_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for data, expected in [(b'', 'empty'), (b'not a TJ\n', 'invalid')]:
                with self.subTest(expected=expected):
                    log = root / '26111509.log'
                    log.write_bytes(data)
                    result = investigate(write_manifest(root,[native_spec(log)]),root/'state')
                    self.assertEqual(result['sources'][0]['parse_status'], expected)
                    self.assertIsNone(result['durations_seconds']['total'])

    def test_identical_distinct_files_not_silently_deduplicated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            logs=[root/'one.txt',root/'two.txt']
            for log in logs:
                log.write_text(NATIVE,encoding='utf-8')
            bundle=load_manifest(write_manifest(root,[native_spec(x) for x in logs]))
            self.assertEqual(len(bundle['native_events']),2)
            self.assertNotEqual(bundle['native_events'][0]['evidence']['id'],bundle['native_events'][1]['evidence']['id'])

    def test_native_pagination_uses_snapshots_and_exact_property_filters(self):
        from src.techexpert.storage import list_native_events
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            log=root/'26111509.log'
            log.write_text(NATIVE + '46:00.000000-4,EXCP,0,SessionID=13,Descr=error\n' + NATIVE,encoding='utf-8')
            result=investigate(write_manifest(root,[native_spec(log)]),root/'state')
            log.write_bytes(b'changed')
            page=list_native_events(root/'state',result['case_id'],event='CALL',properties={'SessionID':'12'},offset=1,limit=1)
            self.assertEqual(page['matched_count'],2)
            self.assertEqual(len(page['records']),1)
            self.assertEqual(page['records'][0]['evidence']['id'],'s1:4')
            self.assertIsNone(page['next_offset'])
            self.assertTrue(page['integrity_verified'])
            self.assertEqual(page['job_correlation'],'not_established')

    def test_native_query_rejects_bad_bounds_and_unknown_source(self):
        from src.techexpert.storage import list_native_events
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            log=root/'26111509.log'
            log.write_text(NATIVE,encoding='utf-8')
            result=investigate(write_manifest(root,[native_spec(log)]),root/'state')
            for args in [dict(offset=-1),dict(limit=101),dict(limit=0),dict(source_id='s2')]:
                with self.subTest(args=args), self.assertRaises(InputError):
                    list_native_events(root/'state',result['case_id'],**args)

    def test_events_cli_returns_filtered_page_and_structured_invalid_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            log=root/'26111509.log'
            log.write_text(NATIVE,encoding='utf-8')
            result=investigate(write_manifest(root,[native_spec(log)]),root/'state')
            command=[sys.executable,str(Path(__file__).resolve().parents[1]/'techexpert.py'),
                     '--state-dir',str(root/'state'),'events',result['case_id']]
            page=subprocess.run(command+['--event','CALL','--property','SessionID=12','--limit','1'],
                                capture_output=True,encoding='utf-8',timeout=15)
            self.assertEqual(page.returncode,0,page.stdout+page.stderr)
            self.assertEqual(json.loads(page.stdout)['matched_count'],1)
            bad=subprocess.run(command+['--property','broken'],capture_output=True,encoding='utf-8',timeout=15)
            self.assertEqual(bad.returncode,2)
            self.assertEqual(json.loads(bad.stdout)['status'],'error')


if __name__ == '__main__':
    unittest.main()
