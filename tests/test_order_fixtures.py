"""Integrity and behavioral checks of sanitized real order-loading captures."""
import copy
import hashlib
import json
import unittest
from collections import Counter
from pathlib import Path

from src.techexpert.inputs import load_manifest
from src.techexpert.job_correlation import correlate_job
from src.techexpert.native_tj import parse_tj, validate_profile
from src.techexpert.order_load import analyze_order_load


FIXTURES = Path(__file__).parent / 'fixtures' / 'order-load'
REPOSITORY = Path(__file__).resolve().parents[1]
PUBLIC_BASE = r'C:\controlled\order-ib'
PUBLIC_INPUT = r'C:\controlled\orders.csv'
INPUT_SHA = '7567e0106e4477d791d5b7ff75658984947fb08338d372f6b44f2d0e9ca65dd8'
RESULT_SHA = '1ec9e8834b1085135e0010b8a380ffb56322231489384a1847c904df97053ec5'


def read_json(name):
    return json.loads((FIXTURES / name).read_text(encoding='utf-8'))


def digest(value):
    return hashlib.sha256(value).hexdigest()


def analyze(bundle):
    correlation = correlate_job(bundle['lifecycle_documents'], bundle['native_events'],
                                bundle['manifest']['selection'])
    return correlation, analyze_order_load(bundle, {'job_correlation': correlation})


def change_document(bundle, format, edit, role=None):
    """Make a consistent in-memory negative input, including new snapshot hashes."""
    wrapped = next((d for d in bundle['lifecycle_documents'] if d['role'] == role), None)
    if role is None:
        source = next(s for s in bundle['sources'] if s['format'] == format)
    else:
        source = next(s for s in bundle['sources'] if s['id'] == wrapped['evidence']['source'])
    document = json.loads(source['data'])
    edit(document)
    raw = (json.dumps(document, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    source.update(data=raw, sha256=digest(raw), size=len(raw))
    if 'evidence' in source:
        source['evidence'].update(sha256=digest(raw), byte_end=len(raw),
                                  line=1, end_line=len(raw.splitlines()))
    if wrapped is not None:
        wrapped['data'] = document
        wrapped['evidence'].update(sha256=digest(raw), byte_end=len(raw),
                                   line=1, end_line=len(raw.splitlines()))


class OrderFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.passport = read_json('passport.json')
        cls.cases = {case['case']: case for case in cls.passport['cases']}
        cls.bundles = {name: load_manifest(FIXTURES / case['manifest'])
                       for name, case in cls.cases.items()}

    def test_passport_hashes_every_file_and_source_dependency(self):
        self.assertEqual(self.passport['provenance'], 'sanitized_real_capture')
        self.assertIs(self.passport['byte_identical_to_original'], False)
        names = {p.name for p in FIXTURES.iterdir() if p.is_file()}
        self.assertEqual(set(self.passport['files']), names - {'passport.json'})
        for name, expected in {**self.passport['files'], **self.passport['dependencies']}.items():
            with self.subTest(file=name):
                path = (FIXTURES / name).resolve()
                self.assertTrue(path.is_relative_to(REPOSITORY))
                raw = path.read_bytes()
                self.assertEqual(len(raw), expected['bytes'])
                self.assertEqual(digest(raw), expected['sha256'])
        self.assertEqual(digest((FIXTURES / 'orders.csv').read_bytes()), INPUT_SHA)
        self.assertEqual(self.passport['invariants']['business_result_sha256'], RESULT_SHA)
        for case in self.cases.values():
            for artifact in case['artifacts']:
                source = artifact['source']
                self.assertRegex(source['sha256'], r'^[0-9a-f]{64}$')
                self.assertEqual((source['byte_start'], source['byte_end']), (0, source['bytes']))
                if artifact['byte_identical_to_original']:
                    self.assertEqual(digest((FIXTURES / artifact['file']).read_bytes()), source['sha256'])

    def test_manifests_select_actual_runs_and_use_relative_local_sources(self):
        self.assertEqual(set(self.cases), {'baseline', 'cached'})
        self.assertNotEqual(self.cases['baseline']['job_uuid'], self.cases['cached']['job_uuid'])
        for name, case in self.cases.items():
            with self.subTest(case=name):
                manifest = self.bundles[name]['manifest']
                self.assertEqual(manifest['selection'], {'run': case['job_uuid']})
                self.assertEqual(manifest['correlation_profile'], '1c-file-job-markers-v1')
                self.assertEqual(manifest['workload_profile'], 'sc01-order-load-v1')
                self.assertEqual(manifest['origin'], 'provided')
                for spec in manifest['sources']:
                    path = Path(spec['path'])
                    self.assertFalse(path.is_absolute())
                    resolved = (FIXTURES / path).resolve()
                    self.assertTrue(resolved.is_relative_to(REPOSITORY))
                    self.assertTrue(resolved.is_file())

    def test_native_excerpt_keeps_whole_body_and_all_duplicate_func_values(self):
        for name, case in self.cases.items():
            with self.subTest(case=name):
                native = case['native']
                raw = (FIXTURES / native['file']).read_bytes()
                spec = self.bundles[name]['manifest']['sources'][0]
                parsed = parse_tj(raw, validate_profile(spec, native['file']))
                records = parsed['records']
                self.assertEqual(parsed['status'], 'partial')
                self.assertEqual(len(records), 1007)
                self.assertEqual(Counter(r['event'] for r in records), {'SDBL': 1005, 'SESN': 2})
                self.assertEqual([r['properties']['Func'] for r in (records[0], records[-1])],
                                 ['Start', 'Finish'])
                for record in (records[0], records[-1]):
                    self.assertEqual(record['properties']['ID'], case['session_uuid'])
                    self.assertEqual(record['properties']['Nmb'], str(case['session_number']))
                    self.assertEqual(record['properties']['IB'], PUBLIC_BASE)
                ambiguous = [r for r in records if r['ambiguous_properties']]
                self.assertEqual(len(ambiguous), 200)
                for record in ambiguous:
                    self.assertEqual(set(record['ambiguous_properties']), {'Func'})
                    self.assertNotIn('Func', record['properties'])
                    self.assertGreaterEqual(len(record['ambiguous_properties']['Func']), 2)
                summary = parsed['limitations'][-1]
                self.assertEqual(summary['code'], 'additional_limitations')
                self.assertEqual(summary['counts_by_code'], {'ambiguous_property': 1})
                self.assertEqual(len(parsed['limitations']), 200)
                self.assertEqual([r['label'] for r in native['ranges']],
                                 ['session_start', 'complete_body_window', 'session_finish'])
                for section in native['ranges']:
                    published = section['published']
                    chunk = raw[published['byte_start']:published['byte_end']]
                    self.assertEqual(digest(chunk), published['sha256'])
                body = native['ranges'][1]
                self.assertEqual(body['source']['record_count'], 1005)
                self.assertEqual(body['source']['record_index_end_0'] - body['source']['record_index_start_0'], 1004)
                self.assertEqual(body['source']['sha256'], body['published']['sha256'])
                for stage, record in [('body_enter', records[1]), ('body_exit', records[-2])]:
                    marker = 'SC01LIFECYCLE:' + stage + ':' + case['nonce'] + ':' + case['job_uuid']
                    self.assertEqual(record['properties']['Sdbl'], 'SELECT\n"' + marker + '"\n')

    def test_actual_calls_and_business_results_are_verified_independently(self):
        for name, expected_calls in [('baseline', 200), ('cached', 10)]:
            with self.subTest(case=name):
                correlation, result = analyze(self.bundles[name])
                captured = self.cases[name]['observed']
                self.assertEqual(correlation['job_lifecycle']['status'], 'established')
                self.assertEqual(correlation['job_lifecycle']['state'], 'completed')
                self.assertEqual(correlation['job_lifecycle']['job_uuid'], self.cases[name]['job_uuid'])
                self.assertEqual(correlation['native_link']['linked_count'], 1005)
                self.assertEqual(result['status'], 'observed')
                self.assertEqual(result['limitations'], [])
                self.assertEqual(result['capture_validation']['status'], 'verified')
                self.assertEqual(result['capture_validation']['input_sha256'], INPUT_SHA)
                self.assertEqual(result['capture_validation']['database_seed_sha256'],
                                 result['capture_validation']['database_before_sha256'])
                validation, calls = result['result_validation'], result['external_calls']
                self.assertEqual(validation['status'], 'matches_expected')
                self.assertEqual((validation['expected_count'], validation['actual_count'], validation['written_count']),
                                 (200, 200, 200))
                self.assertEqual(validation['expected_sha256'], RESULT_SHA)
                self.assertEqual(validation['actual_sha256'], RESULT_SHA)
                self.assertEqual(calls['status'], 'verified')
                self.assertEqual(calls['count'], expected_calls)
                self.assertEqual(calls['unique_skus'], 10)
                self.assertEqual(calls['repeated_lookups'], expected_calls - 10)
                self.assertEqual(result['load_duration_ms'], captured['load_duration_ms'])
                self.assertAlmostEqual(calls['server_elapsed_seconds'], captured['server_elapsed_seconds'])
                self.assertAlmostEqual(calls['client_elapsed_seconds'], captured['client_elapsed_seconds'])
                self.assertNotIn('cause', result)
                self.assertIsNone(correlation['job_lifecycle']['queue_seconds'])

    def test_changed_business_value_is_rejected_after_snapshot_validation(self):
        bundle = copy.deepcopy(self.bundles['baseline'])
        change_document(bundle, '1c-job-runtime-v1',
                        lambda d: d['result_rows'][0].update(amount=d['result_rows'][0]['amount'] + 1),
                        role='controller')
        correlation, result = analyze(bundle)
        self.assertEqual(correlation['job_lifecycle']['status'], 'established')
        self.assertEqual(result['result_validation']['status'], 'mismatch')
        self.assertEqual(result['result_validation']['mismatch_count'], 1)
        self.assertNotEqual(result['result_validation']['expected_sha256'], result['result_validation']['actual_sha256'])
        self.assertEqual(result['external_calls']['status'], 'verified')
        self.assertEqual(result['external_calls']['count'], 200)

    def test_missing_server_request_does_not_become_a_successful_reduced_count(self):
        bundle = copy.deepcopy(self.bundles['baseline'])
        change_document(bundle, 'sc01-http-service-v1', lambda d: d['requests'].pop())
        _, result = analyze(bundle)
        self.assertEqual(result['external_calls']['status'], 'not_verified')
        self.assertIsNone(result['external_calls']['count'])
        self.assertEqual(result['result_validation']['status'], 'matches_expected')
        self.assertIn('client_server_request_sets_differ', [x['code'] for x in result['limitations']])

    def test_other_real_run_cannot_supply_a_server_request(self):
        bundle = copy.deepcopy(self.bundles['baseline'])
        other_job = self.cases['cached']['job_uuid']
        change_document(bundle, 'sc01-http-service-v1', lambda d: d['requests'][0].update(job_uuid=other_job))
        _, result = analyze(bundle)
        self.assertEqual(result['external_calls']['status'], 'not_verified')
        self.assertIn('artifact_run_identity_mismatch', [x['code'] for x in result['limitations']])

    def test_mode_label_does_not_create_a_cached_result_or_diagnosis(self):
        bundle = copy.deepcopy(self.bundles['baseline'])
        change_document(bundle, '1c-job-runtime-v1', lambda d: d['workload'].update(mode='cached'), role='worker_exit')
        _, result = analyze(bundle)
        self.assertEqual(result['mode'], 'cached')
        self.assertEqual(result['external_calls']['count'], 200)
        self.assertEqual(result['external_calls']['repeated_lookups'], 190)
        self.assertEqual(result['result_validation']['actual_sha256'], RESULT_SHA)
        self.assertNotIn('cause', result)

    def test_public_files_have_only_controlled_paths_and_host_aliases(self):
        def hosts(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == 'computer_name':
                        self.assertEqual(item, 'controlled-host')
                    hosts(item)
            elif isinstance(value, list):
                for item in value:
                    hosts(item)

        paths = [p for p in FIXTURES.iterdir() if p.is_file()]
        paths += [(FIXTURES / name).resolve() for name in self.passport['dependencies']]
        for path in paths:
            with self.subTest(file=path.name):
                text = path.read_bytes().decode('utf-8-sig')
                normalized = text.replace('\\\\', '\\').replace(PUBLIC_BASE, '').replace(PUBLIC_INPUT, '')
                self.assertNotRegex(normalized, r'(?<![A-Za-z0-9_])[A-Za-z]:[\\/]')
                self.assertNotRegex(normalized, r'(?i)([\\/]Users[\\/]|\.local[\\/]|file://)')
                if path.suffix == '.json':
                    hosts(json.loads(text))


if __name__ == '__main__':
    unittest.main()
