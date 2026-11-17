"""Describe explicit retained observations without declaring a normal workload."""
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from src.techexpert import artifacts, input_intake, storage
from src.techexpert.input_adapters import import_selected
from src.techexpert.inputs import InputError
from test_sc01 import SCOPE

ROOT = Path(__file__).resolve().parents[1]


def measurement(identity='1', value=2, *, operation='post', success=True, started='2026-11-17T09:00:00Z'):
    return dict(id=identity, operation=operation, started_at=started, duration_seconds=value, success=success)


class SampleDescriptionTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.sample_description'),
                             'Retained sample description is not implemented')
        self.api = importlib.import_module('src.techexpert.sample_description')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'state'
        self.number = 0

    def case(self, seconds=2):
        self.number += 1
        selection = dict(SCOPE, run='run-' + str(self.number))
        start = datetime(2026, 11, 17, 9, self.number, tzinfo=timezone.utc)
        rows = [dict(kind='started', timestamp=start.isoformat(), scope=selection)]
        if seconds is not None:
            rows.append(dict(kind='finished', timestamp=(start + timedelta(seconds=seconds)).isoformat(), scope=selection))
        path = self.root / ('events-' + str(self.number) + '.jsonl')
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        manifest = self.root / ('case-' + str(self.number) + '.json')
        manifest.write_text(json.dumps(dict(schema=1, scenario='SC-01', origin='synthetic', selection=selection,
            reported_normal_seconds=300, sources=[dict(path=str(path), format='normalized-events-v1')])), encoding='utf-8')
        report = storage.investigate(manifest, self.state)
        return dict(kind='case', id=report['case_id'])

    def apdex(self, rows, name=None):
        self.number += 1
        path = self.root / (name or ('measurements-' + str(self.number) + '.json'))
        path.write_text(json.dumps(rows), encoding='utf-8')
        report = artifacts.import_apdex(self.state, path, 97, operation='post')
        return dict(kind='artifact', id=report['artifact_id'])

    def describe(self, refs, **options):
        return self.api.describe(self.state, refs, operation='post', **options)

    def change(self, ref, edit):
        folder = self.state / ('cases' if ref['kind'] == 'case' else 'artifacts') / ref['id']
        report = json.loads((folder / 'report.json').read_text(encoding='utf-8'))
        edit(report)
        storage.write_json(folder / 'report.json', report)
        receipt = json.loads((folder / 'receipt.json').read_text(encoding='utf-8'))
        receipt['report_sha256'] = hashlib.sha256((folder / 'report.json').read_bytes()).hexdigest()
        storage.write_json(folder / 'receipt.json', receipt)

    def test_case_sample_has_spread_and_preserves_reported_context_and_norm(self):
        refs = [self.case(n) for n in (1, 2, 3, 4)]
        result = self.describe(refs, context=dict(platform_version='reported-version', workload='10 rows', launch_conditions='test copy'),
            reported_normal_seconds=300)
        self.assertEqual(result['statistics']['count'], 4)
        self.assertEqual(result['statistics']['median'], 2.5)
        self.assertEqual(result['statistics']['median_absolute_deviation'], 1)
        self.assertEqual(result['descriptor']['context']['origin'], 'caller_reported_not_verified')
        self.assertEqual(result['descriptor']['reported_normal'], dict(seconds=300, status='user_reported_not_measured'))
        self.assertFalse(result['normal_established'])
        self.assertIsNone(result['independent_runs'])
        self.assertEqual(result['counts']['unknown_outcome'], 4)
        self.assertTrue(all(row['operation_binding'] == 'caller_reported_not_verified' for row in result['records']))
        self.assertEqual(result['period']['first_started_utc'], '2026-11-17T09:01:00+00:00')
        self.assertEqual(len(result['dependencies']), 4)

    def test_apdex_attempts_keep_failures_unknowns_operation_and_window_exclusions(self):
        rows = [measurement('1', 2), measurement('2', 20, success=False), measurement('3', None),
            measurement('4', 3, operation='other'), measurement('5', 6, started='2026-11-17T09:01:00Z')]
        ref = self.apdex(rows)
        result = self.describe([ref], window=dict(start='2026-11-17T09:00:00Z', end='2026-11-17T09:01:00Z'))
        self.assertEqual(result['counts']['inspected'], 5)
        self.assertEqual(result['counts']['selected'], 3)
        self.assertEqual(result['statistics']['count'], 1)
        self.assertEqual(result['statistics']['missing_count'], 1)
        self.assertEqual(result['statistics']['median'], 2)
        self.assertEqual(result['exclusions'], dict(unsuccessful_completion=1, other_operation=1, outside_window=1))
        self.assertEqual(result['descriptor']['reported_normal']['status'], 'not_provided')
        self.assertNotEqual(result['descriptor']['reported_normal']['seconds'], 97)
        self.assertEqual(result['selection']['window_rule'], 'operation_start_in_half_open_window_whole_duration')

    def test_window_keeps_full_execution_and_includes_start_but_excludes_end(self):
        ref = self.case(120)
        result = self.describe([ref], window=dict(start='2026-11-17T09:01:00Z', end='2026-11-17T09:01:01Z'))
        self.assertEqual(result['statistics']['median'], 120)
        excluded = self.describe([ref], window=dict(start='2026-11-17T09:00:00Z', end='2026-11-17T09:01:00Z'))
        self.assertEqual(excluded['statistics']['count'], 0)
        self.assertEqual(excluded['exclusions'], dict(outside_window=1))

    def test_unknown_execution_never_uses_a_call_duration_or_zero(self):
        unknown = self.case(None)
        known = self.case(10)
        result = self.describe([unknown, known])
        self.assertEqual((result['statistics']['count'], result['statistics']['missing_count']), (1, 1))
        self.assertEqual(result['statistics']['median'], 10)
        self.assertEqual(result['records'][0]['status'], 'missing_duration')

    def test_created_at_is_not_an_operation_time_and_missing_start_is_explicit(self):
        ref = self.case(4)
        self.change(ref, lambda report: report.update(timeline=[]))
        result = self.describe([ref])
        self.assertEqual(result['statistics']['median'], 4)
        self.assertIsNone(result['period']['first_started_utc'])
        self.assertEqual(result['period']['missing_start_count'], 1)
        result = self.describe([ref], window=dict(start='2026-11-17T00:00:00Z', end='2026-11-18T00:00:00Z'))
        self.assertEqual(result['exclusions'], dict(unknown_operation_start=1))

    def test_missing_metric_evidence_is_unknown_even_when_a_numeric_duration_is_present(self):
        ref = self.case(2)
        self.change(ref, lambda report: report['metrics'][1].update(evidence=[]))
        result = self.describe([ref])
        self.assertEqual(result['statistics']['count'], 0)
        self.assertEqual(result['statistics']['missing_count'], 1)
        self.assertEqual(result['records'][0]['reason'], 'missing_measurement_evidence')

    def test_native_fixture_uses_platform_execution_with_its_separate_precision(self):
        report = storage.investigate(ROOT / 'tests/fixtures/order-load/baseline.json', self.state)
        result = self.describe([dict(kind='case', id=report['case_id'])])
        self.assertEqual(result['statistics']['median'], report['durations_seconds']['execution'])
        self.assertEqual(result['records'][0]['precision_seconds'], 1)
        self.assertEqual(result['records'][0]['outcome'], 'success')
        self.assertEqual(result['inputs'][0]['declared_platform_versions'], ['8.3.27.1989'])
        self.assertFalse(result['normal_established'])

    def test_failed_case_is_counted_and_excluded_from_completed_duration_distribution(self):
        report = storage.investigate(ROOT / 'tests/fixtures/order-load/baseline.json', self.state)
        ref = dict(kind='case', id=report['case_id'])
        self.change(ref, lambda doc: doc['job_correlation']['job_lifecycle'].update(state='failed'))
        result = self.describe([ref])
        self.assertEqual(result['exclusions'], dict(unsuccessful_completion=1))
        self.assertEqual(result['statistics']['count'], 0)
        self.assertEqual(result['counts']['selected'], 1)

    def test_same_catalogue_member_is_one_input_but_equal_text_from_distinct_files_is_not_merged(self):
        ref = self.apdex([measurement()])
        result = self.describe([ref, self.apdex([measurement()])])
        self.assertEqual(result['statistics']['count'], 2)
        path = self.root / 'provided.json'
        path.write_text(json.dumps([measurement()]), encoding='utf-8')
        plan = input_intake.inspect(self.state, [dict(path=str(path), kind='file')])
        refs = []
        for target in (2, 97):
            artifact = import_selected('apdex.import', dict(measurements=str(path), target_seconds=target,
                input_plan=plan['artifact_id'], members=['m1']), self.state, self.state)
            refs.append(dict(kind='artifact', id=artifact['artifact_id']))
        path.unlink()
        result = self.describe(refs)
        self.assertEqual(result['statistics']['count'], 1)
        self.assertEqual(result['exclusions'], dict(duplicate_input_view=1))
        self.assertEqual(len(result['dependencies']), 3)
        self.assertIsNone(result['independent_runs'])

    def test_deleted_originals_are_not_needed_and_saved_source_corruption_is_refused(self):
        ref = self.apdex([measurement()])
        for path in self.root.glob('*.json'):
            path.unlink()
        self.assertEqual(self.describe([ref])['statistics']['count'], 1)
        source = self.state / 'artifacts' / ref['id'] / 'sources/s1.bin'
        source.write_bytes(b'changed retained bytes')
        with self.assertRaises(InputError):
            self.describe([ref])

    def test_retained_parent_crc_and_binding_cannot_be_bypassed(self):
        path = self.root / 'provided.zip'
        with zipfile.ZipFile(path, 'w') as zipped:
            zipped.writestr('measurements.json', json.dumps([measurement()]))
        plan = input_intake.inspect(self.state, [dict(path=str(path), kind='zip')])
        result = import_selected('apdex.import', dict(measurements=str(path), target_seconds=2,
            input_plan=plan['artifact_id'], members=['m1']), self.state, self.state)
        ref = dict(kind='artifact', id=result['artifact_id'])
        self.assertEqual(self.describe([ref])['statistics']['count'], 1)
        parent_ref = dict(kind='artifact', id=plan['artifact_id'])
        self.change(parent_ref, lambda doc: doc['result']['members'][0].update(crc32=1))
        with self.assertRaises(InputError):
            self.describe([ref])

    def test_only_supported_retained_measurements_and_finite_arguments_are_accepted(self):
        ref = self.case()
        for refs in ([], [ref, ref], [dict(ref, kind='path')], [dict(ref, id='../bad')], [dict(ref, path='original')], [ref] * 17):
            with self.subTest(refs=refs), self.assertRaises(InputError):
                self.describe(refs)
        for options in (dict(context=dict(password='bad')), dict(reported_normal_seconds=True),
                dict(window=dict(start='2026-11-17T00:00:00', end='2026-11-18T00:00:00Z')),
                dict(offset=-1), dict(limit=201)):
            with self.subTest(options=options), self.assertRaises(InputError):
                self.describe([ref], **options)
        artifact = artifacts.save_artifact(self.state, 'os_metrics', {}, [('os', b'{}')], {})
        with self.assertRaises(InputError):
            self.describe([dict(kind='artifact', id=artifact['artifact_id'])])

    def test_pagination_keeps_the_whole_sample_summary_and_preserves_slow_observations(self):
        ref = self.apdex([measurement(str(n), n) for n in (1, 2, 1000)])
        first = self.describe([ref], limit=1)
        last = self.describe([ref], offset=2, limit=1)
        self.assertEqual(first['statistics'], last['statistics'])
        self.assertEqual(first['statistics']['maximum'], 1000)
        self.assertEqual(first['next_offset'], 1)
        self.assertIsNone(last['next_offset'])
        self.assertEqual(last['records'][0]['value_seconds'], 1000)
        self.assertEqual(first['selection_sha256'], last['selection_sha256'])

    def test_large_finite_apdex_duration_is_explicitly_outside_descriptive_profile(self):
        ref = self.apdex([measurement('too-large', 10**400), measurement('usable', 3)])
        result = self.describe([ref])
        self.assertEqual(result['statistics']['median'], 3)
        self.assertEqual(result['exclusions'], dict(duration_outside_supported_range=1))

    def test_same_case_catalogue_view_does_not_create_a_second_operation_observation(self):
        self.case(2)
        manifest = self.root / 'case-1.json'
        document = json.loads(manifest.read_text(encoding='utf-8'))
        path = Path(document['sources'][0]['path'])
        plan = input_intake.inspect(self.state, [dict(path=str(path), kind='file')])
        document['sources'][0]['path'] = 'm1'
        manifest.write_text(json.dumps(document), encoding='utf-8')
        refs = []
        for _ in range(2):
            case = input_intake.analyze(self.state, self.state, manifest, plan['artifact_id'])
            refs.append(dict(kind='case', id=case['case_id']))
        result = self.describe(refs)
        self.assertEqual(result['statistics']['count'], 1)
        self.assertEqual(result['exclusions'], dict(duplicate_input_view=1))
        self.change(refs[1], lambda report: (report['durations_seconds'].update(execution=3), report['metrics'][1].update(value=3)))
        conflicted = self.describe(refs)
        self.assertEqual(conflicted['statistics']['count'], 0)
        self.assertEqual(conflicted['exclusions'], dict(conflicting_input_interpretation=2))
        self.assertEqual(len(conflicted['records']), 2)

    def test_missing_old_case_structures_remain_unknown_without_an_untyped_exception(self):
        ref = self.case(2)
        self.change(ref, lambda report: report.update(timeline=None, job_correlation=None, durations_seconds=None))
        result = self.describe([ref])
        self.assertEqual(result['statistics']['count'], 0)
        self.assertEqual(result['statistics']['missing_count'], 1)
        self.assertIsNone(result['period']['first_started_utc'])

    def test_extreme_values_do_not_escape_the_declared_numeric_output_profile(self):
        ref = self.apdex([measurement('very-large', 10**400)])
        result = self.describe([ref])
        self.assertEqual(result['exclusions'], dict(duration_outside_supported_range=1))
        self.assertIsNone(result['records'][0]['value_seconds'])
        self.assertTrue(result['records'][0]['original_value_in_retained_source'])

    def test_case_time_changes_affect_the_selection_receipt_even_with_same_value(self):
        ref = self.case(2)
        first = self.describe([ref])
        self.change(ref, lambda report: report['timeline'][0].update(timestamp='2026-11-17T10:00:00Z'))
        changed = self.describe([ref])
        self.assertEqual(first['statistics'], changed['statistics'])
        self.assertNotEqual(first['selection_sha256'], changed['selection_sha256'])

    def test_inspected_measurement_work_budget_applies_across_all_selected_inputs(self):
        rows = [measurement(str(n), 1) for n in range(50001)]
        refs = [self.apdex(rows), self.apdex(rows)]
        with self.assertRaisesRegex(InputError, '100000'):
            self.describe(refs)

    def test_parent_request_change_during_binding_validation_is_not_adopted_silently(self):
        path = self.root / 'provided.json'
        path.write_text(json.dumps([measurement()]), encoding='utf-8')
        plan = input_intake.inspect(self.state, [dict(path=str(path), kind='file')])
        artifact = import_selected('apdex.import', dict(measurements=str(path), target_seconds=2,
            input_plan=plan['artifact_id'], members=['m1']), self.state, self.state)
        check = self.api.retained.check_plan
        def concurrent_change(*args):
            check(*args)
            parent = self.state / 'artifacts' / plan['artifact_id']
            request = json.loads((parent / 'request.json').read_text(encoding='utf-8'))
            request['concurrent_change'] = 'a different request'
            storage.write_json(parent / 'request.json', request)
            receipt = json.loads((parent / 'receipt.json').read_text(encoding='utf-8'))
            receipt['request_sha256'] = hashlib.sha256((parent / 'request.json').read_bytes()).hexdigest()
            storage.write_json(parent / 'receipt.json', receipt)
        with patch.object(self.api.retained, 'check_plan', side_effect=concurrent_change), self.assertRaises(InputError):
            self.describe([dict(kind='artifact', id=artifact['artifact_id'])])

    def test_reordering_same_catalogue_files_preserves_one_sample_observation(self):
        paths = []
        for kind, stamp in [('started', '2026-11-17T09:00:00Z'), ('finished', '2026-11-17T09:00:02Z')]:
            path = self.root / (kind + '.jsonl')
            path.write_text(json.dumps(dict(kind=kind, timestamp=stamp, scope=SCOPE)) + '\n', encoding='utf-8')
            paths.append(path)
        plan = input_intake.inspect(self.state, [dict(path=str(path), kind='file') for path in paths])
        manifest = self.root / 'ordered-case.json'
        refs = []
        for members in (['m1', 'm2'], ['m2', 'm1']):
            manifest.write_text(json.dumps(dict(schema=1, scenario='SC-01', origin='synthetic', selection=SCOPE,
                sources=[dict(path=member, format='normalized-events-v1') for member in members])), encoding='utf-8')
            case = input_intake.analyze(self.state, self.state, manifest, plan['artifact_id'])
            self.assertEqual(case['durations_seconds']['execution'], 2)
            refs.append(dict(kind='case', id=case['case_id']))
        result = self.describe(refs)
        self.assertEqual(result['statistics']['count'], 1)
        self.assertEqual(result['exclusions'], dict(duplicate_input_view=1))
        self.assertEqual(result['statistics']['median'], 2)


if __name__ == '__main__':
    unittest.main()
