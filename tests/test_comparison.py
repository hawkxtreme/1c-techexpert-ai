"""Comparison gates on observed effects, never the implementation variant label."""
import copy
import importlib
import importlib.util
import json
import unittest
import uuid


def report(index, seconds, *, requests=200, mode='baseline'):
    evidence = [dict(id='s1:1', source='s1', sha256='a'*64, line=1)]
    return dict(case_id=f'{index:032x}', scenario='SC-01', product_version='0.4.0', origin='provided',
        job_correlation=dict(job_lifecycle=dict(status='established', state='completed',
            job_uuid=str(uuid.UUID(int=index)), execution_seconds=seconds, precision_seconds=1,
            execution_bounds_seconds=[max(0, seconds-1), seconds+1], evidence=evidence),
            native_link=dict(status='established', identity=dict(database_file=r'c:\controlled\orders', process_label='1cv8'))),
        sources=[dict(id='s1', format='1c-tj-text-v1', profile=dict(platform_version='8.3.27.1989')),
                 dict(id='s2', format='1c-job-runtime-v1', profile=dict(platform_version='8.3.27.1989'))],
        order_load=dict(status='observed', scope='controlled_windows_file_8.3.27.1989', mode=mode,
            workload_signature=dict(input_sha256='b'*64, catalog_revision='sc01-catalog-v1', catalog_sha256='c'*64,
                                    row_count=200, service_delay_ms=40, database_seed_sha256='f'*64,
                                    observed_computer_name='controlled-host', service_module_sha256='9'*64,
                                    evidence=evidence),
            result_validation=dict(status='matches_expected', expected_count=200, actual_count=200,
                written_count=200, expected_sha256='d'*64, actual_sha256='d'*64, mismatch_count=0, evidence=evidence),
            external_calls=dict(status='verified', count=requests, unique_skus=10, repeated_lookups=requests-10,
                server_elapsed_seconds=requests*.04, client_elapsed_seconds=requests*.042, evidence=evidence),
            load_duration_ms=seconds*1000+123, load_duration_evidence=evidence, limitations=[]))


def series():
    return ([report(i+1, 10) for i in range(5)],
            [report(i+101, 1, requests=10, mode='cached') for i in range(5)])


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.comparison'),
                             'Comparison implementation does not exist yet')
        self.compare = importlib.import_module('src.techexpert.comparison').compare_reports

    def test_five_distinct_comparable_pairs_verify_effect_and_preserve_evidence(self):
        before, after = series()
        value = self.compare(before, after)
        self.assertEqual(value['status'], 'verified')
        self.assertEqual(value['performance']['status'], 'improved')
        self.assertEqual(value['result_correctness']['status'], 'matches_expected')
        self.assertEqual(value['external_calls']['before_counts'], [200]*5)
        self.assertEqual(value['external_calls']['after_counts'], [10]*5)
        self.assertEqual(value['performance']['before_median_seconds'], 10)
        self.assertEqual(value['performance']['after_median_seconds'], 1)
        self.assertAlmostEqual(value['performance']['conservative_reduction_fraction'], 7/9)
        self.assertEqual(len(value['pairs']), 5)
        self.assertEqual(value['pairs'][0]['before_case_id'], before[0]['case_id'])
        self.assertEqual(value['pairs'][0]['before_execution_evidence']['records'][0]['id'], 's1:1')
        self.assertTrue(value['requires_ai_interpretation'])
        self.assertIsNone(value['cause'])

    def test_group_descriptions_keep_spread_and_missing_values_separate_from_effect_criteria(self):
        before, after = series()
        before[0]['job_correlation']['job_lifecycle'].update(execution_seconds=100, execution_bounds_seconds=[99, 101])
        result = self.compare(before, after)
        self.assertIn('before_distribution', result['performance'], 'Descriptive samples are missing')
        self.assertEqual(result['performance']['before_distribution']['count'], 5)
        self.assertEqual(result['performance']['before_distribution']['maximum'], 100)
        self.assertEqual(result['performance']['before_distribution']['median'], 10)
        self.assertFalse(result['performance']['before_distribution']['population_inference'])
        self.assertEqual(result['performance']['status'], 'improved')
        after[0]['job_correlation']['job_lifecycle']['execution_seconds'] = None
        result = self.compare(before, after)
        self.assertEqual(result['performance']['after_distribution']['count'], 4)
        self.assertEqual(result['performance']['after_distribution']['missing_count'], 1)
        self.assertIsNone(result['performance']['after_median_seconds'])
        self.assertEqual(result['performance']['status'], 'not_comparable')

    def test_protected_projection_keeps_synthetic_calculation_separate(self):
        from src.techexpert.context_fields import comparison_summary

        before, after = series()
        supplied = comparison_summary(self.compare(before, after))
        for report in before + after:
            report['origin'] = 'synthetic'
        synthetic = comparison_summary(self.compare(before, after))
        self.assertEqual(supplied['verification_scope'], 'provided_evidence_only')
        self.assertEqual(synthetic['verification_scope'], 'synthetic_calculations_only')
        self.assertEqual(supplied['provenance']['overall'], 'provided')
        self.assertEqual(synthetic['provenance']['overall'], 'synthetic')
        self.assertFalse(supplied['provenance']['origin_authenticity_verified'])
        self.assertFalse(synthetic['provenance']['origin_authenticity_verified'])

    def test_mode_and_existing_cause_labels_do_not_determine_effect(self):
        before, after = series()
        for case in before+after:
            case['order_load']['mode']='anything'
            case['cause_state']='established_by_someone_else'
        self.assertEqual(self.compare(before,after)['status'],'verified')
        for case in after:
            case['job_correlation']['job_lifecycle'].update(execution_seconds=11,execution_bounds_seconds=[10,12])
        result=self.compare(before,after)
        self.assertNotEqual(result['status'],'verified')
        self.assertNotEqual(result['performance']['status'],'improved')

    def test_each_declared_pair_matters_and_no_unfavorable_run_is_removed(self):
        before,after=series()
        after[3]['job_correlation']['job_lifecycle'].update(execution_seconds=10,execution_bounds_seconds=[9,11])
        result=self.compare(before,after)
        self.assertEqual(len(result['pairs']),5)
        self.assertEqual(result['performance']['status'],'inconclusive')
        self.assertFalse(result['pairs'][3]['strictly_faster_with_precision'])
        self.assertNotEqual(result['status'],'verified')

    def test_zero_after_is_finite_and_bounds_are_used(self):
        before,after=series()
        for case in after:
            case['job_correlation']['job_lifecycle'].update(execution_seconds=0,execution_bounds_seconds=[0,1])
        result=self.compare(before,after)
        self.assertEqual(result['status'],'verified')
        self.assertIsNone(result['performance']['reported_speedup_ratio'])
        json.dumps(result,allow_nan=False)
        for case in before:
            case['job_correlation']['job_lifecycle'].update(execution_seconds=1,execution_bounds_seconds=[0,2])
        self.assertEqual(self.compare(before,after)['performance']['status'],'inconclusive')

    def test_insufficient_or_unbalanced_repeats_are_explicit_not_silently_trimmed(self):
        before,after=series()
        for left,right in [(before[:1],after[:1]),(before,after[:4]),([],[])]:
            with self.subTest(counts=(len(left),len(right))):
                result=self.compare(left,right)
                self.assertNotEqual(result['status'],'verified')
                self.assertIn('insufficient_repeats',[x['code'] for x in result['limitations']])
                self.assertEqual(result['before_count'],len(left))
                self.assertEqual(result['after_count'],len(right))

    def test_duplicate_case_or_job_cannot_inflate_repeat_count(self):
        for field in ('case_id','job_uuid'):
            before,after=series()
            if field=='case_id':
                after[0]['case_id']=before[0]['case_id']
            else:
                after[0]['job_correlation']['job_lifecycle']['job_uuid']=before[0]['job_correlation']['job_lifecycle']['job_uuid']
            result=self.compare(before,after)
            self.assertEqual(result['comparability']['status'],'not_comparable')
            self.assertNotEqual(result['status'],'verified')

    def test_changed_input_catalog_delay_database_or_profile_is_not_comparable(self):
        changes=[('input_sha256','e'*64),('catalog_sha256','e'*64),('catalog_revision','v2'),
                 ('row_count',199),('service_delay_ms',1),('database_seed_sha256','e'*64)]
        for key,value in changes:
            before,after=series();after[0]['order_load']['workload_signature'][key]=value
            self.assertEqual(self.compare(before,after)['comparability']['status'],'not_comparable',key)
        before,after=series();after[0]['job_correlation']['native_link']['identity']['database_file']=r'c:\other'
        self.assertEqual(self.compare(before,after)['comparability']['status'],'not_comparable')
        before,after=series();after[0]['sources'][0]['profile']['platform_version']='8.3.99'
        self.assertEqual(self.compare(before,after)['comparability']['status'],'not_comparable')

    def test_missing_or_unproven_job_evidence_is_not_improvement(self):
        for kind in ('failed','native','order_load','execution','bounds','precision','evidence'):
            before,after=series();case=after[0];life=case['job_correlation']['job_lifecycle']
            if kind=='failed': life['state']='failed'
            if kind=='native': case['job_correlation']['native_link']['status']='not_established'
            if kind=='order_load': case['order_load']['status']='not_verified'
            if kind=='execution': life['execution_seconds']=None
            if kind=='bounds': life['execution_bounds_seconds']=[-1,1]
            if kind=='precision': life['precision_seconds']=0
            if kind=='evidence': life['evidence']=[]
            result=self.compare(before,after)
            self.assertNotEqual(result['status'],'verified',kind)
            self.assertEqual(result['performance']['status'],'not_comparable',kind)

    def test_result_mismatch_stays_separate_from_measured_speed(self):
        before,after=series();actual=after[0]['order_load']['result_validation']
        actual.update(status='mismatch',actual_sha256='e'*64,mismatch_count=1)
        result=self.compare(before,after)
        self.assertEqual(result['result_correctness']['status'],'mismatch')
        self.assertEqual(result['performance']['status'],'improved')
        self.assertEqual(result['status'],'not_verified')

    def test_less_work_cannot_be_reported_as_comparable_speedup(self):
        before,after=series();after[0]['order_load']['result_validation']['written_count']=199
        result=self.compare(before,after)
        self.assertEqual(result['performance']['status'],'not_comparable')
        self.assertNotEqual(result['status'],'verified')

    def test_result_digest_is_checked_not_just_status_and_count(self):
        before,after=series();after[0]['order_load']['result_validation']['actual_sha256']='e'*64
        result=self.compare(before,after)
        self.assertEqual(result['result_correctness']['status'],'mismatch')
        self.assertEqual(result['status'],'not_verified')

    def test_unverified_http_counts_are_unknown_not_zero(self):
        before,after=series();after[0]['order_load']['external_calls']['status']='not_verified'
        result=self.compare(before,after)
        self.assertEqual(result['external_calls']['status'],'not_verified')
        self.assertEqual(result['external_calls']['before_counts'],[200]*5)
        self.assertEqual(result['external_calls']['after_counts'],[None,10,10,10,10])
        self.assertEqual(result['external_calls']['before_median_count'],200)
        self.assertIsNone(result['external_calls']['after_median_count'])

    def test_milliseconds_are_descriptive_not_substituted_for_platform_bounds(self):
        before,after=series()
        for case in after: case['order_load']['load_duration_ms']=999999
        result=self.compare(before,after)
        self.assertEqual(result['performance']['after_median_seconds'],1)
        self.assertEqual(result['load_observations']['after_median_ms'],999999)
        self.assertEqual(result['performance']['status'],'improved')

    def test_defensive_bounds_and_no_input_mutation(self):
        before,after=series();original=copy.deepcopy((before,after))
        self.compare(before,after)
        self.assertEqual((before,after),original)
        for bad in (None,{},'bad'):
            with self.assertRaises(ValueError):self.compare(bad,after)
        with self.assertRaises(ValueError):self.compare(before*5,after)
        for bad in (None,{},'bad'):
            result=self.compare([bad]+before[1:],after)
            self.assertNotEqual(result['status'],'verified')
        for bad in (True,float('nan'),float('inf'),-1):
            before,after=series();after[0]['job_correlation']['job_lifecycle']['execution_seconds']=bad
            result=self.compare(before,after)
            self.assertEqual(result['performance']['status'],'not_comparable')
            json.dumps(result,allow_nan=False)

    def test_unbounded_optional_duration_does_not_crash_or_produce_non_json_output(self):
        before,after=series()
        after[0]['order_load']['load_duration_ms']=10**500
        result=self.compare(before,after)
        self.assertIsNone(result['load_observations']['after_median_ms'])
        json.dumps(result,allow_nan=False)

    def test_missing_or_conflicting_hostname_prevents_same_machine_claim(self):
        for value in (None,'other-host','',[],True):
            before,after=series()
            after[0]['order_load']['workload_signature']['observed_computer_name']=value
            result=self.compare(before,after)
            self.assertEqual(result['comparability']['status'],'not_comparable')
            self.assertEqual(result['status'],'not_verified')
        before,after=series()
        for case in after:
            case['order_load']['workload_signature']['observed_computer_name']='CONTROLLED-HOST'
        result=self.compare(before,after)
        self.assertEqual(result['status'],'verified')
        self.assertIn('not_physical_node_identity',result['comparability']['host_identity_basis'])

    def test_service_code_must_match_but_workload_code_may_be_the_fix(self):
        before,after=series()
        for case in before: case['order_load']['module_sha256']='7'*64
        for case in after: case['order_load']['module_sha256']='8'*64
        self.assertEqual(self.compare(before,after)['status'],'verified')
        for value in (None,'8'*64,'not-a-hash'):
            one,two=copy.deepcopy((before,after))
            two[0]['order_load']['workload_signature']['service_module_sha256']=value
            result=self.compare(one,two)
            self.assertEqual(result['comparability']['status'],'not_comparable')
            self.assertEqual(result['status'],'not_verified')

    def test_declared_origin_is_preserved_without_asserting_authenticity(self):
        before,after=series()
        result=self.compare(before,after)
        self.assertEqual(result['provenance']['before'],'provided')
        self.assertEqual(result['provenance']['after'],'provided')
        self.assertEqual(result['verification_scope'],'provided_evidence_only')
        self.assertFalse(result['provenance']['origin_authenticity_verified'])
        for case in before+after: case['origin']='synthetic'
        result=self.compare(before,after)
        self.assertEqual(result['status'],'verified')
        self.assertEqual(result['provenance']['overall'],'synthetic')
        self.assertEqual(result['verification_scope'],'synthetic_calculations_only')
        after[0]['origin']='provided'
        result=self.compare(before,after)
        self.assertEqual(result['provenance']['after'],'mixed')
        self.assertEqual(result['provenance']['overall'],'mixed')
        self.assertEqual(result['verification_scope'],'mixed_or_unknown_evidence_only')
        del after[0]['origin']
        result=self.compare(before,after)
        self.assertEqual(result['provenance']['after'],'unknown')
        self.assertEqual(result['provenance']['overall'],'unknown')
        self.assertEqual(result['provenance']['case_origins'][5]['origin'],'unknown')


if __name__=='__main__':unittest.main()
