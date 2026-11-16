"""Synthetic contracts for observed order-load evidence, not native validation."""
import copy
import hashlib
import importlib
import importlib.util
import json
import unittest
from uuid import UUID


JOB, NONCE, BATCH, INSTANCE = (str(UUID(int=n)) for n in (1, 2, 3, 4))
REVISION = 'sc01-catalog-v1'
START = 63930406441000
CSV = b'order_id,sku,qty\nO1,SKU000,2\nO2,SKU000,3\nO3,SKU001,1\n'
CODE = b'// Synthetic controlled order loader\n'
SEED = 'e' * 64


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def source(index, format, data, **extra):
    return dict(id=f's{index}', format=format, data=data, size=len(data),
                sha256=hashlib.sha256(data).hexdigest(), **extra)


def reference(source):
    return dict(id=source['id'] + ':1', source=source['id'], sha256=source['sha256'],
                line=1, byte_start=0, byte_end=len(source['data']))


def fixture():
    catalog = {'SKU000':100, 'SKU001':200}
    calls, requests = [], []
    for i,sku in enumerate(('SKU000','SKU000','SKU001')):
        rid = str(UUID(int=10+i))
        calls.append(dict(request_id=rid, response_request_id=rid, sku=sku, status=200,
                          started_utc_ms=START+i*50, finished_utc_ms=START+i*50+45,
                          catalog_revision=REVISION))
        requests.append(dict(request_id=rid,job_uuid=JOB,nonce=NONCE,batch_id=BATCH,sku=sku,
                             price=catalog[sku],catalog_revision=REVISION,status=200,
                             started_utc='2026-11-16T06:14:01.000+00:00',
                             finished_utc='2026-11-16T06:14:01.040+00:00',
                             started_monotonic_ns=1000000000+i*50000000,
                             finished_monotonic_ns=1040000000+i*50000000,
                             elapsed_us=40000, completed=True))
    rows = [dict(order_id=oid,sku=sku,qty=qty,price=catalog[sku],amount=qty*catalog[sku],catalog_revision=REVISION)
            for oid,sku,qty in (('O1','SKU000',2),('O2','SKU000',3),('O3','SKU001',1))]
    common = dict(schema=1,origin='controlled_real_background_job',job_uuid=JOB,nonce=NONCE,batch_id=BATCH,
                  computer_name='TEST-PC')
    controller = dict(common,input_sha256=hashlib.sha256(CSV).hexdigest(),result_rows=rows)
    enter = dict(common,observed_utc_ms=START-10)
    leave = dict(common,observed_utc_ms=START+160,workload=dict(mode='baseline',
                 input_sha256=hashlib.sha256(CSV).hexdigest(),input_rows=3,unique_skus=2,
                 http_calls=calls,written_count=3,load_started_utc_ms=START,load_finished_utc_ms=START+150))
    service = dict(schema=1,origin='controlled_loopback_http_service',service_instance=INSTANCE,
                   catalog_revision=REVISION,catalog=catalog,delay_ms=40,host='127.0.0.1',port=12345,
                   job_uuid=JOB,nonce=NONCE,batch_id=BATCH,requests=requests)
    capture = dict(schema=1,origin='controlled_isolated_1c_runner',job_uuid=JOB,nonce=NONCE,batch_id=BATCH,
                   platform_version='8.3.27.1989',database_file=r'C:\controlled\ib',
                   database_seed_sha256=SEED,database_before_sha256=SEED,
                   module_sha256=hashlib.sha256(CODE).hexdigest(),service_module_sha256='f'*64,
                   input_sha256=hashlib.sha256(CSV).hexdigest(),
                   process_exit_code=0,natural_exit=True)
    sources = [source(1,'1c-tj-text-v1',b'synthetic native evidence',profile={'platform_version':'8.3.27.1989'}),
               source(2,'1c-job-runtime-v1',encoded(controller)),source(3,'1c-job-runtime-v1',encoded(enter)),
               source(4,'1c-job-runtime-v1',encoded(leave)),source(5,'sc01-orders-csv-v1',CSV),
               source(6,'sc01-http-service-v1',encoded(service)),source(7,'sc01-run-capture-v1',encoded(capture)),
               source(8,'1c-source-text-v1',CODE)]
    docs = [dict(role=role,data=data,evidence=reference(sources[index]))
            for role,data,index in (('controller',controller,1),('worker_enter',enter,2),('worker_exit',leave,3))]
    report = dict(job_correlation=dict(job_lifecycle=dict(status='established',job_uuid=JOB,state='completed',
                    evidence=[d['evidence'] for d in docs]),
                 native_link=dict(status='established',identity=dict(job_uuid=JOB,nonce=NONCE,source='s1',
                    sha256=sources[0]['sha256'],database_file=r'c:\controlled\ib',process_label='1cv8'),
                    body=dict(runtime_evidence=[docs[1]['evidence'],docs[2]['evidence']]))))
    return dict(sources=sources,lifecycle_documents=docs), report


def update_json_source(bundle, format, edit):
    item = next(x for x in bundle['sources'] if x['format'] == format)
    value = json.loads(item['data'])
    edit(value)
    item.update(data=encoded(value),sha256=hashlib.sha256(encoded(value)).hexdigest(),size=len(encoded(value)))


def update_runtime(bundle, report, role, edit):
    doc = next(d for d in bundle['lifecycle_documents'] if d['role'] == role)
    edit(doc['data'])
    item = next(s for s in bundle['sources'] if s['id'] == doc['evidence']['source'])
    item.update(data=encoded(doc['data']),sha256=hashlib.sha256(encoded(doc['data'])).hexdigest(),size=len(encoded(doc['data'])))
    doc['evidence'] = reference(item)
    report['job_correlation']['job_lifecycle']['evidence'] = [d['evidence'] for d in bundle['lifecycle_documents']]
    report['job_correlation']['native_link']['body']['runtime_evidence'] = [d['evidence'] for d in bundle['lifecycle_documents'] if d['role'] != 'controller']


class OrderLoadTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.order_load'))
        self.analyze = importlib.import_module('src.techexpert.order_load').analyze_order_load

    def test_observed_calls_oracle_and_capture_are_independent_verified_outputs(self):
        bundle,report = fixture(); result = self.analyze(bundle,report)
        self.assertEqual(result['status'],'observed')
        self.assertEqual(result['capture_validation']['status'],'verified')
        self.assertEqual(result['capture_validation']['provenance'],'capture_runner_attested')
        validation = result['result_validation']; calls = result['external_calls']
        self.assertEqual(validation['status'],'matches_expected')
        self.assertEqual(validation['expected_sha256'],validation['actual_sha256'])
        self.assertEqual((validation['expected_count'],validation['actual_count'],validation['written_count']),(3,3,3))
        self.assertEqual(validation['mismatch_count'],0)
        self.assertEqual((calls['status'],calls['count'],calls['unique_skus'],calls['repeated_lookups']),('verified',3,2,1))
        self.assertAlmostEqual(calls['server_elapsed_seconds'],0.12)
        self.assertAlmostEqual(calls['client_elapsed_seconds'],0.135)
        self.assertEqual(result['load_duration_ms'],150)
        self.assertEqual(result['workload_signature']['database_seed_sha256'],SEED)
        self.assertEqual(result['workload_signature']['service_delay_ms'],40)
        self.assertEqual(result['workload_signature']['observed_computer_name'],'test-pc')
        self.assertEqual(result['workload_signature']['service_module_sha256'],'f'*64)
        for section in ('workload_signature','result_validation','external_calls','capture_validation'):
            self.assertTrue(result[section]['evidence'])
        self.assertTrue(result['load_duration_evidence'])

    def test_mode_does_not_determine_metrics_cause_or_signature(self):
        bundle,report = fixture(); before = self.analyze(bundle,report)
        update_runtime(bundle,report,'worker_exit',lambda d:d['workload'].update(mode='cached'))
        after = self.analyze(bundle,report)
        self.assertEqual(after['external_calls']['count'],3)
        self.assertEqual(after['external_calls']['repeated_lookups'],1)
        self.assertEqual(after['result_validation']['status'],'matches_expected')
        self.assertNotIn('mode',after['workload_signature'])
        for key in before['workload_signature']:
            if key != 'evidence': self.assertEqual(before['workload_signature'][key],after['workload_signature'][key])
        self.assertNotIn('cause',after)

    def test_reduced_actual_requests_are_counted_even_with_baseline_label(self):
        bundle,report=fixture()
        update_runtime(bundle,report,'worker_exit',lambda d:d['workload']['http_calls'].pop(1))
        update_json_source(bundle,'sc01-http-service-v1',lambda d:d['requests'].pop(1))
        result=self.analyze(bundle,report)
        self.assertEqual(result['status'],'observed')
        self.assertEqual(result['mode'],'baseline')
        self.assertEqual((result['external_calls']['count'],result['external_calls']['repeated_lookups']),(2,0))

    def test_wrong_business_field_does_not_erase_known_call_metrics(self):
        for field,value in (('order_id','other'),('sku','SKU001'),('qty',7),('price',101),('amount',999),('catalog_revision','wrong')):
            bundle,report = fixture()
            update_runtime(bundle,report,'controller',lambda d:d['result_rows'][0].update({field:value}))
            result = self.analyze(bundle,report)
            with self.subTest(field=field):
                self.assertEqual(result['result_validation']['status'],'mismatch')
                self.assertNotEqual(result['result_validation']['expected_sha256'],result['result_validation']['actual_sha256'])
                self.assertEqual(result['external_calls']['status'],'verified')

    def test_missing_extra_and_duplicate_result_rows_are_not_count_only_checks(self):
        for edit,status in ((lambda rows:rows.pop(),'mismatch'),
                            (lambda rows:rows.append(dict(rows[0])),'mismatch'),
                            (lambda rows:rows.reverse(),'matches_expected')):
            bundle,report = fixture(); update_runtime(bundle,report,'controller',lambda d:edit(d['result_rows']))
            result = self.analyze(bundle,report)['result_validation']
            self.assertEqual(result['status'],status)
        bundle,report = fixture()
        update_runtime(bundle,report,'controller',lambda d:d['result_rows'].__setitem__(1,dict(d['result_rows'][0])))
        self.assertEqual(self.analyze(bundle,report)['result_validation']['status'],'mismatch')

    def test_written_count_conflict_is_visible_even_when_projection_matches(self):
        bundle,report = fixture(); update_runtime(bundle,report,'worker_exit',lambda d:d['workload'].update(written_count=2))
        result = self.analyze(bundle,report)
        self.assertEqual(result['result_validation']['status'],'mismatch')
        self.assertEqual(result['external_calls']['status'],'verified')

    def test_missing_input_hash_in_either_runtime_witness_is_not_verified(self):
        for role in ('controller','worker_exit'):
            bundle,report = fixture()
            update_runtime(bundle,report,role,lambda d:(d['workload'] if role=='worker_exit' else d).pop('input_sha256'))
            self.assertNotEqual(self.analyze(bundle,report)['status'],'observed')

    def test_bad_source_hash_and_unsnapshotted_runtime_data_are_rejected(self):
        bundle,report=fixture(); bundle['sources'][4]['sha256']='0'*64
        self.assertEqual(self.analyze(bundle,report)['status'],'not_verified')

    def test_malformed_source_reference_types_degrade_without_exception(self):
        bundle,report=fixture();report['job_correlation']['native_link']['identity']['source']=[]
        self.assertEqual(self.analyze(bundle,report)['status'],'not_verified')
        bundle,report=fixture();bundle['lifecycle_documents'][0]['evidence']['source']={}
        self.assertEqual(self.analyze(bundle,report)['status'],'not_verified')
        bundle,report=fixture(); bundle['lifecycle_documents'][2]['data']['workload']['written_count']=99
        self.assertEqual(self.analyze(bundle,report)['status'],'not_verified')

    def test_wrong_report_run_nonce_native_hash_or_status_cannot_bind_workload(self):
        for path,value in ((('job_lifecycle','job_uuid'),str(UUID(int=99))),
                           (('native_link','status'),'not_established'),
                           (('native_link','identity','nonce'),str(UUID(int=99))),
                           (('native_link','identity','sha256'),'0'*64)):
            bundle,report=fixture(); target=report['job_correlation']
            for key in path[:-1]: target=target[key]
            target[path[-1]]=value
            self.assertEqual(self.analyze(bundle,report)['status'],'not_verified')

    def test_duplicate_roles_and_mixed_runtime_batches_are_rejected(self):
        bundle,report=fixture(); bundle['lifecycle_documents'].append(copy.deepcopy(bundle['lifecycle_documents'][0]))
        self.assertEqual(self.analyze(bundle,report)['status'],'not_verified')
        bundle,report=fixture(); update_runtime(bundle,report,'worker_exit',lambda d:d.update(batch_id=str(UUID(int=99))))
        self.assertEqual(self.analyze(bundle,report)['status'],'not_verified')

    def test_server_client_correspondence_is_bijective_and_response_id_is_required(self):
        edits=(lambda d:d['workload']['http_calls'][0].pop('response_request_id'),
               lambda d:d['workload']['http_calls'][0].update(response_request_id=str(UUID(int=99))),
               lambda d:d['workload']['http_calls'].append(dict(d['workload']['http_calls'][0])))
        for edit in edits:
            bundle,report=fixture();update_runtime(bundle,report,'worker_exit',edit)
            self.assertEqual(self.analyze(bundle,report)['external_calls']['status'],'not_verified')
        for edit in (lambda d:d['requests'].pop(),lambda d:d['requests'].append(dict(d['requests'][0]))):
            bundle,report=fixture();update_json_source(bundle,'sc01-http-service-v1',edit)
            self.assertEqual(self.analyze(bundle,report)['external_calls']['status'],'not_verified')

    def test_each_server_identity_response_and_catalog_field_is_checked(self):
        for key,value in (('job_uuid',str(UUID(int=99))),('nonce',str(UUID(int=99))),('batch_id',str(UUID(int=99))),
                          ('sku','SKU001'),('price',999),('catalog_revision','wrong'),('status',500),('completed',False)):
            bundle,report=fixture();update_json_source(bundle,'sc01-http-service-v1',lambda d:d['requests'][0].update({key:value}))
            with self.subTest(key=key): self.assertEqual(self.analyze(bundle,report)['external_calls']['status'],'not_verified')

    def test_monotonic_service_elapsed_must_match_integer_ns_and_is_not_job_wait(self):
        for key,value in (('elapsed_us',39999),('started_monotonic_ns',True),('finished_monotonic_ns',0)):
            bundle,report=fixture();update_json_source(bundle,'sc01-http-service-v1',lambda d:d['requests'][0].update({key:value}))
            self.assertEqual(self.analyze(bundle,report)['external_calls']['status'],'not_verified')
        bundle,report=fixture()
        update_json_source(bundle,'sc01-http-service-v1',lambda d:[r.update(started_monotonic_ns=1000000000,finished_monotonic_ns=1040000000) for r in d['requests']])
        result=self.analyze(bundle,report)
        self.assertEqual(result['external_calls']['status'],'verified')
        self.assertAlmostEqual(result['external_calls']['server_elapsed_seconds'],0.12)
        self.assertNotIn('wait_seconds',result)

    def test_bad_client_or_load_time_does_not_become_negative_duration(self):
        bundle,report=fixture()
        update_runtime(bundle,report,'worker_exit',lambda d:d['workload']['http_calls'][0].update(finished_utc_ms=START-1))
        self.assertEqual(self.analyze(bundle,report)['external_calls']['status'],'not_verified')
        bundle,report=fixture();update_runtime(bundle,report,'worker_exit',lambda d:d['workload'].update(load_finished_utc_ms=START-1))
        self.assertIsNone(self.analyze(bundle,report)['load_duration_ms'])

    def test_capture_seed_module_identity_and_natural_exit_are_required(self):
        for key,value in (('database_before_sha256','d'*64),('module_sha256','d'*64),('input_sha256','d'*64),
                          ('job_uuid',str(UUID(int=99))),('nonce',str(UUID(int=99))),('batch_id',str(UUID(int=99))),
                          ('database_file',r'C:\different'),('platform_version','8.3.28.1'),
                          ('process_exit_code',1),('natural_exit',False)):
            bundle,report=fixture();update_json_source(bundle,'sc01-run-capture-v1',lambda d:d.update({key:value}))
            with self.subTest(key=key):
                result=self.analyze(bundle,report)
                self.assertNotEqual(result['status'],'observed')
                self.assertEqual(result['capture_validation']['status'],'not_verified')
                self.assertEqual(result['result_validation']['status'],'matches_expected')

    def test_missing_capture_or_source_preserves_independent_result_checks(self):
        for format in ('sc01-run-capture-v1','1c-source-text-v1'):
            bundle,report=fixture();bundle['sources']=[s for s in bundle['sources'] if s['format']!=format]
            result=self.analyze(bundle,report)
            self.assertEqual(result['capture_validation']['status'],'not_verified')
            self.assertEqual(result['result_validation']['status'],'matches_expected')
            self.assertNotEqual(result['status'],'observed')

    def test_missing_computer_name_in_any_runtime_role_blocks_comparability_only(self):
        for role in ('controller','worker_enter','worker_exit'):
            bundle,report=fixture()
            update_runtime(bundle,report,role,lambda d:d.pop('computer_name'))
            result=self.analyze(bundle,report)
            with self.subTest(role=role):
                self.assertEqual(result['status'],'partial')
                self.assertIsNone(result['workload_signature']['observed_computer_name'])
                self.assertEqual(result['capture_validation']['status'],'not_verified')
                self.assertEqual(result['result_validation']['status'],'matches_expected')
                self.assertEqual(result['external_calls']['status'],'verified')

    def test_conflicting_runtime_or_final_snapshot_computer_name_is_not_inferred(self):
        for edit in (lambda b,r:update_runtime(b,r,'worker_enter',lambda d:d.update(computer_name='OTHER-PC')),
                     lambda b,r:update_runtime(b,r,'controller',lambda d:d.update(final_job_snapshot={'computer_name':'OTHER-PC'}))):
            bundle,report=fixture();edit(bundle,report)
            result=self.analyze(bundle,report)
            self.assertIsNone(result['workload_signature']['observed_computer_name'])
            self.assertEqual(result['capture_validation']['status'],'not_verified')
            self.assertEqual(result['external_calls']['status'],'verified')

    def test_observed_computer_name_is_bounded_casefolded_and_evidenced(self):
        bundle,report=fixture()
        update_runtime(bundle,report,'worker_enter',lambda d:d.update(computer_name='test-pc'))
        update_runtime(bundle,report,'worker_exit',lambda d:d.update(computer_name='TeSt-Pc'))
        result=self.analyze(bundle,report)
        self.assertEqual(result['status'],'observed')
        self.assertEqual(result['workload_signature']['observed_computer_name'],'test-pc')
        refs={r['source'] for r in result['workload_signature']['evidence']}
        self.assertTrue({'s2','s3','s4'}.issubset(refs))
        for value in ('','x'*256,'ß'*200,True,None,' TEST-PC','TEST\tPC'):
            bundle,report=fixture()
            update_runtime(bundle,report,'worker_exit',lambda d:d.update(computer_name=value))
            with self.subTest(value=value):
                self.assertEqual(self.analyze(bundle,report)['capture_validation']['status'],'not_verified')

    def test_missing_or_invalid_service_module_attestation_preserves_other_facts(self):
        for value in (None,'g'*64,'a'*63,'a'*65,True):
            bundle,report=fixture()
            def edit(data):
                if value is None: data.pop('service_module_sha256')
                else: data['service_module_sha256']=value
            update_json_source(bundle,'sc01-run-capture-v1',edit)
            result=self.analyze(bundle,report)
            with self.subTest(value=value):
                self.assertEqual(result['status'],'partial')
                self.assertIsNone(result['workload_signature']['service_module_sha256'])
                self.assertEqual(result['capture_validation']['status'],'not_verified')
                self.assertEqual(result['result_validation']['status'],'matches_expected')
                self.assertEqual(result['external_calls']['status'],'verified')

    def test_service_module_hash_is_canonical_runner_attestation_separate_from_bsl(self):
        bundle,report=fixture()
        update_json_source(bundle,'sc01-run-capture-v1',lambda d:d.update(service_module_sha256='AB'*32))
        result=self.analyze(bundle,report)
        self.assertEqual(result['status'],'observed')
        self.assertEqual(result['workload_signature']['service_module_sha256'],'ab'*32)
        self.assertEqual(result['capture_validation']['service_module_sha256'],'ab'*32)
        self.assertEqual(result['capture_validation']['module_sha256'],hashlib.sha256(CODE).hexdigest())
        self.assertEqual(result['capture_validation']['provenance'],'capture_runner_attested')

    def test_json_duplicates_bools_and_noninteger_business_numbers_are_invalid(self):
        bundle,report=fixture();item=bundle['sources'][5]
        item['data']=item['data'].replace(b'"schema":1',b'"schema":1,"schema":1')
        item.update(sha256=hashlib.sha256(item['data']).hexdigest(),size=len(item['data']))
        self.assertNotEqual(self.analyze(bundle,report)['status'],'observed')
        for value in (True,1.0):
            bundle,report=fixture();update_runtime(bundle,report,'controller',lambda d:d['result_rows'][0].update(qty=value))
            self.assertNotEqual(self.analyze(bundle,report)['result_validation']['status'],'matches_expected')
        bundle,report=fixture();update_json_source(bundle,'sc01-http-service-v1',lambda d:d.update(schema=True))
        self.assertEqual(self.analyze(bundle,report)['external_calls']['status'],'not_verified')

    def test_boolean_controller_port_is_not_an_integer_endpoint(self):
        bundle,report=fixture()
        update_runtime(bundle,report,'controller',lambda d:d.update(port=True))
        update_json_source(bundle,'sc01-http-service-v1',lambda d:d.update(port=1))
        self.assertNotEqual(self.analyze(bundle,report)['status'],'observed')

    def test_service_delay_is_observed_signature_not_assumed_from_mode(self):
        bundle,report=fixture();update_json_source(bundle,'sc01-http-service-v1',lambda d:d.update(delay_ms=20))
        result=self.analyze(bundle,report)
        self.assertEqual(result['workload_signature']['service_delay_ms'],20)
        self.assertEqual(result['external_calls']['server_elapsed_seconds'],0.12)

    def test_strict_csv_header_unique_ids_positive_integer_and_utf8(self):
        for data in (CSV.replace(b'order_id,sku,qty',b'order,sku,qty'),CSV.replace(b'O2,',b'O1,'),
                     CSV.replace(b'SKU000,2',b'SKU000,0'),CSV.replace(b'SKU000,2',b'SKU000,2.0'),b'\xff'):
            bundle,report=fixture();item=bundle['sources'][4]
            item.update(data=data,sha256=hashlib.sha256(data).hexdigest(),size=len(data))
            update_runtime(bundle,report,'controller',lambda d:d.update(input_sha256=item['sha256']))
            update_runtime(bundle,report,'worker_exit',lambda d:d['workload'].update(input_sha256=item['sha256']))
            self.assertNotEqual(self.analyze(bundle,report)['result_validation']['status'],'matches_expected')

    def test_limits_and_mismatch_preview_are_bounded_without_mutating_inputs(self):
        bundle,report=fixture();before=copy.deepcopy((bundle,report));self.analyze(bundle,report)
        self.assertEqual((bundle,report),before)
        update_runtime(bundle,report,'controller',lambda d:d.update(result_rows=d['result_rows']*100))
        result=self.analyze(bundle,report)
        self.assertEqual(result['result_validation']['status'],'mismatch')
        self.assertLessEqual(len(result['result_validation']['mismatches']),20)
        self.assertLessEqual(len(result['limitations']),100)
        bundle,report=fixture();bundle['sources']=bundle['sources']*5
        self.assertEqual(self.analyze(bundle,report)['status'],'not_verified')


if __name__ == '__main__':
    unittest.main()
