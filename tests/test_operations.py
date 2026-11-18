import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


class ManagedOperationTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.operations'),'Managed operation execution is missing')
        self.api=importlib.import_module('src.techexpert.operations')
        self.catalogue=importlib.import_module('src.techexpert.capabilities')
        self.state_api=importlib.import_module('src.techexpert.operation_state')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name);self.state=self.folder/'state'

    def request(self,operation='knowledge.search',**arguments):
        return dict(schema_version=1,operation_key='test-key',executor_id='test-harness',operation=operation,arguments=arguments or dict(query='очередь выполнение'))

    def run_request(self,request):return self.api.run(self.state,request)

    def test_catalogue_is_executable_bounded_and_has_no_source_or_process_side_effects(self):
        with patch('subprocess.Popen',side_effect=AssertionError('catalogue launched a process')):
            doc=self.catalogue.catalogue()
        self.assertFalse(self.state.exists())
        self.assertIn('case.analyze',[op['id'] for op in doc['operations']])
        for operation in doc['operations']:
            self.assertTrue({'input_schema','output_schema','required_sources','rights','scope','timeout_seconds','max_result_bytes','impact'}<=operation.keys())
            self.assertFalse(operation['input_schema']['additionalProperties'])
            self.assertLessEqual(operation['max_result_bytes'],16*1024**2)

    def test_unknown_fields_operations_and_invalid_filters_fail_before_state_or_source_read(self):
        requests=[self.request('arbitrary.shell',code='whoami'),dict(self.request(),password='private'),
            self.request('case.events',case_id='a'*32,limit=True),
            self.request('case.events',case_id='a'*32,limit=101),
            self.request('source.check',manifest=str(self.folder/'missing'),window=dict(start='2026-11-16T00:00:00Z',end='2026-11-15T00:00:00Z'))]
        for request in requests:
            with self.subTest(request=request):
                with patch('src.techexpert.inputs.read_snapshot',side_effect=AssertionError('invalid input opened a source')):
                    with self.assertRaises(ValueError):self.run_request(request)
                self.assertFalse(self.state.exists())

    def test_normalized_requests_can_be_reused_without_reinterpreting_missing_optional_values(self):
        for request in [self.request('os.collect',duration_seconds=2,interval_seconds=1),
            self.request('case.coverage',case_id='a'*32),self.request('source.check',manifest=str(self.folder/'input.json'))]:
            with self.subTest(operation=request['operation']):
                canonical=self.catalogue.normalize_request(request)
                self.assertEqual(self.catalogue.normalize_request(canonical),canonical)

    def test_completed_key_replays_one_result_without_launching_or_reading_original(self):
        case=self.folder/'эпизод с пробелами.json';case.write_bytes((ROOT/'examples/sc01/case.json').read_bytes())
        manifest=json.loads(case.read_text(encoding='utf-8'))
        for source in manifest['sources']:source['path']=str(ROOT/'examples/sc01'/source['path'])
        case.write_text(json.dumps(manifest),encoding='utf-8')
        request=self.request('case.analyze',manifest=str(case));first=self.run_request(request)
        self.assertEqual(first['status'],'succeeded');self.assertEqual(first['data']['durations_seconds']['execution'],2460)
        self.assertEqual(len(list((self.state/'cases').iterdir())),1)
        case.unlink()
        with patch('src.techexpert.operation_process.run',side_effect=AssertionError('replay launched a child')):
            second=self.run_request(request)
        self.assertEqual(first['run_id'],second['run_id']);self.assertEqual(first['data'],second['data'])
        self.assertTrue(second['replayed']);self.assertTrue(second['integrity_verified'])

    def test_same_key_with_changed_arguments_conflicts(self):
        self.run_request(self.request())
        with self.assertRaisesRegex(ValueError,'key|conflict'):self.run_request(self.request(query='other'))

    def test_repeated_key_from_another_executor_is_a_read_of_the_original_run(self):
        request=self.request();first=self.run_request(request);request['executor_id']='another-harness'
        second=self.run_request(request)
        self.assertEqual(first['run_id'],second['run_id']);self.assertEqual(second['executor_id'],'test-harness')
        self.assertTrue(second['replayed'])

    def test_registered_routes_use_real_adapters_and_normal_saved_products(self):
        covered=set()
        def call(operation_id,*,expected='succeeded',**arguments):
            request=self.request(operation_id);request['arguments']=arguments
            request['operation_key']='route-'+str(len(covered))+'-'+operation_id
            result=self.run_request(request);covered.add(operation_id)
            self.assertEqual(result['status'],expected,result)
            self.assertTrue(result['integrity_verified']);return result['data']
        before=call('case.analyze',manifest=str(ROOT/'tests/fixtures/order-load/baseline.json'))
        # A separate new key is an explicit second sample import, not a replay.
        req=self.request('case.analyze',manifest=str(ROOT/'tests/fixtures/order-load/cached.json'));req['operation_key']='after-import'
        after=self.run_request(req)['data']
        cid=before['case_id']
        self.assertEqual(call('case.show',case_id=cid)['order_load']['external_calls']['count'],200)
        self.assertEqual(call('case.coverage',case_id=cid,required_events=['SDBL'])['sources'][0]['record_count'],1007)
        page=call('case.events',case_id=cid,event='SDBL',limit=2)
        self.assertEqual(len(page['records']),2)
        call('case.evidence',case_id=cid,evidence_id=page['records'][0]['evidence']['id'])
        comparison=call('case.compare',before=[cid],after=[after['case_id']])
        self.assertEqual(call('comparison.show',comparison_id=comparison['comparison_id'])['performance']['status'],'inconclusive')
        source_change=call('source.compare',before=dict(kind='case',id=cid,source_id='s1'),after=dict(kind='case',id=after['case_id'],source_id='s1'))
        self.assertEqual(source_change['observation']['relation'],'unknown_origin')
        self.assertFalse(source_change['counts']['events_deduplicated'])
        sample=call('sample.describe',inputs=[dict(kind='case',id=cid),dict(kind='case',id=after['case_id'])],operation='load orders')
        self.assertEqual(sample['statistics']['count'],2)
        self.assertFalse(sample['normal_established'])
        call('source.check',manifest=str(ROOT/'tests/fixtures/order-load/baseline.json'),required_fields=['Sdbl'])
        call('knowledge.search',query='очередь')
        card=call('knowledge.card',card_id='SC01-ORDER-LOAD',limit=40);self.assertTrue(card['body_truncated'])
        artifact=call('os.collect',duration_seconds=1,interval_seconds=1)
        call('artifact.show',artifact_id=artifact['artifact_id'])
        call('os.import',measurements=str(self.state/'artifacts'/artifact['artifact_id']/'sources/s1.bin'))
        program=call('code.execute',program='return {"unknown": None, "total": sum([2, 3])}')
        self.assertEqual(program['value'],dict(unknown=None,total=5))
        inspected=call('code.inspect',run_id=program['audit']['run_id'])
        self.assertTrue(inspected['audit_available'])
        call('artifact.evidence',artifact_id=artifact['artifact_id'],source_id='s1')
        measurement=self.folder/'apdex.json';measurement.write_text(json.dumps([dict(id='1',operation='read',started_at='2026-11-17T09:00:00Z',duration_seconds=1,success=True)]),encoding='utf-8')
        call('apdex.import',measurements=str(measurement),target_seconds=2)
        journal=call('jr.import',path=str(ROOT/'tests/fixtures/native-jr'),platform_version='8.3.27.1989')
        page=call('jr.events',artifact_id=journal['artifact_id'],limit=1)
        call('jr.record',artifact_id=journal['artifact_id'],record_id=page['records'][0]['id'])
        source=self.folder/'source';source.mkdir();(source/'Module.bsl').write_text('Процедура Проверить()\nКонецПроцедуры',encoding='utf-8')
        snapshot=call('source.snapshot',path=str(source))
        call('source.search',artifact_id=snapshot['artifact_id'],query='Проверить')
        call('source.read',artifact_id=snapshot['artifact_id'],path='Module.bsl')
        call('rac.observe',endpoint='localhost:1545',query='clusters',executable=str(self.folder/'missing-rac'),expected='partial')
        call('postgresql.observe',database='test',query='activity',executable=str(self.folder/'missing-psql'),expected='partial')
        call('sqlserver.observe',database='test',host='localhost',query='requests',executable=str(self.folder/'missing-sqlcmd'),expected='partial')
        from test_client_episode import document
        episode=self.folder/'client.json';episode.write_text(json.dumps(document('manual')),encoding='utf-8')
        self.assertEqual(call('client.import',path=str(episode))['result']['ready_basis'],'operator_reported_marker')
        call('client.observe',endpoint=dict(port=1,pid=1,lifetime='1'),python=str(self.folder/'python.exe'),expected='partial')
        from src.techexpert.investigations import create
        doc=create(self.state,dict(task='Read exact saved source context'))
        call('investigation.sources',investigation_id=doc['investigation_id'],revision=1)
        call('input.inspect',inputs=[dict(path=str(ROOT/'tests/fixtures/order-load/baseline-native.txt'),kind='file')])
        config=self.folder/'supplied-logcfg.xml'
        config.write_bytes(b'<config xmlns="http://v8.1c.ru/v8/tech-log"><dump create="false"/></config>')
        prepared=call('logcfg.prepare',current_file=str(config),node='client',os='windows',mode='file',process='client',
            platform_version='8.3.27.1989',config_path='C:/onec/conf/logcfg.xml',log_location='C:/tj/incident',events=['CALL'],purpose='finite test')
        config.write_bytes((self.state/'artifacts'/prepared['artifact_id']/'sources/logcfg.xml').read_bytes())
        rollback=call('logcfg.rollback_plan',proposal_id=prepared['artifact_id'],current_file=str(config))
        self.assertEqual(rollback['result']['action'],'replace_file')
        from test_remote_budget import settings as remote_settings
        from test_remote_intake import capture as remote_fixture
        from src.techexpert.remote_transfers import dependency
        from src.techexpert.artifacts import save_artifact
        import stat
        remote_args=dict(remote_settings(self.folder),investigation_id=doc['investigation_id'])
        remote_args['sources'][0]['connection'].update(host='reader@127.0.0.1',port=9)
        remote_plan=call('remote.plan',**remote_args)
        call('remote.inspect',plan_id=remote_plan['artifact_id'],source_id='tj',protocol_bytes=16384,timeout_seconds=1,expected='partial')
        catalogue=save_artifact(self.state,'remote_catalog',{},[],dict(schema_version=1,profile='sftp-v3-catalogue-v1',transfer_status='completed',
            plan=dependency(self.state,remote_plan),source_id='tj',members=[dict(id='m1',relative_path='one.log',bytes=3,attributes=dict(size=3,permissions=stat.S_IFREG|0o600,mtime=1),importable=True)]))
        call('remote.capture',plan_id=remote_plan['artifact_id'],source_id='tj',catalog_id=catalogue['artifact_id'],members=['m1'],protocol_bytes=16384,max_bytes=10,timeout_seconds=1,expected='partial')
        retained=remote_fixture(self.state,[('os.json',(self.state/'artifacts'/artifact['artifact_id']/'sources/s1.bin').read_bytes())])
        call('remote.parse',capture_id=retained['artifact_id'],adapter='os',settings=dict(members=['m1']))
        from test_profile_ssh import graph as ssh_profile
        from src.techexpert import profiles,investigations
        profile=ssh_profile();profile['connections'][0]['settings']['known_hosts_file']=remote_args['sources'][0]['connection']['known_hosts_file']
        profiles.save_profile(self.state,profile,expected_revision=0)
        configured=investigations.create(self.state,dict(task='Profile-bound remote acquisition'))
        call('remote.profile_plan',investigation_id=configured['investigation_id'],revision=1,source_ids=['tj','jr'])
        self.assertEqual(covered,set(self.catalogue.ROUTES))

    def test_inflight_run_keeps_pinned_context_without_overwriting_a_new_investigation_revision(self):
        from src.techexpert.investigations import create,revise,load
        doc=create(self.state,dict(task='SC01 pinned context',template_id='TPL-02',time_mode='past',scale='background'))
        request=self.request('os.collect',duration_seconds=2,interval_seconds=1)
        request['context']=dict(investigation_id=doc['investigation_id'],expected_revision=1)
        p=self.launch(request);self.await_live(request,p)
        revised=revise(self.state,doc['investigation_id'],dict(open_questions=['Independent edit']),expected_revision=1)
        out,err=p.communicate(timeout=10);self.assertEqual(p.returncode,0,err)
        result=json.loads(out);self.assertEqual(result['context']['expected_revision'],1)
        self.assertEqual(load(self.state,doc['investigation_id']),revised)

    def test_output_limit_is_a_structured_failure_and_never_a_second_attempt(self):
        request=self.request('case.analyze',manifest=str(ROOT/'tests/fixtures/order-load/baseline.json'))
        request['budget']=dict(max_result_bytes=16384)
        result=self.run_request(request)
        self.assertEqual(result['status'],'failed');self.assertEqual(result['stop_reason'],'output_limit')
        self.assertFalse((self.state/'cases').exists())

    def test_full_envelope_budget_is_checked_before_publishing_new_case(self):
        request=self.request('case.analyze',manifest=str(ROOT/'tests/fixtures/order-load/baseline.json'))
        first=self.run_request(request)
        limit=len(self.state_api.encode(first))-700
        self.assertGreater(limit,16384)
        request['operation_key']='envelope-budget';request['budget']=dict(max_result_bytes=limit)
        failed=self.run_request(request)
        self.assertEqual(failed['status'],'failed')
        self.assertEqual(len(list((self.state/'cases').iterdir())),1,'failed envelope published another case')

    def test_presentation_fields_are_budgeted_before_product_promotion(self):
        request=self.request('case.analyze',manifest=str(ROOT/'tests/fixtures/order-load/baseline.json'))
        first=self.run_request(request)
        saved=self.state_api.read(self.state/'operations'/first['run_id']/'output.json')
        saved_size=len(self.state_api.encode(saved));returned_size=len(self.state_api.encode(first))
        self.assertGreater(returned_size,saved_size)
        request['operation_key']='presentation-budget';request['budget']=dict(max_result_bytes=(saved_size+returned_size)//2)
        failed=self.run_request(request)
        self.assertEqual(failed['status'],'failed');self.assertEqual(failed['stop_reason'],'output_limit')
        self.assertEqual(len(list((self.state/'cases').iterdir())),1)

    def test_cli_wire_budget_uses_utf8_lf_including_presentation_and_final_newline(self):
        request=self.request('case.analyze',manifest=str(ROOT/'tests/fixtures/order-load/baseline.json'))
        first=self.run_request(request);limit=len(self.state_api.encode(first))+1024
        request['operation_key']='wire-budget';request['budget']=dict(max_result_bytes=limit)
        p=self.launch(request);out,err=p.communicate(timeout=15)
        self.assertEqual(p.returncode,0,(out,err));self.assertEqual(json.loads(out)['status'],'succeeded')
        self.assertLessEqual(len(out),limit);self.assertNotIn(b'\r\n',out)

    def test_grown_replay_knowledge_overlay_is_bounded_without_rewriting_or_rerunning(self):
        request=self.request('knowledge.card',card_id='SC01-ORDER-LOAD',limit=20);request['budget']=dict(max_result_bytes=16384)
        first=self.run_request(request);self.assertEqual(first['status'],'succeeded')
        path=self.state/'operations'/first['run_id']/'output.json';before=path.read_bytes()
        warning=dict(status='review_required',technical_truth_judged=False,detail='x'*30000)
        with patch('src.techexpert.knowledge_review.review_legacy_report',return_value=warning):
            with patch('src.techexpert.operation_process.run',side_effect=AssertionError('large overlay caused a rerun')):
                view=self.run_request(request)
                cancelled=self.api.cancel(self.state,first['run_id'],executor_id='reader')
        self.assertLessEqual(len(self.state_api.encode(view)),16384)
        self.assertEqual(view['status'],'partial');self.assertEqual(view['execution_status'],'succeeded')
        self.assertTrue(view['truncated']);self.assertTrue(view['data_omitted']);self.assertIsNone(view['data'])
        self.assertTrue(cancelled['cancel_too_late']);self.assertLessEqual(len(self.state_api.encode(cancelled)),16384)
        self.assertEqual(path.read_bytes(),before)

    def test_first_return_is_not_mislabelled_as_a_replayed_computation(self):
        first=self.run_request(self.request());self.assertFalse(first['replayed'])
        self.assertTrue(self.run_request(self.request())['replayed'])

    def test_envelope_exposes_adapter_preview_truncation(self):
        result=self.run_request(self.request('case.analyze',manifest=str(ROOT/'tests/fixtures/order-load/baseline.json')))
        self.assertTrue(result['data']['native_observations']['preview_limited'])
        self.assertTrue(result['truncated'])

    def test_replay_checks_retained_evidence_and_does_not_replace_a_corrupt_snapshot(self):
        request=self.request('case.analyze',manifest=str(ROOT/'examples/sc01/case.json'))
        first=self.run_request(request)
        source=self.state/'cases'/first['data']['case_id']/'sources/s1.bin';source.write_bytes(b'corrupt')
        with patch('src.techexpert.operation_process.run',side_effect=AssertionError('corruption caused a rerun')):
            with self.assertRaises(ValueError):self.run_request(request)
        self.assertEqual(source.read_bytes(),b'corrupt')

    def test_replay_adds_current_knowledge_warning_without_rewriting_saved_data(self):
        request=self.request();first=self.run_request(request)
        folder=self.state/'operations'/first['run_id'];before=(folder/'output.json').read_bytes()
        with patch('src.techexpert.knowledge_review.load_library',return_value=dict(legacy_digest='changed',revision='synthetic-revision')):
            replay=self.api.result(self.state,first['run_id'])
        self.assertEqual(replay['current_knowledge_review']['status'],'review_required')
        self.assertEqual(replay['data'],first['data']);self.assertEqual((folder/'output.json').read_bytes(),before)

    def test_recovery_requires_the_compatible_rules_before_publishing_old_worker_output(self):
        request=self.request('case.analyze',manifest=str(ROOT/'examples/sc01/case.json'))
        p=self.launch(request,crash_before_promotion=True);out,err=p.communicate(timeout=10);self.assertEqual(p.returncode,73,(out,err))
        run_id=hashlib.sha256(request['operation_key'].encode()).hexdigest()
        with patch('src.techexpert.operations._versions',return_value=dict(product='different',rules_inventory_sha256='changed')):
            with self.assertRaisesRegex(ValueError,'version|rules|compatible'):self.api.reconcile(self.state,run_id)
        self.assertFalse((self.state/'cases').exists())

    def test_state_budget_is_checked_before_a_new_run_is_created(self):
        usage=shutil.disk_usage(self.folder)
        with patch('src.techexpert.operations.shutil.disk_usage',return_value=type(usage)(usage.total,usage.total-100,100)):
            with self.assertRaisesRegex(ValueError,'space|GiB'):self.run_request(self.request())
        self.assertFalse(self.state.exists())

    def test_stale_investigation_context_starts_no_child(self):
        from src.techexpert.investigations import create,revise
        doc=create(self.state,dict(task='SC01 context',template_id='TPL-02',time_mode='past',scale='background'))
        revise(self.state,doc['investigation_id'],dict(open_questions=['Changed']),expected_revision=1)
        request=self.request();request['context']=dict(investigation_id=doc['investigation_id'],expected_revision=1)
        with patch('src.techexpert.operation_process.run',side_effect=AssertionError('stale context launched a child')):
            with self.assertRaisesRegex(ValueError,'revision|conflict'):self.run_request(request)

    def launch(self,request,*,crash_before_promotion=False):
        file=self.folder/('request-'+request['operation_key']+'.json');file.write_text(json.dumps(request),encoding='utf-8')
        argv=[sys.executable,'-X','utf8',str(ROOT/'techexpert.py'),'--state-dir',str(self.state),'operation-run',str(file)]
        if crash_before_promotion:
            code='import json,os,sys;from src.techexpert import operations;operations._promote=lambda *a,**k:os._exit(73);print(json.dumps(operations.run(sys.argv[1],json.load(open(sys.argv[2],encoding="utf-8")))))'
            argv=[sys.executable,'-X','utf8','-c',code,str(self.state),str(file)]
        p=subprocess.Popen(argv,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        def cleanup():
            if p.poll() is None:p.kill();p.communicate(timeout=5)
        self.addCleanup(cleanup)
        return p

    def await_live(self,request,process):
        run_id=hashlib.sha256(request['operation_key'].encode()).hexdigest();deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            if process.poll() is not None:
                out,err=process.communicate(timeout=5)
                self.fail('managed run exited before the concurrent action: '+out.decode('utf-8',errors='replace')+err.decode('utf-8',errors='replace'))
            try:
                status=self.api.status(self.state,run_id)
                if status['status']=='running' and status.get('child'):return status
            except (OSError,ValueError):pass
            time.sleep(.03)
        self.fail('no live managed child observed')

    def test_two_sessions_share_one_live_run_and_create_only_one_artifact(self):
        request=self.request('os.collect',duration_seconds=2,interval_seconds=1)
        p=self.launch(request);live=self.await_live(request,p)
        replay=self.run_request(request)
        self.assertEqual(replay['run_id'],live['run_id']);self.assertTrue(replay['replayed'])
        self.assertEqual(replay['child'],live['child'])
        out,err=p.communicate(timeout=10);self.assertEqual(p.returncode,0,err)
        finished=json.loads(out);self.assertEqual(finished['status'],'succeeded')
        self.assertEqual(len(list((self.state/'artifacts').iterdir())),1)

    def test_cancel_is_a_request_then_verified_stop_with_partial_local_samples(self):
        request=self.request('os.collect',duration_seconds=15,interval_seconds=1)
        p=self.launch(request);live=self.await_live(request,p)
        time.sleep(.7)
        cancelled=self.api.cancel(self.state,live['run_id'],executor_id='second-harness')
        self.assertTrue(cancelled['cancellation_requested'])
        out,err=p.communicate(timeout=10);self.assertEqual(p.returncode,130,err)
        result=json.loads(out);self.assertEqual(result['status'],'cancelled');self.assertTrue(result['stop_verified'])
        self.assertIsNotNone(result['data']);self.assertEqual(result['data']['result']['collection_status'],'cancelled')
        self.assertNotEqual(result['data']['result']['coverage_status'],'complete')

    def test_cancel_racing_with_completion_retains_request_without_rewriting_the_finished_result(self):
        request=self.request('knowledge.card',card_id='SC01-ORDER-LOAD',limit=20)
        first=self.run_request(request);path=self.state/'operations'/first['run_id']/'output.json';before=path.read_bytes()
        actual_status=self.api.status;calls=0
        def stale_then_current(state,run_id):
            nonlocal calls
            calls+=1
            if calls==1:return dict(first,status='running',stop_verified=False,data=None)
            return actual_status(state,run_id)
        with patch('src.techexpert.operations.status',side_effect=stale_then_current):
            cancelled=self.api.cancel(self.state,first['run_id'],executor_id='late-reader')
        self.assertEqual(cancelled['status'],'succeeded');self.assertTrue(cancelled['cancel_too_late'])
        self.assertTrue(cancelled['cancellation_requested']);self.assertEqual(path.read_bytes(),before)

    def test_timeout_stops_owned_run_and_never_restarts_the_same_key(self):
        request=self.request('os.collect',duration_seconds=5,interval_seconds=1);request['budget']=dict(timeout_seconds=1)
        result=self.run_request(request)
        self.assertIn(result['status'],['partial','failed']);self.assertEqual(result['stop_reason'],'timeout')
        self.assertTrue(result['stop_verified'])
        with patch('src.techexpert.operation_process.run',side_effect=AssertionError('timeout repeated collection')):
            replay=self.run_request(request)
        self.assertTrue(replay['replayed']);self.assertEqual(replay['run_id'],result['run_id'])

    def test_recovery_can_commit_sealed_child_output_without_repeating_processing(self):
        request=self.request('case.analyze',manifest=str(ROOT/'examples/sc01/case.json'))
        p=self.launch(request,crash_before_promotion=True);out,err=p.communicate(timeout=10)
        self.assertEqual(p.returncode,73,(out,err))
        run_id=hashlib.sha256(request['operation_key'].encode()).hexdigest()
        with patch('src.techexpert.operation_process.run',side_effect=AssertionError('reconcile ran computation')):
            recovered=self.api.reconcile(self.state,run_id)
        self.assertEqual(recovered['status'],'succeeded');self.assertTrue(recovered['integrity_verified'])
        self.assertEqual(len(list((self.state/'cases').iterdir())),1)

    def test_failed_final_receipt_can_be_repaired_without_repeating_the_finished_worker(self):
        request=self.request('case.analyze',manifest=str(ROOT/'examples/sc01/case.json'))
        real_write=self.state_api.write
        def disk_failure(path,value):
            if Path(path).name=='output-receipt.json':raise OSError('simulated final receipt disk failure')
            return real_write(path,value)
        with patch('src.techexpert.operation_state.write',side_effect=disk_failure):failed=self.run_request(request)
        self.assertEqual(failed['status'],'partial');self.assertEqual(failed['execution_status'],'failed')
        self.assertEqual(failed['result_availability'],'incomplete_commit')
        self.assertEqual(len(list((self.state/'cases').iterdir())),1)
        self.assertEqual(self.api.result(self.state,failed['run_id'])['result_availability'],'incomplete_commit')
        self.assertEqual(self.run_request(request)['result_availability'],'incomplete_commit')
        # The owning CLI has finished; its persisted lifetime must be verified
        # before a new writer repairs only the failed final commit.
        with patch('src.techexpert.operation_state.inspect_process',return_value=dict(state='not_running')):
            with patch('src.techexpert.operation_process.run',side_effect=AssertionError('receipt repair repeated the worker')):
                repaired=self.api.reconcile(self.state,failed['run_id'])
        self.assertEqual(repaired['status'],'succeeded');self.assertTrue(repaired['integrity_verified'])
        self.assertIsNone(repaired['stop_reason'])
        journal=(self.state/'operations'/failed['run_id']/'journal.jsonl').read_text(encoding='utf-8')
        self.assertIn('simulated final receipt disk failure',journal)
        self.assertEqual(len(list((self.state/'cases').iterdir())),1)

    def test_tight_final_receipt_repair_preserves_validated_output_and_bounds_new_diagnostics(self):
        request=self.request('case.analyze',manifest=str(ROOT/'tests/fixtures/order-load/baseline.json'))
        first=self.run_request(request)
        request['operation_key']='tight-repair';request['budget']=dict(max_result_bytes=len(self.state_api.encode(first))+256)
        real_write=self.state_api.write
        def disk_failure(path,value):
            if Path(path).name=='output-receipt.json':raise OSError('final receipt '+('x'*480))
            return real_write(path,value)
        with patch('src.techexpert.operation_state.write',side_effect=disk_failure):failed=self.run_request(request)
        self.assertEqual(failed['result_availability'],'incomplete_commit')
        folder=self.state/'operations'/failed['run_id'];original=(folder/'output.json').read_bytes()
        with patch('src.techexpert.operation_state.inspect_process',return_value=dict(state='not_running')):
            with patch('src.techexpert.operation_process.run',side_effect=AssertionError('tight repair repeated the worker')):
                repaired=self.api.reconcile(self.state,failed['run_id'])
        self.assertLessEqual(len(self.state_api.encode(repaired)),request['budget']['max_result_bytes'])
        self.assertEqual(repaired['execution_status'],'succeeded');self.assertTrue(repaired['data_omitted'])
        self.assertEqual((folder/'output.json').read_bytes(),original)
        self.assertTrue((folder/'output-receipt.json').exists())
        self.assertEqual(len(list((self.state/'cases').iterdir())),2)

    def test_corrupt_prepared_output_refuses_recovery_without_publishing_or_repeating(self):
        request=self.request('case.analyze',manifest=str(ROOT/'examples/sc01/case.json'))
        p=self.launch(request,crash_before_promotion=True);out,err=p.communicate(timeout=10)
        self.assertEqual(p.returncode,73,(out,err))
        run_id=hashlib.sha256(request['operation_key'].encode()).hexdigest()
        path=self.state/'operations'/run_id/'prepared-output.json';prepared=self.state_api.read(path)
        prepared['value']['data']['durations_seconds']['execution']=1
        self.state_api.write(path,prepared)
        with patch('src.techexpert.operation_process.run',side_effect=AssertionError('corrupt preparation launched worker')):
            with self.assertRaisesRegex(ValueError,'prepared|integrity'):self.api.reconcile(self.state,run_id)
        self.assertFalse((self.state/'cases').exists())

    def test_reconcile_does_not_bypass_the_first_presentation_budget_gate(self):
        request=self.request('case.analyze',manifest=str(ROOT/'tests/fixtures/order-load/baseline.json'))
        first=self.run_request(request);saved=self.state_api.read(self.state/'operations'/first['run_id']/'output.json')
        request['operation_key']='failed-gate';request['budget']=dict(max_result_bytes=(len(self.state_api.encode(saved))+len(self.state_api.encode(first)))//2)
        failed=self.run_request(request);self.assertEqual(failed['stop_reason'],'output_limit')
        with patch('src.techexpert.operation_state.inspect_process',return_value=dict(state='not_running')):
            with self.assertRaisesRegex(ValueError,'output_limit'):self.api.reconcile(self.state,failed['run_id'])
        self.assertEqual(len(list((self.state/'cases').iterdir())),1)

    def test_unknown_process_identity_prevents_reconciliation(self):
        request=self.request('os.collect',duration_seconds=3,interval_seconds=1)
        p=self.launch(request);live=self.await_live(request,p)
        with patch('src.techexpert.operation_state.inspect_process',return_value=dict(state='unknown')):
            with self.assertRaisesRegex(ValueError,'unknown|active|live'):self.api.reconcile(self.state,live['run_id'])
        self.api.cancel(self.state,live['run_id'],executor_id='test-cleanup');p.communicate(timeout=10)

    def test_process_identity_is_lifetime_scoped(self):
        identity=self.state_api.process_identity(os.getpid())
        self.assertEqual(self.state_api.inspect_process(identity)['state'],'running')
        changed=dict(identity,lifetime='not-the-same-process')
        self.assertNotEqual(self.state_api.inspect_process(changed)['state'],'running')
        foreign=dict(identity,platform='posix' if os.name=='nt' else 'nt')
        self.assertEqual(self.state_api.inspect_process(foreign)['state'],'unknown')
        if os.name!='nt':
            foreign=dict(identity,pid_namespace='another-namespace')
            self.assertEqual(self.state_api.inspect_process(foreign)['state'],'unknown')
            self.assertEqual(self.state_api.inspect_group(foreign)['state'],'unknown')

    def test_live_budget_scan_records_disappearing_atomic_temps_without_hiding_other_errors(self):
        transient='status.json.'+'a'*32+'.tmp'
        with patch('src.techexpert.operation_state.os.walk',return_value=iter([(str(self.folder),[],[transient])])):
            measured=self.state_api.inventory(self.folder)
        self.assertEqual(measured['transient_files_disappeared'],1)
        with patch('src.techexpert.operation_state.os.walk',return_value=iter([(str(self.folder),[],['missing-evidence.bin'])])):
            with self.assertRaises(OSError):self.state_api.inventory(self.folder)

    @unittest.skipIf(os.name=='nt','Linux process-group ownership')
    def test_dead_group_leader_does_not_prove_its_descendants_stopped(self):
        child='import time;time.sleep(20)'
        code='import subprocess,sys,time;subprocess.Popen([sys.executable,"-c",'+repr(child)+']);time.sleep(.5)'
        p=subprocess.Popen([sys.executable,'-c',code],start_new_session=True)
        identity=self.state_api.process_identity(p.pid)
        try:
            p.wait(timeout=5)
            self.assertEqual(self.state_api.inspect_group(identity)['state'],'running')
        finally:
            import signal
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            p.wait(timeout=5)
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            if self.state_api.inspect_group(identity)['state']=='stopped':break
            time.sleep(.03)
        self.assertEqual(self.state_api.inspect_group(identity)['state'],'stopped')

    def test_abrupt_manager_exit_is_observed_and_does_not_repeat_the_operation(self):
        request=self.request('os.collect',duration_seconds=2,interval_seconds=1)
        p=self.launch(request);live=self.await_live(request,p)
        p.kill();p.communicate(timeout=5)
        deadline=time.monotonic()+7
        while time.monotonic()<deadline:
            observed=self.state_api.inspect_process(live['child'])
            owner=self.state_api.inspect_process(live['owner'])
            if all(p['state'] in ('not_running','different_lifetime') for p in (observed,owner)):break
            time.sleep(.05)
        self.assertNotEqual(self.state_api.inspect_process(live['child'])['state'],'running')
        self.assertNotEqual(self.state_api.inspect_process(live['owner'])['state'],'running')
        with patch('src.techexpert.operation_process.run',side_effect=AssertionError('manager death caused a repeated collection')):
            recovered=self.api.reconcile(self.state,live['run_id'])
            replay=self.run_request(request)
        self.assertIn(recovered['status'],['succeeded','partial','interrupted'])
        if recovered['status']=='partial':self.assertEqual(recovered['data']['result']['collection_status'],'timeout')
        self.assertEqual(replay['run_id'],live['run_id'])


if __name__=='__main__':unittest.main()
