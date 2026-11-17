"""Useful near-data programs and capability isolation on the real SC-01 kernel."""
import hashlib
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


class CodeLanguageTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.code_language'),'Bounded program interpreter is missing')
        self.lang=importlib.import_module('src.techexpert.code_language')

    def evaluate(self,source,bindings=None,api=None,**limits):
        machine=self.lang.Machine(self.lang.parse_program(source),bindings or {},api or self.no_api,**limits)
        return machine.run(),machine

    def no_api(self,*args):raise AssertionError('Program made an unexpected API call')

    def test_real_program_filters_aggregates_and_paginates_before_returning_compact_json(self):
        pages={0:dict(records=[dict(kind='CALL',duration=3),dict(kind='SDBL',duration=8)],next_offset=2),
               2:dict(records=[dict(kind='CALL',duration=4)],next_offset=None)}
        calls=[]
        def api(name,args):
            self.assertEqual(name,'case.events');calls.append(args['offset']);return pages[args['offset']]
        value,machine=self.evaluate('''offset = 0
durations = []
while True:
    page = api("case.events", {"offset": offset})
    durations = durations + [row["duration"] for row in page["records"] if row["kind"] == "CALL"]
    offset = page["next_offset"]
    if offset is None:
        break
return {"count": len(durations), "total": sum(durations), "ordered": sorted(durations)}
''',api=api)
        self.assertEqual(value,dict(count=2,total=7,ordered=[3,4]));self.assertEqual(calls,[0,2])
        self.assertGreater(machine.metrics['steps'],10)

    def test_forbidden_python_and_indirect_calls_are_rejected_before_any_api(self):
        forbidden=['import os','return open("secret")','return __import__("os")','return api.__globals__',
            'return ().__class__.__base__.__subclasses__()', 'fn = api\nreturn fn("case.show", {})',
            'return eval("1+1")','return exec("pass")','return [x for x in [1]].__class__',
            'def f():\n    return 1\nreturn f()', 'return 2 ** 1000000000',
            'return api("case.show", {})\nimport socket']
        for source in forbidden:
            with self.subTest(source=source),self.assertRaises(ValueError):self.evaluate(source)

    def test_unknown_values_are_preserved_and_bindings_are_not_mutated(self):
        original={'input':{'queue':None,'events':[3,1,3]}}
        value,_=self.evaluate('''copy = input
copy["events"][0] = 8
return {"queue": copy["queue"], "values": copy["events"], "unique": len({str(x): True for x in copy["events"]})}
''',original)
        self.assertEqual(value,dict(queue=None,values=[8,1,3],unique=3))
        self.assertEqual(original['input']['events'],[3,1,3])
        with self.assertRaises(ValueError):self.evaluate('return input["queue"] + 1',original)

    def test_cpu_allocation_and_cyclic_values_hit_explicit_limits(self):
        for source,limits in [('while True:\n    pass',dict(max_steps=1000)),
            ('return "x" * 1000000000',{}),('return range(1000000000)',{}),
            ('x = {}\nx["self"] = x\nreturn x',{}),('return 9223372036854775807 * 1000000',{})]:
            with self.subTest(source=source),self.assertRaises(ValueError):self.evaluate(source,**limits)


class CodeModeIntegrationTests(unittest.TestCase):
    def setUp(self):
        from src.techexpert import capabilities,kernel,storage
        self.assertTrue('code.execute' in capabilities.ROUTES,'Managed CodeMode route is missing')
        self.assertTrue('code.inspect' in capabilities.ROUTES,'Saved program inspection is missing')
        self.kernel=kernel;self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name);self.state=self.folder/'state';self.sequence=0
        self.before=storage.investigate(ROOT/'tests/fixtures/order-load/baseline.json',self.state)
        self.after=storage.investigate(ROOT/'tests/fixtures/order-load/cached.json',self.state)

    def call(self,operation,*,key=None,budget=None,**arguments):
        self.sequence+=1
        request=dict(schema_version=1,operation_key=key or 'code-test-'+str(self.sequence),executor_id='code-test-harness',
            operation=operation,arguments=arguments)
        if budget:request['budget']=budget
        path=self.folder/('request-'+str(self.sequence)+'.json');path.write_text(json.dumps(request,ensure_ascii=False),encoding='utf-8')
        call=self.kernel.invoke(self.state,'run',dict(request=str(path)))
        output=io.StringIO();self.kernel.emit(call,output);return json.loads(output.getvalue())

    def program(self,source,*,key=None,scope=None,bindings=None,resources=None,budget=None):
        args=dict(program=source,bindings=bindings or {},scope=scope or {})
        if resources:args['resources']=resources
        return self.call('code.execute',key=key,budget=budget,**args)

    def test_sc01_program_joins_two_cases_and_all_linked_event_pages(self):
        source='''left = api("case.show", {"case_id": before})
right = api("case.show", {"case_id": after})
counts = {}
offset = 0
while True:
    page = api("case.events", {"case_id": before, "linked_run": True, "event": "SDBL", "offset": offset, "limit": 100})
    for row in page["data"]["records"]:
        event = row["event"]
        counts[event] = get(counts, event, 0) + 1
    offset = page["data"]["next_offset"]
    if offset is None:
        break
return {"before": left["data"]["durations_seconds"]["execution"], "after": right["data"]["durations_seconds"]["execution"], "queue": left["data"]["durations_seconds"]["queue"], "linked": counts["SDBL"]}
'''
        b=self.before['case_id'];a=self.after['case_id']
        result=self.program(source,bindings=dict(before=b,after=a),scope=dict(operations=['case.show','case.events'],cases=[b,a]))
        self.assertEqual(result['status'],'succeeded',result)
        self.assertEqual(result['data']['value'],dict(before=14,after=3,queue=None,linked=1005))
        self.assertEqual(result['data']['program_sha256'],hashlib.sha256(source.encode()).hexdigest())
        self.assertEqual(result['data']['metrics']['calls_started'],13)
        self.assertEqual({s['id'] for s in result['snapshots']},{b,a})
        receipt=self.kernel.inspect_call(self.state,result['kernel_call_id'])
        self.assertTrue(receipt['controller']['tree_finished']);self.assertIsNone(receipt['model_tokens'])
        inspected=self.call('code.inspect',run_id=result['run_id'])
        self.assertEqual(inspected['data']['program'],source);self.assertEqual(len(inspected['data']['calls']),13)

    def test_denied_scope_never_launches_a_second_managed_job(self):
        result=self.program('return api("case.show", {"case_id": "'+self.after['case_id']+'"})',
            scope=dict(operations=['case.show'],cases=[self.before['case_id']]))
        self.assertEqual(result['status'],'invalid_input',result)
        self.assertEqual(result['data']['metrics']['calls_started'],0)
        self.assertEqual(len(list((self.state/'operations').iterdir())),1)
        self.assertEqual(result['data']['diagnostic']['code'],'scope_denied')

    def test_approved_import_can_be_queried_but_does_not_grant_other_files(self):
        manifest=str(ROOT/'tests/fixtures/order-load/baseline.json')
        source='''imported = api("case.analyze", {"manifest": input_path})
report = api("case.show", {"case_id": imported["data"]["case_id"]})
return {"case_id": report["data"]["case_id"], "duration": report["data"]["durations_seconds"]["execution"]}
'''
        result=self.program(source,bindings=dict(input_path=manifest),scope=dict(operations=['case.analyze','case.show'],manifests=[manifest]))
        self.assertEqual(result['status'],'succeeded',result);self.assertEqual(result['data']['value']['duration'],14)
        self.assertEqual(len(list((self.state/'cases').iterdir())),3)
        denied=self.program('return api("case.analyze", {"manifest": other})',bindings=dict(other=str(self.folder/'secret.json')),
            scope=dict(operations=['case.analyze'],manifests=[manifest]))
        self.assertEqual(denied['data']['diagnostic']['code'],'scope_denied');self.assertEqual(denied['data']['metrics']['calls_started'],0)

    def test_call_limit_retains_the_first_fact_and_same_key_does_not_run_again(self):
        source='''first = api("case.show", {"case_id": selected})
second = api("case.show", {"case_id": selected})
return second["data"]["case_id"]
'''
        args=dict(bindings=dict(selected=self.before['case_id']),scope=dict(operations=['case.show'],cases=[self.before['case_id']]),resources=dict(max_calls=1),key='call-budget')
        result=self.program(source,**args);self.assertEqual(result['status'],'partial',result)
        self.assertEqual(result['data']['metrics']['calls_started'],1)
        self.assertEqual(result['data']['diagnostic']['code'],'call_limit')
        before={p.name for p in (self.state/'operations').iterdir()}
        again=self.program(source,**args);self.assertTrue(again['replayed'])
        self.assertEqual(again['data'],result['data']);self.assertEqual(before,{p.name for p in (self.state/'operations').iterdir()})

    def test_replay_checks_source_journal_child_output_and_retained_bytes_without_originals(self):
        from src.techexpert import operations
        manifest=self.folder/'original.json'
        doc=json.loads((ROOT/'tests/fixtures/order-load/baseline.json').read_text(encoding='utf-8'))
        for item in doc['sources']:item['path']=str((ROOT/'tests/fixtures/order-load'/item['path']).resolve())
        manifest.write_text(json.dumps(doc),encoding='utf-8')
        source='return api("case.analyze", {"manifest": selected})["data"]["case_id"]'
        args=dict(key='immutable-program',bindings=dict(selected=str(manifest)),scope=dict(operations=['case.analyze'],manifests=[str(manifest)]))
        result=self.program(source,**args);self.assertEqual(result['status'],'succeeded',result)
        manifest.unlink()
        with patch('src.techexpert.operation_process.run',side_effect=AssertionError('Replay executed a worker')):
            self.assertEqual(operations.result(self.state,result['run_id'])['data'],result['data'])
            self.assertEqual(operations.run(self.state,json.loads((self.folder/'request-1.json').read_text()))['data'],result['data'])
            outer=self.state/'operations'/result['run_id'];child=self.state/'operations'/result['data']['calls'][0]['run_id']
            case=self.state/'cases'/result['data']['value']
            for path in [outer/'code-program.json',outer/'code-journal.json',child/'output.json',case/'sources/s1.bin']:
                with self.subTest(path=path.name):
                    original=path.read_bytes()
                    try:
                        path.write_bytes(b'{}')
                        with self.assertRaises((ValueError,OSError,KeyError)):operations.result(self.state,result['run_id'])
                    finally:path.write_bytes(original)

    def test_static_forbidden_syntax_and_cpu_limit_do_not_issue_api_jobs(self):
        scope=dict(operations=['case.show'],cases=[self.before['case_id']])
        source='api("case.show", {"case_id": selected})\nimport socket\nreturn 1'
        invalid=self.program(source,bindings=dict(selected=self.before['case_id']),scope=scope)
        self.assertEqual(invalid['status'],'invalid_input',invalid)
        self.assertEqual(invalid['data']['metrics']['calls_started'],0)
        loop=self.program('while True:\n    pass',resources=dict(max_steps=1000))
        self.assertEqual(loop['status'],'failed',loop);self.assertEqual(loop['data']['diagnostic']['code'],'step_limit')

    def test_api_byte_limit_retains_first_api_fact_and_stops_new_dispatch(self):
        source='''first = api("case.show", {"case_id": selected})
second = api("case.show", {"case_id": selected})
return second
'''
        result=self.program(source,bindings=dict(selected=self.before['case_id']),
            scope=dict(operations=['case.show'],cases=[self.before['case_id']]),resources=dict(max_api_bytes=16384))
        self.assertEqual(result['status'],'partial',result)
        self.assertEqual(result['data']['metrics']['calls_started'],1)
        self.assertEqual(result['data']['diagnostic']['code'],'api_byte_limit')

    def test_actual_os_memory_boundary_differs_from_the_value_and_step_limits(self):
        source='\n'.join('part'+str(i)+' = ["x" * 60000 for item in range(80)]' for i in range(12))+'\nreturn len(part11)'
        small=self.program(source,resources=dict(memory_bytes=64*1024**2))
        large=self.program(source,resources=dict(memory_bytes=256*1024**2))
        self.assertEqual(large['status'],'succeeded',large);self.assertEqual(large['data']['value'],80)
        self.assertEqual(small['status'],'failed',small)
        self.assertEqual(small['data']['diagnostic']['code'],'code_memory_limit')
        self.assertGreater(small['data']['metrics']['steps'],0,'OOM must retain the steps executed before memory exhaustion')
        if os.name!='nt':self.assertLessEqual(small['metrics']['effective_address_space_limit_bytes'],64*1024**2)
        else:self.assertEqual(small['process']['resource_usage']['enforced_job_memory_limit_bytes'],64*1024**2)

    def test_collector_runs_only_inside_the_explicit_plan_and_repeat_count(self):
        settings=dict(transport='local',duration_seconds=1,interval_seconds=1)
        source='''first = api("os.collect", {"transport": "local", "duration_seconds": 1, "interval_seconds": 1})
second = api("os.collect", {"transport": "local", "duration_seconds": 1, "interval_seconds": 1})
return second
'''
        result=self.program(source,scope=dict(operations=['os.collect'],collectors=[dict(settings=settings,max_runs=1)]))
        self.assertEqual(result['status'],'partial',result)
        self.assertEqual(result['data']['diagnostic']['code'],'scope_denied')
        self.assertEqual(result['data']['metrics']['calls_started'],1)
        self.assertEqual(len(list((self.state/'artifacts').iterdir())),1)

    def test_owned_disk_limit_cannot_turn_an_unsealed_api_failure_into_success(self):
        manifest=str(ROOT/'tests/fixtures/order-load/baseline.json')
        result=self.program('for item in range(1000):\n    pass\nreturn api("case.analyze", {"manifest": selected})["status"]',
            bindings=dict(selected=manifest),scope=dict(operations=['case.analyze'],manifests=[manifest]),
            resources=dict(max_owned_bytes=1024**2))
        self.assertIn(result['status'],('failed','partial'),result)
        from src.techexpert.code_runtime import inspect_program,nested_observations
        calls=inspect_program(self.state,result['run_id'])['calls']
        self.assertEqual(len(calls),1)
        self.assertIsNotNone(calls[0]['run_id'])
        if os.name=='nt':
            # This owned Job covers both the program and API manager. The API
            # manager can be stopped before it writes its own final status.
            self.assertTrue(result['stop_verified'])
            self.assertTrue(result['process']['tree_finished'])
        else:
            deadline=time.monotonic()+8
            while not nested_observations(self.state,result['run_id'])['stop_verified'] and time.monotonic()<deadline:time.sleep(.05)
            if not nested_observations(self.state,result['run_id'])['stop_verified']:self.assertFalse(result['stop_verified'])
        self.assertLessEqual(len(list((self.state/'cases').iterdir())),3)

    def test_program_disk_limit_covers_worker_output_and_finalization_without_recovery_bypass(self):
        from src.techexpert import operations
        for count in (40,8):
            with self.subTest(count=count):
                result=self.program('return ["x" * 60000 for item in range('+str(count)+')]',resources=dict(max_owned_bytes=1024**2))
                self.assertIn(result['status'],('failed','partial'),result['status'])
                self.assertEqual(result['stop_reason'],'owned_disk_limit')
                folder=self.state/'operations'/result['run_id']
                self.assertTrue((folder/'code-program.json').exists(),'Retain the partial audit, even if serialization was interrupted')
                self.assertFalse((folder/'output-receipt.json').exists(),'Over-budget output must not be published')
                with patch('src.techexpert.operation_process.run',side_effect=AssertionError('Recovery launched the program')):
                    if (folder/'worker-receipt.json').exists():
                        with self.assertRaisesRegex(ValueError,'owned_disk_limit'):operations.reconcile(self.state,result['run_id'])
                    else:self.assertNotEqual(operations.reconcile(self.state,result['run_id'])['status'],'succeeded')
                    self.assertNotEqual(operations.result(self.state,result['run_id'])['status'],'succeeded')

    def test_program_preserves_the_original_thirteen_diagnostic_operations(self):
        from src.techexpert.capabilities import BASE_API
        measurement=self.folder/'measurement.json'
        measurement.write_text(json.dumps(dict(schema_version=1,profile='os-metrics-v1',node='test',role='onec',scope='host',
            plan=dict(duration_seconds=1,interval_seconds=1,max_bytes=8388608),status='completed',
            samples=[dict(elapsed_seconds=0,metrics=[])])),encoding='utf-8')
        manifest=str(ROOT/'tests/fixtures/order-load/baseline.json')
        source='''imported = api("case.analyze", {"manifest": input_path})
cid = imported["data"]["case_id"]
report = api("case.show", {"case_id": cid})
coverage = api("case.coverage", {"case_id": cid})
page = api("case.events", {"case_id": cid, "limit": 1})
excerpt = api("case.evidence", {"case_id": cid, "evidence_id": page["data"]["records"][0]["evidence"]["id"]})
comparison = api("case.compare", {"before": [cid], "after": [fixed]})
saved = api("comparison.show", {"comparison_id": comparison["data"]["comparison_id"]})
check = api("source.check", {"manifest": input_path})
found = api("knowledge.search", {"query": "очередь"})
card = api("knowledge.card", {"card_id": "SC01-ORDER-LOAD", "limit": 40})
collected = api("os.collect", {"duration_seconds": 1, "interval_seconds": 1})
loaded = api("artifact.show", {"artifact_id": collected["data"]["artifact_id"]})
other = api("os.import", {"measurements": measurement_path})
return {"duration": report["data"]["durations_seconds"]["execution"], "excerpt": excerpt["data"]["evidence_id"], "imported_coverage": other["data"]["result"]["coverage_status"]}
'''
        result=self.program(source,bindings=dict(input_path=manifest,fixed=self.after['case_id'],measurement_path=str(measurement)),
            scope=dict(operations=list(BASE_API),cases=[self.after['case_id']],manifests=[manifest],measurements=[str(measurement)],
                collectors=[dict(settings=dict(duration_seconds=1,interval_seconds=1))]))
        self.assertEqual(result['status'],'succeeded',result)
        self.assertEqual({call['operation'] for call in result['data']['calls']},set(BASE_API))
        self.assertEqual(result['data']['value']['duration'],14)
        self.assertEqual(result['data']['value']['imported_coverage'],'incomplete')

    def test_cancel_reaches_nested_collector_and_prevents_following_job(self):
        from src.techexpert import operations,operation_state as fs,code_runtime
        settings=dict(transport='local',duration_seconds=20,interval_seconds=1)
        source='''first = api("os.collect", {"transport": "local", "duration_seconds": 20, "interval_seconds": 1})
return api("knowledge.search", {"query": "очередь"})
'''
        request=dict(schema_version=1,operation_key='nested-cancel',executor_id='test',operation='code.execute',
            arguments=dict(program=source,scope=dict(operations=['os.collect','knowledge.search'],collectors=[dict(settings=settings)])))
        path=self.folder/'cancel-request.json';path.write_text(json.dumps(request),encoding='utf-8')
        p=subprocess.Popen([sys.executable,'-X','utf8',str(ROOT/'techexpert.py'),'--state-dir',str(self.state),'operation-run',str(path)],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        run_id=hashlib.sha256(b'nested-cancel').hexdigest();nested=None
        try:
            until=time.monotonic()+10
            while time.monotonic()<until and p.poll() is None:
                try:
                    calls=code_runtime.inspect_program(self.state,run_id)['calls']
                    if calls and calls[0]['run_id']:
                        nested=fs.read(fs.folder(self.state,calls[0]['run_id'])/'status.json',65536)
                        if nested['status']=='running':break
                except (OSError,ValueError,KeyError):pass
                time.sleep(.04)
            self.assertIsNotNone(nested,'No live nested collector was observed')
            self.assertEqual(nested['status'],'running')
            cancelled=operations.cancel(self.state,run_id,executor_id='test')
            self.assertTrue(cancelled['cancellation_requested'])
            out,err=p.communicate(timeout=10)
            result=json.loads(out);self.assertEqual(result['status'],'cancelled',(result,err))
            self.assertTrue(result['stop_verified']);self.assertEqual(len(list((self.state/'operations').iterdir())),2)
            self.assertTrue(code_runtime.nested_observations(self.state,run_id)['stop_verified'])
            self.assertIn(fs.inspect_process(nested['child'])['state'],('not_running','different_lifetime'))
        finally:
            if p.poll() is None:
                try:operations.cancel(self.state,run_id,executor_id='test-cleanup')
                except (OSError,ValueError):pass
                try:p.communicate(timeout=10)
                except subprocess.TimeoutExpired:p.kill();p.communicate(timeout=5)

    def test_manager_death_stops_nested_workers_without_starting_another_job(self):
        from src.techexpert import operations,operation_state as fs,code_runtime
        settings=dict(duration_seconds=20,interval_seconds=1)
        request=dict(schema_version=1,operation_key='nested-owner-death',executor_id='test',operation='code.execute',
            arguments=dict(program='first = api("os.collect", {"duration_seconds": 20, "interval_seconds": 1})\nreturn api("knowledge.search", {"query": "очередь"})',
                scope=dict(operations=['os.collect','knowledge.search'],collectors=[dict(settings=settings)])))
        path=self.folder/'owner-request.json';path.write_text(json.dumps(request),encoding='utf-8')
        p=subprocess.Popen([sys.executable,'-X','utf8',str(ROOT/'techexpert.py'),'--state-dir',str(self.state),'operation-run',str(path)],
            cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        run_id=hashlib.sha256(b'nested-owner-death').hexdigest();nested=None
        try:
            deadline=time.monotonic()+10
            while time.monotonic()<deadline and p.poll() is None:
                try:
                    calls=code_runtime.inspect_program(self.state,run_id)['calls']
                    if calls and calls[0]['run_id']:
                        nested=fs.read(fs.folder(self.state,calls[0]['run_id'])/'status.json',65536)
                        if nested['status']=='running':break
                except (OSError,ValueError,KeyError):pass
                time.sleep(.04)
            self.assertIsNotNone(nested);self.assertEqual(nested['status'],'running')
            controller=fs.read(fs.folder(self.state,run_id)/'status.json',65536)['owner']
            # The test owns this Popen handle. No termination by a discovered PID.
            p.kill();p.communicate(timeout=5)
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                identities=[controller,nested['owner'],nested['child']]
                stopped=all(fs.inspect_process(i)['state'] in ('not_running','different_lifetime') for i in identities)
                if stopped and (os.name=='nt' or all(fs.inspect_group(i)['state']=='stopped' for i in identities)):break
                time.sleep(.05)
            self.assertTrue(stopped,'An owned nested worker outlived the observed manager death')
            if os.name!='nt':
                for identity in identities:self.assertEqual(fs.inspect_group(identity)['state'],'stopped')
            self.assertEqual(len(list((self.state/'operations').iterdir())),2)
            with patch('src.techexpert.operation_process.run',side_effect=AssertionError('Read restarted the program')):
                self.assertEqual(operations.result(self.state,run_id)['run_id'],run_id)
        finally:
            if p.poll() is None:
                try:operations.cancel(self.state,run_id,executor_id='test-cleanup')
                except (OSError,ValueError):pass
                p.communicate(timeout=10)


if __name__=='__main__':unittest.main()
