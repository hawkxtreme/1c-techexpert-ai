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


class KernelBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.kernel'),'Managed controller boundary is missing')
        self.api=importlib.import_module('src.techexpert.kernel')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name);self.state=self.folder/'state'

    def request(self,operation='knowledge.card',**arguments):
        request=dict(schema_version=1,operation_key='kernel-test',executor_id='kernel-verifier',operation=operation,
            arguments=arguments or dict(card_id='SC01-ORDER-LOAD',limit=20))
        path=self.folder/'запрос с пробелами.json';path.write_text(json.dumps(request,ensure_ascii=False),encoding='utf-8')
        return path,request

    def response(self,call):
        output=io.StringIO();self.api.emit(call,output)
        return json.loads(output.getvalue())

    def test_request_decode_and_saved_query_use_a_measured_owned_controller(self):
        path,request=self.request();call=self.api.invoke(self.state,'run',dict(request=str(path)))
        self.assertEqual(call['exit_code'],0)
        value=self.response(call);self.assertEqual(value['status'],'succeeded')
        self.assertEqual(value['kernel_call_id'],call['call_id'])
        receipt=self.api.inspect_call(self.state,call['call_id'])
        self.assertTrue(receipt['controller']['tree_finished'])
        self.assertNotEqual(receipt['controller']['pid'],os.getpid())
        self.assertIsNone(receipt['model_tokens']);self.assertIsNone(receipt['harness_memory_bytes'])
        self.assertEqual(receipt['limits']['memory_bytes'],1024**3)
        self.assertEqual(receipt['response']['bytes'],(Path(call['folder'])/call['response_name']).stat().st_size)
        query=self.api.invoke(self.state,'result',dict(run_id=value['run_id']))
        self.assertEqual(self.response(query)['data'],value['data'])

    def test_unknown_controller_action_starts_no_source_or_state_work(self):
        with self.assertRaisesRegex(ValueError,'action|unsupported'):
            self.api.invoke(self.state,'shell',dict(code='whoami'))
        self.assertFalse(self.state.exists())

    def test_completed_response_corruption_is_refused_without_another_controller(self):
        path,request=self.request();call=self.api.invoke(self.state,'run',dict(request=str(path)))
        response=Path(call['folder'])/call['response_name'];response.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError,'integrity|response'):
            self.response(call)
        self.assertEqual(len(list((self.state/'kernel-calls').iterdir())),1)

    def injected(self,code):
        code='import sys;sys.path.insert(0,'+repr(str(ROOT))+');'+code
        return lambda folder,memory:[sys.executable,'-X','utf8','-c',code,str(folder),str(memory)]

    def test_hung_admission_is_stopped_without_reading_an_original_or_starting_an_operation(self):
        argv=self.injected('import time;time.sleep(10)')
        started=time.monotonic()
        with patch('src.techexpert.kernel_process.controller_argv',side_effect=argv):
            call=self.api.invoke(self.state,'run',dict(request=str(self.folder/'unopened.json')),limits=dict(admission_seconds=.5))
        value=self.response(call)
        self.assertEqual(call['exit_code'],3);self.assertEqual(value['stop_reason'],'kernel_admission_timeout')
        self.assertLess(time.monotonic()-started,4)
        self.assertFalse((self.state/'operations').exists())
        self.assertTrue(self.api.inspect_call(self.state,call['call_id'])['controller']['tree_finished'])

    def test_replay_has_a_hard_controller_deadline_and_preserves_the_saved_result(self):
        path,request=self.request();first=self.api.invoke(self.state,'run',dict(request=str(path)))
        value=self.response(first);saved=self.state/'operations'/value['run_id']/'output.json';original=saved.read_bytes()
        code='import sys,time;from src.techexpert import kernel_controller,operations;operations.result=lambda *a,**k:time.sleep(10);kernel_controller.main(sys.argv[1],int(sys.argv[2]))'
        with patch('src.techexpert.kernel_process.controller_argv',side_effect=self.injected(code)):
            call=self.api.invoke(self.state,'result',dict(run_id=value['run_id']),limits=dict(query_seconds=.5))
        self.assertEqual(self.response(call)['stop_reason'],'kernel_timeout')
        self.assertEqual(saved.read_bytes(),original)
        self.assertEqual(len(list((self.state/'operations').iterdir())),1)

    def test_finalization_is_bounded_and_sealed_work_can_be_resumed_without_reimport(self):
        path,request=self.request('case.analyze',manifest=str(ROOT/'examples/sc01/case.json'))
        # Allow the fixture to seal on slower volumes before the injected 10-second promotion delay.
        request['budget']=dict(timeout_seconds=5);path.write_text(json.dumps(request),encoding='utf-8')
        code='import sys,time;from src.techexpert import kernel_controller,operations;operations._promote=lambda *a,**k:time.sleep(10);kernel_controller.main(sys.argv[1],int(sys.argv[2]))'
        with patch('src.techexpert.kernel_process.controller_argv',side_effect=self.injected(code)):
            call=self.api.invoke(self.state,'run',dict(request=str(path)))
        failed=self.response(call);self.assertEqual(failed['stop_reason'],'kernel_timeout')
        run_id=failed['run_id'];folder=self.state/'operations'/run_id
        self.assertTrue((folder/'prepared-output.json').exists())
        recovered=self.api.invoke(self.state,'reconcile',dict(run_id=run_id))
        self.assertEqual(self.response(recovered)['status'],'succeeded')
        self.assertEqual(len(list((self.state/'cases').iterdir())),1)

    def test_controller_memory_error_is_distinct_from_an_unexplained_process_exit(self):
        code='import sys;from src.techexpert import kernel_controller,operations;operations.result=lambda *a,**k:bytearray(512*1024**2);kernel_controller.main(sys.argv[1],int(sys.argv[2]))'
        with patch('src.techexpert.kernel_process.controller_argv',side_effect=self.injected(code)):
            call=self.api.invoke(self.state,'result',dict(run_id='a'*64),limits=dict(memory_bytes=128*1024**2))
        self.assertEqual(self.response(call)['stop_reason'],'kernel_memory_limit')
        with patch('src.techexpert.kernel_process.controller_argv',side_effect=self.injected('import os;os._exit(71)')):
            unexplained=self.api.invoke(self.state,'result',dict(run_id='a'*64))
        self.assertEqual(self.response(unexplained)['stop_reason'],'kernel_process_failure')

    def test_utf8_response_forwarding_handles_multibyte_chunk_boundaries(self):
        path,request=self.request(limit=6000,card_id='SC01-ORDER-LOAD')
        call=self.api.invoke(self.state,'run',dict(request=str(path)))
        with patch('src.techexpert.kernel.CHUNK',7):value=self.response(call)
        self.assertIn('Повторные обращения',value['data']['body'])

    def test_cli_routes_managed_commands_through_the_controller_boundary(self):
        path,request=self.request()
        result=subprocess.run([sys.executable,'-X','utf8',str(ROOT/'techexpert.py'),'--state-dir',str(self.state),
            'operation-run',str(path)],cwd=ROOT,capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        value=json.loads(result.stdout);self.assertIn('kernel_call_id',value)
        receipt=self.api.inspect_call(self.state,value['kernel_call_id'])
        self.assertTrue(receipt['controller']['tree_finished'])
        self.assertNotIn(b'\r\n',result.stdout)

    @unittest.skipUnless(os.name=='nt','Windows virtual-environment launcher')
    def test_windows_venv_preserves_exact_pids_for_managed_cli_and_direct_workers(self):
        import venv
        from src.techexpert.operation_state import read
        environment=self.folder/'среда с пробелами'
        venv.EnvBuilder(with_pip=False,symlinks=False).create(environment)
        python=str(environment/'Scripts/python.exe')
        program='return api("knowledge.search", {"query": "SC-01"})["data"]["knowledge_revision"]'
        path,request=self.request('code.execute',program=program,scope=dict(operations=['knowledge.search']))
        direct='''import json, sys
from pathlib import Path
from src.techexpert import operations
request = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
print(json.dumps(operations.run(Path(sys.argv[1]), request), ensure_ascii=False))
'''
        env=dict(os.environ,PYTHONPATH='',PYTHONDONTWRITEBYTECODE='1')
        for route in ('cli','direct'):
            with self.subTest(route=route):
                state=self.folder/route
                args=(['techexpert.py','--state-dir',str(state),'operation-run',str(path)] if route=='cli'
                    else ['-c',direct,str(state),str(path)])
                result=subprocess.run([python,'-B','-X','utf8',*args],cwd=ROOT,env=env,capture_output=True,timeout=25)
                value=json.loads(result.stdout)
                self.assertEqual((result.returncode,value['status']),(0,'succeeded'),value)
                self.assertTrue(value['data']['value'])
                self.assertTrue(value['stop_verified'])
                worker=state/'operations'/value['run_id']
                self.assertEqual(read(worker/'start-permit.json')['child'],read(worker/'worker-identity.json'))
                if route=='cli':
                    call=self.api.inspect_call(state,value['kernel_call_id'])
                    controller=state/'kernel-calls'/call['call_id']
                    permit=read(controller/'start-permit.json')
                    self.assertEqual(permit['child']['pid'],call['controller']['pid'])
                    self.assertTrue(call['controller']['tree_finished'])

    def test_a_corrupt_saved_usage_counter_is_not_presented_as_verified_measurement(self):
        path,request=self.request();call=self.api.invoke(self.state,'run',dict(request=str(path)))
        receipt=Path(call['folder'])/'call-receipt.json';original=receipt.read_text(encoding='utf-8')
        changed=original.replace('"model_tokens": null','"model_tokens": 1',1);self.assertNotEqual(original,changed)
        receipt.write_text(changed,encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'integrity'):self.api.inspect_call(self.state,call['call_id'])

    def test_kernel_reference_is_inside_the_first_wire_budget_gate(self):
        path,request=self.request('case.analyze',manifest=str(ROOT/'tests/fixtures/order-load/baseline.json'))
        first=self.api.invoke(self.state,'run',dict(request=str(path)));value=self.response(first)
        saved=self.state/'operations'/value['run_id']/'output.json'
        limit=(saved.stat().st_size+(Path(first['folder'])/first['response_name']).stat().st_size)//2
        request.update(operation_key='tight-kernel-gate',budget=dict(max_result_bytes=limit))
        path.write_text(json.dumps(request),encoding='utf-8')
        failed=self.api.invoke(self.state,'run',dict(request=str(path)));reply=self.response(failed)
        self.assertEqual(reply['status'],'failed');self.assertEqual(reply['stop_reason'],'output_limit')
        self.assertLessEqual((Path(failed['folder'])/failed['response_name']).stat().st_size,limit)
        self.assertEqual(len(list((self.state/'cases').iterdir())),1)

    def test_oversized_original_request_is_rejected_inside_admission(self):
        path=self.folder/'too-large.json';path.write_bytes(b'x'*(128*1024+1))
        call=self.api.invoke(self.state,'run',dict(request=str(path)))
        self.assertEqual(call['exit_code'],2);self.assertIn('byte limit',self.response(call)['message'])
        self.assertFalse((self.state/'operations').exists())

    def test_keyboard_cancel_has_its_own_status_and_exit_code(self):
        with patch('src.techexpert.kernel_process.controller_argv',side_effect=self.injected('import time;time.sleep(10)')):
            with patch('src.techexpert.kernel.fs.inventory',side_effect=KeyboardInterrupt):
                call=self.api.invoke(self.state,'result',dict(run_id='a'*64))
        self.assertEqual(call['exit_code'],130);self.assertEqual(self.response(call)['status'],'cancelled')

    def test_reduced_memory_bound_is_preserved_by_the_real_nested_worker(self):
        path,request=self.request()
        call=self.api.invoke(self.state,'run',dict(request=str(path)),limits=dict(memory_bytes=128*1024**2))
        self.assertEqual(call['exit_code'],0,self.response(call))
        receipt=self.api.inspect_call(self.state,call['call_id'])
        self.assertEqual(receipt['limits']['memory_bytes'],128*1024**2)
        if os.name!='nt':self.assertEqual(self.response(call)['metrics'].get('effective_address_space_limit_bytes'),128*1024**2)

    def test_malformed_or_expanded_admission_is_a_bounded_retained_failure(self):
        for payload in ('[]',"dict(plan_sha256=fs.digest(plan),timeout_seconds=.75,run_id='a'*64)"):
            code='import sys,time;from pathlib import Path;from src.techexpert import operation_state as fs;p=Path(sys.argv[1]);plan=fs.read(p/"plan.json");fs.write(p/"admitted.json",'+payload+');time.sleep(2)'
            with self.subTest(payload=payload):
                with patch('src.techexpert.kernel_process.controller_argv',side_effect=self.injected(code)):
                    call=self.api.invoke(self.state,'result',dict(run_id='a'*64),limits=dict(query_seconds=.5))
                self.assertEqual(call['exit_code'],3)
                self.assertEqual(self.response(call)['stop_reason'],'kernel_admission_integrity')
                self.assertTrue((Path(call['folder'])/'admitted.json').exists())

    def test_missing_invocation_receipt_is_partial_metadata_and_does_not_erase_the_response(self):
        path,request=self.request();call=self.api.invoke(self.state,'run',dict(request=str(path)))
        response=Path(call['folder'])/call['response_name'];original=response.read_bytes()
        (Path(call['folder'])/'call-receipt.json').unlink()
        incomplete=self.api.inspect_call(self.state,call['call_id'])
        self.assertEqual(incomplete['status'],'partial')
        self.assertEqual(incomplete['result_availability'],'incomplete_invocation_receipt')
        self.assertEqual(response.read_bytes(),original)

    def test_memory_error_while_serializing_the_response_is_distinct_from_unknown_exit(self):
        code='''import sys
from src.techexpert import kernel_controller,operations,operation_state
operations.result=lambda *a,**k:dict(status='succeeded',data='serialization-memory-fixture')
original=operation_state.encode
def failing(value):
    if isinstance(value,dict) and value.get('data')=='serialization-memory-fixture':raise MemoryError()
    return original(value)
operation_state.encode=failing
kernel_controller.main(sys.argv[1],int(sys.argv[2]))
'''
        with patch('src.techexpert.kernel_process.controller_argv',side_effect=self.injected(code)):
            call=self.api.invoke(self.state,'result',dict(run_id='a'*64))
        self.assertEqual(self.response(call)['stop_reason'],'kernel_memory_limit')

    @unittest.skipIf(os.name=='nt','Linux unreaped session ownership')
    def test_the_session_leader_pid_remains_reserved_until_its_owned_group_is_stopped(self):
        import signal
        from src.techexpert import operation_state,operations
        original=os.killpg;observed=[]
        def check_owned(pid,sig):
            if sig==signal.SIGKILL:
                identity=operation_state.process_identity(pid)
                self.assertIsNotNone(identity['lifetime'],'leader was reaped before group stop; its ID can already be reused')
                observed.append(identity)
            return original(pid,sig)
        with patch('src.techexpert.kernel_process.os.killpg',side_effect=check_owned):
            with patch('src.techexpert.kernel_process.controller_argv',side_effect=self.injected('import os;os._exit(71)')):
                self.api.invoke(self.state,'result',dict(run_id='a'*64))
            _,request=self.request()
            request['operation_key']='direct-reserved-leader';operations.run(self.state,request)
        self.assertGreaterEqual(len(observed),2)

    def test_launcher_failure_is_structured_without_claiming_a_verified_stop(self):
        with patch('src.techexpert.kernel_process.run',side_effect=OSError('controlled launcher failure')):
            try:call=self.api.invoke(self.state,'result',dict(run_id='a'*64))
            except OSError:self.fail('launcher exception escaped the bounded response protocol')
        value=self.response(call)
        self.assertEqual(call['exit_code'],3);self.assertEqual(value['stop_reason'],'kernel_launcher_failure')
        self.assertFalse(value['stop_verified'])

    def test_actual_final_receipt_write_failure_retains_the_response_and_returns_partial(self):
        path,request=self.request();original_write=self.api._write_checked
        def fail_receipt(path,value):
            if Path(path).name=='call-receipt.json':raise OSError('controlled final receipt failure')
            return original_write(path,value)
        with patch('src.techexpert.kernel._write_checked',side_effect=fail_receipt):
            call=self.api.invoke(self.state,'run',dict(request=str(path)))
        value=self.response(call)
        self.assertEqual(call['exit_code'],1);self.assertEqual(value['status'],'partial')
        self.assertEqual(value['result_availability'],'incomplete_invocation_receipt')
        original=Path(call['folder'])/'response.json';before=original.read_bytes()
        self.assertEqual(json.loads(before)['status'],'succeeded')
        self.assertEqual(self.api.inspect_call(self.state,call['call_id'])['status'],'partial')
        self.assertEqual(original.read_bytes(),before)
        self.assertEqual(len(list((self.state/'kernel-calls').iterdir())),1)

    def test_final_receipt_and_failure_frame_write_denial_still_return_a_bounded_partial(self):
        path,request=self.request();original_write=self.api._write_checked
        def fail_receipts(path,value):
            if Path(path).name in ('call-receipt.json','receipt-error-response-receipt.json'):raise OSError('controlled receipt writes denied')
            return original_write(path,value)
        with patch('src.techexpert.kernel._write_checked',side_effect=fail_receipts):
            call=self.api.invoke(self.state,'run',dict(request=str(path)))
        value=self.response(call)
        self.assertEqual(call['exit_code'],1);self.assertEqual(value['status'],'partial')
        self.assertLess(len(json.dumps(value).encode()),16384)
        self.assertEqual(json.loads((Path(call['folder'])/'response.json').read_text(encoding='utf-8'))['status'],'succeeded')

    def test_dead_owner_after_a_real_final_receipt_fault_is_partial_and_not_running(self):
        path,request=self.request()
        code='''import json,sys
from pathlib import Path
from src.techexpert import kernel
original=kernel._write_checked
def fault(path,value):
    if Path(path).name=='call-receipt.json':raise OSError('controlled actual final receipt fault')
    return original(path,value)
kernel._write_checked=fault
try:
    call=kernel.invoke(Path(sys.argv[1]),'run',dict(request=sys.argv[2]))
    kernel.emit(call,sys.stdout)
    sys.exit(call['exit_code'])
except OSError:
    print(json.dumps(dict(kernel_call_id=next((Path(sys.argv[1])/'kernel-calls').iterdir()).name)))
'''
        run=subprocess.run([sys.executable,'-X','utf8','-c',code,str(self.state),str(path)],cwd=ROOT,capture_output=True,timeout=15)
        value=json.loads(run.stdout);call=self.api.inspect_call(self.state,value['kernel_call_id'])
        self.assertEqual(call['status'],'partial');self.assertEqual(call['result_availability'],'incomplete_invocation_receipt')
        self.assertIn(call['observed_owner']['state'],('not_running','different_lifetime'))
        self.assertIn(call['observed_child']['state'],('not_running','different_lifetime'))
        self.assertEqual(run.returncode,1,run.stderr)

    def test_advisory_status_write_failure_does_not_hide_a_checked_finished_response(self):
        path,request=self.request()
        from src.techexpert import operation_state
        original=operation_state.write
        def fault(path,value):
            if Path(path).name=='status.json' and value.get('status')=='finished':raise OSError('controlled advisory status failure')
            return original(path,value)
        with patch('src.techexpert.operation_state.write',side_effect=fault):
            call=self.api.invoke(self.state,'run',dict(request=str(path)))
        self.assertEqual(call['exit_code'],0);self.assertEqual(self.response(call)['status'],'succeeded')
        self.assertTrue(call['diagnostics'])
        self.assertEqual(self.api.inspect_call(self.state,call['call_id'])['status'],'finished')


if __name__=='__main__':unittest.main()
