"""Real stdio and managed-kernel contracts; no external server or model required."""
import importlib
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
MODERN='2026-07-28'
LEGACY='2025-11-25'
META={'io.modelcontextprotocol/protocolVersion':MODERN,'io.modelcontextprotocol/clientCapabilities':{}}


class MCPTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.mcp_tools'),'Finite MCP adapter is missing')
        self.api=importlib.import_module('src.techexpert.mcp_tools')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name);self.state=self.folder/'private state'

    def tools(self):return {tool['name']:tool for tool in self.api.tools()}

    def start(self,reader_enabled=True,profile='full'):
        errors=(self.folder/'stderr.txt').open('wb');self.addCleanup(errors.close)
        p=subprocess.Popen([sys.executable,'-X','utf8',str(ROOT/'techexpert.py'),'--state-dir',str(self.state),'mcp-stdio','--profile',profile],
            cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=errors)
        replies=queue.Queue()
        def reader():
            for line in p.stdout:replies.put(line)
            replies.put(None)
        if reader_enabled:threading.Thread(target=reader,daemon=True).start()
        def cleanup():
            if p.poll() is None:
                p.stdin.close()
                try:p.wait(timeout=12)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
            p.stdout.close()
            if not p.stdin.closed:p.stdin.close()
        self.addCleanup(cleanup)
        return p,replies

    def send(self,p,method,params=None,identifier=1,modern=True):
        params={} if params is None else dict(params)
        if modern and identifier is not None:params['_meta']=dict(META)
        value=dict(jsonrpc='2.0',method=method,params=params)
        if identifier is not None:value['id']=identifier
        p.stdin.write((json.dumps(value,ensure_ascii=False)+'\n').encode());p.stdin.flush()

    def receive(self,replies,identifier=1):
        line=replies.get(timeout=15);self.assertIsNotNone(line,'Server exited instead of replying')
        self.assertEqual(line.count(b'\n'),1)
        value=json.loads(line);self.assertEqual(value['id'],identifier)
        return value

    def args(self,key='mcp-case',**args):
        return dict(operation_key=key,executor_id='test-harness',arguments=args or dict(card_id='SC01-ORDER-LOAD',limit=80))

    def test_catalogue_is_passive_complete_and_closed(self):
        from src.techexpert.capabilities import ROUTES
        tools=self.tools();self.assertEqual(len(tools),42)
        self.assertTrue({'techexpert_'+name.replace('.','_') for name in ROUTES}<=tools.keys())
        self.assertFalse(self.state.exists())
        for tool in tools.values():
            self.assertFalse(tool['inputSchema']['additionalProperties'])
            self.assertEqual(tool['outputSchema']['type'],'object')
            self.assertIn('data',tool['outputSchema']['required'])
        self.assertFalse(tools['techexpert_os_collect']['annotations']['readOnlyHint'])
        self.assertTrue(tools['techexpert_case_show']['annotations']['readOnlyHint'])

    def test_program_and_direct_profiles_separate_composition_without_weakening_the_api(self):
        for profile,count,allowed,hidden in [
            ('program',7,'techexpert_code_execute','techexpert_knowledge_search'),
            ('direct',40,'techexpert_knowledge_search','techexpert_code_execute')]:
            with self.subTest(profile=profile):
                before={str(f.relative_to(self.state)):hashlib.sha256(f.read_bytes()).hexdigest() for f in self.state.rglob('*') if f.is_file()}
                p,q=self.start(profile=profile);self.send(p,'tools/list')
                catalogue=self.receive(q)['result']['tools'];self.assertEqual(len(catalogue),count)
                self.assertIn(allowed,{t['name'] for t in catalogue});self.assertNotIn(hidden,{t['name'] for t in catalogue})
                self.send(p,'tools/call',dict(name=hidden,arguments={}),identifier=2)
                self.assertEqual(self.receive(q,2)['error']['code'],-32602)
                self.assertEqual(before,{str(f.relative_to(self.state)):hashlib.sha256(f.read_bytes()).hexdigest() for f in self.state.rglob('*') if f.is_file()})
                arguments=self.args(key='profile-'+profile,query='очередь') if profile=='direct' else self.args(key='profile-'+profile,
                    program='return api("knowledge.search", {"query": "очередь"})["data"]["knowledge_revision"]',
                    scope=dict(operations=['knowledge.search']))
                self.send(p,'tools/call',dict(name=allowed,arguments=arguments),identifier=3)
                result=self.receive(q,3)['result']['structuredContent']
                self.assertEqual(result['status'],'succeeded',result)
                self.assertTrue(result['integrity_verified'])
                p.stdin.close();self.assertEqual(p.wait(timeout=10),0)

    def test_modern_discovery_without_initialize_has_no_source_or_state_side_effect(self):
        p,q=self.start();self.send(p,'server/discover')
        result=self.receive(q)['result']
        self.assertEqual(result['resultType'],'complete');self.assertIn(MODERN,result['supportedVersions'])
        self.assertEqual(result.get('cacheScope'),'public');self.assertEqual(result.get('ttlMs'),0)
        self.assertEqual(result['capabilities'],{'tools':{'listChanged':False}})
        self.send(p,'tools/list',identifier=2)
        self.assertEqual(self.receive(q,2)['result']['tools'],self.api.tools())
        self.assertFalse(self.state.exists())

    def test_legacy_initialize_and_tools_list(self):
        p,q=self.start()
        self.send(p,'initialize',dict(protocolVersion=LEGACY,capabilities={},clientInfo=dict(name='test',version='1')),modern=False)
        self.assertEqual(self.receive(q)['result']['protocolVersion'],LEGACY)
        self.send(p,'notifications/initialized',identifier=None,modern=False)
        self.send(p,'tools/list',identifier=2,modern=False)
        result=self.receive(q,2)['result'];self.assertNotIn('resultType',result)
        self.assertEqual(len(result['tools']),42);self.assertFalse(self.state.exists())

    def test_modern_metadata_required_on_every_request_and_not_borrowed_from_previous(self):
        p,q=self.start();self.send(p,'server/discover');self.receive(q)
        self.send(p,'tools/list',identifier=2,modern=False)
        self.assertEqual(self.receive(q,2)['error']['code'],-32602)
        params={'_meta':dict(META,**{'io.modelcontextprotocol/protocolVersion':'2099-01-01'})}
        self.send(p,'tools/list',params,identifier=3,modern=False)
        error=self.receive(q,3)['error'];self.assertEqual(error['code'],-32022)
        self.assertIn(MODERN,error['data']['supported']);self.assertFalse(self.state.exists())

    def test_real_tool_has_matching_text_structure_receipt_and_cli_replay(self):
        from src.techexpert import kernel,operation_state as fs
        p,q=self.start();args=self.args()
        self.send(p,'tools/call',dict(name='techexpert_knowledge_card',arguments=args))
        result=self.receive(q)['result'];self.assertFalse(result['isError'])
        value=result['structuredContent'];self.assertEqual(json.loads(result['content'][0]['text']),value)
        self.assertEqual(value['status'],'succeeded');self.assertEqual(value['data']['id'],'SC01-ORDER-LOAD')
        receipt=kernel.inspect_call(self.state,value['kernel_call_id'])
        self.assertFalse(receipt['transport']['full_response_json_decoded'])
        wire=receipt['response']
        self.assertEqual(wire.get('encoding'),'mcp-tool-result-compact-v1')
        self.assertEqual(wire.get('structured_payload_compact_bytes'),len(result['content'][0]['text'].encode('utf-8')))
        self.assertEqual(wire.get('tool_result_wrapper_bytes'),wire['bytes']-wire['structured_payload_compact_bytes'])
        self.assertTrue(receipt['controller']['tree_finished']);self.assertIsNone(receipt['model_tokens'])
        saved=self.state/'operations'/value['run_id']/'output.json';before=saved.read_bytes()
        cli=kernel.invoke(self.state,'result',dict(run_id=value['run_id']))
        out=io.StringIO();kernel.emit(cli,out);replay=json.loads(out.getvalue())
        self.assertEqual(value['data'],replay['data']);self.assertEqual(saved.read_bytes(),before)
        self.assertEqual(len(list((self.state/'operations').iterdir())),1)
        for path in (self.state/'kernel-calls'/value['kernel_call_id']).glob('*.json'):
            self.assertNotIn('io.modelcontextprotocol/clientCapabilities',path.read_text(encoding='utf-8'))

    def test_unknown_tool_and_invalid_arguments_start_no_kernel_and_keep_secrets_out_of_state(self):
        p,q=self.start();self.send(p,'tools/call',dict(name='shell',arguments=dict(command='secret-do-not-store')))
        self.assertEqual(self.receive(q)['error']['code'],-32602)
        self.send(p,'tools/call',dict(name='techexpert_knowledge_card',arguments=dict(self.args(),password='secret-do-not-store')),identifier=2)
        result=self.receive(q,2)['result'];self.assertTrue(result['isError'])
        self.assertEqual(result['structuredContent']['status'],'invalid_input')
        self.assertFalse(self.state.exists())

    def test_real_missing_case_is_tool_error_with_common_output_fields(self):
        p,q=self.start();self.send(p,'tools/call',dict(name='techexpert_case_show',arguments=self.args(case_id='a'*32)))
        result=self.receive(q)['result'];self.assertTrue(result['isError'])
        value=result['structuredContent'];self.assertIn(value['status'],('invalid_input','failed'))
        self.assertTrue(set(['schema_version','run_id','operation','status','data','snapshots','evidence','limitations','truncated'])<=value.keys())
        self.assertIsNone(value['data'])

    def test_duplicate_keys_and_bad_json_do_not_desynchronize_following_line(self):
        p,q=self.start()
        for raw in (b'{bad}\n',b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}\n'):
            p.stdin.write(raw);p.stdin.flush();value=json.loads(q.get(timeout=5))
            self.assertEqual(value['error']['code'],-32700)
        self.send(p,'ping',identifier=4);self.assertEqual(self.receive(q,4)['result']['resultType'],'complete')
        self.assertFalse(self.state.exists())

    def test_cancel_long_collect_keeps_discovery_responsive_and_owns_only_that_invocation(self):
        p,q=self.start();args=self.args('cancel-this-collect',transport='local',duration_seconds=20,interval_seconds=1)
        self.send(p,'tools/call',dict(name='techexpert_os_collect',arguments=args))
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and not list(self.state.glob('operations/*/worker-started.json')):time.sleep(.05)
        self.assertTrue(list(self.state.glob('operations/*/worker-started.json')))
        self.send(p,'ping',identifier=2);self.assertIn('result',self.receive(q,2))
        started=time.monotonic();self.send(p,'notifications/cancelled',dict(requestId=1),identifier=None)
        self.send(p,'tools/list',identifier=3);self.assertIn('tools',self.receive(q,3)['result'])
        deadline=started+9
        from src.techexpert import kernel
        receipt=None
        while time.monotonic()<deadline:
            paths=list(self.state.glob('kernel-calls/*/call-receipt.json'))
            if paths:
                receipt=kernel.inspect_call(self.state,paths[0].parent.name);break
            time.sleep(.05)
        self.assertIsNotNone(receipt,'Cancelled controller did not finish promptly')
        self.assertTrue(receipt['controller']['tree_finished'])
        self.assertLess(time.monotonic()-started,9)
        self.assertEqual(len(list(self.state.glob('operations/*'))),1)
        self.assertTrue(q.empty(),'Cancelled request must have no response')

    def test_client_eof_cancels_its_owned_collection_and_exits_without_waiting_for_duration(self):
        p,q=self.start();self.send(p,'tools/call',dict(name='techexpert_os_collect',
            arguments=self.args('closed-client',transport='local',duration_seconds=20,interval_seconds=1)))
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and not list(self.state.glob('operations/*/worker-started.json')):time.sleep(.05)
        self.assertTrue(list(self.state.glob('operations/*/worker-started.json')))
        started=time.monotonic();p.stdin.close();p.wait(timeout=10)
        self.assertEqual(p.returncode,0);self.assertLess(time.monotonic()-started,10)
        from src.techexpert import kernel
        paths=list(self.state.glob('kernel-calls/*/call-receipt.json'));self.assertEqual(len(paths),1)
        self.assertTrue(kernel.inspect_call(self.state,paths[0].parent.name)['controller']['tree_finished'])

    def test_cancelling_same_key_observer_does_not_cancel_original_collect(self):
        p,q=self.start();args=self.args('original-owner',transport='local',duration_seconds=4,interval_seconds=1)
        self.send(p,'tools/call',dict(name='techexpert_os_collect',arguments=args))
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and not list(self.state.glob('operations/*/worker-started.json')):time.sleep(.02)
        self.assertTrue(list(self.state.glob('operations/*/worker-started.json')))
        self.send(p,'tools/call',dict(name='techexpert_os_collect',arguments=dict(args,executor_id='observer')),identifier=2)
        self.send(p,'notifications/cancelled',dict(requestId=2),identifier=None)
        value=self.receive(q)['result']['structuredContent']
        self.assertEqual(value['status'],'succeeded');self.assertFalse(list(self.state.glob('operations/*/cancel.json')))
        self.assertEqual(len(list(self.state.glob('operations/*/worker-started.json'))),1)

    def test_large_compact_wire_is_formed_inside_controller_and_streamed_in_bounded_chunks(self):
        from src.techexpert import kernel
        code=('import sys;sys.path.insert(0,'+repr(str(ROOT))+');from src.techexpert import kernel_controller,operations;'
            'operations.result=lambda *a,**k:dict(status="succeeded",data=dict(body=("Привет\\n\\\"\\\\"*150000)));'
            'kernel_controller.main(sys.argv[1],int(sys.argv[2]))')
        def argv(folder,memory):return [sys.executable,'-X','utf8','-c',code,str(folder),str(memory)]
        with patch('src.techexpert.kernel_process.controller_argv',side_effect=argv):
            call=kernel.invoke(self.state,'result',dict(run_id='a'*64),wire_version=MODERN)
        sizes=[];output=io.StringIO()
        class Sink:
            def write(self,text):sizes.append(len(text.encode('utf-8')));output.write(text)
            def flush(self):pass
        kernel.emit(call,Sink());raw=output.getvalue();self.assertNotIn('\n',raw)
        result=json.loads(raw);self.assertEqual(json.loads(result['content'][0]['text']),result['structuredContent'])
        self.assertGreater(len(raw.encode('utf-8')),3*1024**2);self.assertLessEqual(max(sizes),kernel.CHUNK+4)
        self.assertFalse(kernel.inspect_call(self.state,call['call_id'])['transport']['full_response_json_decoded'])

    def test_cancellation_of_a_stuck_controller_is_recorded_as_cancellation_not_unexplained_failure(self):
        from src.techexpert import kernel
        event=threading.Event()
        code=('import sys,time;sys.path.insert(0,'+repr(str(ROOT))+');'
            'from src.techexpert import kernel_controller,operations;'
            'operations.result=lambda *a,**k:time.sleep(20);'
            'kernel_controller.main(sys.argv[1],int(sys.argv[2]))')
        def argv(folder,memory):return [sys.executable,'-X','utf8','-c',code,str(folder),str(memory)]
        def cancel_after_admission():
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                if list(self.state.glob('kernel-calls/*/admitted.json')):event.set();return
                time.sleep(.02)
        thread=threading.Thread(target=cancel_after_admission,daemon=True);thread.start()
        started=time.monotonic()
        with patch('src.techexpert.kernel_process.controller_argv',side_effect=argv):
            call=kernel.invoke(self.state,'result',dict(run_id='a'*64),wire_version=MODERN,cancel_event=event)
        thread.join(timeout=1);out=io.StringIO();kernel.emit(call,out)
        value=json.loads(out.getvalue())['structuredContent']
        self.assertEqual(value['status'],'cancelled');self.assertEqual(value['stop_reason'],'cancelled')
        receipt=kernel.inspect_call(self.state,call['call_id'])
        self.assertTrue(receipt.get('cancellation_requested'));self.assertTrue(receipt['controller']['tree_finished'])
        self.assertLess(time.monotonic()-started,9)

    def test_closed_output_terminates_transport_even_while_stdin_stays_open(self):
        p,q=self.start(reader_enabled=False);p.stdout.close()
        self.send(p,'ping');p.wait(timeout=4);self.assertEqual(p.returncode,0)

    def test_oversized_line_and_deep_json_are_rejected_then_ping_still_works(self):
        p,q=self.start()
        for raw in (b' '*270000+b'\n',b'{"nested":'+b'['*40+b'0'+b']'*40+b'}\n'):
            p.stdin.write(raw);p.stdin.flush();value=json.loads(q.get(timeout=5))
            self.assertEqual(value['error']['code'],-32700)
        self.send(p,'ping',identifier=3);self.assertIn('result',self.receive(q,3));self.assertFalse(self.state.exists())

    def test_portable_sc01_smoke_verifies_ten_answers_without_claiming_an_llm_evaluation(self):
        script=ROOT/'scripts/mcp_sc01_smoke.py'
        self.assertTrue(script.is_file(),'Portable SC01 MCP evaluation preparation is missing')
        result=subprocess.run([sys.executable,'-X','utf8',str(script),'--state-dir',str(self.state)],
            cwd=ROOT,capture_output=True,timeout=50)
        self.assertEqual(result.returncode,0,result.stderr.decode('utf-8',errors='replace'))
        value=json.loads(result.stdout);self.assertEqual(value['verified_answers'],10)
        self.assertFalse(value['llm_evaluation_performed']);self.assertFalse(value['server_license_used'])
        self.assertEqual(value['protocol'],MODERN)


    def test_huge_numeric_arguments_return_tool_error_and_keep_connection(self):
        p,q=self.start();big=10**400
        inputs=[('techexpert_knowledge_card',dict(self.args(),budget=dict(max_result_bytes=big))),
            ('techexpert_knowledge_card',dict(self.args(),budget=dict(timeout_seconds=big))),
            ('techexpert_knowledge_card',self.args(card_id='SC01-ORDER-LOAD',limit=big)),
            ('techexpert_os_collect',self.args(transport='local',duration_seconds=-big))]
        for index,(name,args) in enumerate(inputs,1):
            self.send(p,'tools/call',dict(name=name,arguments=args),identifier=index)
            result=self.receive(q,index)['result'];self.assertTrue(result['isError'])
            self.assertEqual(result['structuredContent']['status'],'invalid_input')
        self.send(p,'ping',identifier=5);self.assertIn('result',self.receive(q,5));self.assertFalse(self.state.exists())

    def test_huge_number_in_another_request_does_not_cancel_the_running_collection(self):
        p,q=self.start();self.send(p,'tools/call',dict(name='techexpert_os_collect',
            arguments=self.args('survive-invalid-other-request',transport='local',duration_seconds=4,interval_seconds=1)))
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and not list(self.state.glob('operations/*/worker-started.json')):time.sleep(.02)
        self.assertTrue(list(self.state.glob('operations/*/worker-started.json')))
        self.send(p,'tools/call',dict(name='techexpert_knowledge_card',arguments=dict(self.args(),budget=dict(max_result_bytes=10**400))),identifier=2)
        self.assertTrue(self.receive(q,2)['result']['isError'])
        self.send(p,'ping',identifier=3);self.assertIn('result',self.receive(q,3))
        self.assertEqual(self.receive(q)['result']['structuredContent']['status'],'succeeded')
        self.assertEqual(len(list(self.state.glob('operations/*'))),1);self.assertFalse(list(self.state.glob('kernel-calls/*/cancel.json')))

    def test_surrogate_escape_in_id_or_metadata_is_rejected_then_ping_still_works(self):
        p,q=self.start()
        values=[dict(jsonrpc='2.0',id='\ud800',method='ping',params={'_meta':dict(META)}),
            dict(jsonrpc='2.0',id=2,method='ping',params={'_meta':dict(META,**{'io.modelcontextprotocol/protocolVersion':'\ud800'})})]
        for v in values:
            p.stdin.write((json.dumps(v,ensure_ascii=True)+'\n').encode('utf-8'));p.stdin.flush()
            line=q.get(timeout=5);self.assertIsNotNone(line,'Invalid Unicode must not close the transport')
            self.assertEqual(json.loads(line)['error']['code'],-32700)
        self.send(p,'ping',identifier=3);self.assertIn('result',self.receive(q,3));self.assertFalse(self.state.exists())

if __name__=='__main__':unittest.main()
