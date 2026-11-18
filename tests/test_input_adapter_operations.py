"""Selected imports share finite schemas, scope, receipts and retained replay."""
import json
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from src.techexpert import capabilities,operations,input_intake,mcp_tools
from src.techexpert.storage import write_json
from src.techexpert.inputs import InputError
from test_input_adapter_intake import FIXTURE,os_document,apdex_rows

ROOT=Path(__file__).resolve().parents[1]


class AdapterOperationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.state=self.root/'state';self.archive=self.root/'provided.zip';self.counter=0
        with zipfile.ZipFile(self.archive,'w',compression=zipfile.ZIP_DEFLATED) as zipped:
            for name in ('1Cv8.lgf','20261116000000.lgp'):zipped.writestr('jr/'+name,(FIXTURE/name).read_bytes())
            zipped.writestr('os.json',json.dumps(os_document()));zipped.writestr('os-b.json',json.dumps(os_document('host-b')));zipped.writestr('apdex.json',json.dumps(apdex_rows()))
        self.settings=dict(inputs=[dict(path=str(self.archive),kind='zip')]);self.plan=input_intake.inspect(self.state,**self.settings);self.pid=self.plan['artifact_id'];self.ids={m['relative_path']:m['id'] for m in self.plan['result']['members']}

    def req(self,op,args,key=None):
        self.counter+=1;return dict(schema_version=1,operation_key=key or 'adapter-'+str(self.counter),executor_id='test-harness',operation=op,arguments=args)

    def arguments(self,op):
        if op=='jr.import':return dict(path=str(self.archive),platform_version='8.3.27.1989',utc_offset='+03:00',input_plan=self.pid,members=[self.ids['jr/1Cv8.lgf'],self.ids['jr/20261116000000.lgp']])
        return dict(measurements=str(self.archive),input_plan=self.pid,members=[self.ids['os.json' if op=='os.import' else 'apdex.json']],**(dict(target_seconds=2) if op=='apdex.import' else {}))

    def program(self,source,bindings,scope):return operations.run(self.state,self.req('code.execute',dict(program=source,bindings=bindings,scope=scope)))

    def test_missing_pair_is_rejected_before_managed_child_and_original_access(self):
        for operation in ('jr.import','os.import','apdex.import'):
            for missing in ('input_plan','members'):
                args=self.arguments(operation);args.pop(missing)
                with self.subTest(operation=operation,missing=missing),patch('src.techexpert.operation_process.run',side_effect=AssertionError('Invalid pair launched a worker')):
                    with self.assertRaises(InputError):operations.run(self.state,self.req(operation,args))

    def test_three_managed_imports_keep_parent_plan_and_replay_after_original_is_gone(self):
        saved=[]
        for op in ('jr.import','os.import','apdex.import'):
            request=self.req(op,self.arguments(op));result=operations.run(self.state,request)
            self.assertEqual(result['status'],'succeeded',result);self.assertEqual(len(result['snapshots']),2)
            self.assertIn(self.pid,{s['id'] for s in result['snapshots']});saved.append((request,result))
        self.archive.unlink()
        for request,first in saved:
            replay=operations.run(self.state,request);self.assertTrue(replay['replayed']);self.assertEqual(first['data'],replay['data'])
        (self.state/'artifacts'/self.pid/'report.json').write_bytes(b'changed catalogue')
        for _,first in saved:
            with self.assertRaises(InputError):operations.result(self.state,first['run_id'])

    def test_cli_invokes_selected_adapter_inside_measured_controller(self):
        path=self.root/'request.json';path.write_text(json.dumps(self.req('os.import',self.arguments('os.import'))),encoding='utf-8')
        run=subprocess.run([sys.executable,'-X','utf8',str(ROOT/'techexpert.py'),'--state-dir',str(self.state),'operation-run',str(path)],capture_output=True,timeout=30)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr);value=json.loads(run.stdout)
        self.assertEqual(value['data']['result']['missing_samples'],1);self.assertTrue(value['kernel_call_id']);self.assertEqual(len(value['snapshots']),2)

    def test_mcp_arguments_use_same_pair_validation_and_no_additional_tools(self):
        self.assertEqual(len(mcp_tools.tools()),40)
        for op in ('jr.import','os.import','apdex.import'):
            name='techexpert_'+op.replace('.','_');args=self.arguments(op)
            _,_,request=mcp_tools.prepare(name,dict(operation_key='sdk-selected',executor_id='harness',arguments=args));self.assertEqual(request['arguments']['members'],args['members'])
            args.pop('members')
            with self.assertRaises(InputError):mcp_tools.prepare(name,dict(operation_key='sdk-selected',executor_id='harness',arguments=args))

    def test_program_can_inspect_once_then_import_journal_os_and_apdex(self):
        source='''plan = api("input.inspect", settings)
jr = api("jr.import", {"path": original, "platform_version": "8.3.27.1989", "utc_offset": "+03:00", "input_plan": plan["data"]["artifact_id"], "members": jr_members})
os = api("os.import", {"measurements": original, "input_plan": plan["data"]["artifact_id"], "members": os_members})
quality = api("apdex.import", {"measurements": original, "input_plan": plan["data"]["artifact_id"], "members": apdex_members, "target_seconds": 2})
return {"jr": jr["data"]["result"]["event_count"], "gap": os["data"]["result"]["missing_samples"], "score": quality["data"]["result"]["score"]}'''
        scope=dict(operations=['input.inspect','jr.import','os.import','apdex.import'],intakes=[dict(settings=self.settings)],journals=[dict(path=str(self.archive),platform_version='8.3.27.1989',utc_offset='+03:00')],measurements=[str(self.archive)])
        bindings=dict(settings=self.settings,original=str(self.archive),jr_members=self.arguments('jr.import')['members'],os_members=self.arguments('os.import')['members'],apdex_members=self.arguments('apdex.import')['members'])
        request=self.req('code.execute',dict(program=source,scope=scope,bindings=bindings));first=operations.run(self.state,request)
        self.assertEqual(first['status'],'succeeded',first);self.assertEqual(first['data']['value'],dict(jr=5,gap=1,score=.75));self.assertEqual(len(first['snapshots']),4)
        self.archive.unlink();again=operations.run(self.state,request);self.assertTrue(again['replayed']);self.assertEqual(again['data'],first['data'])

    def test_unapproved_plan_or_journal_profile_is_denied_before_any_api_call(self):
        for op in ('jr.import','os.import','apdex.import'):
            args=self.arguments(op);field='journals' if op=='jr.import' else 'measurements';settings=[dict(path=str(self.archive),platform_version='8.3.27.1989',utc_offset='+03:00')] if field=='journals' else [str(self.archive)]
            result=self.program('return api("'+op+'", args)',dict(args=args),dict(operations=[op],**{field:settings}))
            self.assertEqual(result['data']['diagnostic']['code'],'scope_denied');self.assertEqual(result['data']['metrics']['calls_started'],0)
        args=self.arguments('jr.import');args['utc_offset']='+00:00'
        result=self.program('return api("jr.import", args)',dict(args=args),dict(operations=['jr.import'],artifacts=[self.pid],journals=[dict(path=str(self.archive),platform_version='8.3.27.1989',utc_offset='+03:00')]))
        self.assertEqual(result['data']['diagnostic']['code'],'scope_denied');self.assertEqual(result['data']['metrics']['calls_started'],0)

    def test_distinct_os_members_can_import_once_each_but_repetition_is_denied(self):
        args=self.arguments('os.import');second=dict(args,members=[self.ids['os-b.json']])
        result=self.program('first = api("os.import", one)\nsecond = api("os.import", two)\nreturn api("os.import", one)',dict(one=args,two=second),dict(operations=['os.import'],artifacts=[self.pid],measurements=[str(self.archive)]))
        self.assertEqual(result['data']['diagnostic']['code'],'scope_denied');self.assertEqual(result['data']['metrics']['calls_started'],2)
        self.assertEqual(len(list((self.state/'artifacts').iterdir())),3)

    def test_reordered_journal_selection_cannot_repeat_the_same_capture(self):
        args=self.arguments('jr.import');other=dict(args,members=list(reversed(args['members'])))
        result=self.program('first = api("jr.import", one)\nreturn api("jr.import", two)',dict(one=args,two=other),dict(operations=['jr.import'],artifacts=[self.pid],journals=[dict(path=str(self.archive),platform_version='8.3.27.1989',utc_offset='+03:00')]))
        self.assertEqual(result['data']['diagnostic']['code'],'scope_denied');self.assertEqual(result['data']['metrics']['calls_started'],1)

    def test_old_plain_requests_do_not_acquire_new_default_selection_fields(self):
        for op,args in (('jr.import',dict(path=str(FIXTURE),platform_version='8.3.27.1989')),('os.import',dict(measurements='plain.json')),('apdex.import',dict(measurements='plain.json',target_seconds=2))):
            normalized=capabilities.normalize_request(self.req(op,args));self.assertNotIn('input_plan',normalized['arguments']);self.assertNotIn('members',normalized['arguments'])

    def test_first_output_cannot_pin_a_different_parent_than_the_one_captured(self):
        args=self.arguments('os.import');output=self.root/'output';data,_=capabilities.execute('os.import',args,self.state,output)
        self.assertEqual(len(operations._snapshots(self.state,'os.import',args,data,output=output)),2)
        folder=self.state/'artifacts'/self.pid;report=json.loads((folder/'report.json').read_text(encoding='utf-8'));report['result']['identity_scope']='Changed after capture'
        write_json(folder/'report.json',report);receipt=json.loads((folder/'receipt.json').read_text());receipt['report_sha256']=hashlib.sha256((folder/'report.json').read_bytes()).hexdigest();write_json(folder/'receipt.json',receipt)
        with self.assertRaises(InputError):operations._snapshots(self.state,'os.import',args,data,output=output)

if __name__=='__main__':unittest.main()
