"""One finite input preview shared by managed CLI, MCP and scoped programs."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from src.techexpert import capabilities,operations,mcp_tools
from src.techexpert.inputs import InputError
from test_input_intake import ROW,PROFILE


class InputIntakeOperationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.state=self.root/'state';self.number=0
        self.zip=self.root/'данные.zip'
        with zipfile.ZipFile(self.zip,'w',compression=zipfile.ZIP_DEFLATED) as z:z.writestr('26111609.log',ROW)
        self.settings=dict(inputs=[dict(path=str(self.zip),kind='zip')])
        self.manifest=self.root/'selected.json';self.manifest.write_text(json.dumps(dict(schema=1,scenario='SC-01',origin='provided',selection={k:'reported' for k in ('database','node','process','epoch','run')},sources=[dict(PROFILE,path='m1')])),encoding='utf-8')

    def request(self,op,args,key=None):
        self.number+=1;return dict(schema_version=1,operation_key=key or 'intake-'+str(self.number),executor_id='test-harness',operation=op,arguments=args)

    def run_op(self,op,args,key=None):return operations.run(self.state,self.request(op,args,key))

    def test_finite_catalogue_and_mcp_declare_real_inspection_and_optional_plan(self):
        self.assertIn('input.inspect',capabilities.CODE_API)
        tool=next(t for t in mcp_tools.tools() if t['title']=='input.inspect')
        self.assertFalse(tool['annotations']['readOnlyHint']);self.assertTrue(tool['annotations']['openWorldHint'])
        self.assertIn('input_plan',capabilities.ROUTES['case.analyze']['input_schema']['properties'])

    def test_managed_preview_and_import_replay_without_original_or_duplicate_case(self):
        request=self.request('input.inspect',self.settings,'preview');plan=operations.run(self.state,request);self.assertEqual(plan['status'],'succeeded',plan)
        before=self.zip.read_bytes();replayed=operations.run(self.state,request);self.assertTrue(replayed['replayed']);self.assertEqual(plan['data'],replayed['data'])
        args=dict(manifest=str(self.manifest),input_plan=plan['data']['artifact_id']);request=self.request('case.analyze',args,'selected-import')
        case=operations.run(self.state,request);self.assertEqual(case['status'],'succeeded',case)
        self.assertEqual(self.zip.read_bytes(),before);self.zip.unlink();self.manifest.unlink()
        replay=operations.run(self.state,request);self.assertTrue(replay['replayed']);self.assertEqual(case['data'],replay['data']);self.assertEqual(len(list((self.state/'cases').iterdir())),1)
        self.assertEqual({s['kind'] for s in case['snapshots']},{'cases','artifacts'})
        saved=self.state/'artifacts'/plan['data']['artifact_id']/'report.json';saved.write_bytes(b'changed plan')
        with self.assertRaises(InputError):operations.result(self.state,case['run_id'])

    def test_mcp_normalization_rejects_unknown_inspection_fields_before_state(self):
        action,_,req=mcp_tools.prepare('techexpert_input_inspect',dict(operation_key='p',executor_id='h',arguments=self.settings))
        self.assertEqual(action,'run');self.assertEqual(req['operation'],'input.inspect');self.assertFalse(self.state.exists())
        with self.assertRaises(InputError):mcp_tools.prepare('techexpert_input_inspect',dict(operation_key='p',executor_id='h',arguments=dict(self.settings,extract_all=True)))

    def test_scoped_program_can_preview_then_analyze_and_replay_both_products(self):
        program='plan = api("input.inspect", selected)\ncase = api("case.analyze", {"manifest": manifest, "input_plan": plan["data"]["artifact_id"]})\nreturn {"case_id": case["data"]["case_id"], "members": plan["data"]["result"]["file_count"]}'
        args=dict(program=program,bindings=dict(selected=self.settings,manifest=str(self.manifest)),scope=dict(operations=['input.inspect','case.analyze'],intakes=[dict(settings=self.settings)],manifests=[str(self.manifest)]))
        request=self.request('code.execute',args,'program');result=operations.run(self.state,request);self.assertEqual(result['status'],'succeeded',result)
        self.assertEqual(result['data']['value']['members'],1);self.assertEqual(len(result['data']['calls']),2);self.assertEqual(len(result['snapshots']),2)
        self.zip.unlink();self.manifest.unlink();replay=operations.run(self.state,request);self.assertTrue(replay['replayed']);self.assertEqual(result['data'],replay['data'])

    def test_program_cannot_inspect_other_path_or_use_unapproved_plan(self):
        plan=self.run_op('input.inspect',self.settings)['data']['artifact_id']
        args=dict(program='return api("case.analyze", {"manifest": manifest, "input_plan": plan})',bindings=dict(manifest=str(self.manifest),plan=plan),scope=dict(operations=['case.analyze'],manifests=[str(self.manifest)]))
        result=self.run_op('code.execute',args);self.assertEqual(result['data']['execution_status'],'invalid_input');self.assertFalse((self.state/'cases').exists())
        self.assertEqual(result['data']['diagnostic']['code'],'scope_denied');self.assertEqual(result['data']['metrics']['calls_started'],0)
        other=dict(inputs=[dict(path=str(self.root/'other.zip'),kind='zip')])
        args=dict(program='return api("input.inspect", other)',bindings=dict(other=other),scope=dict(operations=['input.inspect'],intakes=[dict(settings=self.settings)]))
        result=self.run_op('code.execute',args);self.assertEqual(result['data']['execution_status'],'invalid_input')
        self.assertEqual(result['data']['diagnostic']['code'],'scope_denied');self.assertEqual(result['data']['metrics']['calls_started'],0)

    def test_program_inspection_repeat_limit_keeps_first_product_without_second_read(self):
        args=dict(program='first = api("input.inspect", selected)\nreturn api("input.inspect", selected)',bindings=dict(selected=self.settings),scope=dict(operations=['input.inspect'],intakes=[dict(settings=self.settings)]))
        result=self.run_op('code.execute',args);self.assertEqual(result['data']['diagnostic']['code'],'scope_denied');self.assertEqual(result['data']['metrics']['calls_started'],1)
        self.assertEqual(len(list((self.state/'artifacts').iterdir())),1)

    def test_same_preview_key_does_not_refresh_changed_original(self):
        request=self.request('input.inspect',self.settings,'stable-preview');result=operations.run(self.state,request);self.zip.write_bytes(b'changed original')
        replay=operations.run(self.state,request);self.assertTrue(replay['replayed']);self.assertEqual(result['data'],replay['data'])

if __name__=='__main__':unittest.main()
