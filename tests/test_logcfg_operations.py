"""Offline collection setup uses the same bounded managed/API paths."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from src.techexpert import artifacts, capabilities, mcp_tools, operations
from src.techexpert.inputs import InputError
from test_logcfg import BASE,settings

ROOT=Path(__file__).resolve().parents[1]


class LogcfgOperationTests(unittest.TestCase):
    def setUp(self):
        self.assertIn('logcfg.prepare',capabilities.CODE_API)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.state=self.root/'state';self.input=self.root/'copy.xml';self.input.write_bytes(BASE)
        self.args=settings(self.input)

    def request(self,op='logcfg.prepare',args=None,key='cfg-prepare'):
        return dict(schema_version=1,operation_key=key,executor_id='fixture',operation=op,arguments=self.args if args is None else args)

    def test_managed_prepare_and_rollback_replay_without_originals_and_pin_parent(self):
        prepared=operations.run(self.state,self.request())
        self.assertEqual(prepared['status'],'succeeded',prepared)
        report=prepared['data']; folder=artifacts.artifact_folder(self.state,report['artifact_id'])
        self.input.write_bytes((folder/'sources/logcfg.xml').read_bytes().replace(b'create="false"',b'create="true"'))
        request=self.request('logcfg.rollback_plan',dict(current_file=str(self.input),proposal_id=report['artifact_id']),'cfg-rollback')
        rollback=operations.run(self.state,request)
        self.assertEqual(rollback['status'],'succeeded',rollback)
        self.assertEqual(len(rollback['snapshots']),2)
        self.input.unlink()
        self.assertTrue(operations.run(self.state,self.request())['replayed'])
        self.assertTrue(operations.run(self.state,request)['replayed'])
        (folder/'sources/logcfg.xml').write_bytes(b'corrupt')
        with self.assertRaises(InputError): operations.result(self.state,rollback['run_id'])

    def test_scoped_program_requires_exact_settings_and_parent_scope(self):
        normalized=capabilities.normalize_request(self.request())['arguments']
        for allowed in (False,True):
            settings_allowed=copy.deepcopy(normalized)
            if not allowed:settings_allowed['max_bytes']*=2
            scope=dict(operations=['logcfg.prepare','artifact.evidence','logcfg.rollback_plan'],
                logcfg_plans=[dict(settings=settings_allowed,max_runs=1)])
            program='p=api("logcfg.prepare", selected)\nreturn api("artifact.evidence", {"artifact_id":p["data"]["artifact_id"],"source_id":"s2"})'
            result=operations.run(self.state,self.request('code.execute',dict(program=program,bindings=dict(selected=normalized),scope=scope),'cfg-scope-'+str(allowed)))
            if allowed:
                self.assertEqual(result['status'],'succeeded',result)
                self.assertEqual(Path(result['data']['value']['data']['file_path']).name,'logcfg.xml')
            else:
                self.assertEqual(result['data']['metrics']['calls_started'],0)
                self.assertEqual(result['data']['diagnostic']['code'],'scope_denied')

    def test_scoped_rollback_needs_current_copy_grant_and_parent_id(self):
        prepared=operations.run(self.state,self.request())['data']
        self.input.write_bytes((artifacts.artifact_folder(self.state,prepared['artifact_id'])/'sources/logcfg.xml').read_bytes())
        args=dict(proposal_id=prepared['artifact_id'],current_file=str(self.input))
        program='return api("logcfg.rollback_plan", selected)'
        for grant in ('none','file','both'):
            scope=dict(operations=['logcfg.rollback_plan'],artifacts=[prepared['artifact_id']] if grant=='both' else [],
                logcfg_rollbacks=[dict(settings=args,max_runs=1)] if grant!='none' else [])
            result=operations.run(self.state,self.request('code.execute',dict(program=program,bindings=dict(selected=args),scope=scope),'cfg-rollscope-'+grant))
            self.assertEqual(result['data']['metrics']['calls_started'],1 if grant=='both' else 0)

    def test_repeat_within_program_is_refused(self):
        normalized=capabilities.normalize_request(self.request())['arguments']
        program='api("logcfg.prepare", selected)\nreturn api("logcfg.prepare", selected)'
        scope=dict(operations=['logcfg.prepare'],logcfg_plans=[dict(settings=normalized,max_runs=1)])
        result=operations.run(self.state,self.request('code.execute',dict(program=program,bindings=dict(selected=normalized),scope=scope),'cfg-repeat'))
        self.assertEqual(result['data']['metrics']['calls_started'],1)
        self.assertEqual(result['data']['diagnostic']['code'],'scope_denied')

    def test_parent_resealed_between_work_and_first_output_is_refused(self):
        prepared=operations.run(self.state,self.request())['data']
        folder=artifacts.artifact_folder(self.state,prepared['artifact_id'])
        self.input.write_bytes((folder/'sources/logcfg.xml').read_bytes())
        args=dict(proposal_id=prepared['artifact_id'],current_file=str(self.input))
        data,_=capabilities.execute('logcfg.rollback_plan',args,self.state,self.state)
        document=json.loads((folder/'report.json').read_text(encoding='utf-8')); document['note']='changed'
        artifacts.write_json(folder/'report.json',document)
        receipt=json.loads((folder/'receipt.json').read_text(encoding='utf-8'));receipt['report_sha256']=hashlib.sha256((folder/'report.json').read_bytes()).hexdigest()
        artifacts.write_json(folder/'receipt.json',receipt)
        with self.assertRaises(InputError):operations._snapshots(self.state,'logcfg.rollback_plan',args,data)

    def test_mcp_is_finite_and_reports_preparation_mutation_truthfully(self):
        self.assertEqual(len(capabilities.BASE_API),13)
        for name in ('logcfg.prepare','logcfg.rollback_plan'):
            tool=next(t for t in mcp_tools.tools() if t['name']=='techexpert_'+name.replace('.','_'))
            self.assertFalse(tool['annotations']['readOnlyHint'])
            self.assertFalse(tool['annotations']['destructiveHint'])
        tool=next(t for t in mcp_tools.tools() if t['name']=='techexpert_logcfg_prepare')
        _,_,request=mcp_tools.prepare(tool['name'],dict(operation_key='cfg-mcp',executor_id='fixture',arguments=self.args))
        self.assertEqual(request['arguments']['events'],sorted(self.args['events']))
        self.assertNotIn('logcfg.apply',capabilities.ROUTES)
        evidence_tool=next(t for t in mcp_tools.tools() if t['name']=='techexpert_artifact_evidence')
        self.assertEqual(evidence_tool['outputSchema']['properties']['data']['anyOf'][0]['properties']['file_path']['type'],'string')

    def test_bad_xml_is_partial_and_cli_uses_bounded_controller(self):
        self.input.write_bytes(b'<broken>')
        path=self.root/'request.json';path.write_text(json.dumps(self.request()),encoding='utf-8')
        result=subprocess.run([sys.executable,'-B','-X','utf8',str(ROOT/'techexpert.py'),'--state-dir',str(self.state),'operation-run',str(path)],capture_output=True,timeout=30)
        self.assertEqual(result.returncode,1,result.stderr)
        report=json.loads(result.stdout)
        self.assertEqual(report['status'],'partial',report)
        self.assertEqual(report['data']['result']['status'],'needs_review')
        self.assertTrue(report['kernel_call_id'])
