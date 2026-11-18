"""Finite managed remote operations, replay and explicit resource/network scopes."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from src.techexpert import artifacts,capabilities,investigations,mcp_tools,operations,operation_state as fs
from src.techexpert.inputs import InputError
from test_remote_budget import settings
from test_remote_intake import capture
from test_sc01 import SCOPE


class RemoteOperationTests(unittest.TestCase):
    def setUp(self):
        self.assertIn('remote.plan',capabilities.CODE_API)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.state=self.root/'state'
        inv=investigations.create(self.state,dict(task='Remote observations'))
        self.args=dict(settings(self.root),investigation_id=inv['investigation_id'])
        self.args['sources'][0]['connection'].update(host='reader@127.0.0.1',port=9)

    def request(self,operation,args,key):return dict(schema_version=1,operation_key=key,executor_id='fixture',operation=operation,arguments=args)

    def plan(self):
        result=operations.run(self.state,self.request('remote.plan',self.args,'remote-plan'))
        self.assertEqual(result['status'],'succeeded',result);return result

    def test_offline_plan_replays_after_trust_input_removed_and_preserves_investigation(self):
        first=self.plan();self.assertEqual(len(first['snapshots']),2)
        Path(self.args['sources'][0]['connection']['known_hosts_file']).unlink()
        replay=operations.run(self.state,self.request('remote.plan',self.args,'remote-plan'))
        self.assertTrue(replay['replayed']);self.assertEqual(first['data'],replay['data'])
        self.assertFalse((self.state/'remote-budgets').exists())

    def test_failed_real_client_call_is_retained_and_same_key_never_reconnects(self):
        plan=self.plan()['data']['artifact_id']
        args=dict(plan_id=plan,source_id='tj',protocol_bytes=16384,timeout_seconds=1)
        request=self.request('remote.inspect',args,'remote-denied')
        result=operations.run(self.state,request)
        self.assertEqual(result['status'],'partial',result)
        self.assertEqual(result['data']['sources'],[])
        self.assertFalse(result['data']['result']['listing_complete'])
        replay=operations.run(self.state,request)
        self.assertTrue(replay['replayed']);self.assertEqual(replay['data'],result['data'])
        charges=list((self.state/'remote-budgets'/self.args['investigation_id']/'charges').glob('*.json'))
        self.assertEqual(len(charges),1)

    def test_remote_parse_is_scoped_to_retained_capture_and_pins_source_bytes(self):
        rows=[dict(kind=k,timestamp=t,scope=SCOPE) for k,t in [('started','2026-11-18T00:00:00Z'),('finished','2026-11-18T00:00:02Z')]]
        parent=capture(self.state,[('events.jsonl',''.join(json.dumps(r)+'\n' for r in rows).encode())])
        args=dict(capture_id=parent['artifact_id'],adapter='case',settings=dict(manifest=dict(schema=1,scenario='SC-01',origin='synthetic',selection=SCOPE,sources=[dict(path='m1',format='normalized-events-v1')])))
        program='p=api("remote.parse", selected)\nreturn api("case.show", {"case_id":p["data"]["case_id"]})["data"]["durations_seconds"]["execution"]'
        for granted in (False,True):
            scope=dict(operations=['remote.parse','case.show'],artifacts=[parent['artifact_id']] if granted else [])
            result=operations.run(self.state,self.request('code.execute',dict(program=program,bindings=dict(selected=args),scope=scope),'remote-parser-'+str(granted)))
            if granted:
                self.assertEqual(result['status'],'succeeded',result);self.assertEqual(result['data']['value'],2)
                self.assertEqual(len(result['snapshots']),2)
            else:self.assertEqual(result['data']['metrics']['calls_started'],0)
        path=artifacts.artifact_folder(self.state,parent['artifact_id'])/'sources/s1.bin';path.write_bytes(b'bad')
        with self.assertRaises(InputError):operations.result(self.state,result['run_id'])

    def test_program_network_calls_need_exact_plan_source_and_sum_reservation(self):
        plan=self.plan()['data']['artifact_id']
        args=dict(plan_id=plan,source_id='tj',protocol_bytes=16384,timeout_seconds=1)
        program='api("remote.inspect", selected)\nreturn api("remote.inspect", selected)'
        scope=dict(operations=['remote.inspect'],artifacts=[plan],remote_calls=[dict(plan_id=plan,source_id='tj',max_calls=1,max_protocol_bytes=16384,max_retained_bytes=1000,max_timeout_seconds=1)])
        result=operations.run(self.state,self.request('code.execute',dict(program=program,bindings=dict(selected=args),scope=scope),'remote-program-limit'))
        self.assertEqual(result['data']['metrics']['calls_started'],1)
        self.assertEqual(result['data']['diagnostic']['code'],'scope_denied')

    def test_transfer_cannot_silently_switch_investigation_context(self):
        plan=self.plan()['data']['artifact_id']
        other=investigations.create(self.state,dict(task='Different investigation'))
        request=self.request('remote.inspect',dict(plan_id=plan,source_id='tj',protocol_bytes=16384,timeout_seconds=1),'wrong-investigation')
        request['context']=dict(investigation_id=other['investigation_id'],expected_revision=1)
        result=operations.run(self.state,request)
        self.assertEqual(result['status'],'invalid_input',result)
        self.assertFalse((self.state/'remote-budgets').exists())

    def test_new_mcp_tools_are_real_finite_operations_and_passive_discovery(self):
        self.assertEqual(len(capabilities.BASE_API),13)
        names={t['name'] for t in mcp_tools.tools()}
        self.assertTrue({'techexpert_remote_plan','techexpert_remote_inspect','techexpert_remote_capture','techexpert_remote_parse'}<=names)
        self.assertFalse((self.state/'remote-budgets').exists())
        with self.assertRaises(InputError):capabilities.normalize_request(self.request('remote.inspect',dict(plan_id='a'*32,source_id='tj',command='whoami'),'invalid-command'))


if __name__=='__main__':unittest.main()
