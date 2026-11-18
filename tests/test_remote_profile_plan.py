"""Profile-derived SFTP plans pin exact private investigation configuration."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from src.techexpert import capabilities,investigations,operations,profiles,operation_state as fs
from src.techexpert.inputs import InputError
from test_profile_ssh import graph


class RemoteProfilePlanTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.state=self.root/'state';self.known=self.root/'known_hosts'
        self.known.write_bytes(b'logs.invalid ssh-ed25519 SYNTHETIC\n')
        value=graph();value['connections'][0]['settings']['known_hosts_file']=str(self.known)
        self.profile=profiles.save_profile(self.state,value,expected_revision=0)
        self.inv=investigations.create(self.state,dict(task='Selected diagnostic sources'))
        self.args=dict(investigation_id=self.inv['investigation_id'],revision=1,source_ids=['tj','jr'],max_connections=4,max_protocol_bytes=1048576,max_retained_bytes=65536)

    def request(self,operation,args,key):return dict(schema_version=1,operation_key=key,executor_id='profile-qa',operation=operation,arguments=args)

    def test_exact_profile_plan_is_offline_pinned_and_replays_after_current_profile_changes(self):
        self.assertIn('remote.profile_plan',capabilities.CODE_API)
        request=self.request('remote.profile_plan',self.args,'profile-plan')
        first=operations.run(self.state,request);self.assertEqual(first['status'],'succeeded',first)
        result=first['data']['result'];binding=result['profile_binding']
        self.assertEqual(binding['profile_revision'],1);self.assertEqual(binding['profile_sha256'],self.inv['profile_sha256'])
        self.assertEqual(binding['source_ids'],['tj','jr'])
        self.assertEqual([s['connection']['root'] for s in result['settings']['sources']],['/var/log/onec/tj','/var/log/onec/jr-a'])
        self.assertFalse(result['network_started']);self.assertFalse((self.state/'remote-budgets').exists())
        changed=deepcopy(self.profile);changed['connections'][0]['address']='reader@replacement.invalid'
        profiles.save_profile(self.state,changed,expected_revision=1);self.known.unlink()
        again=operations.run(self.state,request);self.assertTrue(again['replayed']);self.assertEqual(again['data'],first['data'])
        self.assertEqual(investigations.load(self.state,self.inv['investigation_id'],revision=1)['profile_snapshot'],self.profile)

    def test_selected_source_must_exist_and_have_a_supported_journal_transport(self):
        for ids in (['missing'],['os'],['tj','tj']):
            with self.subTest(ids=ids):
                try:result=operations.run(self.state,self.request('remote.profile_plan',dict(self.args,source_ids=ids),'reject-'+str(len(ids))+'-'+ids[0]))
                except InputError:continue
                self.assertEqual(result['status'],'invalid_input',result)
        self.assertFalse((self.state/'remote-budgets').exists())

    def test_same_configured_root_is_transferred_once_and_keeps_both_parser_bindings(self):
        value=deepcopy(self.profile);value['sources'][1]['path']=value['sources'][0]['path']
        profiles.save_profile(self.state,value,expected_revision=1)
        inv=investigations.create(self.state,dict(task='Shared configured root'))
        first=operations.run(self.state,self.request('remote.profile_plan',dict(self.args,investigation_id=inv['investigation_id']),'shared-root'))
        self.assertEqual(first['status'],'succeeded',first)
        result=first['data']['result'];self.assertEqual(len(result['settings']['sources']),1)
        bindings=result['profile_binding']['sources'];self.assertEqual(len(bindings),2)
        self.assertEqual(bindings[0]['plan_source_id'],bindings[1]['plan_source_id'])

    def test_program_needs_the_exact_profile_plan_and_retains_its_products(self):
        program='p=api("remote.profile_plan", selected)\nreturn api("artifact.show", {"artifact_id":p["data"]["artifact_id"]})["data"]["result"]["network_started"]'
        for allowed in (False,True):
            scope=dict(operations=['remote.profile_plan','artifact.show'],remote_profile_plans=[dict(settings=self.args,max_runs=1)] if allowed else [])
            result=operations.run(self.state,self.request('code.execute',dict(program=program,bindings=dict(selected=self.args),scope=scope),'profile-program-'+str(allowed)))
            if allowed:self.assertEqual(result['status'],'succeeded',result);self.assertIs(result['data']['value'],False)
            else:self.assertEqual(result['data']['metrics']['calls_started'],0)

    def test_replay_refuses_changed_retained_investigation_profile(self):
        first=operations.run(self.state,self.request('remote.profile_plan',self.args,'corrupt-parent'));self.assertEqual(first['status'],'succeeded',first)
        path=investigations.revision_folder(self.state,self.inv['investigation_id'],1)/'report.json'
        self.assertTrue(path.exists())
        path.write_bytes(b'{}')
        with self.assertRaises(InputError):operations.result(self.state,first['run_id'])

    def test_other_context_or_missing_pinned_profile_cannot_select_current_environment(self):
        other=investigations.create(self.state,dict(task='Other investigation'))
        request=self.request('remote.profile_plan',self.args,'other-context')
        request['context']=dict(investigation_id=other['investigation_id'],expected_revision=1)
        self.assertEqual(operations.run(self.state,request)['status'],'invalid_input')
        empty=self.root/'without-profile';missing=investigations.create(empty,dict(task='Not configured'))
        result=operations.run(empty,self.request('remote.profile_plan',dict(self.args,investigation_id=missing['investigation_id']),'missing-snapshot'))
        self.assertEqual(result['status'],'invalid_input',result)
        self.assertFalse((empty/'remote-budgets').exists())


if __name__=='__main__':unittest.main()
