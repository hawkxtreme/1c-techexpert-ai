"""Selected infobase metadata stays scoped and cannot become another RAC action."""
from pathlib import Path
import json
import tempfile
import unittest

from src.techexpert import capabilities as cap
from src.techexpert import rac
from src.techexpert.code_policy import Scope
from src.techexpert.inputs import InputError

CLUSTER='11111111-1111-1111-1111-111111111111'
INFOBASE='22222222-2222-2222-2222-222222222222'
OTHER='33333333-3333-3333-3333-333333333333'


class InfobaseInfoTests(unittest.TestCase):
    def request(self,**args):
        return cap.normalize_request(dict(schema_version=1,operation_key='rac-info-test',executor_id='test',operation='rac.observe',arguments=dict(endpoint='ras.invalid:1545',**args)))

    def scope(self,selected):
        arguments=dict(program='return None',scope=dict(operations=['rac.observe'],rac=[dict(settings=dict(endpoint='ras.invalid:1545'),queries=['infobase_info'],clusters=[CLUSTER],infobases=selected,max_calls=2)]))
        request=cap.normalize_request(dict(schema_version=1,operation_key='info-program',executor_id='test',operation='code.execute',arguments=arguments))
        return Scope(request['arguments']['scope'],cap.CODE_API)

    def test_selected_info_command_is_fixed_and_requires_both_scoped_uuids(self):
        client=rac.RacClient('ras.invalid:1545')
        self.assertEqual(client.command('infobase_info',cluster=CLUSTER,infobase=INFOBASE),['rac','infobase','info','--cluster='+CLUSTER,'--infobase='+INFOBASE,'ras.invalid:1545'])
        for operation,cluster,infobase in [('infobase_info',None,INFOBASE),('infobase_info',CLUSTER,None),('sessions',CLUSTER,INFOBASE),('clusters',None,INFOBASE),('infobase_info',CLUSTER,'--db-pwd=private-secret')]:
            with self.subTest(operation=operation,infobase=infobase),self.assertRaises(InputError):client.command(operation,cluster=cluster,infobase=infobase)

    def test_invalid_info_selection_is_rejected_at_admission_without_state(self):
        request=self.request(query='infobase_info',cluster=CLUSTER,infobase=INFOBASE)
        self.assertEqual(request['arguments']['infobase'],INFOBASE)
        for args in (dict(query='infobase_info',cluster=CLUSTER),dict(query='sessions',cluster=CLUSTER,infobase=INFOBASE),dict(query='infobase_info',cluster=CLUSTER,infobase='private-secret')):
            with self.subTest(args=args),self.assertRaises(InputError):self.request(**args)

    def test_program_cannot_read_an_unselected_infobase_or_another_cluster(self):
        args=self.request(query='infobase_info',cluster=CLUSTER,infobase=INFOBASE)['arguments'];policy=self.scope([INFOBASE])
        with self.assertRaises(ValueError):policy.authorize('rac.observe',dict(args,infobase=OTHER))
        with self.assertRaises(ValueError):policy.authorize('rac.observe',dict(args,cluster=OTHER))
        policy.authorize('rac.observe',args)
        with self.assertRaises(ValueError):self.scope([]).authorize('rac.observe',args)

    def test_info_snapshot_retains_requested_identity_without_historical_ownership(self):
        class Fake(rac.RacClient):
            def execute(self,operation,cluster=None,**kwargs):
                self.command(operation,cluster=cluster,infobase=kwargs.get('infobase'))
                return 'infobase : '+INFOBASE+'\nname : orders\ndbms : PostgreSQL\ndb-server : db.invalid\ndb-name : orders_sql\n'
        with tempfile.TemporaryDirectory() as temp:
            report=rac.collect_rac(Path(temp),Fake('ras.invalid:1545'),'infobase_info',cluster=CLUSTER,infobase=INFOBASE)
            request=json.loads((Path(temp)/'artifacts'/report['artifact_id']/'request.json').read_text(encoding='utf-8'))
            self.assertEqual(request['infobase'],INFOBASE)
            self.assertEqual(report['result']['status'],'observed');self.assertEqual(report['result']['rows'][0]['db-name'],'orders_sql')
            self.assertFalse(report['result']['historical_identity_established'])

    def test_info_response_for_another_infobase_is_unavailable_not_an_observation(self):
        class Wrong(rac.RacClient):
            def execute(self,*args,**kwargs):return 'infobase : '+OTHER+'\nname : orders\n'
        with tempfile.TemporaryDirectory() as temp:
            report=rac.collect_rac(temp,Wrong('ras.invalid:1545'),'infobase_info',cluster=CLUSTER,infobase=INFOBASE)
            self.assertEqual(report['result']['status'],'unavailable');self.assertIsNone(report['result']['rows'])

    def test_info_retains_only_needed_metadata_and_never_access_secrets(self):
        class Sensitive(rac.RacClient):
            def execute(self,*args,**kwargs):return 'infobase : '+INFOBASE+'\nname : orders\ndbms : PostgreSQL\ndb-user : private-admin\ndb-pwd : private-password\npermission-code : private-bypass-code\n'
        with tempfile.TemporaryDirectory() as temp:
            report=rac.collect_rac(temp,Sensitive('ras.invalid:1545'),'infobase_info',cluster=CLUSTER,infobase=INFOBASE)
            data=(Path(temp)/'artifacts'/report['artifact_id']/'sources/s1.bin').read_text(encoding='utf-8')
            for private in ('private-admin','private-password','private-bypass-code'):
                self.assertNotIn(private,str(report));self.assertNotIn(private,data)
            self.assertEqual(report['result']['evidence_projection'],'selected_infobase_metadata_fields')

    def test_legacy_program_scope_defaults_keep_saved_request_semantics(self):
        arguments=dict(program='return None',scope=dict(operations=['rac.observe'],rac=[dict(settings=dict(endpoint='ras.invalid:1545'),queries=['sessions'],clusters=[CLUSTER])]))
        request=cap.normalize_request(dict(schema_version=1,operation_key='legacy-scope',executor_id='test',operation='code.execute',arguments=arguments))
        profile=request['arguments']['scope']['rac'][0]
        self.assertNotIn('infobases',profile);self.assertEqual(profile['max_calls'],6)

    def test_cancelled_info_does_not_retain_raw_partial_credentials(self):
        from src.techexpert.processes import CommandStopped
        class Cancelled(rac.RacClient):
            def execute(self,*args,**kwargs):raise CommandStopped('cancelled',stdout=b'db-pwd : private-password',returncode=-9,process_started=True)
        with tempfile.TemporaryDirectory() as temp:
            report=rac.collect_rac(temp,Cancelled('ras.invalid:1545'),'infobase_info',cluster=CLUSTER,infobase=INFOBASE)
            source=(Path(temp)/'artifacts'/report['artifact_id']/'sources/s1.bin').read_bytes()
            self.assertNotIn(b'private-password',source);self.assertIsNone(report['result']['rows'])
            self.assertEqual(report['result']['status'],'cancelled')
