"""SQLServer admission, exact history grants and sealed offline replay."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from src.techexpert import capabilities as cap,operations,mcp_tools
from src.techexpert.inputs import InputError
from test_sqlserver import WINDOW


class SQLServerOperationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.state=Path(self.temp.name)/'state';self.n=0
        self.settings=dict(database='diag',host='host.invalid',executable=str(Path(self.temp.name)/'missing-sqlcmd'))
    def request(self,op,args):
        self.n+=1;return dict(schema_version=1,operation_key='sqlserver-'+str(self.n),executor_id='tests',operation=op,arguments=args)
    def test_passive_catalogue_uses_one_api_and_shared_schemas(self):
        self.assertIn('sqlserver.observe',cap.ROUTES)
        self.assertEqual(len(mcp_tools.tools()),48)
        self.assertIn('query_store',cap.ROUTES['sqlserver.observe']['input_schema']['properties']['query']['enum'])
        with patch('src.techexpert.sqlserver.run_bounded',side_effect=AssertionError('schema must be passive')):
            value=cap.normalize_request(self.request('sqlserver.observe',dict(self.settings,query='query_store',window=WINDOW)))
        self.assertEqual(value['arguments']['window']['start'],'2026-11-18T06:00:00+00:00')
    def test_invalid_query_window_or_connection_is_rejected_before_worker(self):
        for change in (dict(query='arbitrary'),dict(query='query_store'),dict(window=WINDOW),dict(host='-Sbad'),dict(password='private')):
            args=dict(self.settings,query='requests');args.update(change)
            with self.subTest(change=change),patch('src.techexpert.operation_process.run',side_effect=AssertionError('invalid request launched worker')):
                with self.assertRaises(ValueError):operations.run(self.state,self.request('sqlserver.observe',args))
    def test_unavailable_managed_observation_is_retained_and_replayed_without_client(self):
        request=self.request('sqlserver.observe',dict(self.settings,query='requests'));first=operations.run(self.state,request)
        self.assertEqual(first['status'],'partial',first);self.assertIsNone(first['data']['result']['rows'])
        with patch('src.techexpert.operation_process.run',side_effect=AssertionError('replay must not launch')):
            again=operations.run(self.state,request)
        self.assertTrue(again['replayed']);self.assertEqual(first['data'],again['data'])
        folder=self.state/'artifacts'/first['data']['artifact_id'];(folder/'sources/s1.bin').write_bytes(b'changed')
        with self.assertRaises(InputError):operations.result(self.state,first['run_id'])
    def program(self,args,profile,source=None):
        scope=dict(operations=['sqlserver.observe','artifact.show'],sqlserver=[profile])
        return operations.run(self.state,self.request('code.execute',dict(program=source or 'return api("sqlserver.observe", args)',bindings=dict(args=args),scope=scope)))
    def test_query_store_needs_exact_approved_window_not_merely_query_permission(self):
        args=dict(self.settings,query='query_store',window=WINDOW)
        for profile in (dict(settings=self.settings,queries=['query_store']),
                        dict(settings=self.settings,queries=['query_store'],windows=[dict(WINDOW,end='2026-11-18T10:00:00+03:00')])):
            value=self.program(args,profile)
            self.assertEqual(value['data']['diagnostic']['code'],'scope_denied',value)
            self.assertEqual(value['data']['metrics']['calls_started'],0)
    def test_approved_window_produces_readable_artifact_and_repetition_is_bounded(self):
        args=dict(self.settings,query='query_store',window=WINDOW)
        profile=dict(settings=self.settings,queries=['query_store'],windows=[WINDOW],max_calls=1)
        source='first = api("sqlserver.observe", args)\nsaved = api("artifact.show", {"artifact_id": first["data"]["artifact_id"]})\nreturn saved["data"]["result"]["rows"]'
        first=self.program(args,profile,source)
        self.assertEqual(first['status'],'partial',first);self.assertIsNone(first['data']['value'])
        self.assertEqual(first['data']['execution_status'],'succeeded')
        repeat=self.program(args,profile,'one = api("sqlserver.observe", args)\nreturn api("sqlserver.observe", args)')
        self.assertEqual(repeat['data']['diagnostic']['code'],'scope_denied',repeat)
        self.assertEqual(repeat['data']['metrics']['calls_started'],1)
    def test_public_sql_excerpt_omits_statement_literals_and_private_sql_names(self):
        import json
        from test_incident_drafts import IncidentDraftTests
        from src.techexpert.artifacts import save_artifact
        from src.techexpert.investigations import revise
        from src.techexpert import incident_drafts
        inv=IncidentDraftTests().investigation(self.state)
        meta=dict(server_name='PrivateSqlHost',machine_name='PrivateMachine',instance_name='PrivateInstance',login_name='PrivateLogin')
        doc=dict(metadata=meta,rows=[dict(batch_text="SELECT customer FROM private_table WHERE name=N'PrivateCustomer'",program_name='PrivateApplication')])
        report=save_artifact(self.state,'sqlserver',{},[('sqlserver-response.json',json.dumps(doc).encode())],doc)
        attachment=dict(id='A-SQL',kind='artifact',target_id=report['artifact_id'])
        inv=revise(self.state,inv['investigation_id'],dict(attachments=inv['attachments']+[attachment],
            evidence=inv['evidence']+[dict(id='E-SQL',attachment='A-SQL',record='s1')]),expected_revision=2)
        preview=incident_drafts.prepare(self.state,inv['investigation_id'],evidence_ids=['E-SQL']);text=json.dumps(preview)
        for value in (*meta.values(),'PrivateApplication','PrivateCustomer','private_table'):
            self.assertNotIn(value,text)


if __name__=='__main__':unittest.main()
