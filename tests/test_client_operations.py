"""Client data follows the same sealed CLI, MCP and programme boundaries."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import capabilities,operations,mcp_tools
from src.techexpert.inputs import InputError
from test_client_episode import document


class ClientOperationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.state=self.root/'state'
        self.trace=self.root/'trace.json'
        self.trace.write_text(json.dumps(document('manual'),ensure_ascii=False),encoding='utf-8')
        self.live=dict(endpoint=dict(port=62353,pid=170471,lifetime='134131874954012300'),
                       python=str(self.root/'python.exe'),database_mode='file')

    def req(self,operation,arguments,key='client-operation'):
        return dict(schema_version=1,operation_key=key,executor_id='tests',operation=operation,arguments=arguments)

    def programme(self,program,scope,bindings,key):
        return operations.run(self.state,self.req('code.execute',dict(program=program,scope=scope,bindings=bindings),key))

    def test_managed_client_import_replays_and_checks_its_snapshot(self):
        request=self.req('client.import',dict(path=str(self.trace)))
        result=operations.run(self.state,request)
        self.assertEqual(result['status'],'succeeded')
        self.assertIsNotNone(result['data']['result']['durations_seconds']['reported_wall_clock'])
        identifier=result['data']['artifact_id']
        self.trace.unlink()
        replay=operations.run(self.state,request)
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['data'],result['data'])
        (self.state/'artifacts'/identifier/'sources/s1.bin').write_bytes(b'changed')
        with self.assertRaises(InputError):
            operations.result(self.state,result['run_id'])

    def test_navigation_without_exact_grant_is_rejected_before_any_api_start(self):
        approved=dict(self.live)
        args=dict(self.live,navigation=dict(link='e1cib/list/Документ.Sales',ready_form='Документ.Sales.ФормаСписка'))
        result=self.programme('return api("client.observe", args)',
            dict(operations=['client.observe'],testpilot=[dict(settings=approved)]),dict(args=args),'denied-navigation')
        self.assertEqual(result['data']['diagnostic']['code'],'scope_denied')
        self.assertEqual(result['data']['metrics']['calls_started'],0)

    def test_exact_configured_import_is_allowed_and_retained_as_programme_product(self):
        source='one = api("client.import", args)\nreturn api("artifact.show", {"artifact_id": one["data"]["artifact_id"]})["data"]["result"]["ready_basis"]'
        args=dict(path=str(self.trace))
        result=self.programme(source,dict(operations=['client.import','artifact.show'],client_episodes=[str(self.trace)]),dict(args=args),'episode')
        self.assertEqual(result['data']['value'],'operator_reported_marker',result)
        self.assertEqual(result['data']['metrics']['calls_started'],2)
        self.assertEqual(len(result['snapshots']),1)

    def test_a_program_cannot_repeat_an_approved_navigation_via_another_grant(self):
        from src.techexpert.code_policy import Scope
        from src.techexpert.code_values import CodeError
        first=dict(self.live,navigation=dict(link='e1cib/list/Документ.Sales',ready_form='Документ.Sales.ФормаСписка'))
        second=dict(self.live,navigation=dict(link='e1cib/list/Документ.Other',ready_form='Документ.Other.ФормаСписка'))
        scope=dict(operations=['client.observe'],testpilot=[dict(settings=first,max_calls=5),dict(settings=second)])
        normalized=capabilities.normalize_request(self.req('code.execute',dict(program='return None',scope=scope)))['arguments']['scope']
        authorization=Scope(normalized,('client.observe',))
        approved=normalized['testpilot']
        authorization.authorize('client.observe',approved[0]['settings'])
        for grant in approved:
            with self.assertRaisesRegex(CodeError,'One TestClient navigation'):
                authorization.authorize('client.observe',grant['settings'])

    def test_transport_schema_is_passive_and_has_no_arbitrary_target_fields(self):
        with patch('src.techexpert.testpilot_capture.inspect_endpoint',side_effect=AssertionError('discovery accessed endpoint')):
            routes=capabilities.ROUTES
            self.assertIn('client.observe',routes)
            self.assertIn('client.import',routes)
            tools={tool['title']:tool for tool in mcp_tools.tools()}
            self.assertFalse(tools['client.observe']['annotations']['readOnlyHint'])
            self.assertTrue(tools['client.observe']['annotations']['destructiveHint'])
            capabilities.normalize_request(self.req('client.observe',self.live))
        for extra in ('command','host','password'):
            with self.subTest(extra=extra),self.assertRaises(InputError):
                capabilities.normalize_request(self.req('client.observe',dict(self.live,**{extra:'unsupported'})))


if __name__=='__main__':unittest.main()
