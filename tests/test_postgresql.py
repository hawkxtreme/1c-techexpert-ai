import importlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class PostgreSQLTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.postgresql'), 'PostgreSQL adapter is missing')
        self.api=importlib.import_module('src.techexpert.postgresql')

    def test_selected_port_is_passed_for_default_host_and_docker_socket(self):
        for container in (None,'test-postgresql'):
            with self.subTest(container=container):
                client=self.api.PsqlClient(database='ib',port=25432,docker_container=container)
                self.assertIn('--port=25432',client.options)
                self.assertEqual(client.scope['port'],25432)

    def test_named_container_namespace_is_not_mistaken_for_a_host_local_socket(self):
        client=self.api.PsqlClient(database='ib',docker_container='db-node-a')
        self.assertEqual(client.scope['docker_container'],'db-node-a')
        self.assertEqual(client.scope['transport'],'docker_exec')

    def test_catalogue_limits_and_transaction_are_fixed(self):
        for operation in ('capabilities','activity','locks','database_stats','statements'):
            query=self.api.query(operation)
            self.assertIn('BEGIN READ ONLY',query)
            self.assertIn('statement_timeout',query)
            self.assertIn('SET LOCAL search_path=pg_catalog',query)
            self.assertIn('ROLLBACK',query)
            self.assertNotIn('EXPLAIN ANALYZE',query.upper())
        for sql in ('select 1','drop','activity; drop database prod','kill','reset'):
            with self.assertRaises(ValueError):self.api.query(sql)

    def test_unavailable_history_is_not_replaced_with_zero(self):
        class FakeClient:
            scope=dict(database='ib',host='node',user='observer')
            def execute(self,operation):
                return 0,json.dumps(dict(captured_at='2026-11-16T00:00:00Z',database='ib',rows=[dict(calls=7,stats_reset=None)])).encode(),b''
        with tempfile.TemporaryDirectory() as temp:
            report=self.api.observe(Path(temp),FakeClient(),'statements')
            self.assertEqual(report['result']['temporal_scope'],'cumulative_not_event_history')
            self.assertIsNone(report['result']['historical_window_coverage'])
            self.assertTrue(report['result']['requires_ai_interpretation'])

    def test_failure_and_invalid_connection_never_become_empty_success(self):
        for database in ('prod; select 1','postgres://user:pass@host/db','host=x','-h'):
            with self.assertRaises(ValueError):self.api.PsqlClient(database=database)
        class Denied:
            scope=dict(database='ib',host='node',user='observer')
            def execute(self,operation):return 1,b'',b'permission denied'
        with tempfile.TemporaryDirectory() as temp:
            report=self.api.observe(Path(temp),Denied(),'activity')
            self.assertEqual(report['result']['status'],'unavailable')
            self.assertIsNone(report['result']['rows'])

    def test_cancel_keeps_partial_bytes_without_parsing_an_incomplete_json_document(self):
        from src.techexpert.processes import CommandStopped
        class Cancelled:
            scope=dict(database='ib',host='node',user='observer')
            def execute(self,operation,**kwargs):raise CommandStopped('cancelled',stdout=b'{"rows":[',returncode=-9,process_started=True)
        with tempfile.TemporaryDirectory() as temp:
            report=self.api.observe(Path(temp),Cancelled(),'activity',should_stop=lambda:'cancelled')
            self.assertEqual(report['result']['status'],'cancelled')
            self.assertIsNone(report['result']['rows'])
            from src.techexpert.artifacts import artifact_evidence
            self.assertEqual(artifact_evidence(temp,report['artifact_id'],'s1')['text'],'{"rows":[')

    def test_operator_credential_is_removed_from_rows_and_diagnostics_before_persistence(self):
        secret='synthetic-credential-"-marker'
        class Echo:
            scope=dict(database='ib',host='node',user='observer')
            def execute(self,operation):
                return 0,json.dumps(dict(database='ib',rows=[dict(query='literal '+secret)])).encode(),('notice '+secret).encode()
        with tempfile.TemporaryDirectory() as temp,patch.dict('os.environ',{'PGPASSWORD':secret}):
            report=self.api.observe(Path(temp),Echo(),'activity')
            self.assertNotIn(secret,report['result']['rows'][0]['query'])
            self.assertTrue(report['result']['operator_credential_redacted'])
            from src.techexpert.artifacts import artifact_evidence
            for source in report['sources']:
                text=artifact_evidence(temp,report['artifact_id'],source['id'])['text']
                self.assertNotIn(secret,text);self.assertNotIn(json.dumps(secret)[1:-1],text)

    def test_malformed_response_retains_bytes_but_never_becomes_empty_success(self):
        class Malformed:
            scope=dict(database='ib',host='node',user='observer')
            def execute(self,operation):return 0,b'{"rows":[1]}',b''
        with tempfile.TemporaryDirectory() as temp:
            report=self.api.observe(temp,Malformed(),'activity')
            self.assertEqual(report['result']['status'],'unavailable')
            self.assertIsNone(report['result']['rows'])
            from src.techexpert.artifacts import artifact_evidence
            self.assertEqual(artifact_evidence(temp,report['artifact_id'],'s1')['text'],'{"rows":[1]}')


if __name__=='__main__':unittest.main()
