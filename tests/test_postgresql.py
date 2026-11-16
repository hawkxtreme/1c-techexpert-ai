import importlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


class PostgreSQLTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.postgresql'), 'PostgreSQL adapter is missing')
        self.api=importlib.import_module('src.techexpert.postgresql')

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


if __name__=='__main__':unittest.main()
