"""SQLServer data is a bounded observation, not a cause or a historical execution."""
from copy import deepcopy
import importlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert.inputs import InputError
from src.techexpert.processes import CommandStopped

WINDOW=dict(start='2026-11-18T09:00:00+03:00',end='2026-11-18T09:30:00+03:00')


def document(operation='requests',rows=None):
    return dict(profile='sqlserver-2022-monitor-v1',operation=operation,metadata=dict(product_major_version=16,
        product_version='16.0.4325.4',database='diag',database_id=5,captured_at_utc='2026-11-18T06:01:00.0000000Z',
        server_name='reported-server',machine_name='reported-node',instance_name=None,server_local_time='2026-11-18T09:01:00+03:00',
        login_name='reader',view_server_performance_state=False,view_database_performance_state=False,query_store_options=None),
        rows=[] if rows is None else rows)


def packet(value,*,width=8000):
    text=json.dumps(value,ensure_ascii=False,allow_nan=False).encode('utf-16-le').hex().upper()
    return ('TECHEXPERT_SQLSERVER_V1\n'+'\n'.join(text[i:i+width] for i in range(0,len(text),width))+'\nTECHEXPERT_END\n').encode('ascii')


class SQLServerTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.sqlserver'),'The executable SQLServer adapter is missing')
        self.api=importlib.import_module('src.techexpert.sqlserver');self.queries=importlib.import_module('src.techexpert.sqlserver_queries')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.state=self.root/'state'

    def fake(self,doc=None,*,code=0,error=b'',stopped=None):
        outer=self
        class Client:
            scope=dict(database='diag',host='supplied.invalid',port=1433,user='reader',auth='sql',transport='local_process',client_variant='go',client_version='1.10.0')
            calls=[]
            def execute(self,operation,*,window=None,should_stop=None):
                self.calls.append((operation,window))
                if stopped:raise stopped
                value=document(operation) if doc is None else doc
                return code,packet(value) if isinstance(value,dict) else value,error
        return Client()

    def test_catalogue_and_history_window_are_finite_and_do_not_interpolate_input_sql(self):
        self.assertEqual(set(self.queries.OPERATIONS),{'capabilities','requests','waits','locks','query_store'})
        for op in self.queries.OPERATIONS:
            sql=self.queries.script(op,window=WINDOW if op=='query_store' else None)
            self.assertNotRegex(sql,r'(?i)\b(?:DROP|ALTER|INSERT|UPDATE|DELETE|GRANT|REVOKE|TRUNCATE|KILL|DBCC|EXECUTE|EXEC|BACKUP|RESTORE)\b')
            self.assertIn('SET LOCK_TIMEOUT 500',sql);self.assertIn('ROLLBACK',sql)
            self.assertIn('TECHEXPERT_SQLSERVER_V1',sql);self.assertIn('TECHEXPERT_END',sql)
        history=self.queries.script('query_store',window=WINDOW)
        self.assertIn('2026-11-18T06:00:00+00:00',history)
        self.assertIn('GROUP BY',history);self.assertIn('count_executions',history)
        for op,window in [('anything',None),('requests',WINDOW),('query_store',None),('query_store',dict(WINDOW,start="x'; DROP TABLE q--"))]:
            with self.subTest(op=op),self.assertRaises(ValueError):self.queries.script(op,window=window)

    def test_history_window_requires_known_zones_bounded_range_and_supported_precision(self):
        normalized=self.queries.normalize_window(WINDOW)
        self.assertEqual(normalized,dict(start='2026-11-18T06:00:00+00:00',end='2026-11-18T06:30:00+00:00'))
        for value in ({},[],dict(WINDOW,extra=True),dict(WINDOW,start='2026-11-18T06:00:00'),
            dict(WINDOW,start='2026-11-18T06:00:00-00:00'),dict(WINDOW,end=WINDOW['start']),
            dict(WINDOW,end='2027-01-18T09:30:00+03:00'),dict(WINDOW,start='2026-11-18T06:00:00.0000001Z'),
            dict(WINDOW,start='2026-11-18T06:00:00+00:60')):
            with self.subTest(value=value),self.assertRaises(ValueError):self.queries.normalize_window(value)

    def test_connection_options_are_not_connection_strings_or_password_arguments(self):
        good=self.api.SqlcmdClient(database='База 1С',host='sql.example.invalid',auth='sql',user='reader')
        self.assertEqual(good.scope['database'],'База 1С')
        for bad in (dict(host='-S bad'),dict(host='sql;Password=secret'),dict(database='db;DROP TABLE t'),dict(port=True),
                    dict(port=0),dict(auth='sql',user=None),dict(auth='integrated',user='reader'),
                    dict(client_variant='anything'),dict(trust_server_certificate='yes'),dict(docker_container='a;bad')):
            kwargs=dict(database='diag',host='supplied.invalid');kwargs.update(bad)
            with self.subTest(bad=bad),self.assertRaises(ValueError):self.api.SqlcmdClient(**kwargs)
        with self.assertRaises(TypeError):self.api.SqlcmdClient(database='diag',host='host',password='must-not-be-supported')

    def test_unicode_wrapped_frame_preserves_nulls_and_negative_blockers(self):
        doc=document(rows=[dict(session_id=61,login_time='2026-11-18T05:00:00',blocking_session_id=-2,wait_type=None,query_text='Запрос\n!! data')])
        result=self.api.decode_packet(packet(doc,width=41),'requests')
        self.assertEqual(result,doc)
        self.assertIsNone(result['rows'][0]['wait_type']);self.assertEqual(result['rows'][0]['blocking_session_id'],-2)

    def test_invalid_or_oversize_frame_never_becomes_observed_empty_rows(self):
        valid=packet(document())
        variants=[b'',valid[:-5],b'prefix\n'+valid,valid.replace(b'TECHEXPERT_END',b'TECHEXPERT_END\nTECHEXPERT_END'),
                  b'TECHEXPERT_SQLSERVER_V1\nXYZ\nTECHEXPERT_END\n',packet(document(operation='locks'))]
        wrong=deepcopy(document());wrong['metadata']['product_major_version']=17;variants.append(packet(wrong))
        wrong=deepcopy(document());wrong['rows']=[None];variants.append(packet(wrong))
        wrong=deepcopy(document());wrong['rows']=[{}]*201;variants.append(packet(wrong))
        raw='{"profile":"sqlserver-2022-monitor-v1","profile":"other","operation":"requests","metadata":{},"rows":[]}'
        variants.append(b'TECHEXPERT_SQLSERVER_V1\n'+raw.encode('utf-16-le').hex().encode()+b'\nTECHEXPERT_END\n')
        raw=json.dumps(document(rows=[dict(wait_time_ms=12345)])).replace('12345','1e1000')
        variants.append(b'TECHEXPERT_SQLSERVER_V1\n'+raw.encode('utf-16-le').hex().encode()+b'\nTECHEXPERT_END\n')
        variants.append(packet(document(rows=[dict(wait_type={'unrecognized':'nested'})])))
        for raw in variants:
            with self.subTest(length=len(raw)),self.assertRaises(ValueError):self.api.decode_packet(raw,'requests')
        with self.assertRaises(ValueError):self.api.decode_packet(b'F'*(4*1024**2+1),'requests')

    def test_observation_keeps_partial_visibility_and_current_scope_separate_from_history(self):
        client=self.fake(document(rows=[dict(session_id=61,blocking_session_id=None,wait_time_ms=0)]))
        artifact=self.api.observe(self.state,client,'requests');result=artifact['result']
        self.assertEqual(result['status'],'observed');self.assertEqual(result['temporal_scope'],'current_snapshot_only')
        self.assertIsNone(result['historical_window_coverage']);self.assertEqual(result['database'],'diag')
        self.assertEqual(result['visibility'],'permission_limited_or_unknown')
        self.assertIsNone(result['cause']);self.assertTrue(result['requires_ai_interpretation'])
        self.assertEqual(result['units']['wait_time_ms'],'milliseconds')
        self.assertEqual(artifact['kind'],'sqlserver')
        doc=document('query_store',[dict(plan_id=10,query_id=20,runtime_stats_interval_id=30,execution_type=0,count_executions=2,
            avg_duration_us=1000,interval_start='2026-11-18T06:00:00Z',interval_end='2026-11-18T07:00:00Z')])
        doc['metadata']['view_database_performance_state']=True
        result=self.api.observe(self.state,self.fake(doc),'query_store',window=WINDOW)['result']
        self.assertEqual(result['temporal_scope'],'query_store_interval_aggregates')
        self.assertEqual(result['units']['avg_duration_us'],'microseconds');self.assertEqual(result['rows'][0]['count_executions'],2)
        self.assertEqual(result['visibility'],'database_performance_permission_reported')
        self.assertIsNone(result['historical_window_coverage']);self.assertEqual(result['window']['end'],'2026-11-18T06:30:00+00:00')

    def test_unavailable_and_cancelled_rows_stay_unknown(self):
        failed=self.api.observe(self.state,self.fake(b'',code=1,error=b'Permission denied'),'waits')['result']
        self.assertEqual(failed['status'],'unavailable');self.assertIsNone(failed['rows'])
        stop=CommandStopped('cancelled',stdout=b'partial',process_started=True)
        cancelled=self.api.observe(self.state,self.fake(stopped=stop),'locks')['result']
        self.assertEqual(cancelled['status'],'cancelled');self.assertIsNone(cancelled['rows'])
        with self.assertRaises(ValueError):self.api.observe(self.state,self.fake(),'arbitrary')

    def test_known_operator_secret_is_removed_from_success_and_failed_encoded_sources(self):
        secret='Unique34"пароль\\value';doc=document(rows=[dict(query_text='literal '+secret),
            dict(query_text='escaped '+json.dumps(secret,ensure_ascii=True)[1:-1])])
        raw=packet(doc,width=17)
        with patch.dict(os.environ,{'SQLCMDPASSWORD':secret}):
            good=self.api.observe(self.state,self.fake(doc),'requests')
            failed=self.api.observe(self.state,self.fake(raw[:-5],code=1,error=('reflected '+secret).encode()),'requests')
        for report in (good,failed):
            self.assertTrue(report['result']['operator_credential_redacted'])
        self.assertEqual(good['result']['rows'][1]['query_text'],'escaped [redacted operator credential]')
        variants=[secret.encode(),json.dumps(secret,ensure_ascii=True)[1:-1].encode(),secret.encode('utf-16-le').hex().upper().encode()]
        for file in self.state.rglob('*'):
            if file.is_file():
                data=file.read_bytes();compact=b''.join(data.split())
                for value in variants:self.assertNotIn(value,compact,str(file))

    def test_credentials_matching_protocol_keys_do_not_break_a_valid_observation(self):
        for secret in ('metadata','rows'):
            with self.subTest(secret=secret),patch.dict(os.environ,{'SQLCMDPASSWORD':secret}):
                client=self.fake(document(rows=[dict(query_text='reflected '+secret)]))
                result=self.api.observe(self.state,client,'requests')['result']
                self.assertEqual(result['status'],'observed')
                self.assertEqual(result['rows'][0]['query_text'],'reflected [redacted operator credential]')
                self.assertTrue(result['operator_credential_redacted'])

    def test_credential_in_an_untrusted_row_key_discards_the_packet(self):
        secret='SyntheticPrivateWord'
        doc=document(rows=[{'unexpected_'+secret:123}])
        with patch.dict(os.environ,{'SQLCMDPASSWORD':secret}):
            result=self.api.observe(self.state,self.fake(doc),'requests')['result']
        self.assertEqual(result['status'],'unavailable')
        self.assertIsNone(result['rows'])
        self.assertTrue(result['operator_credential_redacted'])
        self.assertFalse(any(secret.encode() in file.read_bytes() for file in self.state.rglob('*') if file.is_file()))

    def test_real_command_options_use_supported_variants_and_never_password_argv_or_ini(self):
        secret='Aa1!fixture-session-secret';calls=[]
        def command(argv,**kwargs):
            calls.append((argv,kwargs))
            if '-?' in argv:return 0,b'Version: v1.10.0\n',b''
            self.assertIn('-Q',argv);self.assertIn('-x',argv);self.assertNotIn('-X1',argv)
            self.assertNotIn('-P',argv);self.assertNotIn(secret,' '.join(argv))
            self.assertEqual(kwargs['env']['SQLCMDPASSWORD'],secret);self.assertNotIn('SQLCMDINI',kwargs['env'])
            return 0,packet(document()),b''
        with patch.dict(os.environ,{'SQLCMDPASSWORD':secret,'SQLCMDINI':'unapproved-startup.sql'}),patch.object(self.api,'run_bounded',side_effect=command):
            client=self.api.SqlcmdClient(database='diag',host='host',auth='sql',user='reader')
            self.assertEqual(client.execute('requests')[0],0)
        self.assertEqual(len(calls),2);self.assertNotIn('SQLCMDPASSWORD',calls[0][1]['env'])
        self.assertEqual(client.scope['client_variant'],'go')
        self.assertEqual(client.scope['client_version'],'1.10.0')

    def test_missing_credential_or_unsupported_client_never_falls_back_to_prompt(self):
        with patch.dict(os.environ,{},clear=True),patch.object(self.api,'run_bounded',side_effect=AssertionError('No client must start')):
            client=self.api.SqlcmdClient(database='diag',host='host',auth='sql',user='reader')
            result=self.api.observe(self.state,client,'capabilities')['result']
        self.assertEqual(result['status'],'unavailable');self.assertIsNone(result['rows'])
        self.assertEqual(result['reason'],'credential_profile_unavailable')
        with patch.object(self.api,'run_bounded',return_value=(0,b'Unknown sqlcmd99',b'')):
            result=self.api.observe(self.state,self.api.SqlcmdClient(database='diag',host='host'),'capabilities')['result']
        self.assertEqual(result['status'],'unavailable');self.assertEqual(result['reason'],'unsupported_client_profile')


if __name__=='__main__':unittest.main()
