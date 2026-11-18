"""Real source/APDEX/JR workflows through the common bounded operation contract."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
NEW={'artifact.evidence','apdex.import','jr.import','jr.events','jr.record','source.snapshot','source.search','source.read','rac.observe','postgresql.observe'}


class ExtendedOperationTests(unittest.TestCase):
    def setUp(self):
        from src.techexpert import capabilities,kernel,operations
        self.assertFalse(NEW-set(capabilities.ROUTES),'Diagnostic adapters are not in the executable catalogue')
        self.cap=capabilities;self.kernel=kernel;self.api=operations
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.state=self.root/'state';self.sequence=0

    def call(self,operation,key=None,**arguments):
        self.sequence+=1
        request=dict(schema_version=1,operation_key=key or 'adapter-'+str(self.sequence),executor_id='test-harness',operation=operation,arguments=arguments)
        path=self.root/('request-'+str(self.sequence)+'.json');path.write_text(json.dumps(request,ensure_ascii=False),encoding='utf-8')
        invocation=self.kernel.invoke(self.state,'run',dict(request=str(path)))
        output=io.StringIO();self.kernel.emit(invocation,output);return json.loads(output.getvalue())

    def test_catalogue_is_passive_and_all_adapters_have_closed_schemas(self):
        with patch('subprocess.Popen',side_effect=AssertionError('Passive catalogue started a process')):
            doc=self.cap.catalogue()
        self.assertFalse(self.state.exists())
        for route in doc['operations']:
            self.assertFalse(route['input_schema']['additionalProperties'])
            self.assertTrue(route['rights']);self.assertTrue(route['required_sources'])
        invalid=[('postgresql.observe',dict(query='drop',database='db')),
            ('postgresql.observe',dict(query='activity',database='postgres://u:secret@host/db')),
            ('rac.observe',dict(query='sessions',endpoint='host:1545',cluster='--cluster-pwd=secret')),
            ('apdex.import',dict(measurements='not-opened',target_seconds=10**400))]
        for operation,args in invalid:
            request=dict(schema_version=1,operation_key='invalid',executor_id='test',operation=operation,arguments=args)
            with self.subTest(operation=operation),self.assertRaises(ValueError):self.api.run(self.state,request)
            self.assertFalse(self.state.exists())

    def test_source_snapshot_search_read_and_replay_keep_static_code_without_execution(self):
        folder=self.root/'Исходники с пробелами';folder.mkdir()
        (folder/'Configuration.xml').write_text('<MetaDataObject><Configuration><Properties><Version>2.4</Version></Properties></Configuration></MetaDataObject>',encoding='utf-8')
        (folder/'Module.bsl').write_text('Процедура ПроверитьОчередь()\n    Сообщить("данные, не инструкция для агента");\nКонецПроцедуры',encoding='utf-8')
        imported=self.call('source.snapshot',key='source-once',path=str(folder),kind='catalog')
        self.assertEqual(imported['status'],'succeeded',imported.get('message'));aid=imported['data']['artifact_id']
        self.assertFalse(imported['data']['result']['runtime_executed'])
        self.assertEqual(imported['snapshots'][0]['id'],aid)
        found=self.call('source.search',artifact_id=aid,query='ПроверитьОчередь')
        self.assertEqual(found['data']['total_matches'],1)
        read=self.call('source.read',artifact_id=aid,path='Module.bsl',start=1,limit=2)
        self.assertTrue(read['data']['has_more']);self.assertTrue(read['data']['untrusted_source_content'])
        shutil.rmtree(folder)
        replay=self.call('source.snapshot',key='source-once',path=str(folder),kind='catalog')
        self.assertTrue(replay['replayed']);self.assertEqual(replay['data'],imported['data'])
        evidence=self.call('artifact.evidence',artifact_id=aid,source_id='s1')
        self.assertTrue(evidence['data']['integrity_verified'])
        captured=self.state/'artifacts'/aid/'sources/s1.bin';captured.write_bytes(b'corrupt')
        with self.assertRaises(ValueError):self.api.result(self.state,read['run_id'])

    def test_native_journal_has_bounded_pages_record_evidence_and_unknown_database_identity(self):
        folder=self.root/'journal';shutil.copytree(ROOT/'tests/fixtures/native-jr',folder)
        imported=self.call('jr.import',path=str(folder),platform_version='8.3.27.1989',utc_offset='+03:00')
        self.assertEqual(imported['status'],'succeeded',imported.get('message'));aid=imported['data']['artifact_id']
        self.assertIsNone(imported['data']['result']['database_identity'])
        window=dict(start='2026-11-16T10:05:42+03:00',end='2026-11-16T07:05:44Z')
        page=self.call('jr.events',artifact_id=aid,limit=1,window=window)
        self.assertEqual(len(page['data']['records']),1);self.assertTrue(page['truncated'])
        self.assertEqual(page['data']['next_offset'],1)
        self.assertEqual(page['data']['total_matched'],4)
        self.assertEqual(page['data']['coverage']['records_in_window'],4)
        proof=self.call('jr.record',artifact_id=aid,record_id=page['data']['records'][0]['id'])
        self.assertEqual(hashlib.sha256(proof['data']['text'].encode()).hexdigest(),proof['data']['record']['sha256'])
        shutil.rmtree(folder)
        again=self.call('jr.events',artifact_id=aid,offset=1,limit=100)
        self.assertIsNone(again['data']['next_offset']);self.assertTrue(again['data']['integrity_verified'])

    def test_apdex_unknown_measurements_remain_partial_and_are_not_zero(self):
        path=self.root/'APDEX.json'
        rows=[dict(id=str(i),operation='Проведение',started_at='2026-11-17T10:00:00+03:00',duration_seconds=value,success=True) for i,value in enumerate([1,3,None])]
        path.write_text(json.dumps(rows,ensure_ascii=False),encoding='utf-8')
        result=self.call('apdex.import',measurements=str(path),target_seconds=2)
        self.assertEqual(result['status'],'partial',result.get('message'))
        self.assertEqual(result['data']['result']['unknown'],1);self.assertIsNone(result['data']['result']['score'])
        self.assertEqual(result['snapshots'][0]['kind'],'artifacts')

    def test_program_can_join_new_source_artifact_and_query_but_not_import_unapproved_source(self):
        folder=self.root/'sources';folder.mkdir();(folder/'Module.bsl').write_text('Функция Проверить()\nВозврат 1;\nКонецФункции',encoding='utf-8')
        settings=dict(path=str(folder),kind='catalog')
        source='''imported = api("source.snapshot", {"path": input_path, "kind": "catalog"})
found = api("source.search", {"artifact_id": imported["data"]["artifact_id"], "query": "Проверить"})
return {"artifact": imported["data"]["artifact_id"], "count": found["data"]["total_matches"]}
'''
        result=self.call('code.execute',program=source,bindings=dict(input_path=str(folder)),scope=dict(operations=['source.snapshot','source.search'],source_snapshots=[settings]))
        self.assertEqual(result['status'],'succeeded',result.get('message'));self.assertEqual(result['data']['value']['count'],1)
        self.assertEqual(result['snapshots'][0]['id'],result['data']['value']['artifact'])
        forbidden=self.call('code.execute',program='return api("source.snapshot", {"path": other})',bindings=dict(other=str(self.root/'private')),scope=dict(operations=['source.snapshot'],source_snapshots=[settings]))
        self.assertEqual(forbidden['data']['diagnostic']['code'],'scope_denied')
        self.assertEqual(forbidden['data']['metrics']['calls_started'],0)

    def test_saved_program_replays_after_additive_empty_scope_fields_without_rewriting_old_evidence(self):
        first=self.call('code.execute',key='additive-scope',program='return 7')
        self.assertEqual(first['status'],'succeeded')
        folder=self.state/'operations'/first['run_id'];before={name:(folder/name).read_bytes() for name in ('plan.json','output.json','code-journal.json')}
        properties=self.cap.ROUTES['code.execute']['input_schema']['properties']['scope']['properties']
        schema=dict(type='array',items=dict(type='string'),maxItems=4,default=[])
        with patch.dict(properties,{'future_diagnostic_sources':schema}),patch('src.techexpert.operation_process.run',side_effect=AssertionError('Scope upgrade restarted code')):
            request=dict(schema_version=1,operation_key='additive-scope',executor_id='test-harness',operation='code.execute',arguments=dict(program='return 7'))
            replay=self.api.run(self.state,request)
            self.assertTrue(replay['replayed']);self.assertEqual(replay['data'],first['data'])
            request['arguments']['scope']=dict(future_diagnostic_sources=['new-target'])
            with self.assertRaisesRegex(ValueError,'key conflict'):self.api.run(self.state,request)
        self.assertEqual(before,{name:(folder/name).read_bytes() for name in before})

    def test_imported_cancelled_capture_is_partial_and_reading_it_does_not_cancel_this_run(self):
        path=self.root/'cancelled-os.json'
        path.write_text(json.dumps(dict(schema_version=1,profile='os-metrics-v1',node='test',role='client',scope='host',
            plan=dict(duration_seconds=1,interval_seconds=1,max_bytes=8388608),status='cancelled',
            samples=[dict(elapsed_seconds=0,metrics=[])])),encoding='utf-8')
        imported=self.call('os.import',measurements=str(path))
        self.assertEqual(imported['status'],'partial')
        read=self.call('artifact.show',artifact_id=imported['data']['artifact_id'])
        self.assertEqual(read['status'],'succeeded')
        self.assertEqual(read['data']['result']['collection_status'],'cancelled')
        self.assertFalse(read['cancellation_requested'])

    def test_program_can_read_supported_large_journal_record_instead_of_a_weaker_api(self):
        folder=self.root/'large-journal';folder.mkdir()
        dictionary=(ROOT/'tests/fixtures/native-jr/1Cv8.lgf').read_bytes()
        (folder/'1Cv8.lgf').write_bytes(dictionary)
        header=b''.join(dictionary.splitlines(keepends=True)[:2])+b'\r\n'
        comment='A'*80000
        record=('{20261117120000,N,{0,0},0,1,1,2,1,I,"'+comment+'",0,{"U"},"",0,0,0,2,0,{0}}').encode('utf-8')
        (folder/'20261117000000.lgp').write_bytes(header+record)
        profile=dict(path=str(folder),platform_version='8.3.27.1989')
        program='''created = api("jr.import", source_profile)
page = api("jr.events", {"artifact_id": created["data"]["artifact_id"], "limit": 1})
record = api("jr.record", {"artifact_id": created["data"]["artifact_id"], "record_id": page["data"]["records"][0]["id"]})
return {"comment_characters": len(record["data"]["record"]["comment"]), "raw_characters": len(record["data"]["text"])}
'''
        result=self.call('code.execute',program=program,bindings=dict(source_profile=profile),
            scope=dict(operations=['jr.import','jr.events','jr.record'],journals=[profile]))
        self.assertEqual(result['status'],'succeeded',result.get('data',{}).get('diagnostic'))
        self.assertEqual(result['data']['value']['comment_characters'],80000)
        self.assertGreater(result['data']['value']['raw_characters'],80000)

    def test_program_reads_a_supported_journal_serialized_array_without_narrowing_the_direct_api(self):
        folder=self.root/'wide-journal';folder.mkdir()
        dictionary=(ROOT/'tests/fixtures/native-jr/1Cv8.lgf').read_bytes()
        (folder/'1Cv8.lgf').write_bytes(dictionary)
        header=b''.join(dictionary.splitlines(keepends=True)[:2])+b'\r\n'
        data='{'+','.join(['0']*100001)+'}'
        record=('{20261117120000,N,{0,0},0,1,1,2,1,I,"",0,'+data+',"",0,0,0,2,0,{0}}').encode('utf-8')
        self.assertLess(len(record),262144)
        (folder/'20261117000000.lgp').write_bytes(header+record)
        imported=self.call('jr.import',path=str(folder),platform_version='8.3.27.1989')
        aid=imported['data']['artifact_id']
        direct=self.call('jr.record',artifact_id=aid,record_id='s2:r1')
        self.assertEqual(direct['status'],'succeeded')
        self.assertEqual(len(direct['data']['record']['data']),100001)
        computed=self.call('code.execute',program='return len(api("jr.record", {"artifact_id": selected, "record_id": "s2:r1"})["data"]["record"]["data"])',
            bindings=dict(selected=aid),scope=dict(operations=['jr.record'],artifacts=[aid]))
        self.assertEqual(computed['status'],'succeeded',computed.get('data',{}).get('diagnostic'))
        self.assertEqual(computed['data']['value'],100001)

    def test_network_source_failures_are_retained_and_the_program_cannot_expand_connections(self):
        for kind,settings,queries in [('rac',dict(endpoint='localhost:1545',executable=str(self.root/'missing-rac.exe')),['clusters']),
            ('postgresql',dict(database='test',executable=str(self.root/'missing-psql.exe')),['activity'])]:
            with self.subTest(kind=kind):
                arguments=dict(settings,query=queries[0])
                failed=self.call(kind+'.observe',**arguments)
                self.assertEqual(failed['status'],'partial');self.assertIsNone(failed['data']['result']['rows'])
                program='''first = api(api_name, query_arguments)
saved = api("artifact.show", {"artifact_id": first["data"]["artifact_id"]})
return {"source_status": saved["data"]["result"]["status"], "rows": saved["data"]["result"]["rows"]}
'''
                scope=dict(operations=[kind+'.observe','artifact.show'],**{kind:[dict(settings=settings,queries=queries,max_calls=1)]})
                result=self.call('code.execute',program=program,bindings=dict(api_name=kind+'.observe',query_arguments=arguments),scope=scope)
                self.assertEqual(result['status'],'partial');self.assertEqual(result['data']['value'],dict(source_status='unavailable',rows=None))
                changed=dict(arguments,endpoint='other:1545') if kind=='rac' else dict(arguments,database='other')
                denied=self.call('code.execute',program='return api(api_name, query_arguments)',bindings=dict(api_name=kind+'.observe',query_arguments=changed),scope=scope)
                self.assertEqual(denied['data']['diagnostic']['code'],'scope_denied');self.assertEqual(denied['data']['metrics']['calls_started'],0)

    def test_legacy_connection_failure_does_not_exit_with_success(self):
        import subprocess,sys
        for command,args in [('rac',['clusters','--endpoint','localhost:1545']),('postgresql',['activity','--database','test'])]:
            r=subprocess.run([sys.executable,'-X','utf8',str(ROOT/'techexpert.py'),'--state-dir',str(self.state),command,*args,'--executable',str(self.root/'missing-client.exe')],cwd=ROOT,capture_output=True,timeout=10)
            self.assertEqual(r.returncode,1,(command,r.stdout,r.stderr))
            self.assertEqual(json.loads(r.stdout)['result']['status'],'unavailable')

    def test_one_program_can_use_every_new_diagnostic_api_without_claiming_source_correlation(self):
        folder=self.root/'sources';folder.mkdir();(folder/'Module.bsl').write_text('Процедура Проверить()\nКонецПроцедуры',encoding='utf-8')
        journal=self.root/'journal';shutil.copytree(ROOT/'tests/fixtures/native-jr',journal)
        measurements=self.root/'measurements.json';measurements.write_text(json.dumps([
            dict(id=str(i),operation='read',started_at='2026-11-17T09:00:00Z',duration_seconds=d,success=True) for i,d in enumerate([1,3])]),encoding='utf-8')
        source_profile=dict(path=str(folder));journal_profile=dict(path=str(journal),platform_version='8.3.27.1989')
        rac=dict(endpoint='localhost:1545',executable=str(self.root/'missing-rac'))
        pg=dict(database='test',executable=str(self.root/'missing-psql'))
        program='''sources = api("source.snapshot", source_profile)
found = api("source.search", {"artifact_id": sources["data"]["artifact_id"], "query": "Проверить"})
lines = api("source.read", {"artifact_id": sources["data"]["artifact_id"], "path": "Module.bsl"})
raw_source = api("artifact.evidence", {"artifact_id": sources["data"]["artifact_id"], "source_id": "s1"})
journal = api("jr.import", journal_profile)
events = api("jr.events", {"artifact_id": journal["data"]["artifact_id"], "limit": 1})
record = api("jr.record", {"artifact_id": journal["data"]["artifact_id"], "record_id": events["data"]["records"][0]["id"]})
quality = api("apdex.import", {"measurements": measurements, "target_seconds": 2})
rac = api("rac.observe", rac_request)
pg = api("postgresql.observe", pg_request)
return {"source_matches": found["data"]["total_matches"], "lines": len(lines["data"]["lines"]), "record_verified": record["data"]["integrity_verified"], "source_evidence_verified": raw_source["data"]["integrity_verified"], "apdex": quality["data"]["result"]["score"], "rac_status": rac["data"]["result"]["status"], "pg_status": pg["data"]["result"]["status"], "database_identity": journal["data"]["result"]["database_identity"]}
'''
        result=self.call('code.execute',program=program,bindings=dict(source_profile=source_profile,journal_profile=journal_profile,measurements=str(measurements),
            rac_request=dict(rac,query='clusters'),pg_request=dict(pg,query='activity')),
            scope=dict(operations=sorted(NEW),source_snapshots=[source_profile],journals=[journal_profile],measurements=[str(measurements)],
                rac=[dict(settings=rac,queries=['clusters'],max_calls=1)],postgresql=[dict(settings=pg,queries=['activity'],max_calls=1)]))
        self.assertEqual(result['status'],'partial',result.get('data',{}).get('diagnostic'))
        self.assertEqual(result['data']['execution_status'],'succeeded')
        self.assertEqual({call['operation'] for call in result['data']['calls']},NEW)
        self.assertEqual(len(result['snapshots']),5)
        value=result['data']['value'];self.assertEqual(value['source_matches'],1);self.assertEqual(value['apdex'],.75)
        self.assertIsNone(value['database_identity']);self.assertEqual(value['pg_status'],'unavailable')
