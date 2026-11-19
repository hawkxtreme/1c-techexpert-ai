"""General native TJ input must not require an invented SC01 operation identity."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from src.techexpert import storage,inputs,source_coverage,operations,capabilities,mcp_tools

ROOT=Path(__file__).resolve().parents[1]
PROFILE=dict(format='1c-tj-text-v1',platform_version='8.3.27.1989',encoding='utf-8',placement='plain',timestamp_format='iso',utc_offset='+03:00')
RAW=(b'2026-11-18T09:00:00.000000-1200000000,CALL,1,SessionID=12\n'
     b'2026-11-18T09:01:00.000000-100,CALL,1,SessionID=12\n'
     b'2026-11-18T09:02:00.000000-50,EXCP,1,SessionID=12\n'
     b'2026-11-18T09:02:30.000000-75,CALL,1,SessionID=13\n'
     b'2026-11-18T09:05:00.000000-5,CALL,1,SessionID=12\n')
WINDOW=dict(start='2026-11-18T09:01:00+03:00',end='2026-11-18T09:02:00+03:00')


class GenericTJTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.state=self.root/'state';self.log=self.root/'journal.log';self.log.write_bytes(RAW)
        self.manifest=self.root/'input.json';self.doc=dict(schema=2,origin='provided',symptom='Document save is slow',sources=[dict(PROFILE,path=str(self.log))])
        self.write(self.doc)

    def write(self,doc):self.manifest.write_text(json.dumps(doc,ensure_ascii=False),encoding='utf-8')

    def case(self):
        try:return storage.investigate(self.manifest,self.state)
        except inputs.InputError as exc:self.fail('General native TJ still requires SC01-specific input: '+str(exc))

    def request(self,op,args,key):return dict(schema_version=1,operation=op,arguments=args,operation_key=key,executor_id='generic-tj-fixture')

    def test_native_only_capture_preserves_unknown_identity_and_exact_inputs(self):
        raw=self.manifest.read_bytes();case=self.case();cid=case['case_id'];folder=storage.case_folder(self.state,cid);saved_report=(folder/'report.json').read_bytes()
        self.assertEqual(case['scenario'],'native-tj-observations')
        self.assertEqual(case['analysis_profile'],'native-tj-observation-v1')
        self.assertEqual(case['selection'],{})
        self.assertEqual(case['durations_seconds'],dict(queue=None,execution=None,total=None))
        self.assertIsNone(case['wait_seconds']);self.assertEqual(case['timeline'],[])
        self.assertEqual(case['cause_state'],'insufficient_data');self.assertNotIn('order_load',case)
        self.assertNotIn('job_correlation',case)
        self.assertEqual(case['native_observations']['event_count'],5)
        self.assertEqual(case['native_observations']['longest_events'][0]['duration_us'],1200000000)
        self.assertEqual(case['source_coverage']['scope'],'native_TJ_only')
        self.assertFalse(case['source_coverage']['can_establish_absence'])
        self.assertNotIn('задани',' '.join(case['next_steps']).casefold())
        self.assertEqual((folder/'manifest.json').read_bytes(),raw)
        self.assertEqual((folder/'sources/s1.bin').read_bytes(),RAW)
        self.log.unlink();self.manifest.unlink()
        self.assertEqual(storage.verified_case(self.state,cid),case)
        self.assertTrue(storage.read_evidence(self.state,cid,'s1:2')['integrity_verified'])
        coverage=source_coverage.inspect_case(self.state,cid,window=WINDOW)
        self.assertEqual(coverage['scope'],'native_TJ_only');self.assertFalse(coverage['original_paths_read'])
        self.assertEqual((folder/'report.json').read_bytes(),saved_report)

    def test_supplied_native_json_keeps_original_bytes_and_replays_direct_evidence(self):
        raw = (b'\xef\xbb\xbf{"ts":"2026-11-18T09:01:00.000001","duration":"17","name":"SDBL",'
               b'"depth":"3","Func":"One","Func":"Two","OSThread":"2"}\r\n')
        self.log.write_bytes(raw)
        source = dict(PROFILE, path=str(self.log), format='1c-tj-json-v1')
        self.write(dict(self.doc, sources=[source], incident_window=WINDOW))
        case = self.case()
        case_id = case['case_id']
        self.assertEqual(case['input_contract'], '1c-tj-json-v1')
        self.assertEqual(case['native_observations']['event_count'], 1)
        self.assertEqual(storage.case_source_path(self.state, case_id, 's1').read_bytes(), raw)
        self.log.unlink()
        self.assertEqual(storage.list_native_events(self.state, case_id, window=WINDOW)['matched_count'], 1)
        proof = storage.read_evidence(self.state, case_id, 's1:1')
        self.assertEqual((proof['byte_start'], proof['byte_end']), (3, len(raw)))
        self.assertIn('"Func":"One","Func":"Two"', proof['text'])
        coverage = source_coverage.inspect_case(self.state, case_id, window=WINDOW, required_fields=['Func'])
        self.assertEqual(coverage['snapshot_sources_verified'], ['s1'])
        self.assertEqual(coverage['sources'][0]['requirements']['fields']['Func']['status'], 'only_ambiguous_or_empty')
        self.assertFalse(coverage['can_establish_absence'])

    def test_manifest_v2_refuses_special_profiles_and_other_formats_before_source_io(self):
        invalid=[dict(self.doc,selection={}),dict(self.doc,scenario='SC-01'),dict(self.doc,correlation_profile='1c-file-job-markers-v1'),
            dict(self.doc,workload_profile='sc01-order-load-v1'),dict(self.doc,schema=True),dict(self.doc,unknown=True),
            dict(self.doc,symptom=' '*5),dict(self.doc,symptom='x'*8193)]
        invalid += [dict(self.doc,reported_normal_seconds=v) for v in (True,0,-1,'300',float('inf'),10**400)]
        for fmt in ('normalized-events-v1','1c-job-runtime-v1','1c-source-text-v1','sc01-http-service-v1'):
            invalid.append(dict(self.doc,sources=[dict(PROFILE,path=str(self.log)),dict(format=fmt,path='not-read')]))
        original=inputs.read_snapshot
        def read(path,*args,**kwargs):
            self.assertEqual(Path(path),self.manifest,'Invalid manifest opened a source');return original(path,*args,**kwargs)
        for doc in invalid:
            with self.subTest(doc=doc):
                self.write(doc)
                with patch.object(inputs,'read_snapshot',side_effect=read):
                    with self.assertRaises(ValueError):inputs.load_manifest(self.manifest)
        self.assertFalse(self.state.exists())

    def test_schema2_keeps_existing_parser_and_inspection_limits(self):
        doc=deepcopy(self.doc);doc['sources'][0]['platform_version']='8.3.99';self.write(doc)
        with self.assertRaisesRegex(ValueError,'platform_version'):inputs.load_manifest(self.manifest)
        check=source_coverage.inspect_manifest(self.manifest)
        self.assertEqual(check['sources'][0]['availability'],'unsupported_profile')
        self.assertFalse(check['state_created']);self.assertFalse(self.state.exists())
        doc=deepcopy(self.doc);doc['sources'][0]['read_mode']='tj-prefix-v1';doc['incident_window']=WINDOW;doc['reported_normal_seconds']=300;self.write(doc)
        case=self.case();self.assertEqual(case['baseline'],dict(reported_seconds=300,status='user_reported_not_measured'))
        self.assertEqual(case['sources'][0]['acquisition']['method'],'tj-prefix-v1')
        self.assertEqual(case['source_coverage']['request']['window']['start'],'2026-11-18T06:01:00+00:00')

    def test_schema2_source_declarations_are_finite_and_time_mode_specific_before_read(self):
        variants=[dict(PROFILE,unknown=True),dict(PROFILE,role='controller'),dict(PROFILE,duration_unit='seconds'),
            dict(PROFILE,file_hour='2026-11-18T09:00:00+03:00'),dict(PROFILE,rotation_hours=True),dict(PROFILE,rotation_hours=1),
            dict(PROFILE,timestamp_format='minute',rotation_hours=1,file_hour='2026-11-18T09:00:00+03:00'),
            dict(PROFILE,timestamp_format='minute',rotation_hours=1,file_hour='2026-11-18T09:00:00+03:00',utc_offset='+09:00')]
        original=inputs.read_snapshot
        def read(path,*args,**kwargs):
            self.assertEqual(Path(path),self.manifest,'Unsupported source declaration opened original data')
            return original(path,*args,**kwargs)
        for source in variants:
            with self.subTest(source=source):
                self.write(dict(self.doc,sources=[dict(PROFILE,path=str(self.log)),dict(source,path=str(self.log))]))
                with patch.object(inputs,'read_snapshot',side_effect=read):
                    with self.assertRaises(ValueError):inputs.load_manifest(self.manifest)
                self.write(dict(self.doc,sources=[dict(source,path=str(self.log))]))
                with patch.object(inputs,'read_snapshot',side_effect=read):result=source_coverage.inspect_manifest(self.manifest)
                self.assertEqual(result['sources'][0]['availability'],'unsupported_profile')
        minute=dict(PROFILE,timestamp_format='minute',rotation_hours=1,file_hour='2026-11-18T09:00:00+03:00');minute.pop('utc_offset')
        self.log.write_bytes(b'00:00.000001-5,CALL,1,k=v\n');self.write(dict(self.doc,sources=[dict(minute,path=str(self.log))]))
        result=self.case();self.assertEqual(result['native_observations']['first_timestamp_utc'],'2026-11-18T06:00:00.000001+00:00')

    def test_selected_generic_declarations_fail_before_original_catalogue_capture(self):
        from src.techexpert import input_intake
        archive=self.root/'provided.zip'
        with zipfile.ZipFile(archive,'w') as zipped:zipped.writestr('logs/one.log',RAW)
        preview=operations.run(self.state,self.request('input.inspect',dict(inputs=[dict(path=str(archive),kind='zip')]),'strict-general-preview'))
        self.assertEqual(preview['status'],'succeeded',preview);pid=preview['data']['artifact_id'];member=preview['data']['result']['members'][0]['id']
        for fields in (dict(role='controller'),dict(file_hour='2026-11-18T09:00:00+03:00'),dict(unknown=True)):
            with self.subTest(fields=fields):
                self.write(dict(self.doc,sources=[dict(PROFILE,path=member,**fields)]))
                with patch.object(input_intake,'capture_selected',side_effect=AssertionError('Invalid declarations captured an original catalogue member')):
                    with self.assertRaises(ValueError):input_intake.analyze(self.state,self.root/'output',self.manifest,pid)
        self.assertFalse((self.root/'output').exists())

    def test_window_filters_recorded_time_with_half_open_bounds_and_exact_filters(self):
        cid=self.case()['case_id'];query=storage.list_native_events
        result=query(self.state,cid,window=WINDOW)
        self.assertEqual([r['evidence']['id'] for r in result['records']],['s1:2'])
        self.assertEqual(result['time_selection_basis'],'recorded_timestamp_half_open_not_operation_overlap')
        self.assertEqual(result['window'],dict(start='2026-11-18T06:01:00+00:00',end='2026-11-18T06:02:00+00:00'))
        self.assertEqual(result['clock_alignment'],'not_verified');self.assertEqual(result['job_correlation'],'not_established')
        wide=dict(WINDOW,end='2026-11-18T09:03:00+03:00')
        first=query(self.state,cid,window=wide,event='CALL',limit=1)
        self.assertEqual(first['matched_count'],2);self.assertEqual(first['next_offset'],1)
        second=query(self.state,cid,window=wide,event='CALL',limit=1,offset=1)
        self.assertEqual(second['records'][0]['properties']['SessionID'],'13')
        exact=query(self.state,cid,window=wide,event='CALL',properties={'SessionID':'12'},source_id='s1')
        self.assertEqual(exact['matched_count'],1)
        self.assertNotIn('window',query(self.state,cid))

    def test_invalid_windows_fail_before_case_io(self):
        invalid=[{},[],dict(start=WINDOW['start']),dict(WINDOW,extra=True),dict(start='2026-11-18T09:00:00',end=WINDOW['end']),
            dict(WINDOW,end=WINDOW['start']),dict(WINDOW,end='2026-11-17T09:00:00+03:00'),dict(WINDOW,start='2026-11-18T09:01:00-00:00')]
        for value in invalid:
            with self.subTest(window=value),patch.object(storage,'load_case',side_effect=AssertionError('case read before validation')):
                with self.assertRaises(ValueError):storage.list_native_events(self.state,'a'*32,window=value)

    def test_unreturned_corrupt_suffix_refuses_a_window_page(self):
        cid=self.case()['case_id'];saved=storage.case_folder(self.state,cid)/'sources/s1.bin'
        self.log.unlink();saved.write_bytes(RAW[:-2]+b'X\n')
        with self.assertRaisesRegex(ValueError,'integrity|hash|snapshot'):
            storage.list_native_events(self.state,cid,window=WINDOW,limit=1)

    def test_managed_input_period_query_and_scoped_program_replay_without_originals(self):
        request=self.request('case.analyze',dict(manifest=str(self.manifest)),'generic-import')
        case=operations.run(self.state,request);self.assertEqual(case['status'],'succeeded',case)
        cid=case['data']['case_id'];folder=storage.case_folder(self.state,cid);old_report=(folder/'report.json').read_bytes()
        selected=dict(case_id=cid,window=WINDOW,event='CALL')
        event_request=self.request('case.events',selected,'generic-window');page=operations.run(self.state,event_request)
        self.assertEqual(page['status'],'succeeded',page);self.assertEqual(page['data']['matched_count'],1)
        arguments=dict(program='rows=api("case.events", selected)\nreturn api("case.evidence", {"case_id":selected["case_id"],"evidence_id":rows["data"]["records"][0]["evidence"]["id"]})["data"]["integrity_verified"]',
            bindings=dict(selected=selected),scope=dict(operations=['case.events','case.evidence'],cases=[cid]))
        program_request=self.request('code.execute',arguments,'generic-program');program=operations.run(self.state,program_request)
        self.assertEqual(program['status'],'succeeded',program);self.assertIs(program['data']['value'],True)
        self.assertEqual(program['data']['metrics']['calls_started'],2)
        self.log.unlink();self.manifest.unlink()
        for wanted,original in ((request,case),(event_request,page),(program_request,program)):
            again=operations.run(self.state,wanted);self.assertTrue(again['replayed']);self.assertEqual(again['data'],original['data'])
        self.assertEqual((folder/'report.json').read_bytes(),old_report)
        (folder/'sources/s1.bin').write_bytes(b'corrupt')
        for result in (page,program):
            with self.assertRaises(ValueError):operations.result(self.state,result['run_id'])

    def test_managed_window_normalization_and_mcp_schema_are_shared(self):
        cid='a'*32;selected=dict(case_id=cid,window=WINDOW)
        request=capabilities.normalize_request(self.request('case.events',selected,'normalize-window'))
        self.assertEqual(request['arguments']['window']['start'],'2026-11-18T06:01:00+00:00')
        _,_,mcp=mcp_tools.prepare('techexpert_case_events',dict(operation_key='mcp-window',executor_id='fixture',arguments=selected))
        self.assertEqual(mcp['arguments']['window'],request['arguments']['window'])

    def test_cli_general_input_and_paired_period_flags(self):
        def cli(*args,expected=0):
            result=subprocess.run([sys.executable,'-B','-X','utf8',str(ROOT/'techexpert.py'),'--state-dir',str(self.state),*args],cwd=self.root,capture_output=True,timeout=30)
            self.assertEqual(result.returncode,expected,(result.stdout+result.stderr).decode('utf-8','replace'))
            return json.loads(result.stdout)
        cid=cli('analyze',str(self.manifest))['case_id']
        self.assertEqual(cli('events',cid,'--start',WINDOW['start'],'--end',WINDOW['end'])['matched_count'],1)
        error=cli('events',cid,'--start',WINDOW['start'],expected=2)
        self.assertEqual(error['code'],'input_or_state_error');self.assertIn('both',error['message'])

    def test_explicit_old_sc01_profiles_remain_unchanged(self):
        self.write(dict(self.doc,schema=1,scenario='SC-01'))
        with self.assertRaisesRegex(ValueError,'selection'):inputs.load_manifest(self.manifest)
        fixture=ROOT/'tests/fixtures/order-load/baseline.json';report=storage.investigate(fixture,self.state)
        self.assertEqual(report['scenario'],'SC-01');self.assertEqual(report['order_load']['status'],'observed')
        self.assertEqual(report['source_coverage']['scope'],'SC01_native_TJ_only')

    def test_unselected_call_durations_do_not_become_a_verified_improvement(self):
        before=self.case()['case_id'];self.log.write_bytes(RAW.replace(b'1200000000',b'1'));after=self.case()['case_id']
        result=storage.compare_cases(self.state,[before],[after])
        self.assertEqual(result['status'],'not_verified')
        self.assertEqual(result['performance']['status'],'not_comparable')
        self.assertIsNone(result['cause'])

    def test_selected_zip_inputs_use_the_general_manifest_without_sc01_labels(self):
        archive=self.root/'provided.zip'
        with zipfile.ZipFile(archive,'w') as zipped:zipped.writestr('logs/one.log',RAW)
        inspected=operations.run(self.state,self.request('input.inspect',dict(inputs=[dict(path=str(archive),kind='zip')]),'generic-preview'))
        self.assertEqual(inspected['status'],'succeeded',inspected)
        member=inspected['data']['result']['members'][0]['id']
        self.write(dict(self.doc,sources=[dict(PROFILE,path=member)]))
        request=self.request('case.analyze',dict(manifest=str(self.manifest),input_plan=inspected['data']['artifact_id']),'generic-selected')
        captured=operations.run(self.state,request);self.assertEqual(captured['status'],'succeeded',captured)
        cid=captured['data']['case_id'];self.assertEqual(captured['data']['scenario'],'native-tj-observations')
        self.assertEqual(storage.list_native_events(self.state,cid,window=WINDOW)['matched_count'],1)
        self.manifest.unlink();archive.unlink();self.log.unlink()
        self.assertEqual(operations.run(self.state,request)['data'],captured['data'])


if __name__=='__main__':unittest.main()
