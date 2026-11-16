import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import tempfile
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from src.techexpert.inputs import load_manifest,read_snapshot
from src.techexpert.storage import investigate,load_case,ROOT

SCOPE=dict(database='orders',node='node-a',process='rphost-1',epoch='boot-1',run='job-42')
WINDOW=dict(start='2026-11-16T10:00:00+03:00',end='2026-11-16T10:05:00+03:00')


class SourceCoverageTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.source_coverage'),
                             'SC-01 source coverage check is missing')
        self.api=importlib.import_module('src.techexpert.source_coverage')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.state=self.root/'state'
        self.log=self.root/'provided-tj.txt';self.log.write_text(self.record('10:02:00','CALL','SQL="select 1",SessionID=12'),encoding='utf-8')

    @staticmethod
    def record(time,event='CALL',properties='SessionID=12'):
        return '2026-11-16T'+time+'.000001-123,'+event+',1,'+properties+'\n'

    def spec(self,**kwargs):
        return dict(path=str(self.log),format='1c-tj-text-v1',platform_version='8.3.27.1989',encoding='utf-8',
                    placement='plain',timestamp_format='iso',utc_offset='+03:00',**kwargs)

    def manifest(self,sources=None,**kwargs):
        path=self.root/'manifest.json'
        path.write_text(json.dumps(dict(schema=1,scenario='SC-01',origin='provided',selection=SCOPE,
            sources=sources if sources is not None else [self.spec()],**kwargs)),encoding='utf-8')
        return path

    def check(self,**kwargs):return self.api.inspect_manifest(self.manifest(),**kwargs)

    def test_observed_range_never_proves_continuity_or_clock_alignment(self):
        result=self.check(window=WINDOW);source=result['sources'][0]
        self.assertEqual(source['availability'],'captured')
        self.assertEqual(source['period']['records_in_window'],1)
        self.assertEqual(source['period']['status'],'observed_timestamps_in_window')
        self.assertEqual(source['continuity'],'unknown')
        self.assertEqual(source['clock_alignment'],'not_verified')
        self.assertFalse(result['can_establish_absence'])
        self.assertFalse(self.state.exists())

    def test_straddling_range_with_no_record_inside_is_not_coverage(self):
        self.log.write_text(self.record('09:50:00')+self.record('10:10:00'),encoding='utf-8')
        source=self.check(window=WINDOW)['sources'][0]
        self.assertTrue(source['period']['span_intersects_window'])
        self.assertEqual(source['period']['records_in_window'],0)
        self.assertEqual(source['period']['status'],'no_recorded_timestamps_in_window')
        self.assertEqual(source['continuity'],'unknown')

    def test_half_open_window_and_offset_conversion(self):
        self.log.write_text((self.record('10:00:00')+self.record('10:05:00')).replace('.000001','.000000'),encoding='utf-8')
        window=dict(start='2026-11-16T07:00:00Z',end='2026-11-16T07:05:00Z')
        self.assertEqual(self.check(window=window)['sources'][0]['period']['records_in_window'],1)

    def test_invalid_requests_are_rejected_before_reading_logs(self):
        for window in (dict(start='2026-11-16T10:00:00',end=WINDOW['end']),dict(start=WINDOW['end'],end=WINDOW['start']),dict(WINDOW,unknown=True)):
            with self.subTest(window=window),self.assertRaises(ValueError):self.check(window=window)
        for kwargs in (dict(required_events=['CALL']*17),dict(required_events=['CALL','CALL']),dict(required_fields=['SQL\nsecret']),dict(required_events=['not an event'])):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):self.check(**kwargs)

    def test_missing_event_is_unknown_without_collection_evidence(self):
        source=self.check(window=WINDOW,required_events=['DBMSSQL'])['sources'][0]
        self.assertEqual(source['requirements']['events']['DBMSSQL']['status'],'not_observed_collection_unknown')
        self.assertEqual(source['collection']['status'],'unknown')

    def test_declared_filters_remain_unverified_and_conflicts_visible(self):
        spec=self.spec(collection=dict(events=['SDBL'],filters='duration > 1000000',window=WINDOW))
        result=self.api.inspect_manifest(self.manifest([spec]),window=WINDOW,required_events=['DBMSSQL','CALL'])
        source=result['sources'][0]
        self.assertEqual(source['collection']['status'],'user_declared_not_verified')
        self.assertEqual(source['requirements']['events']['DBMSSQL']['status'],'not_collected_declared')
        self.assertEqual(source['requirements']['events']['CALL']['status'],'declaration_conflicts_with_observed')
        self.assertFalse(result['can_establish_absence'])

    def test_collection_declaration_applies_only_within_its_declared_period(self):
        self.log.write_text(self.record('09:59:00','CALL')+self.record('10:02:00','SDBL'),encoding='utf-8')
        manifest=self.manifest([self.spec(collection=dict(events=['SDBL'],window=WINDOW))])
        inside=self.api.inspect_manifest(manifest,window=WINDOW,required_events=['CALL'])['sources'][0]
        self.assertEqual(inside['requirements']['events']['CALL']['status'],'not_collected_declared')
        outside_window=dict(start='2026-11-16T09:50:00+03:00',end='2026-11-16T09:55:00+03:00')
        outside=self.api.inspect_manifest(manifest,window=outside_window,required_events=['CALL'])['sources'][0]
        self.assertEqual(outside['requirements']['events']['CALL']['status'],'not_observed_collection_unknown')

    def test_fields_are_checked_only_for_requested_events_and_window(self):
        self.log.write_text(self.record('09:59:00','DBMSSQL','SQL="outside"')+
            self.record('10:02:00','CALL','SQL="unrelated"')+
            self.record('10:03:00','DBMSSQL','SessionID=12'),encoding='utf-8')
        source=self.check(window=WINDOW,required_events=['DBMSSQL'],required_fields=['SQL'])['sources'][0]
        field=source['requirements']['fields']['SQL']
        self.assertEqual(field['usable_records'],0)
        self.assertEqual(field['considered_records'],1)
        self.assertEqual(field['status'],'not_observed')

    def test_duplicate_and_empty_fields_do_not_become_usable(self):
        self.log.write_text(self.record('10:01:00','CALL','SQL="",SessionID=12')+
            self.record('10:02:00','CALL','SQL="one",SQL="two"'),encoding='utf-8')
        source=self.check(required_fields=['SQL'])['sources'][0];field=source['requirements']['fields']['SQL']
        self.assertEqual(field['usable_records'],0)
        self.assertEqual(field['empty_records'],1)
        self.assertEqual(field['ambiguous_records'],1)
        self.assertEqual(source['parse_status'],'partial')
        self.assertTrue(any(issue['code']=='ambiguous_property' for issue in source['issues']))

    def test_unknown_event_and_declared_context_are_not_identity_proof(self):
        self.log.write_text(self.record('10:02:00','NEW_EVENT','p:processName=orders'),encoding='utf-8')
        result=self.api.inspect_manifest(self.manifest([self.spec(context=dict(node='user-node'))]))
        source=result['sources'][0]
        self.assertEqual(source['events']['observed_counts'],{'NEW_EVENT':1})
        self.assertEqual(source['identity']['status'],'not_established_by_coverage')
        self.assertEqual(source['identity']['declared_context'],{'node':'user-node'})

    def test_empty_invalid_and_missing_inputs_remain_distinct(self):
        for data,parse_status in ((b'','empty'),(b'not TJ\n','invalid')):
            self.log.write_bytes(data)
            source=self.check()['sources'][0]
            self.assertEqual(source['availability'],'captured');self.assertEqual(source['parse_status'],parse_status)
        self.log.unlink();source=self.check()['sources'][0]
        self.assertEqual(source['availability'],'not_found')

    def test_access_error_and_byte_budget_are_not_no_data(self):
        def reader(path,*args,**kwargs):
            if Path(path)==self.log:raise PermissionError('access denied test')
            return read_snapshot(path,*args,**kwargs)
        with patch('src.techexpert.inputs.read_snapshot',side_effect=reader):
            self.assertEqual(self.check()['sources'][0]['availability'],'access_denied')
        with patch('src.techexpert.inputs.MAX_FILE_BYTES',4):
            self.assertEqual(self.check()['sources'][0]['availability'],'byte_limit')

    def test_inspection_keeps_good_sources_and_does_not_open_unsupported_path(self):
        sources=[dict(path='//unreachable/private',format='unsupported-format'),self.spec()]
        result=self.api.inspect_manifest(self.manifest(sources))
        self.assertEqual([s['availability'] for s in result['sources']],['unsupported_format','captured'])
        self.assertEqual(result['sources'][1]['record_count'],1)

        with self.assertRaises(ValueError):load_manifest(self.manifest(sources))
        sources=[dict(self.spec(),platform_version='8.3.99.1'),self.spec()]
        result=self.api.inspect_manifest(self.manifest(sources))
        self.assertEqual(result['sources'][0]['availability'],'unsupported_profile')
        self.assertEqual(result['sources'][1]['record_count'],1)

    def test_tolerant_inspection_handles_invalid_context_and_non_tj_profile(self):
        declarations=[dict(path='//unreachable',format='1c-job-runtime-v1'),
            dict(path='//unreachable',format='sc01-orders-csv-v1'),
            dict(self.spec(),path='bad\x00path'),dict(self.spec(),context=['not a context'])]
        for spec in declarations:
            with self.subTest(spec=spec):
                result=self.api.inspect_manifest(self.manifest([spec,self.spec()]))
                self.assertNotEqual(result['sources'][0]['availability'],'captured')
                self.assertEqual(result['sources'][1]['record_count'],1)

    def test_changed_snapshot_and_generic_read_failure_have_exact_states(self):
        from src.techexpert.inputs import SnapshotReadError
        for error,expected in ((SnapshotReadError('changed','changed_during_read'),'changed_during_read'),(OSError('I/O failure'),'read_error')):
            def reader(path,*args,**kwargs):
                if Path(path)==self.log:raise error
                return read_snapshot(path,*args,**kwargs)
            with self.subTest(expected=expected),patch('src.techexpert.inputs.read_snapshot',side_effect=reader):
                self.assertEqual(self.check()['sources'][0]['availability'],expected)

    def test_same_path_different_collection_declarations_are_not_merged(self):
        result=self.api.inspect_manifest(self.manifest([self.spec(collection=dict(events=['CALL'])),self.spec(collection=dict(events=['SDBL']))]))
        self.assertEqual(result['sources'][1]['availability'],'conflicting_profile')

    def test_duplicate_declarations_do_not_double_count_observations(self):
        result=self.api.inspect_manifest(self.manifest([self.spec(),self.spec()]))
        self.assertEqual(result['sources'][1]['availability'],'duplicate_source')
        self.assertEqual(result['sources'][1]['duplicate_of'],'s1')

    def test_event_and_field_summaries_are_bounded_with_explicit_omission(self):
        self.log.write_text(''.join(self.record('10:02:00','NEW_'+str(i),'Field'+str(i)+'=value') for i in range(300)),encoding='utf-8')
        source=self.check()['sources'][0]
        self.assertEqual(source['record_count'],300)
        self.assertLessEqual(len(source['events']['observed_counts']),100)
        self.assertLessEqual(len(source['fields']['observed_counts']),100)
        self.assertTrue(source['events']['names_truncated'])
        self.assertTrue(source['fields']['names_truncated'])

    def test_unusable_period_is_visible_at_the_report_level(self):
        self.log.write_text(self.record('11:00:00'),encoding='utf-8')
        result=self.check(window=WINDOW)
        self.assertEqual(result['status'],'no_usable_tj_records_in_scope')

    def test_parse_errors_have_bounded_locations_and_no_false_fullness(self):
        self.log.write_bytes(self.record('10:02:00').encode()+b'\xff\n'+b'bad record\n'*30)
        source=self.check()['sources'][0]
        self.assertLessEqual(len(source['issues']),20)
        self.assertTrue(source['issues_truncated'])
        self.assertEqual(source['parse_status'],'partial')
        self.assertTrue(any('byte_start' in issue for issue in source['issues']))

    def test_analyze_embeds_coverage_and_manifest_window(self):
        result=investigate(self.manifest(incident_window=WINDOW),self.state)
        self.assertEqual(result['source_coverage']['sources'][0]['period']['records_in_window'],1)
        self.assertFalse(result['source_coverage']['can_establish_absence'])
        self.assertEqual(load_case(self.state,result['case_id'])['source_coverage'],result['source_coverage'])

    def test_saved_replay_never_reads_original_and_preserves_report(self):
        result=investigate(self.manifest(),self.state)
        folder=self.state/'cases'/result['case_id'];before=(folder/'report.json').read_bytes()
        self.log.write_text('original changed',encoding='utf-8')
        replay=self.api.inspect_case(self.state,result['case_id'],window=WINDOW,required_fields=['SQL'])
        self.assertEqual(replay['sources'][0]['record_count'],1)
        self.assertTrue(replay['native_snapshot_integrity_verified'])
        self.assertEqual((folder/'report.json').read_bytes(),before)
        self.assertEqual(replay['case_report_sha256'],hashlib.sha256(before).hexdigest())
        (folder/'sources/s1.bin').write_bytes(b'corrupted')
        with self.assertRaises(ValueError):self.api.inspect_case(self.state,result['case_id'])

    @unittest.skipUnless(os.name=='nt','Windows junction boundary')
    def test_saved_replay_rejects_a_snapshot_directory_junction(self):
        result=investigate(self.manifest(),self.state);folder=self.state/'cases'/result['case_id']
        leaf=folder/'sources';data=(leaf/'s1.bin').read_bytes();target=self.root/'external';target.mkdir();(target/'s1.bin').write_bytes(data)
        (leaf/'s1.bin').unlink();leaf.rmdir()
        script=self.root/'junction.ps1';script.write_text("param([string]$LeafPath,[string]$TargetPath)\n$ErrorActionPreference='Stop'\nNew-Item -ItemType Junction -Path $LeafPath -Target $TargetPath -ErrorAction Stop | Out-Null\n",encoding='utf-8-sig')
        run=subprocess.run(['C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(script),'-LeafPath',str(leaf),'-TargetPath',str(target)],capture_output=True,timeout=10)
        if run.returncode:self.skipTest('Junction creation unavailable, exit '+str(run.returncode))
        try:
            with self.assertRaises(ValueError):self.api.inspect_case(self.state,result['case_id'])
        finally:os.rmdir(leaf)
        self.assertEqual((target/'s1.bin').read_bytes(),data)

    def test_legacy_case_without_coverage_is_derived_without_rewrite(self):
        result=investigate(self.manifest(),self.state);folder=self.state/'cases'/result['case_id']
        report=json.loads((folder/'report.json').read_text(encoding='utf-8'));report.pop('source_coverage',None);report.pop('source_acquisition',None)
        data=json.dumps(report).encode();(folder/'report.json').write_bytes(data)
        receipt=json.loads((folder/'receipt.json').read_text(encoding='utf-8'));receipt['report_sha256']=hashlib.sha256(data).hexdigest();(folder/'receipt.json').write_text(json.dumps(receipt),encoding='utf-8')
        self.log.unlink();replay=self.api.inspect_case(self.state,result['case_id'])
        self.assertFalse(replay['persisted_coverage_available'])
        self.assertEqual(replay['sources'][0]['record_count'],1)
        self.assertEqual((folder/'report.json').read_bytes(),data)

    def test_non_tj_sources_are_not_assessed_as_tj_coverage(self):
        path=self.root/'demo.json';path.write_bytes((ROOT/'examples/sc01/case.json').read_bytes())
        doc=json.loads(path.read_text(encoding='utf-8'));doc['sources'][0]['path']=str(ROOT/'examples/sc01/events.jsonl');path.write_text(json.dumps(doc),encoding='utf-8')
        result=self.api.inspect_manifest(path)
        self.assertEqual(result['sources'][0]['assessment'],'not_assessed_by_tj_check')
        self.assertFalse(result['can_establish_absence'])

    def test_cli_preflight_and_saved_query_do_not_need_native_process_or_original(self):
        manifest=self.manifest();env=dict(os.environ)
        command=[sys.executable,'-X','utf8',str(ROOT/'techexpert.py'),'--state-dir',str(self.state)]
        first=subprocess.run(command+['source-check',str(manifest),'--start',WINDOW['start'],'--end',WINDOW['end'],'--require-event','CALL'],cwd=self.root,capture_output=True,env=env,timeout=15)
        self.assertEqual(first.returncode,0,first.stderr.decode('utf-8',errors='replace'))
        self.assertEqual(json.loads(first.stdout)['sources'][0]['period']['records_in_window'],1)
        self.assertFalse(self.state.exists())
        case=investigate(manifest,self.state);self.log.unlink()
        second=subprocess.run(command+['coverage',case['case_id'],'--require-field','SQL'],cwd=self.root,capture_output=True,env=env,timeout=15)
        self.assertEqual(second.returncode,0,second.stderr.decode('utf-8',errors='replace'))
        self.assertTrue(json.loads(second.stdout)['native_snapshot_integrity_verified'])


if __name__=='__main__':unittest.main()
