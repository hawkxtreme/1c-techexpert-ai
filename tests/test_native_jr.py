import hashlib
import importlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import json
import subprocess
import sys

JOURNAL='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
HEADER=('\ufeff1CV8LOG(ver 2.0)\r\n'+JOURNAL+'\r\n\r\n').encode()
DICTIONARY=HEADER+b'{2,"host-a",1},\r\n{3,"BackgroundJob",1},\r\n{4,"_$Job$_.Start",1},\r\n{4,"_$Job$_.Finish",2}'

def event(timestamp='20261116120000',kind='1',comment='""'):
    return ('{'+timestamp+',N,{0,0},0,1,1,2,'+kind+',I,'+comment+',0,{"U"},"",0,0,0,2,0,{0}}').encode()

class NativeJRTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.native_jr'),'native sequential JR reader is missing')
        self.api=importlib.import_module('src.techexpert.native_jr')

    def test_captured_sanitized_native_fixture_matches_its_passport(self):
        root=Path(__file__).parent/'fixtures/native-jr'
        passport=json.loads((root/'passport.json').read_text(encoding='utf-8'))
        sources=[]
        for name,metadata in passport['members'].items():
            data=(root/name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(),metadata['sha256'])
            sources.append((name,data))
        result=self.api.parse_snapshot(sources)
        self.assertEqual(result['event_count'],passport['expected']['event_count'])
        self.assertEqual([r['event'] for r in result['records']],passport['expected']['event_names'])
        self.assertFalse(result['issues'])
        self.assertTrue(all(r['computer']=='host-a' for r in result['records']))
        self.assertIsNone(result['complete_incident_coverage'])

    def test_nested_multiline_quoted_braces_and_byte_evidence(self):
        raw=event(comment='"Строка {x},\r\nи ""кавычки"""')
        data=HEADER+raw+b',\r\n'+event('20261116120003','2')
        result=self.api.parse_snapshot([('1Cv8.lgf',DICTIONARY),('20261116000000.lgp',data)],utc_offset='+03:00')
        self.assertEqual(result['event_count'],2)
        first=result['records'][0]
        self.assertEqual(first['event'],'_$Job$_.Start')
        self.assertEqual(first['comment'],'Строка {x},\r\nи "кавычки"')
        self.assertEqual(first['timestamp'],'2026-11-16T12:00:00+03:00')
        self.assertEqual(data[first['byte_start']:first['byte_end']],raw)
        self.assertEqual(first['sha256'],hashlib.sha256(raw).hexdigest())
        self.assertIsNone(result['database_identity'])
        self.assertIsNone(result['complete_incident_coverage'])

    def test_incomplete_tail_keeps_events_and_unknown_timezone_stays_unknown(self):
        data=HEADER+event()+b',\r\n{20261116120003,N,{0,'
        result=self.api.parse_snapshot([('1Cv8.lgf',DICTIONARY),('20261116000000.lgp',data)])
        self.assertEqual(result['event_count'],1)
        self.assertIsNone(result['records'][0]['timestamp'])
        self.assertEqual(result['records'][0]['local_time'],'2026-11-16T12:00:00')
        self.assertEqual(result['status'],'partial')
        self.assertIn('incomplete_record',{issue['code'] for issue in result['issues']})

    def test_mismatched_journal_dictionary_conflict_and_bad_record_are_not_silent(self):
        dictionary=DICTIONARY+b',\n{4,"different-event",1}'
        result=self.api.parse_snapshot([('1Cv8.lgf',dictionary),('20261116000000.lgp',HEADER+event()+b',\n{bad}')])
        self.assertIsNone(result['records'][0]['event'])
        self.assertIn('ambiguous_dictionary',{issue['code'] for issue in result['issues']})
        self.assertIn('invalid_event_record',{issue['code'] for issue in result['issues']})
        bad=HEADER.replace(JOURNAL.encode(),b'ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee')+event()
        with self.assertRaises(ValueError):self.api.parse_snapshot([('1Cv8.lgf',DICTIONARY),('20261116000000.lgp',bad)])

    def test_private_snapshot_resumes_after_original_changes_and_detects_corruption(self):
        from src.techexpert.artifacts import artifact_folder
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);jr=root/'input';jr.mkdir();state=root/'state'
            (jr/'1Cv8.lgf').write_bytes(DICTIONARY)
            (jr/'20261116000000.lgp').write_bytes(HEADER+event()+b',\n'+event('20261116120003','2'))
            report=self.api.read_journal(state,jr,platform_version='8.3.27.1989')
            self.assertEqual(report['result']['event_count'],2)
            self.assertEqual(report['result']['consistency'],'unknown')
            aid=report['artifact_id'];(jr/'20261116000000.lgp').write_bytes(b'changed')
            records=self.api.list_events(state,aid,event='_$Job$_.Finish')
            self.assertEqual(records['total_matched'],1)
            self.assertEqual(records['records'][0]['local_time'],'2026-11-16T12:00:03')
            evidence=self.api.read_record(state,aid,records['records'][0]['id'])
            self.assertTrue(evidence['integrity_verified'])
            source=artifact_folder(state,aid)/'sources/s2.bin';source.write_bytes(b'corrupt')
            with self.assertRaises(ValueError):self.api.list_events(state,aid)

    def test_second_snapshot_read_cannot_become_unverified_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);jr=root/'input';jr.mkdir();state=root/'state'
            (jr/'1Cv8.lgf').write_bytes(DICTIONARY);(jr/'20261116000000.lgp').write_bytes(HEADER+event())
            report=self.api.read_journal(state,jr,platform_version='8.3.27.1989')
            original=self.api.read_snapshot
            def changed(path,*args):
                return HEADER+event('20261116123456') if Path(path).name=='s2.bin' else original(path,*args)
            with patch.object(self.api,'read_snapshot',side_effect=changed):
                with self.assertRaisesRegex(ValueError,'integrity'):self.api.list_events(state,report['artifact_id'])

    def test_cli_import_and_record_use_saved_native_evidence(self):
        repo=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);jr=root/'input';jr.mkdir();state=root/'state'
            (jr/'1Cv8.lgf').write_bytes(DICTIONARY);(jr/'20261116000000.lgp').write_bytes(HEADER+event())
            command=[sys.executable,'-X','utf8',str(repo/'techexpert.py'),'--state-dir',str(state)]
            imported=subprocess.run(command+['jr-import',str(jr),'--platform-version','8.3.27.1989','--utc-offset=+03:00'],capture_output=True,timeout=10)
            self.assertEqual(imported.returncode,0,imported.stderr.decode('utf-8',errors='replace'))
            aid=json.loads(imported.stdout)['artifact_id']
            listed=subprocess.run(command+['jr-events',aid,'--start','2026-11-16T09:00:00Z','--end','2026-11-16T09:00:01Z'],capture_output=True,timeout=10)
            self.assertEqual(listed.returncode,0,listed.stderr.decode('utf-8',errors='replace'))
            record=json.loads(listed.stdout)['records'][0]
            proof=subprocess.run(command+['jr-record',aid,record['id']],capture_output=True,timeout=10)
            self.assertEqual(proof.returncode,0,proof.stderr.decode('utf-8',errors='replace'))
            self.assertEqual(json.loads(proof.stdout)['text'].encode(),event())

    def test_window_preserves_evidence_ids_and_keeps_parse_limits_separate(self):
        window = dict(start='2026-11-16T12:00:00+03:00',end='2026-11-16T10:00:03+01:00')
        expected = dict(start='2026-11-16T09:00:00+00:00',end='2026-11-16T09:00:03+00:00')
        included = event('20261116120000')
        row = [event('20261116120003','2'), included, event('20261116120002','2'), event('20261116115959')]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jr = root/'input'
            jr.mkdir()
            (jr/'1Cv8.lgf').write_bytes(DICTIONARY)
            (jr/'20261116000000.lgp').write_bytes(HEADER+b',\n'.join(row)+b',\n{bad')
            state = root/'state'
            report = self.api.read_journal(state,jr,platform_version='8.3.27.1989',utc_offset='+03:00')
            aid = report['artifact_id']
            jr.rename(root/'original-not-at-selected-path')

            checked = self.api.list_events(state,aid,window=window,event='_$Job$_.Start')
            self.assertEqual(checked['window'],expected)
            self.assertEqual(checked['coverage']['records_in_window'],2)
            self.assertEqual(checked['coverage']['parse_status'],'partial')
            self.assertEqual(checked['coverage']['observed_utc_range'],[
                '2026-11-16T08:59:59+00:00','2026-11-16T09:00:03+00:00'])
            self.assertEqual(checked['coverage']['status'],'observed_timestamps_in_window')
            self.assertFalse(checked['coverage']['can_establish_absence'])
            self.assertIsNone(checked['complete_incident_coverage'])
            self.assertEqual(checked['total_matched'],1)
            self.assertEqual([entry['id'] for entry in checked['records']],['s2:r2'])
            self.assertEqual(self.api.read_record(state,aid,'s2:r2')['text'],included.decode('utf-8'))

            page = self.api.list_events(state,aid,window=window,offset=1,limit=1)
            self.assertEqual(page['total_matched'],2)
            self.assertEqual([entry['id'] for entry in page['records']],['s2:r3'])

    def test_empty_window_and_unknown_offset_have_different_observations(self):
        distant = dict(start='2026-11-17T09:00:00Z',end='2026-11-17T09:00:01Z')
        straddling = dict(start='2026-11-16T09:00:01Z',end='2026-11-16T09:00:02Z')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jr = root/'input'
            jr.mkdir()
            (jr/'1Cv8.lgf').write_bytes(DICTIONARY)
            (jr/'x.lgp').write_bytes(HEADER+event()+b',\n'+event('20261116120003','2'))
            state = root/'state'
            known = self.api.read_journal(state,jr,platform_version='8.3.27.1989',utc_offset='+03:00')['artifact_id']
            outside = self.api.list_events(state,known,window=distant)['coverage']
            gap = self.api.list_events(state,known,window=straddling)['coverage']
            for details in (outside,gap):
                self.assertEqual(details['status'],'no_recorded_timestamps_in_window')
                self.assertEqual(details['records_in_window'],0)
                self.assertFalse(details['can_establish_absence'])
            self.assertFalse(outside['span_intersects_window'])
            self.assertTrue(gap['span_intersects_window'])

            unknown = self.api.read_journal(state,jr,platform_version='8.3.27.1989')['artifact_id']
            page = self.api.list_events(state,unknown,window=distant)
            self.assertEqual(page['records'],[])
            self.assertEqual(page['coverage']['status'],'time_zone_unknown')
            self.assertIsNone(page['coverage']['records_in_window'])
            self.assertIsNone(page['coverage']['span_intersects_window'])
            self.assertEqual(page['coverage']['parsed_records'],2)

    def test_window_requires_two_ordered_explicit_instants_before_snapshot_read(self):
        start = '2026-11-16T09:00:00Z'
        for window in (dict(start=start),dict(start=start,end=start),
                       dict(start='2026-11-16T09:00:00',end=start),
                       dict(start='2026-11-16T08:59:00-00:00',end=start)):
            with self.subTest(window=window), patch.object(self.api,'_saved',side_effect=AssertionError('snapshot read')):
                with self.assertRaises(ValueError):
                    self.api.list_events(Path('.'),'0'*32,window=window)

    def test_unsupported_versions_lgd_links_and_record_budgets_fail_closed(self):
        with self.assertRaisesRegex(ValueError,'record exceeds'):
            self.api.parse_snapshot([('1Cv8.lgf',DICTIONARY),('x.lgp',HEADER+b'{'+b' '*262145+b'}')])
        with self.assertRaises(ValueError):self.api.parse_snapshot([('1Cv8.lgf',DICTIONARY),('x.lgp',HEADER+b'{'+b'a'*262145+b'}')])
        with self.assertRaises(ValueError):self.api.parse_snapshot([('1Cv8.lgf',HEADER+b'{'*40+b'}'*40)])
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            with self.assertRaises(ValueError):self.api.read_journal(root/'state',root,platform_version='8.3.26')
            (root/'1Cv8.lgd').write_bytes(b'SQLite format 3\x00')
            with self.assertRaisesRegex(ValueError,'LGD'):self.api.read_journal(root/'state',root,platform_version='8.3.27.1989')

if __name__=='__main__':unittest.main()
