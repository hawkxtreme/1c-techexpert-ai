"""Reconstruct only supported job boundaries from verified native journal rows."""
from pathlib import Path
import json
import tempfile
import unittest

from src.techexpert import artifacts, context_disclosure, context_policy, investigations, native_jr


PRIVATE='private-job-and-account-marker'
WINDOW=dict(start='2026-11-19T12:00:00Z',end='2026-11-19T12:02:00Z')
UUID='12345678-1234-4321-8123-123456789012'
EVENTS=('Session.Start','Session.Finish','Job.Start','Job.Finish')


class ContextJRJobsTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.state=self.root/'state'
        self.attachment='A-jr'

    def journal(self, parts, *, utc_offset='+00:00'):
        folder=self.root/'jr'
        folder.mkdir(exist_ok=True)
        header=f'1CV8LOG(ver 2.0)\n{UUID}\n'
        dictionary=[f'{{1,"{PRIVATE}",1}}','{2,"LocalMachine",1}','{3,"BackgroundJob",1}']
        for index,event in enumerate(EVENTS,1):
            group,_,action=event.partition('.')
            dictionary.append(f'{{4,"_${group}$_.{action}",{index}}}')
        (folder/'1Cv8.lgf').write_text(header+',\n'.join(dictionary)+',\n',encoding='utf-8')
        for number, rows in enumerate(parts,1):
            records=[]
            for minute,second,kind in rows:
                data=f'{{"S","{PRIVATE}"}}' if kind>2 else '{"U"}'
                records.append(f'{{2026111912{minute:02d}{second:02d},N,0,1,1,1,2,{kind},I,"",0,{data},0,0,0,0,17,0,0}}')
            (folder/f'2026111912{number:02d}00.lgp').write_text(header+',\n'.join(records)+',\n',encoding='utf-8')
        self.artifact=native_jr.read_journal(self.state,folder,platform_version='8.3.27.1989',utc_offset=utc_offset)
        created=investigations.create(self.state,dict(task='Проверить запуск по журналу регистрации'))
        self.iid=created['investigation_id']
        self.revision=investigations.revise(self.state,self.iid,dict(attachments=[
            dict(id=self.attachment,kind='artifact',target_id=self.artifact['artifact_id'])]),expected_revision=1)['revision']

    def allow(self,*categories):
        options=(self.state,self.iid,self.revision,categories,4096)
        saved=context_policy.plan(*options)
        context_policy.save(*options,saved['plan_sha256'])

    def view(self,**args):
        result=context_disclosure.read(self.state,dict(investigation_id=self.iid,revision=self.revision,
            kind='jr-job-runs',attachment=self.attachment,**args))
        self.assertNotIn(PRIVATE,json.dumps(result))
        return result

    def test_window_finds_recorded_pairs_with_separate_epochs_and_byte_evidence(self):
        first=[(0,0,1),(0,1,3),(0,7,4),(0,8,2)]
        second=[(1,0,1),(1,1,3),(1,9,4),(1,10,2)]
        self.journal([first+second])
        self.allow('tj')
        self.assertEqual(self.view(window=WINDOW)['stop_reason'],'context_category_not_allowed')
        self.allow('jr')
        result=self.view(window=WINDOW)
        self.assertEqual(result['status'],'succeeded',result)
        page=result['data']
        self.assertEqual(page['matched_count'],2)
        rows=page['records']
        if page['next_offset'] is not None:
            self.assertTrue(page['byte_limit_reached'])
            continuation=self.view(window=WINDOW,offset=page['next_offset'])['data']
            rows=rows+continuation['records']
        a,b=rows
        self.assertEqual([row['status'] for row in (a,b)],['paired_markers']*2)
        self.assertEqual([row['recorded_wall_seconds'] for row in (a,b)],[6,8])
        self.assertNotEqual(a['session_instance'],b['session_instance'])
        self.assertEqual(a['job_label'],b['job_label'])
        for field,ordinal in (('session_start',1),('start',2),('finish',3),('session_finish',4)):
            proof=a[field]['evidence']
            self.assertEqual(proof['id'],f's2:r{ordinal}')
            self.assertGreater(proof['byte_end'],proof['byte_start'])
            self.assertEqual(proof['source_sha256'],self.artifact['sources'][1]['sha256'])
        self.assertEqual(a['execution_outcome'],'unknown')
        self.assertFalse(result['data']['can_establish_absence'])
        between=self.view(window=dict(start='2026-11-19T12:00:03Z',end='2026-11-19T12:00:04Z'))['data']
        self.assertEqual(between['records'],[a])
        self.assertEqual(self.view(record='s2:r3')['data']['records'],[a])
        held=artifacts.artifact_folder(self.state,self.artifact['artifact_id'])/'sources'/'s2.bin'
        held.write_bytes(b'changed evidence')
        self.assertEqual(self.view(record='s2:r3')['stop_reason'],'context_evidence_unavailable')

    def test_reused_numeric_session_does_not_join_across_missing_boundary(self):
        self.journal([[(0,0,1),(0,1,3),(0,2,1),(0,3,4),(0,4,2)]])
        self.allow('jr')
        first,last=self.view(window=WINDOW)['data']['records']
        self.assertEqual(first['status'],'session_boundary_missing')
        self.assertEqual(last['status'],'unpaired_marker')
        self.assertIsNone(first['finish'])
        self.assertIsNone(last['start'])
        self.assertTrue(all(run['recorded_wall_seconds'] is None for run in (first,last)))

    def test_pairs_across_parts_preserve_candidates_without_confirming_continuity(self):
        self.journal([[(0,0,1),(0,1,3)],[(0,7,4),(0,8,2)]])
        self.allow('jr')
        row,=self.view(window=WINDOW)['data']['records']
        self.assertEqual(row['status'],'different_parts')
        self.assertEqual(row['start']['evidence']['id'],'s2:r2')
        self.assertEqual(row['finish']['evidence']['id'],'s3:r1')
        self.assertIsNone(row['recorded_wall_seconds'])

    def test_unknown_offset_keeps_record_selection_and_blocks_time_matching(self):
        self.journal([[(0,0,1),(0,1,3),(0,7,4),(0,8,2)]],utc_offset=None)
        self.allow('jr')
        data=self.view(window=WINDOW)['data']
        self.assertIsNone(data['matched_count'])
        self.assertEqual(data['coverage']['untimed_candidates'],1)
        row,=self.view(record='s2:r2')['data']['records']
        self.assertEqual(row['status'],'paired_markers')
        self.assertEqual(row['start']['recorded_local_time'],'2026-11-19T12:00:01')
        self.assertIsNone(row['start']['timestamp'])

    def test_repeated_parts_cannot_supply_independent_intervals(self):
        part=[(0,0,1),(0,1,3),(0,7,4),(0,8,2)]
        self.journal([part,part])
        self.allow('jr')
        for record in ('s2:r2','s3:r2'):
            with self.subTest(record=record):
                result=self.view(record=record)['data']
                row,=result['records']
                self.assertEqual(row['status'],'duplicate_part_bytes')
                self.assertIsNone(row['recorded_wall_seconds'])
