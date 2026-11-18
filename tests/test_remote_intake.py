"""A retained remote capture feeds existing parsers without reconnecting."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from src.techexpert import artifacts,input_intake,remote_intake,source_changes
from src.techexpert.inputs import InputError
from test_sc01 import SCOPE


def capture(state,files):
    uri='sftp://reader@example.test:22/logs'
    members=[dict(id='m'+str(n),root=0,relative_path=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),source_id='s'+str(n),importable=True)
             for n,(name,raw) in enumerate(files,1)]
    return artifacts.save_artifact(state,'remote_capture',{},[(uri+'/'+name,raw) for name,raw in files],
        dict(schema_version=1,profile='sftp-v3-capture-v1',capture_complete=True,roots=[dict(kind='sftp',path=uri)],members=members,
            file_count=len(members),expanded_bytes=sum(m['bytes'] for m in members),collection_coverage='unknown',
            transport=dict(node='reported-node',acquisition_started='2026-11-18T00:00:00Z',atomic_snapshot=False)))


class RemoteIntakeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.state=Path(self.temp.name)/'state'

    def test_remote_case_uses_retained_catalogue_member_binding_and_not_remote_paths(self):
        events=[dict(kind=k,timestamp=t,scope=SCOPE) for k,t in [('started','2026-11-18T00:00:00Z'),('finished','2026-11-18T00:00:02Z')]]
        raw=''.join(json.dumps(row)+'\n' for row in events).encode()
        parent=capture(self.state,[('events.jsonl',raw)])
        settings=dict(manifest=dict(schema=1,scenario='SC-01',origin='synthetic',selection=SCOPE,sources=[dict(path='m1',format='normalized-events-v1')]))
        first=remote_intake.parse(self.state,self.state,parent['artifact_id'],'case',settings)
        self.assertEqual(first['durations_seconds']['execution'],2)
        self.assertEqual(first['input_intake']['artifact_id'],parent['artifact_id'])
        self.assertEqual(first['sources'][0]['input_origin']['kind'],'sftp')
        self.assertEqual(first['sources'][0]['input_origin']['path'],'sftp://reader@example.test:22/logs')
        second=remote_intake.parse(self.state,self.state,parent['artifact_id'],'case',settings)
        ref=lambda r:dict(kind='case',id=r['case_id'],source_id='s1')
        compared=source_changes.compare(self.state,before=ref(first),after=ref(second))
        self.assertEqual(compared['observation']['relation'],'same_catalogue_member')

    def test_saved_case_and_acquisition_keep_each_complete_original_remote_locator(self):
        files=[]
        for name,kind,stamp in [('start.jsonl','started','2026-11-18T00:00:00Z'),('finish.jsonl','finished','2026-11-18T00:00:02Z')]:
            files.append((name,(json.dumps(dict(kind=kind,timestamp=stamp,scope=SCOPE))+'\n').encode()))
        parent=capture(self.state,files)
        manifest=dict(schema=1,scenario='SC-01',origin='synthetic',selection=SCOPE,sources=[dict(path='m1',format='normalized-events-v1'),dict(path='m2',format='normalized-events-v1')])
        result=remote_intake.parse(self.state,self.state,parent['artifact_id'],'case',dict(manifest=manifest))
        expected=[s['name'] for s in parent['sources']]
        self.assertEqual([s['path'] for s in result['sources']],expected)
        self.assertEqual([s['path'] for s in result['source_acquisition']],expected)

    def test_os_apdex_and_native_jr_keep_existing_import_profiles(self):
        root=Path(__file__).resolve().parent/'fixtures/native-jr'
        os_data=json.dumps(dict(schema_version=1,profile='os-metrics-v1',node='provided',role='client',scope='host',
            plan=dict(duration_seconds=1,interval_seconds=1,max_bytes=8388608),status='completed',samples=[dict(elapsed_seconds=0,metrics=[])])).encode()
        apdex=json.dumps([dict(id='a',operation='post',started_at='2026-11-18T00:00:00Z',duration_seconds=1,success=True)]).encode()
        files=[('os.json',os_data),('apdex.json',apdex)]+[(p.name,p.read_bytes()) for p in (root/'1Cv8.lgf',root/'20261116000000.lgp')]
        parent=capture(self.state,files)
        os_report=remote_intake.parse(self.state,self.state,parent['artifact_id'],'os',dict(members=['m1']))
        self.assertEqual(os_report['kind'],'os_metrics')
        apdex_report=remote_intake.parse(self.state,self.state,parent['artifact_id'],'apdex',dict(members=['m2'],target_seconds=2))
        self.assertEqual(apdex_report['kind'],'apdex')
        journal=remote_intake.parse(self.state,self.state,parent['artifact_id'],'jr',dict(members=['m3','m4'],platform_version='8.3.27.1989',utc_offset='+03:00'))
        self.assertEqual(journal['kind'],'native-jr')

    def test_partial_or_corrupt_capture_is_not_an_analysis_plan(self):
        parent=capture(self.state,[('log.txt',b'bytes')])
        path=artifacts.artifact_folder(self.state,parent['artifact_id'])/'sources/s1.bin';path.write_bytes(b'bad')
        with self.assertRaises(InputError):input_intake.read_plan(self.state,parent['artifact_id'])
        other=artifacts.save_artifact(self.state,'remote_capture',{},[],dict(schema_version=1,capture_complete=False))
        with self.assertRaises(InputError):input_intake.read_plan(self.state,other['artifact_id'])

    def test_native_source_code_archives_do_not_gain_a_remote_parser(self):
        parent=capture(self.state,[('sources.zip',b'not a source import')])
        with self.assertRaises(InputError):remote_intake.parse(self.state,self.state,parent['artifact_id'],'source',dict(members=['m1']))

    def test_retained_staging_keeps_the_same_private_disk_floor(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        parent=capture(self.state,[('one.log',b'bytes')]);output=Path(self.temp.name)/'output'
        with patch.object(input_intake.shutil,'disk_usage',return_value=SimpleNamespace(free=0)):
            with self.assertRaisesRegex(InputError,'space'):input_intake.capture_selected(self.state,output,parent['artifact_id'],['m1'])
        self.assertFalse(output.exists())

    @unittest.skipUnless(os.name=='nt','Windows drive-casing contract')
    def test_lowercase_output_drive_keeps_case_os_and_apdex_capture_bindings(self):
        events=[dict(kind=k,timestamp=t,scope=SCOPE) for k,t in [('started','2026-11-18T00:00:00Z'),('finished','2026-11-18T00:00:02Z')]]
        os_data=json.dumps(dict(schema_version=1,profile='os-metrics-v1',node='provided',role='client',scope='host',
            plan=dict(duration_seconds=1,interval_seconds=1,max_bytes=8388608),status='completed',samples=[dict(elapsed_seconds=0,metrics=[])])).encode()
        apdex=json.dumps([dict(id='a',operation='post',started_at='2026-11-18T00:00:00Z',duration_seconds=1,success=True)]).encode()
        parent=capture(self.state,[('events.jsonl',''.join(json.dumps(e)+'\n' for e in events).encode()),('os.json',os_data),('apdex.json',apdex)])
        output=Path(str(self.state)[0].lower()+str(self.state)[1:])
        for adapter,args in [('case',dict(manifest=dict(schema=1,scenario='SC-01',origin='synthetic',selection=SCOPE,sources=[dict(path='m1',format='normalized-events-v1')]))),('os',dict(members=['m2'])),('apdex',dict(members=['m3'],target_seconds=2))]:
            with self.subTest(adapter=adapter):
                result=remote_intake.parse(self.state,output,parent['artifact_id'],adapter,args)
                self.assertTrue(result.get('case_id') or result.get('artifact_id'))


if __name__=='__main__':unittest.main()
