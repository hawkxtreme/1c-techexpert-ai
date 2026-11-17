"""Existing diagnostic parsers consume only explicitly selected catalogue bytes."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from src.techexpert import input_intake,artifacts,native_jr
from src.techexpert.inputs import InputError

FIXTURE=Path(__file__).parent/'fixtures/native-jr'


def os_document(node='host-a'):
    return dict(schema_version=1,profile='os-metrics-v1',node=node,role='client',scope='host',platform='provided',
        plan=dict(duration_seconds=2,interval_seconds=1,max_bytes=8388608),started_at='2026-11-16T09:00:00Z',status='completed',samples=[
            dict(elapsed_seconds=0,metrics=[dict(metric='disk.avg_queue',instance='disk-a',value=None,unit='requests',status='warmup')]),
            dict(elapsed_seconds=2,metrics=[dict(metric='disk.avg_queue',instance='disk-a',value=3,unit='requests',status='known')])])


def apdex_rows():return [dict(id=str(i),operation='post',started_at='2026-11-16T09:00:00Z',duration_seconds=d,success=True) for i,d in enumerate((1,3))]


class AdapterInputTests(unittest.TestCase):
    def setUp(self):
        self.api=importlib.import_module('src.techexpert.input_adapters')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.state=self.root/'state';self.output=self.root/'output'
        self.archive=self.root/'data.zip'

    def entries(self):
        return [('log/'+name,(FIXTURE/name).read_bytes()) for name in ('1Cv8.lgf','20261116000000.lgp')]+[
            ('metrics/os.json',json.dumps(os_document()).encode()),('metrics/apdex.json',json.dumps(apdex_rows()).encode())]

    def plan(self,entries=None):
        with zipfile.ZipFile(self.archive,'w',compression=zipfile.ZIP_DEFLATED) as archive:
            for name,data in self.entries() if entries is None else entries:archive.writestr(name,data)
        plan=input_intake.inspect(self.state,[dict(path=str(self.archive),kind='zip')]);self.ids={m['relative_path']:m['id'] for m in plan['result']['members']};self.plan_id=plan['artifact_id'];return plan

    def args(self,operation,members):
        base=dict(input_plan=self.plan_id,members=[self.ids[n] for n in members])
        return dict(base,path=str(self.archive),platform_version='8.3.27.1989',utc_offset='+03:00',consistency='provided_snapshot') if operation=='jr.import' else dict(base,measurements=str(self.archive),**(dict(target_seconds=2) if operation=='apdex.import' else {}))

    def import_data(self,op,members):return self.api.import_selected(op,self.args(op,members),self.state,self.output)

    def test_zip_journal_preserves_native_record_ranges_and_original_locator(self):
        self.plan();result=self.import_data('jr.import',['log/20261116000000.lgp','log/1Cv8.lgf']);self.assertEqual(result['kind'],'native-jr')
        self.assertEqual(result['result']['event_count'],5);self.assertIsNone(result['result']['database_identity']);self.assertFalse(result['result']['atomic_snapshot_verified'])
        self.assertEqual(result['sources'][0]['name'],'1Cv8.lgf');self.assertEqual([s['input_origin']['member'] for s in result['sources']],['log/1Cv8.lgf','log/20261116000000.lgp'])
        pinned=result['result']['input_intake'];self.assertEqual(pinned['artifact_id'],self.plan_id);self.assertEqual([m['source_id'] for m in pinned['selected']],['s1','s2'])
        page=native_jr.list_events(self.output,result['artifact_id']);record=native_jr.read_record(self.output,result['artifact_id'],page['records'][0]['id'])
        raw=(FIXTURE/'20261116000000.lgp').read_bytes();span=record['record'];self.assertEqual(record['text'].encode(),raw[span['byte_start']:span['byte_end']])
        self.archive.unlink();self.assertEqual(artifacts.load_artifact(self.output,result['artifact_id']),result)

    def test_selected_directory_journal_uses_same_parser_without_archive(self):
        folder=self.root/'provided';folder.mkdir()
        for name in ('1Cv8.lgf','20261116000000.lgp'):shutil.copyfile(FIXTURE/name,folder/name)
        plan=input_intake.inspect(self.state,[dict(path=str(folder),kind='directory')]);args=dict(path=str(folder),platform_version='8.3.27.1989',input_plan=plan['artifact_id'],members=[m['id'] for m in plan['result']['members']])
        result=self.api.import_selected('jr.import',args,self.state,self.output);self.assertEqual(result['result']['event_count'],5)
        self.assertTrue(all(s['input_origin']['kind']=='directory' for s in result['sources']))

    def test_os_zip_import_keeps_actual_gaps_units_role_and_no_historical_cause(self):
        self.plan()
        with patch('src.techexpert.os_metrics.collect',side_effect=AssertionError('Import started collection')):
            result=self.import_data('os.import',['metrics/os.json'])
        value=result['result'];self.assertEqual((value['node'],value['role'],value['missing_samples']),('host-a','client',1));self.assertEqual(value['coverage_status'],'incomplete')
        self.assertEqual(value['metrics'][0]['unit'],'requests');self.assertFalse(value['historical_incident_explained'])
        self.assertEqual(result['sources'][0]['input_origin']['member'],'metrics/os.json')
        evidence=artifacts.artifact_evidence(self.output,result['artifact_id'],'s1');self.assertEqual(json.loads(evidence['text']),os_document())

    def test_apdex_zip_import_keeps_explicit_target_and_raw_measurements(self):
        self.plan();result=self.import_data('apdex.import',['metrics/apdex.json']);self.assertEqual(result['result']['score'],.75)
        self.assertEqual(result['sources'][0]['sha256'],hashlib.sha256(json.dumps(apdex_rows()).encode()).hexdigest())
        self.assertEqual(result['sources'][0]['input_origin']['path'],str(self.archive));self.assertEqual(result['result']['input_intake']['database_run_ownership'],'not_established')

    def test_single_file_catalogue_imports_existing_os_and_apdex_formats(self):
        for operation,data in (('os.import',os_document()),('apdex.import',apdex_rows())):
            with self.subTest(operation=operation):
                path=self.root/(operation+'.json');path.write_text(json.dumps(data),encoding='utf-8');plan=input_intake.inspect(self.state,[dict(path=str(path),kind='file')])
                args=dict(measurements=str(path),input_plan=plan['artifact_id'],members=['m1'],**(dict(target_seconds=2) if operation=='apdex.import' else {}))
                result=self.api.import_selected(operation,args,self.state,self.output);self.assertEqual(result['sources'][0]['input_origin']['kind'],'file')

    def test_journal_requires_dictionary_and_parts_with_unique_names_and_one_group(self):
        self.plan()
        for members in (['log/1Cv8.lgf'],['log/20261116000000.lgp'],['log/1Cv8.lgf','metrics/os.json']):
            with self.subTest(members=members),self.assertRaises(InputError):self.import_data('jr.import',members)
        data=[('a/1Cv8.lgf',(FIXTURE/'1Cv8.lgf').read_bytes()),('b/20261116000000.lgp',(FIXTURE/'20261116000000.lgp').read_bytes())];self.plan(data)
        with self.assertRaises(InputError):self.import_data('jr.import',['a/1Cv8.lgf','b/20261116000000.lgp'])
        self.assertFalse(self.output.exists())

    def test_lgd_xml_and_code_members_are_not_declared_supported_by_staging(self):
        dictionary=(FIXTURE/'1Cv8.lgf').read_bytes()
        for name in ('1Cv8.lgd','journal.xml','Module.bsl'):
            self.plan([('1Cv8.lgf',dictionary),(name,b'unsupported')])
            with self.subTest(name=name),self.assertRaises(InputError):self.import_data('jr.import',['1Cv8.lgf',name])
        self.assertFalse(self.output.exists())

    def test_metric_import_requires_exactly_one_member_and_native_wrong_format_is_refused(self):
        self.plan()
        for op in ('os.import','apdex.import'):
            with self.subTest(op=op),self.assertRaises(InputError):self.import_data(op,['metrics/os.json','metrics/apdex.json'])
            with self.subTest(op=op),self.assertRaises(ValueError):self.import_data(op,['log/1Cv8.lgf'])
        self.assertFalse((self.output/'artifacts').exists())

    def test_members_from_another_root_are_refused_before_original_read(self):
        self.plan();other=self.root/'outside.json';other.write_text(json.dumps(os_document()),encoding='utf-8')
        plan=input_intake.inspect(self.state,[dict(path=str(self.archive),kind='zip'),dict(path=str(other),kind='file')]);member=next(m for m in plan['result']['members'] if m['root']==1)
        with patch.object(input_intake,'catalogue',side_effect=AssertionError('Invalid root probed originals')):
            with self.assertRaises(InputError):self.api.import_selected('os.import',dict(measurements=str(self.archive),input_plan=plan['artifact_id'],members=[member['id']]),self.state,self.output)

    def test_changed_archive_and_damaged_plan_never_create_adapter_artifact(self):
        self.plan();self.archive.write_bytes(b'changed')
        with self.assertRaises(ValueError):self.import_data('os.import',['metrics/os.json'])
        self.plan();(self.state/'artifacts'/self.plan_id/'report.json').write_bytes(b'changed plan')
        with self.assertRaises(InputError):self.import_data('os.import',['metrics/os.json'])
        self.assertFalse((self.output/'artifacts').exists())

    def test_captured_bytes_are_rechecked_when_native_adapter_reads_staging(self):
        self.plan();original=native_jr.read_snapshot
        def altered(path,*args,**kwargs):
            raw=original(path,*args,**kwargs);return raw+b'\r\n' if Path(path).suffix.lower()=='.lgp' else raw
        with patch.object(native_jr,'read_snapshot',side_effect=altered),self.assertRaises(InputError):self.import_data('jr.import',['log/1Cv8.lgf','log/20261116000000.lgp'])
        self.assertFalse((self.output/'artifacts').exists())

    def test_selection_pair_and_source_limits_are_validated_before_state_access(self):
        base=dict(measurements=str(self.archive))
        for extra in (dict(input_plan='a'*32),dict(members=['m1']),dict(input_plan='a'*32,members=[]),dict(input_plan='a'*32,members=['m1','m1'])):
            with self.subTest(extra=extra),self.assertRaises(InputError):self.api.import_selected('os.import',dict(base,**extra),self.state,self.output)
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(os.name=='nt','Windows canonical drive casing')
    def test_lowercase_staging_drive_preserves_both_metric_and_case_imports(self):
        self.plan();lower=Path(str(self.output)[0].lower()+str(self.output)[1:])
        metric=self.api.import_selected('os.import',self.args('os.import',['metrics/os.json']),self.state,lower)
        self.assertEqual(metric['result']['missing_samples'],1)
        from test_input_intake import PROFILE,ROW
        file=self.root/'26111609.log';file.write_bytes(ROW);plan=input_intake.inspect(self.state,[dict(path=str(file),kind='file')])
        manifest=self.root/'case.json';manifest.write_text(json.dumps(dict(schema=1,scenario='SC-01',origin='provided',selection={k:'reported' for k in ('database','node','process','epoch','run')},sources=[dict(PROFILE,path='m1')])),encoding='utf-8')
        case=input_intake.analyze(self.state,lower,manifest,plan['artifact_id'])
        self.assertEqual(case['native_observations']['event_count'],1)

if __name__=='__main__':unittest.main()
