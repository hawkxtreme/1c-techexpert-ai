"""Bounded preview and explicit diagnostic intake from independently chosen roots."""
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib

from src.techexpert.inputs import InputError
from src.techexpert import storage

ROW='04:05.123456-7,NEW_EVENT,0,Context="Начало,\r\nконец"\r\n'.encode()
PROFILE=dict(format='1c-tj-text-v1',platform_version='8.3.27.1989',encoding='utf-8',placement='folders',timestamp_format='minute',file_hour='2026-11-16T09:00:00+03:00',rotation_hours=1)


class InputIntakeTests(unittest.TestCase):
    def setUp(self):
        self.api=importlib.import_module('src.techexpert.input_intake')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.state=self.root/'state';self.output=self.root/'output'

    def zip(self,entries,compression=zipfile.ZIP_DEFLATED):
        path=self.root/'данные.zip'
        with zipfile.ZipFile(path,'w',compression=compression) as z:
            for name,data in entries:z.writestr(name,data)
        return path

    def plan(self,path,kind='zip',limits=None):return self.api.inspect(self.state,[dict(path=str(path),kind=kind)],limits=limits)

    def manifest(self,members,**overrides):
        path=self.root/'selected.json';doc=dict(schema=1,scenario='SC-01',origin='provided',symptom='A reported slow operation',selection=dict(database='reported',node='reported',process='reported',epoch='reported',run='reported'),sources=[dict(PROFILE,path=m) for m in members]);doc.update(overrides)
        path.write_text(json.dumps(doc,ensure_ascii=False),encoding='utf-8');return path

    def test_zip_preview_lists_sizes_and_names_without_reading_payload_or_creating_case(self):
        path=self.zip([('logs/26111609.log',ROW),('extra.txt',b'extra')]);before=path.read_bytes()
        with patch.object(zipfile.ZipFile,'open',side_effect=AssertionError('Preview extracted a member')):
            plan=self.plan(path)
        self.assertEqual(plan['kind'],'input_catalog');self.assertEqual(plan['sources'],[])
        result=plan['result'];self.assertEqual(result['expanded_bytes'],len(ROW)+5);self.assertEqual(result['file_count'],2)
        self.assertEqual({m['relative_path'] for m in result['members']},{'logs/26111609.log','extra.txt'})
        self.assertEqual(path.read_bytes(),before);self.assertFalse((self.state/'cases').exists());self.assertFalse(self.output.exists())

    def test_local_directory_and_independent_file_have_stable_bounded_catalogue(self):
        folder=self.root/'logs';folder.mkdir();(folder/'b.log').write_bytes(ROW);(folder/'a.log').write_bytes(ROW)
        other=self.root/'other.log';other.write_bytes(b'other')
        plan=self.api.inspect(self.state,[dict(path=str(folder),kind='directory'),dict(path=str(other),kind='file')])
        members=plan['result']['members'];self.assertEqual([m['relative_path'] for m in members],['a.log','b.log','other.log'])
        self.assertEqual([m['id'] for m in members],['m1','m2','m3']);self.assertEqual(members[0]['sha256'],hashlib.sha256(ROW).hexdigest())

    def test_selected_zip_member_becomes_normal_verified_case_with_original_ranges_and_origin(self):
        path=self.zip([('logs/26111609.log',ROW),('unselected.txt',b'not imported')]);plan=self.plan(path)
        member=next(m for m in plan['result']['members'] if m['relative_path'].endswith('.log'))
        result=self.api.analyze(self.state,self.output,self.manifest([member['id']]),plan['artifact_id'])
        self.assertEqual(len(result['sources']),1);self.assertEqual(result['native_observations']['event_count'],1)
        self.assertEqual(result['sources'][0]['input_origin']['member'],'logs/26111609.log');self.assertEqual(result['sources'][0]['input_origin']['path'],str(path))
        evidence=storage.read_evidence(self.output,result['case_id'],'s1:1');self.assertEqual((evidence['byte_start'],evidence['byte_end'],evidence['end_line']),(0,len(ROW),2))
        self.assertEqual(result['cause_state'],'insufficient_data');self.assertEqual(result['durations_seconds']['execution'],None)
        path.unlink();storage.verified_case(self.output,result['case_id'])

    def test_native_filename_profile_is_resolved_from_member_not_numeric_staging_name(self):
        path=self.zip([('logs/26111609.log',ROW)]);plan=self.plan(path);manifest=self.manifest(['m1']);doc=json.loads(manifest.read_text());doc['sources'][0].pop('file_hour');manifest.write_text(json.dumps(doc),encoding='utf-8')
        with self.assertRaises(InputError):self.api.analyze(self.state,self.output,manifest,plan['artifact_id'])
        # Filename omits century/zone; missing explicit profile remains unknown.

    def test_changed_archive_even_in_unselected_member_refuses_import(self):
        path=self.zip([('a.log',ROW),('b.txt',b'before')]);plan=self.plan(path)
        self.zip([('a.log',ROW),('b.txt',b'after')])
        with self.assertRaises(InputError):self.api.analyze(self.state,self.output,self.manifest(['m1']),plan['artifact_id'])
        self.assertFalse((self.output/'cases').exists())

    def test_directory_addition_and_selected_file_mutation_refuse_import(self):
        for mode in ('addition','mutation'):
            with self.subTest(mode=mode):
                folder=self.root/mode;folder.mkdir();(folder/'a.log').write_bytes(ROW);plan=self.plan(folder,'directory')
                if mode=='addition':(folder/'b.log').write_bytes(ROW)
                else:(folder/'a.log').write_bytes(b'changed')
                with self.assertRaises(InputError):self.api.analyze(self.state,self.output,self.manifest(['m1']),plan['artifact_id'])

    def test_member_ids_are_required_and_duplicates_unknowns_and_paths_are_rejected(self):
        path=self.zip([('a.log',ROW)]);plan=self.plan(path)
        for names in (['../outside'],[str(path)],['m999'],['m1','m1']):
            with self.subTest(names=names),self.assertRaises(InputError):self.api.analyze(self.state,self.output,self.manifest(names),plan['artifact_id'])

    def test_nonstring_member_or_format_is_invalid_input_before_capture(self):
        plan=self.plan(self.zip([('a.log',ROW)]));manifest=self.manifest(['m1']);original=json.loads(manifest.read_text())
        for field,value in (('path',[]),('path',{}),('format',{}),('format',[])):
            doc=json.loads(json.dumps(original));doc['sources'][0][field]=value;manifest.write_text(json.dumps(doc),encoding='utf-8')
            with self.subTest(field=field,value=value),self.assertRaises(InputError):self.api.analyze(self.state,self.output,manifest,plan['artifact_id'])
        self.assertFalse(self.output.exists())

    def test_unsafe_zip_paths_and_portability_aliases_are_refused_before_extraction(self):
        for name in ('../outside','/absolute','C:/file','a\\b.log','a//b','a/../b','a/./b','nul.txt','a./b','a /b','file:ads','a\x01b'):
            with self.subTest(name=name):
                path=self.zip([(name,ROW)])
                if '\\' in name:
                    # ZipInfo normalizes the host separator on Windows; retain
                    # a genuinely backslash-bearing local/central header.
                    path.write_bytes(path.read_bytes().replace(name.replace('\\','/').encode(),name.encode()))
                with self.assertRaises(InputError):self.plan(path)
        self.assertFalse((self.root.parent/'outside').exists())

    def test_duplicate_case_unicode_and_file_directory_collisions_are_refused(self):
        for names in (('A.log','a.log'),('é.log','e\u0301.log'),('a','a/b.log')):
            with self.subTest(names=names):
                path=self.zip([(name,ROW) for name in names])
                with self.assertRaises(InputError):self.plan(path)

    def test_overlapping_roots_cannot_count_the_same_local_file_twice(self):
        folder=self.root/'logs';folder.mkdir();file=folder/'a.log';file.write_bytes(ROW)
        plan=self.api.inspect(self.state,[dict(path=str(folder),kind='directory'),dict(path=str(file),kind='file')])
        self.assertEqual(plan['result']['file_count'],2)
        with self.assertRaises(InputError):self.api.analyze(self.state,self.output,self.manifest(['m1','m2']),plan['artifact_id'])
        self.assertFalse((self.output/'cases').exists())
        one=self.api.analyze(self.state,self.output,self.manifest(['m1']),plan['artifact_id'])
        self.assertEqual(one['native_observations']['event_count'],1)

    def test_console_superscript_and_spaced_device_aliases_are_portably_refused(self):
        for name in ('CONIN$','conout$.log','COM¹.txt','LPT²','LPT³.log','NUL .txt','AUX  .json'):
            with self.subTest(name=name),self.assertRaises(InputError):self.plan(self.zip([(name,ROW)]))

    def test_zip64_trailer_cannot_override_preflight_central_directory_budget(self):
        from src.techexpert import input_zip,input_files
        buffer=io.BytesIO();entry=zipfile.ZipInfo('a.log');entry.comment=b'0'*76
        with zipfile.ZipFile(buffer,'w',compression=zipfile.ZIP_STORED) as archive:archive.writestr(entry,b'x'*(1024**2))
        raw=bytearray(buffer.getvalue());end=raw.rfind(b'PK\x05\x06')
        fake=struct.pack('<4sQ2H2L4Q',b'PK\x06\x06',44,45,45,0,0,1,1,end-76,0)+struct.pack('<4sLQL',b'PK\x06\x07',0,end-76,1)
        self.assertEqual(len(fake),76);raw[end-76:end]=fake
        class Logged(io.BytesIO):
            def __init__(self,data):super().__init__(data);self.reads=[]
            def read(self,size=-1):
                data=super().read(size);self.reads.append(len(data));return data
        stream=Logged(raw)
        with self.assertRaises(InputError):input_zip.catalogue(stream,input_files.limits())
        self.assertLessEqual(max(stream.reads),256*1024,'ZIP64 overrode the checked classic metadata bounds')

    def test_nested_containers_and_special_zip_entries_are_not_admitted(self):
        for name in ('nested.zip','nested.tar.gz','nested.7z'):
            with self.subTest(name=name),self.assertRaises(InputError):self.plan(self.zip([(name,b'container')]))
        for mode in (stat.S_IFLNK,stat.S_IFIFO):
            info=zipfile.ZipInfo('linked');info.create_system=3;info.external_attr=(mode|0o600)<<16
            with self.subTest(mode=mode),self.assertRaises(InputError):self.plan(self.zip([(info,b'outside')]))

    def test_source_code_archives_are_not_a_source_snapshot_input(self):
        path=self.zip([('Module.bsl',b'code')]);plan=self.plan(path)
        self.assertFalse(plan['result']['members'][0]['importable'])
        with self.assertRaises(InputError):self.api.analyze(self.state,self.output,self.manifest(['m1']),plan['artifact_id'])

    def test_local_linked_root_or_member_is_refused_without_following(self):
        original=self.root/'original.log';original.write_bytes(ROW);linked=self.root/'link.log'
        try:linked.symlink_to(original)
        except OSError:self.skipTest('Creating local symlinks is unavailable; Linux QA covers this path')
        with self.assertRaises(InputError):self.plan(linked,'file')
        folder=self.root/'folder';folder.mkdir();(folder/'member').symlink_to(original)
        with self.assertRaises(InputError):self.plan(folder,'directory')

    @unittest.skipUnless(os.name=='nt','Windows junction profile')
    def test_windows_junction_root_is_refused_and_external_target_unchanged(self):
        target=self.root/'target';target.mkdir();original=target/'actual.log';original.write_bytes(ROW);linked=self.root/'junction'
        run=subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(linked),str(target)],capture_output=True,timeout=10)
        self.assertEqual(run.returncode,0,run.stderr)
        try:
            with self.assertRaises(InputError):self.plan(linked,'directory')
            self.assertEqual(original.read_bytes(),ROW)
        finally:os.rmdir(linked)

    def test_file_count_depth_and_expanded_byte_limits_apply_to_directory_and_zip(self):
        folder=self.root/'folder';folder.mkdir();(folder/'a').write_bytes(ROW);(folder/'b').write_bytes(ROW)
        archive=self.zip([('a',ROW),('b',ROW)])
        for path,kind in ((folder,'directory'),(archive,'zip')):
            for limits in (dict(max_files=1),dict(max_total_bytes=len(ROW)),dict(max_file_bytes=2)):
                with self.subTest(kind=kind,limits=limits),self.assertRaises(InputError):self.plan(path,kind,limits)
        path=self.zip([('a/b.log',ROW)])
        with self.assertRaises(InputError):self.plan(path,limits=dict(max_depth=0))

    def test_unsupported_compression_and_corrupt_directory_metadata_are_refused(self):
        path=self.zip([('a',ROW)],zipfile.ZIP_BZIP2)
        with self.assertRaises(InputError):self.plan(path)
        path=self.zip([('a',ROW)]);raw=bytearray(path.read_bytes());offset=raw.rfind(b'PK\x05\x06');struct.pack_into('<I',raw,offset+12,999999);path.write_bytes(raw)
        with self.assertRaises(InputError):self.plan(path)

    def test_forged_expanded_size_or_crc_is_refused_without_case_product(self):
        path=self.zip([('a.log',ROW)]);raw=bytearray(path.read_bytes());offset=raw.index(b'PK\x01\x02');struct.pack_into('<I',raw,offset+16,0);path.write_bytes(raw);plan=self.plan(path)
        with self.assertRaises(InputError):self.api.analyze(self.state,self.output,self.manifest(['m1']),plan['artifact_id'])
        self.assertFalse((self.output/'cases').exists())

    def test_forged_size_with_crc_for_prefix_does_not_silently_truncate_deflate(self):
        path=self.zip([('a.log',ROW+b'additional expanded bytes')]);raw=bytearray(path.read_bytes());offset=raw.index(b'PK\x01\x02')
        struct.pack_into('<I',raw,offset+16,zlib.crc32(ROW));struct.pack_into('<I',raw,offset+24,len(ROW));path.write_bytes(raw);plan=self.plan(path)
        with self.assertRaises(InputError):self.api.analyze(self.state,self.output,self.manifest(['m1']),plan['artifact_id'])
        self.assertFalse((self.output/'cases').exists())

    def test_encrypted_zip_and_local_header_name_conflict_are_rejected(self):
        path=self.zip([('a.log',ROW)]);raw=bytearray(path.read_bytes());offset=raw.index(b'PK\x01\x02');struct.pack_into('<H',raw,offset+8,1);path.write_bytes(raw)
        with self.assertRaises(InputError):self.plan(path)
        path=self.zip([('a.log',ROW)]);raw=path.read_bytes().replace(b'a.log',b'b.log',1);path.write_bytes(raw);plan=self.plan(path)
        with self.assertRaises(InputError):self.api.analyze(self.state,self.output,self.manifest(['m1']),plan['artifact_id'])

    def test_native_member_filename_conflict_is_checked_before_capture(self):
        path=self.zip([('26111610.log',ROW)]);plan=self.plan(path)
        with self.assertRaises(InputError):self.api.analyze(self.state,self.output,self.manifest(['m1']),plan['artifact_id'])
        self.assertFalse(self.output.exists())

    def test_capture_enforces_disk_floor_and_never_changes_original(self):
        path=self.zip([('a.log',ROW)]);before=path.read_bytes();plan=self.plan(path)
        with patch('shutil.disk_usage',return_value=shutil._ntuple_diskusage(100,99,1)),self.assertRaises(InputError):self.api.analyze(self.state,self.output,self.manifest(['m1']),plan['artifact_id'])
        self.assertEqual(path.read_bytes(),before);self.assertFalse((self.output/'cases').exists())

    def test_invalid_limits_raise_before_reading_selected_paths(self):
        for limits in (dict(max_files=129),dict(max_depth=-1),dict(max_file_bytes=True),dict(max_total_bytes=65*1024**2),dict(arbitrary=1)):
            with self.subTest(limits=limits),self.assertRaises(InputError):self.plan(self.root/'missing','file',limits)

    def test_saved_plan_is_integrity_checked_before_original_path_read(self):
        path=self.zip([('a.log',ROW)]);plan=self.plan(path);folder=self.state/'artifacts'/plan['artifact_id'];(folder/'report.json').write_bytes(b'changed')
        with self.assertRaises(InputError):self.api.analyze(self.state,self.output,self.manifest(['m1']),plan['artifact_id'])

    def test_file_input_is_captured_with_declared_format_and_no_job_inference(self):
        path=self.root/'26111609.log';path.write_bytes(ROW);plan=self.plan(path,'file')
        result=self.api.analyze(self.state,self.output,self.manifest(['m1']),plan['artifact_id'])
        self.assertEqual(result['sources'][0]['path'],str(path));self.assertEqual(result['sources'][0]['input_origin']['kind'],'file')
        self.assertEqual(result['native_observations']['by_event'],dict(NEW_EVENT=1))

if __name__=='__main__':unittest.main()
