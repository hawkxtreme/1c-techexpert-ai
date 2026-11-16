import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch
import zipfile

from scripts.package_plugin import build
from src.techexpert.profiles import save_profile,load_profile
from src.techexpert.storage import ROOT


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.readiness'),
                             'Capability-specific first-run readiness is missing')
        self.api=importlib.import_module('src.techexpert.readiness')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name);self.bundle=self.folder/'bundle';self.state=self.folder/'state'
        archive=self.folder/'bundle.zip';build(archive)
        with zipfile.ZipFile(archive) as stream:stream.extractall(self.bundle)
        self.entry_hash=self.canonical_hash(self.bundle/'skills/techexpert/SKILL.md')

    @staticmethod
    def canonical_hash(path):
        return hashlib.sha256(path.read_text(encoding='utf-8').replace('\r\n','\n').encode('utf-8')).hexdigest()

    def check(self,**kwargs):
        return self.api.check(self.state,root=self.bundle,**kwargs)

    def profile(self,name='Local file'):
        return dict(schema_version=1,name=name,bases=[dict(id='ib',name='SC01',mode='file',connection='//unreachable-host/private-ib')],
            sources=[dict(id='tj',type='tj',path='//unreachable-host/private-tj',host='',base_ids=['ib'])])

    def rewrite_manifest(self,relative):
        path=self.bundle/'src/techexpert/assets/bundle-manifest.json';data=json.loads(path.read_text(encoding='utf-8'))
        data['members'][relative]=self.canonical_hash(self.bundle/relative)
        path.write_text(json.dumps(data),encoding='utf-8')

    def test_good_bundle_needs_no_server_tools_or_source_probes(self):
        save_profile(self.state,self.profile(),expected_revision=0)
        with patch('subprocess.run',side_effect=AssertionError('readiness launched a process')), \
             patch('socket.create_connection',side_effect=AssertionError('readiness connected to a source')):
            result=self.check(entrypoint_sha256=self.entry_hash)
        self.assertEqual(result['status'],'ready_for_supplied_files')
        self.assertTrue(result['capabilities']['analyze_supplied_files'])
        self.assertEqual(result['knowledge']['cards'],17)
        self.assertTrue(result['knowledge']['search_verified'])
        self.assertEqual(result['specialized']['sql'],'not_applicable')
        self.assertEqual(result['specialized']['rac'],'not_applicable')
        self.assertEqual(result['sources']['status'],'configured_not_checked')
        self.assertFalse(result['side_effects']['collection_started'])

    def test_read_only_check_does_not_create_state_or_run_demo(self):
        result=self.check()
        self.assertEqual(result['profile']['status'],'not_configured')
        self.assertEqual(result['demonstration']['status'],'not_run')
        self.assertTrue(result['capabilities']['run_synthetic_demo'])
        self.assertFalse(self.state.exists())

    def test_harness_loading_is_explicit_caller_report_not_model_attestation(self):
        result=self.check()
        self.assertEqual(result['harness']['status'],'not_confirmed')
        self.assertFalse(result['capabilities']['analyze_supplied_files'])
        stale=self.check(entrypoint_sha256='0'*64)
        self.assertEqual(stale['harness']['status'],'stale_entrypoint')
        reported=self.check(entrypoint_sha256=self.entry_hash)
        self.assertEqual(reported['harness']['status'],'caller_reported_loaded')
        self.assertFalse(reported['harness']['independently_attested'])

    def test_modified_instruction_blocks_analysis_with_restore_action(self):
        path=self.bundle/'skills/logcfg/SKILL.md';path.write_text('changed',encoding='utf-8')
        result=self.check(entrypoint_sha256=self.entry_hash)
        self.assertEqual(result['status'],'blocked')
        self.assertFalse(result['capabilities']['analyze_supplied_files'])
        issue=next(c for c in result['checks'] if c['id']=='instructions')
        self.assertEqual(issue['status'],'damaged')
        self.assertEqual(issue['action'],'restore_complete_bundle')

    def test_bad_knowledge_relation_is_detected_even_with_updated_file_hash(self):
        relative='knowledge/index.json';path=self.bundle/relative;data=json.loads(path.read_text(encoding='utf-8'))
        data['cards'][0]['related']=['DOES-NOT-EXIST'];path.write_text(json.dumps(data),encoding='utf-8')
        self.rewrite_manifest(relative)
        result=self.check(entrypoint_sha256=self.entry_hash)
        self.assertEqual(result['knowledge']['status'],'damaged')
        self.assertFalse(result['capabilities']['analyze_supplied_files'])
        self.assertFalse(result['capabilities']['run_synthetic_demo'])

    def test_manifest_version_and_missing_required_members_fail_closed(self):
        path=self.bundle/'src/techexpert/assets/bundle-manifest.json';original=json.loads(path.read_text(encoding='utf-8'))
        for replacement in (dict(original,schema_version=99),dict(original,product_version='999.0.0'),
                            dict(original,members={k:v for k,v in original['members'].items() if k!='AGENTS.md'})):
            with self.subTest(replacement=replacement['product_version']):
                path.write_text(json.dumps(replacement),encoding='utf-8');result=self.check()
                self.assertEqual(result['status'],'blocked')
                self.assertFalse(result['capabilities']['run_synthetic_demo'])

    def test_manifest_cannot_select_external_file(self):
        path=self.bundle/'src/techexpert/assets/bundle-manifest.json';original=json.loads(path.read_text(encoding='utf-8'))
        for name in ('../private.txt','C:/private.txt','knowledge\\private.md','./private.md'):
            with self.subTest(name=name):
                doc=dict(original,members=dict(original['members']));doc['members'][name]='0'*64
                path.write_text(json.dumps(doc),encoding='utf-8');self.assertEqual(self.check()['status'],'blocked')
        path.write_text(json.dumps(original),encoding='utf-8')

    def test_linked_member_is_rejected(self):
        target=self.folder/'private.txt';target.write_text('private',encoding='utf-8')
        member=self.bundle/'AGENTS.md';member.unlink()
        try:os.symlink(target,member)
        except OSError as exc:self.skipTest('Symlink creation unavailable: '+str(exc))
        self.assertEqual(self.check()['status'],'blocked')

    @unittest.skipUnless(os.name=='nt','Real Windows junction check')
    def test_windows_junction_member_is_rejected_without_changing_target(self):
        member=self.bundle/'skills/logcfg';data=(member/'SKILL.md').read_bytes()
        target=self.folder/'external-skill';target.mkdir();(target/'SKILL.md').write_bytes(data)
        (member/'SKILL.md').unlink();member.rmdir()
        script=self.folder/'create-junction.ps1'
        script.write_text("param([string]$LeafPath,[string]$TargetPath)\n$ErrorActionPreference='Stop'\nNew-Item -ItemType Junction -Path $LeafPath -Target $TargetPath -ErrorAction Stop | Out-Null\n",encoding='utf-8-sig')
        result=subprocess.run(['C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(script),'-LeafPath',str(member),'-TargetPath',str(target)],capture_output=True,timeout=10)
        if result.returncode:self.skipTest('Junction creation unavailable; exit '+str(result.returncode))
        try:
            self.assertTrue(member.lstat().st_file_attributes&0x400)
            self.assertEqual(self.check()['status'],'blocked')
        finally:os.rmdir(member)  # Remove only this known leaf, never recurse into its target.
        self.assertEqual((target/'SKILL.md').read_bytes(),data)

    def test_invalid_json_shape_returns_actionable_damage(self):
        for relative in ('knowledge/index.json','src/techexpert/assets/incident-templates.json','examples/sc01/case.json'):
            with self.subTest(relative=relative):
                path=self.bundle/relative;original=path.read_bytes();path.write_text('[]',encoding='utf-8');self.rewrite_manifest(relative)
                try:
                    result=self.check();self.assertFalse(result['capabilities']['run_synthetic_demo'])
                finally:path.write_bytes(original);self.rewrite_manifest(relative)

    def test_uninventoried_card_is_not_opened_by_the_search_validator(self):
        relative='knowledge/index.json';path=self.bundle/relative;doc=json.loads(path.read_text(encoding='utf-8'))
        doc['cards'][0]['path']='private.md';path.write_text(json.dumps(doc),encoding='utf-8');self.rewrite_manifest(relative)
        with patch('src.techexpert.readiness.load_library',side_effect=AssertionError('unlisted card reached the loader')):
            self.assertEqual(self.check()['knowledge']['status'],'damaged')

    def test_crlf_conversion_does_not_break_release_integrity(self):
        path=self.bundle/'skills/logcfg/SKILL.md'
        path.write_bytes(path.read_bytes().replace(b'\r\n',b'\n').replace(b'\n',b'\r\n'))
        self.assertTrue(self.check(entrypoint_sha256=self.entry_hash)['capabilities']['analyze_supplied_files'])

    def test_missing_demo_blocks_only_demo_and_does_not_become_native_input(self):
        (self.bundle/'examples/sc01/events.jsonl').unlink()
        result=self.check(entrypoint_sha256=self.entry_hash)
        self.assertFalse(result['capabilities']['run_synthetic_demo'])
        self.assertTrue(result['capabilities']['analyze_supplied_files'])

    def test_demo_manifest_cannot_read_outside_bundle_even_if_rehashed(self):
        relative='examples/sc01/case.json';path=self.bundle/relative;data=json.loads(path.read_text(encoding='utf-8'))
        data['sources'][0]['path']=str(self.folder/'private.jsonl');path.write_text(json.dumps(data),encoding='utf-8')
        self.rewrite_manifest(relative)
        self.assertFalse(self.check()['capabilities']['run_synthetic_demo'])
        with self.assertRaises(ValueError):self.api.run_demo(self.state,root=self.bundle)
        self.assertFalse(self.state.exists())

    def test_bad_profile_is_not_silently_replaced_or_a_demo_blocker(self):
        folder=self.state/'profiles';folder.mkdir(parents=True);path=folder/'current.json';path.write_text('{broken',encoding='utf-8')
        result=self.check(entrypoint_sha256=self.entry_hash)
        self.assertEqual(result['profile']['status'],'invalid')
        self.assertTrue(result['capabilities']['run_synthetic_demo'])
        self.assertEqual(path.read_text(encoding='utf-8'),'{broken')

    def test_selected_case_readiness_uses_its_pinned_profile(self):
        from src.techexpert.investigations import create
        first=save_profile(self.state,self.profile('Pinned A'),expected_revision=0)
        case=create(self.state,dict(task='SC01 file job',template_id='TPL-02',time_mode='past',scale='background'))
        second=self.profile('Current B');second['bases'][0].update(mode='server',connection='Srvr=example;Ref=sc01');save_profile(self.state,second,expected_revision=first['revision'])
        result=self.check(investigation_id=case['investigation_id'])
        self.assertEqual(result['profile']['name'],'Pinned A')
        self.assertEqual(result['profile']['revision'],first['revision'])
        self.assertEqual(result['specialized']['sql'],'not_applicable')

    def test_demo_receipt_survives_resume_and_never_changes_real_context(self):
        first=save_profile(self.state,self.profile(),expected_revision=0)
        with patch('subprocess.run',side_effect=AssertionError('demo launched native process')):
            result=self.api.run_demo(self.state,root=self.bundle)
        self.assertEqual(result['origin'],'synthetic')
        self.assertEqual(result['durations_seconds'],dict(queue=240.0,execution=2460.0,total=2700.0))
        self.assertEqual(load_profile(self.state),first)
        checked=self.api.read_demo(self.state)
        self.assertEqual(checked['case_id'],result['case_id'])
        self.assertTrue(checked['integrity_verified'])
        self.assertEqual(self.check()['demonstration']['case_id'],result['case_id'])
        report=self.state/'cases'/result['case_id']/'report.json'
        self.assertTrue(report.exists())
        report.write_text('{}',encoding='utf-8')
        with self.assertRaises(ValueError):self.api.read_demo(self.state)
        self.assertEqual(self.check()['demonstration']['status'],'damaged')

    def test_demo_source_tampering_is_not_an_integrity_verified_result(self):
        result=self.api.run_demo(self.state,root=self.bundle)
        source=self.state/'cases'/result['case_id']/'sources/s1.bin';source.write_bytes(b'changed')
        with self.assertRaises(ValueError):self.api.read_demo(self.state)

    def test_unpacked_cli_readiness_works_without_optional_path_tools(self):
        args=[sys.executable,'-X','utf8',str(self.bundle/'techexpert.py'),'--state-dir',str(self.state),
              'readiness','--entrypoint-sha256',self.entry_hash]
        env=dict(os.environ,PATH='')
        result=subprocess.run(args,cwd=self.folder,env=env,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode('utf-8',errors='replace'))
        report=json.loads(result.stdout);self.assertTrue(report['capabilities']['analyze_supplied_files'])
        self.assertFalse(self.state.exists())
        (self.bundle/'knowledge/index.json').write_text('{}',encoding='utf-8')
        failed=subprocess.run(args,cwd=self.folder,env=env,capture_output=True,timeout=10)
        self.assertEqual(failed.returncode,2)
        self.assertEqual(json.loads(failed.stdout)['status'],'blocked')
        self.assertFalse(self.state.exists())


if __name__=='__main__':unittest.main()
