import hashlib
import importlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch


CONFIG=b'<MetaDataObject><Configuration uuid="12345678-1234-4234-8234-123456789012"><Properties><Name>SC01</Name><Version>1.0</Version></Properties></Configuration></MetaDataObject>'


class SourceExportTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.source_export'),'file source export assistant is missing')
        self.api=importlib.import_module('src.techexpert.source_export')

    def request(self,root,**changes):
        binary=root/'bin';binary.mkdir(exist_ok=True);exe=binary/'1cv8.exe';exe.write_bytes(b'synthetic platform binary')
        database=root/'original';database.mkdir(exist_ok=True);(database/'1Cv8.1CD').write_bytes(b'synthetic closed file IB')
        return dict(schema_version=1,platform_executable=str(exe),database_path=str(database),database_closed=True,
            database_mode='file',platform_version='8.3.27.1989',configuration='main',timeout_seconds=20,**changes)

    def copied(self,source,target,**limits):
        data=source.read_bytes();target.write_bytes(data)
        return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),source_identity=self.api.native.file_identity(source),consistency='synthetic_test_substitute')

    def designer(self,argv,*,cwd,guard,timeout):
        self.assertNotIn('/UpdateDBCfg',argv);self.assertNotIn('/P',argv);self.assertNotIn('/LoadConfigFromFiles',argv)
        work=Path(argv[argv.index('/F')+1]);self.assertNotEqual(work.name,'original')
        self.assertTrue((work/'1Cv8.1CD').exists())
        out=Path(argv[argv.index('/DumpConfigToFiles')+1]);out.mkdir(exist_ok=True)
        (out/'Configuration.xml').write_bytes(CONFIG)
        (out/'ConfigDumpInfo.xml').write_text('<ConfigDumpInfo/>',encoding='utf-8')
        module=out/'CommonModules'/'LoadOrders'/'Ext';module.mkdir(parents=True)
        (module/'Module.bsl').write_text('Процедура ЗагрузитьЗаказы()\nКонецПроцедуры\n',encoding='utf-8')
        Path(argv[argv.index('/DumpResult')+1]).write_text('0\n',encoding='utf-8')
        Path(argv[argv.index('/Out')+1]).write_text('Synthetic completed dump',encoding='utf-8')
        guard()
        return dict(status='completed',exit_code=0,elapsed_seconds=.01,tree_finished=True,stop_reason=None,pid=None)

    def runtime(self,runner=None,version='8.3.27.1989'):
        from contextlib import ExitStack
        stack=ExitStack();stack.enter_context(patch.object(self.api.native,'file_version',return_value=version))
        stack.enter_context(patch.object(self.api.native,'copy_locked',side_effect=self.copied))
        stack.enter_context(patch.object(self.api.native,'run',side_effect=runner or self.designer))
        return stack

    def test_plan_does_not_launch_and_hash_refuses_unreviewed_execution(self):
        with tempfile.TemporaryDirectory() as temp,self.runtime():
            root=Path(temp);request=self.request(root);state=root/'state'
            plan=self.api.prepare(state,request)
            self.assertFalse(plan['execution_started']);self.assertTrue(plan['requires_explicit_run'])
            self.assertEqual(plan['configuration_scope'],'editable_main_configuration')
            self.assertFalse((Path(plan['working_directory'])/'1Cv8.1CD').exists())
            with self.assertRaisesRegex(ValueError,'plan'):self.api.execute(state,plan['plan_id'],expected_sha256='0'*64)
            self.api.native.run.assert_not_called()

    def test_closed_schema_file_only_exact_version_and_no_secret_arguments(self):
        with tempfile.TemporaryDirectory() as temp,self.runtime():
            root=Path(temp);request=self.request(root)
            cases=[dict(request,password='secret'),dict(request,argv=['/Execute','x']),dict(request,database_mode='server'),
                dict(request,database_closed=False),dict(request,platform_version='8.3.26.1'),dict(request,configuration='database'),
                dict(request,timeout_seconds=True),dict(request,schema_version=True),dict(request,max_copy_bytes=0),dict(request,output_directory=str(root/'sources.zip'))]
            for candidate in cases:
                with self.subTest(keys=list(candidate)),self.assertRaises(ValueError):self.api.prepare(root/'state',candidate)
            self.api.native.run.assert_not_called()

    def test_existing_output_and_path_inside_original_are_refused(self):
        with tempfile.TemporaryDirectory() as temp,self.runtime():
            root=Path(temp);request=self.request(root);existing=root/'existing';existing.mkdir();(existing/'user.txt').write_text('keep')
            for target in (existing,Path(request['database_path'])/'export',root/'state'):
                with self.subTest(target=target),self.assertRaises(ValueError):self.api.prepare(root/'state',dict(request,output_directory=str(target)))
            self.assertEqual((existing/'user.txt').read_text(),'keep')

    def test_stale_source_and_executable_are_refused_before_native_launch(self):
        with tempfile.TemporaryDirectory() as temp,self.runtime():
            root=Path(temp);request=self.request(root);state=root/'state';first=self.api.prepare(state,request)
            (Path(request['database_path'])/'1Cv8.1CD').write_bytes(b'source changed')
            result=self.api.execute(state,first['plan_id'],expected_sha256=first['plan_sha256'])
            self.assertEqual(result['status'],'failed_preflight')
            second=self.api.prepare(state,request);Path(request['platform_executable']).write_bytes(b'changed platform')
            result=self.api.execute(state,second['plan_id'],expected_sha256=second['plan_sha256'])
            self.assertEqual(result['status'],'failed_preflight');self.api.native.run.assert_not_called()

    def test_export_uses_private_copy_snapshots_sources_and_does_not_rerun(self):
        from src.techexpert.source_code import search_source
        with tempfile.TemporaryDirectory() as temp,self.runtime():
            root=Path(temp);request=self.request(root);source=Path(request['database_path'])/'1Cv8.1CD';original=source.read_bytes();state=root/'state'
            plan=self.api.prepare(state,request);result=self.api.execute(state,plan['plan_id'],expected_sha256=plan['plan_sha256'])
            self.assertEqual(result['status'],'completed');self.assertEqual(source.read_bytes(),original)
            self.assertEqual(result['working_version_match'],'unknown');self.assertFalse(result['extensions_included'])
            found=search_source(state,result['source_artifact_id'],'ЗагрузитьЗаказы')
            self.assertEqual(found['matches'][0]['line'],1)
            again=self.api.execute(state,plan['plan_id'],expected_sha256=plan['plan_sha256'])
            self.assertEqual(again['artifact_id'],result['artifact_id']);self.assertEqual(self.api.native.run.call_count,1)
            self.assertNotIn('.1CD',' '.join(s['name'] for s in self.api.status(state,plan['plan_id'])['artifact_sources']))

    def test_successful_exit_without_platform_result_is_partial(self):
        def missing(*args,**kwargs):
            result=self.designer(*args,**kwargs);Path(args[0][args[0].index('/DumpResult')+1]).unlink();return result
        with tempfile.TemporaryDirectory() as temp,self.runtime(missing):
            root=Path(temp);plan=self.api.prepare(root/'state',self.request(root))
            result=self.api.execute(root/'state',plan['plan_id'],expected_sha256=plan['plan_sha256'])
            self.assertEqual(result['status'],'failed_export');self.assertIsNone(result['source_artifact_id'])

    def test_missing_or_entity_configuration_is_not_an_indexed_export(self):
        for content in (None,b'<!DOCTYPE x [<!ENTITY a "secret">]><MetaDataObject><Configuration>&a;</Configuration></MetaDataObject>',
                        '<!DOCTYPE x [<!ENTITY a "SC01">]><MetaDataObject><Configuration><Properties><Name>&a;</Name></Properties></Configuration></MetaDataObject>'.encode('utf-16')):
            def bad(*args,**kwargs):
                result=self.designer(*args,**kwargs);out=Path(args[0][args[0].index('/DumpConfigToFiles')+1])/'Configuration.xml'
                if content is None:out.unlink()
                else:out.write_bytes(content)
                return result
            with self.subTest(content=content),tempfile.TemporaryDirectory() as temp,self.runtime(bad):
                root=Path(temp);plan=self.api.prepare(root/'state',self.request(root))
                result=self.api.execute(root/'state',plan['plan_id'],expected_sha256=plan['plan_sha256'])
                self.assertEqual(result['status'],'failed_export')

    def test_cancelled_native_execution_keeps_its_own_status(self):
        def cancelled(*args,**kwargs):return dict(status='stopped',stop_reason='cancelled',exit_code=1,tree_finished=True)
        with tempfile.TemporaryDirectory() as temp,self.runtime(cancelled):
            root=Path(temp);state=root/'state';plan=self.api.prepare(state,self.request(root))
            result=self.api.execute(state,plan['plan_id'],expected_sha256=plan['plan_sha256'])
            self.assertEqual(result['status'],'cancelled');self.assertIsNone(result['source_artifact_id'])

    def test_tampering_and_interrupted_marker_do_not_launch_a_second_process(self):
        with tempfile.TemporaryDirectory() as temp,self.runtime():
            root=Path(temp);state=root/'state';request=self.request(root);plan=self.api.prepare(state,request)
            folder=state/'source-exports'/plan['plan_id'];(folder/'plan.json').write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError,'integrity'):self.api.status(state,plan['plan_id'])
            next_plan=self.api.prepare(state,request);folder=state/'source-exports'/next_plan['plan_id'];(folder/'started.json').write_text('{}')
            self.assertEqual(self.api.status(state,next_plan['plan_id'])['status'],'running_or_interrupted')
            with self.assertRaisesRegex(ValueError,'unknown'):self.api.execute(state,next_plan['plan_id'],expected_sha256=next_plan['plan_sha256'])
            self.api.native.run.assert_not_called()

    def test_native_nonzero_result_and_unfinished_tree_are_not_indexed(self):
        for mode in ('result','tree'):
            def incomplete(*args,**kwargs):
                result=self.designer(*args,**kwargs)
                if mode=='result':Path(args[0][args[0].index('/DumpResult')+1]).write_text('1')
                else:result['tree_finished']=False
                return result
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temp,self.runtime(incomplete):
                root=Path(temp);state=root/'state';plan=self.api.prepare(state,self.request(root))
                result=self.api.execute(state,plan['plan_id'],expected_sha256=plan['plan_sha256'])
                self.assertEqual(result['status'],'failed_export');self.assertIsNone(result['source_artifact_id'])

    def test_valid_large_dump_stays_exported_but_not_indexed(self):
        def large(*args,**kwargs):
            result=self.designer(*args,**kwargs);out=Path(args[0][args[0].index('/DumpConfigToFiles')+1]);(out/'LargeModule.bsl').write_bytes(b' '* (8*1024*1024));return result
        with tempfile.TemporaryDirectory() as temp,self.runtime(large):
            root=Path(temp);state=root/'state';plan=self.api.prepare(state,self.request(root));result=self.api.execute(state,plan['plan_id'],expected_sha256=plan['plan_sha256'])
            self.assertEqual(result['status'],'exported_not_indexed');self.assertIsNone(result['source_artifact_id'])
            self.assertTrue((Path(result['output_directory'])/'LargeModule.bsl').is_file())

    def test_unc_device_and_existing_reparse_ancestors_are_refused(self):
        with tempfile.TemporaryDirectory() as temp,self.runtime():
            root=Path(temp);request=self.request(root)
            for path in ('\\\\server\\share\\ib','\\\\?\\C:\\ib','relative/ib'):
                with self.subTest(path=path),self.assertRaises(ValueError):self.api.prepare(root/'state',dict(request,database_path=path))
            linked=root/'linked'
            if os.name=='nt':
                import subprocess
                subprocess.run(['cmd','/c','mklink','/J',str(linked),request['database_path']],capture_output=True,check=True)
            else:linked.symlink_to(request['database_path'],target_is_directory=True)
            try:
                with self.assertRaisesRegex(ValueError,'link|reparse'):self.api.prepare(root/'state',dict(request,database_path=str(linked)))
            finally:
                if os.name=='nt':os.rmdir(linked)
                else:linked.unlink()

    def test_linked_source_corruption_is_detected_on_status(self):
        from src.techexpert.artifacts import artifact_folder
        with tempfile.TemporaryDirectory() as temp,self.runtime():
            root=Path(temp);state=root/'state';plan=self.api.prepare(state,self.request(root));result=self.api.execute(state,plan['plan_id'],expected_sha256=plan['plan_sha256'])
            (artifact_folder(state,result['source_artifact_id'])/'sources/s1.bin').write_bytes(b'corrupted')
            with self.assertRaises(ValueError):self.api.status(state,plan['plan_id'])

    def test_low_disk_space_and_unsupported_detected_version_do_not_start(self):
        with tempfile.TemporaryDirectory() as temp,self.runtime(version='8.3.26.1'):
            root=Path(temp)
            with self.assertRaisesRegex(ValueError,'version'):self.api.prepare(root/'state',self.request(root))
        with tempfile.TemporaryDirectory() as temp,self.runtime(),patch('src.techexpert.source_export.shutil.disk_usage') as usage:
            usage.return_value=type('Disk',(),dict(free=1))()
            root=Path(temp)
            with self.assertRaisesRegex(ValueError,'space'):self.api.prepare(root/'state',self.request(root))
            self.api.native.run.assert_not_called()

    def test_cli_exposes_the_real_commands_and_refuses_secret_request_without_echo(self):
        cli=Path(__file__).resolve().parents[1]/'techexpert.py'
        help_result=subprocess.run([sys.executable,str(cli),'--help'],capture_output=True,encoding='utf-8',timeout=10)
        for command in ('source-export-plan','source-export','source-export-status'):self.assertIn(command,help_result.stdout)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);request=self.request(root);request['password']='SYNTHETIC-NOT-FOR-OUTPUT'
            path=root/'request.json';path.write_text(json.dumps(request),encoding='utf-8')
            run=subprocess.run([sys.executable,str(cli),'--state-dir',str(root/'state'),'source-export-plan',str(path)],capture_output=True,encoding='utf-8',timeout=10)
            self.assertEqual(run.returncode,2);self.assertNotIn(request['password'],run.stdout+run.stderr)
            self.assertEqual(json.loads(run.stdout)['status'],'error')

    def test_cli_can_connect_a_ready_catalog_without_repeating_gui_input(self):
        from src.techexpert.profiles import save_profile,load_profile
        cli=Path(__file__).resolve().parents[1]/'techexpert.py'
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);state=root/'state';ready=root/'ready';ready.mkdir()
            profile=dict(schema_version=1,name='SC01',bases=[dict(id='file',name='File',mode='file',connection=str(root/'IB'))],sources=[])
            saved=save_profile(state,profile);profile['sources']=[dict(id='code',type='source',path=str(ready),host='',base_ids=['file'],settings=dict(kind='catalog',match_status='unknown'))]
            document=root/'profile.json';document.write_text(json.dumps(profile),encoding='utf-8')
            run=subprocess.run([sys.executable,str(cli),'--state-dir',str(state),'profile-save',str(document),'--expected-revision',str(saved['revision'])],capture_output=True,encoding='utf-8',timeout=10)
            self.assertTrue(run.stdout,'profile-save command is missing')
            self.assertEqual(run.returncode,0,run.stdout+run.stderr)
            self.assertEqual(load_profile(state)['sources'][0]['path'],str(ready))
            self.assertEqual(json.loads(run.stdout)['capability_status'],'configured_not_connected')


if __name__=='__main__':unittest.main()
