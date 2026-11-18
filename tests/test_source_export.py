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

    def cleanup_cli(self, state, *args, expected=0):
        cli = Path(__file__).resolve().parents[1] / 'techexpert.py'
        run = subprocess.run(
            [sys.executable, '-B', '-X', 'utf8', str(cli), '--state-dir', str(state), *map(str, args)],
            capture_output=True, encoding='utf-8', timeout=20,
        )
        self.assertEqual(run.returncode, expected, run.stdout + run.stderr)
        return json.loads(run.stdout)

    def completed_for_cleanup(self, root):
        def modifies_work_copy(argv, **kwargs):
            result = self.designer(argv, **kwargs)
            work = Path(argv[argv.index('/F') + 1]) / '1Cv8.1CD'
            work.write_bytes(b'Designer updated its private copy')
            return result
        state = root / 'state'
        request = self.request(root)
        with self.runtime(modifies_work_copy):
            plan = self.api.prepare(state, request)
            result = self.api.execute(state, plan['plan_id'], expected_sha256=plan['plan_sha256'])
        self.assertEqual(result['status'], 'completed')
        return state, plan, result

    @unittest.skipUnless(os.name == 'nt', 'verified file-export cleanup uses Windows handles')
    def test_gui_selects_the_export_work_copy_by_its_verified_plan(self):
        from src.techexpert import artifacts, investigations
        from src.techexpert.gui_storage import Storage

        with tempfile.TemporaryDirectory() as temp:
            state, export, result = self.completed_for_cleanup(Path(temp))
            target = Path(export['working_directory']) / '1Cv8.1CD'
            original = Path(export['source_file'])
            original_bytes = original.read_bytes()
            selected = investigations.create(state, {'task': 'Материалы выгрузки'})['investigation_id']
            investigations.revise(state, selected, {'attachments': [dict(id='A-1', kind='artifact',
                                  target_id=result['artifact_id'])]}, expected_revision=1)
            gui = Storage(state)
            page = gui.request(selected, dict(action='materials', category='working_copies'))
            row, = page['entries']
            self.assertEqual(row['export_plan_id'], export['plan_id'])
            preview = gui.request(selected, dict(action='preview', **row['cleanup_selection'], use_policy=False))
            self.assertEqual(preview['path'], str(target))
            self.assertEqual(preview['logical_bytes'], target.stat().st_size)
            done = gui.request(selected, dict(action='apply', plan_sha256=preview['plan_sha256']))
            self.assertEqual(done['status'], 'removed')
            self.assertFalse(target.exists())
            self.assertEqual(original.read_bytes(), original_bytes)
            artifacts.load_artifact(state, result['source_artifact_id'])

    @unittest.skipUnless(os.name == 'nt', 'verified file-export cleanup uses Windows handles')
    def test_reviewed_cleanup_removes_only_current_private_export_copy_once(self):
        from src.techexpert.investigations import create, revise
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state, export, result = self.completed_for_cleanup(root)
            target = Path(export['working_directory']) / '1Cv8.1CD'
            self.assertNotEqual(hashlib.sha256(target.read_bytes()).hexdigest(), result['copy']['sha256'])
            extra = target.with_name('later-user-file.txt')
            extra.write_bytes(b'keep')
            original = Path(export['source_file'])
            export_file = Path(export['output_directory']) / 'Configuration.xml'
            preserved = {path: path.read_bytes() for path in (original, export_file, extra)}
            investigation = create(state, dict(task='Проверить материалы выгрузки'))['investigation_id']
            revise(state, investigation, dict(
                attachments=[dict(id='A-1', kind='artifact', target_id=result['artifact_id'])],
                evidence=[dict(id='E-1', attachment='A-1', record='s1')],
            ), expected_revision=1)
            materials = self.cleanup_cli(state, 'investigation-materials', investigation, '--category', 'working_copies')
            self.assertEqual(materials['entries'][0]['path'], str(target))
            self.assertEqual(materials['entries'][0]['export_plan_id'], export['plan_id'])
            self.assertEqual(materials['categories']['working_copies']['observed_bytes'], target.stat().st_size)
            preview = self.cleanup_cli(state, 'source-export-cleanup-plan', export['plan_id'])
            self.assertEqual(preview['status'], 'ready')
            self.assertEqual(preview['plan']['file']['sha256'], hashlib.sha256(target.read_bytes()).hexdigest())
            self.assertTrue(target.exists())
            document = root / 'reviewed-plan.json'
            document.write_text(json.dumps(preview['plan']), encoding='utf-8')
            self.cleanup_cli(state, 'source-export-cleanup-apply', document, '--expected-sha256', '0' * 64, expected=2)
            self.assertTrue(target.exists())
            applied = self.cleanup_cli(state, 'source-export-cleanup-apply', document,
                                       '--expected-sha256', preview['plan_sha256'])
            self.assertEqual(applied['status'], 'removed')
            self.assertFalse(target.exists())
            self.assertEqual({path: path.read_bytes() for path in preserved}, preserved)
            verified = self.cleanup_cli(state, 'source-export-status', export['plan_id'])
            self.assertEqual(verified['source_artifact_id'], result['source_artifact_id'])
            self.assertEqual(verified['work_copy_cleanup']['status'], 'removed')
            materials = self.cleanup_cli(state, 'investigation-materials', investigation, '--category', 'working_copies')
            self.assertEqual(materials['entries'][0]['status'], 'removed')
            self.assertEqual(materials['categories']['working_copies']['observed_bytes'], 0)
            self.assertEqual(materials['categories']['evidence']['unavailable'], 0)
            target.write_bytes(b'an unrelated later file')
            again = self.cleanup_cli(state, 'source-export-cleanup-apply', document,
                                     '--expected-sha256', preview['plan_sha256'])
            self.assertTrue(again['replayed'])
            self.assertEqual(again['current_file_status'], 'path_reoccupied')
            self.assertEqual(target.read_bytes(), b'an unrelated later file')

    def test_work_copy_policy_defaults_to_keep_and_is_saved_with_an_exact_revision(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = root / 'state'
            first = self.cleanup_cli(state, 'retention-policy')
            self.assertIsNone(first['source_export_work_copy_days'])
            self.assertEqual(first['revision'], 0)
            self.assertFalse(state.exists())
            document = root / 'retention.json'
            document.write_text(json.dumps(dict(schema_version=1, source_export_work_copy_days=7)), encoding='utf-8')
            saved = self.cleanup_cli(state, 'retention-policy-save', document, '--expected-revision', '0')
            self.assertEqual(saved['revision'], 1)
            self.assertEqual(saved['source_export_work_copy_days'], 7)
            self.assertEqual(self.cleanup_cli(state, 'retention-policy'), saved)
            self.cleanup_cli(state, 'retention-policy-save', document, '--expected-revision', '0', expected=2)
            self.assertEqual(self.cleanup_cli(state, 'retention-policy'), saved)

    @unittest.skipUnless(os.name == 'nt', 'file identity and removal use Windows handles')
    def test_legacy_receipt_and_busy_linked_or_changed_copy_are_handled(self):
        from src.techexpert import export_retention
        with tempfile.TemporaryDirectory() as temp:
            state, plan, _ = self.completed_for_cleanup(Path(temp))
            target = Path(plan['working_directory']) / '1Cv8.1CD'
            native = self.api.native.file_identity(target)
            legacy = dict(device=native['volume_serial'], inode=int.from_bytes(bytes.fromhex(native['file_id']), 'little'))
            self.assertTrue(export_retention._same_file(legacy, native))
            with target.open('rb'), self.assertRaises(OSError):
                export_retention.preview(state, plan['plan_id'])
            alias = target.with_name('second-link.1CD')
            os.link(target, alias)
            with self.assertRaisesRegex(ValueError, 'hard-link'):
                export_retention.preview(state, plan['plan_id'])
            alias.unlink()
            reviewed = export_retention.preview(state, plan['plan_id'])
            target.write_bytes(b'changed after preview')
            with self.assertRaisesRegex(ValueError, 'working copy changed'):
                export_retention.apply(state, reviewed['plan'], expected_sha256=reviewed['plan_sha256'])
            self.assertEqual(target.read_bytes(), b'changed after preview')
            self.assertIsNone(export_retention.status(state, plan['plan_id']))

    @unittest.skipUnless(os.name == 'nt', 'file identity and removal use Windows handles')
    def test_selected_policy_is_rechecked_and_an_interrupted_receipt_is_never_retried(self):
        from src.techexpert import export_retention, retention_policy
        with tempfile.TemporaryDirectory() as temp:
            state, plan, _ = self.completed_for_cleanup(Path(temp))
            target = Path(plan['working_directory']) / '1Cv8.1CD'
            export_id = plan['plan_id']
            retained = export_retention.preview(state, export_id, use_policy=True)
            self.assertEqual(retained['status'], 'retained_by_policy')
            retention_policy.save(state, dict(schema_version=1, source_export_work_copy_days=0), expected_revision=0)
            approved = export_retention.preview(state, export_id, use_policy=True)
            self.assertTrue(target.is_file())
            retention_policy.save(state, dict(schema_version=1, source_export_work_copy_days=30), expected_revision=1)
            with self.assertRaisesRegex(ValueError, 'retention policy changed'):
                export_retention.apply(state, approved['plan'], expected_sha256=approved['plan_sha256'])
            self.assertTrue(target.is_file())
            manual = export_retention.preview(state, export_id)
            original_write = export_retention.fs.write

            def fail_completion(path, value):
                if path.name == export_retention.RECEIPT:
                    raise OSError('simulated interruption after the file was removed')
                original_write(path, value)

            with patch.object(export_retention.fs, 'write', side_effect=fail_completion), self.assertRaises(OSError):
                export_retention.apply(state, manual['plan'], expected_sha256=manual['plan_sha256'])
            self.assertFalse(target.exists())
            view = self.api.status(state, export_id)
            self.assertEqual(view['work_copy_cleanup']['status'], 'outcome_unverified')
            target.write_bytes(b'keep this later file')
            retry = export_retention.apply(state, manual['plan'], expected_sha256=manual['plan_sha256'])
            self.assertEqual(retry['status'], 'outcome_unverified')
            self.assertTrue(retry['replayed'])
            self.assertEqual(target.read_bytes(), b'keep this later file')

    @unittest.skipUnless(os.name == 'nt', 'verified file-export cleanup uses Windows handles')
    def test_cleanup_rechecks_known_reuse_as_a_file_base_or_an_export_input(self):
        from src.techexpert import export_retention
        from src.techexpert.profiles import save_profile
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state, plan, _ = self.completed_for_cleanup(root)
            export_id = plan['plan_id']
            work = Path(plan['working_directory'])
            approved = export_retention.preview(state, export_id)
            address = f'Usr="lab";File="{work.parent / "source" / ".." / work.name}";'
            selection = dict(schema_version=1, name='Current registration', sources=[],
                             bases=[dict(id='local', name='Selected copy', mode='file', connection=address)])
            save_profile(state, selection, expected_revision=0)
            with self.assertRaisesRegex(ValueError, 'active environment source'):
                export_retention.apply(state, approved['plan'], expected_sha256=approved['plan_sha256'])
            original_base = dict(selection['bases'][0], connection=str(Path(plan['source_file']).parent))
            save_profile(state, dict(selection, bases=[original_base]), expected_revision=1)
            with self.runtime():
                second = self.api.prepare(state, self.request(root) | {'database_path': str(work)})
            self.assertNotEqual(second['plan_id'], export_id)
            with self.assertRaisesRegex(ValueError, 'selected original of another source export'):
                export_retention.apply(state, approved['plan'], expected_sha256=approved['plan_sha256'])
            self.assertTrue((work / '1Cv8.1CD').is_file())
            self.assertIsNone(export_retention.status(state, export_id))

    @unittest.skipUnless(os.name == 'nt', 'verified file-export cleanup uses Windows handles')
    def test_profile_writer_cannot_enter_between_reuse_check_and_disposition(self):
        from src.techexpert import export_retention
        from src.techexpert.profiles import save_profile
        with tempfile.TemporaryDirectory() as temp:
            state, plan, _ = self.completed_for_cleanup(Path(temp))
            work = Path(plan['working_directory'])
            approved = export_retention.preview(state, plan['plan_id'])
            snapshot = export_retention.native.snapshot_cleanup_file
            profile = dict(schema_version=1, name='Concurrent configuration', sources=[],
                           bases=[dict(id='local', name='Copy', mode='file', connection=str(work))])

            def overlap(path, *, before_remove, **kwargs):
                def attempt_registration(checked):
                    before_remove(checked)
                    with self.assertRaisesRegex(ValueError, 'profile is being saved'):
                        save_profile(state, profile, expected_revision=0)
                return snapshot(path, before_remove=attempt_registration, **kwargs)

            with patch.object(export_retention.native, 'snapshot_cleanup_file', side_effect=overlap):
                done = export_retention.apply(state, approved['plan'], expected_sha256=approved['plan_sha256'])
            self.assertEqual(done['status'], 'removed')
            self.assertFalse((state / 'profiles/current.json').exists())
            self.assertFalse((state / 'profiles/write.lock').exists())


if __name__=='__main__':unittest.main()
