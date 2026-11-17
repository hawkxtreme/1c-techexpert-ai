"""Declared membership, tool observations and bounded cross-source claims."""
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


class PassportFixtures:
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.source_passports'),'Source passports are not implemented')
        self.api=importlib.import_module('src.techexpert.source_passports')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.state=self.root/'state'

    def profile(self,kind='jr'):
        from src.techexpert.profiles import validate_profile
        return dict(validate_profile(dict(schema_version=1,name='Лаборатория',
            bases=[dict(id=key,name='Одинаковое имя',mode='file',connection='//node/share/'+key) for key in ('main','copy')],
            sources=[dict(id=key,type=kind,path='//node/logs/'+key,host='node',base_ids=[base],settings={})
                for key,base in [('first','main'),('second','copy')]])),revision=4)

    def journal(self):
        from src.techexpert.native_jr import read_journal
        folder=self.root/'journal';shutil.copytree(ROOT/'tests/fixtures/native-jr',folder)
        report=read_journal(self.state,str(folder),platform_version='8.3.27.1989')
        return report

    def bind(self,profile,reports,values):
        attachments=[dict(id=key,kind='case' if 'case_id' in report else 'artifact',target_id=report.get('case_id',report.get('artifact_id'))) for key,report in reports.items()]
        return self.api.normalize_bindings(profile,attachments,reports,values)


class SourcePassportTests(PassportFixtures,unittest.TestCase):
    def test_same_names_journal_uuid_and_session_numbers_do_not_establish_database_ownership(self):
        report=self.journal();profile=self.profile()
        bindings=self.bind(profile,{'A-1':report},[
            dict(id='S-1',attachment='A-1',profile_source_id='first'),dict(id='S-2',attachment='A-1',profile_source_id='second')])
        first,second=[b['passport'] for b in bindings]
        self.assertEqual(first['facts']['base_alias']['basis'],'reported')
        self.assertEqual(first['facts']['database_mode']['value'],'file')
        self.assertEqual(first['facts']['infobase_identity']['basis'],'unknown')
        self.assertEqual(first['facts']['journal_identity']['basis'],'observed')
        self.assertEqual(first['facts']['journal_identity']['value'],second['facts']['journal_identity']['value'])
        self.assertNotEqual(first['declared_base_ids'],second['declared_base_ids'])
        link=self.api.normalize_links(bindings,[dict(id='L-1',left='S-1',right='S-2',claim='same_infobase')])[0]
        self.assertFalse(link['check']['exact_correlation_allowed'])
        self.assertIn('different_declared_bases',link['check']['reasons'])
        self.assertTrue(link['check']['clarification'])

    def test_source_version_disagreement_keeps_both_claims_and_the_saved_proof(self):
        from src.techexpert.source_code import snapshot_source
        folder=self.root/'sources';folder.mkdir()
        (folder/'Configuration.xml').write_text('<Configuration><Properties><Version>1.0</Version></Properties></Configuration>',encoding='utf-8')
        report=snapshot_source(self.state,str(folder))
        bindings=self.bind(self.profile('source'),{'A-1':report},[dict(id='S-1',attachment='A-1',profile_source_id='first',reported={'source_configuration_version':'2.0'})])
        fact=bindings[0]['passport']['facts']['source_configuration_version']
        self.assertEqual(fact['basis'],'conflicting');self.assertIsNone(fact['value'])
        self.assertEqual({c['value'] for c in fact['claims']},{'1.0','2.0'})
        observed=next(c for c in fact['claims'] if c['basis']=='observed')
        self.assertEqual(observed['proof']['target_id'],report['artifact_id']);self.assertTrue(observed['proof']['report_sha256'])
        self.assertEqual(bindings[0]['passport']['facts']['runtime_configuration_version']['basis'],'unknown')

    def test_web_connection_does_not_invent_storage_mode_and_ras_does_not_prove_application_transport(self):
        report=self.journal();profile=self.profile()
        for base in profile['bases']:base.update(mode='unknown',connection='https://web.example.test/base')
        web=self.bind(profile,{'A-1':report},[dict(id='S-1',attachment='A-1',profile_source_id='first')])[0]['passport']
        self.assertIsNone(web['facts']['database_mode']['value']);self.assertEqual(web['facts']['database_mode']['basis'],'unknown')
        self.assertEqual(web['facts']['connection_method']['value'],'web')
        for base in profile['bases']:base.update(mode='server',connection='RAS=fixture:1545;Cluster=declared;IB=declared')
        admin=self.bind(profile,{'A-1':report},[dict(id='S-1',attachment='A-1',profile_source_id='first')])[0]['passport']
        self.assertEqual(admin['facts']['database_mode']['value'],'server')
        self.assertIsNone(admin['facts']['connection_method']['value'])

    def test_applicability_is_explicit_not_inferred_from_capture_time_and_requires_timezone(self):
        report=self.journal();profile=self.profile()
        empty=self.bind(profile,{'A-1':report},[dict(id='S-1',attachment='A-1',profile_source_id='first')])[0]
        self.assertEqual(empty['passport']['applicability'],dict(start=None,end=None))
        self.assertIsNone(empty['passport']['facts']['clock_alignment']['value'])
        with self.assertRaises(ValueError):self.bind(profile,{'A-1':report},[dict(id='S-1',attachment='A-1',applicability=dict(start='2026-11-17T10:00:00',end=None))])
        with self.assertRaises(ValueError):self.bind(profile,{'A-1':report},[dict(id='S-1',attachment='A-1',applicability=dict(start='2026-11-17T11:00:00Z',end='2026-11-17T10:00:00Z'))])

    def test_reported_confirmation_cannot_forge_a_tool_observation_or_wrong_adapter(self):
        report=self.journal();profile=self.profile()
        value=dict(id='S-1',attachment='A-1',profile_source_id='first',reported=dict(infobase_identity='user-declared-id'))
        bindings=self.bind(profile,{'A-1':report},[value])
        self.assertEqual(bindings[0]['passport']['facts']['infobase_identity']['basis'],'reported')
        forged=dict(bindings[0]);forged['passport']=dict(forged['passport'],facts={'infobase_identity':dict(value='fake',basis='observed')})
        with self.assertRaises(ValueError):self.bind(profile,{'A-1':report},[forged])
        with self.assertRaises(ValueError):self.bind(self.profile('source'),{'A-1':report},[value])

    def test_provided_file_only_source_is_usable_with_unknown_profile_membership(self):
        report=self.journal()
        with patch('subprocess.Popen',side_effect=AssertionError('Passport derivation launched a process')):
            result=self.bind(None,{'A-1':report},[dict(id='S-1',attachment='A-1')])[0]
        self.assertEqual(result['passport']['declared_base_ids'],[])
        self.assertEqual(result['passport']['facts']['database_mode']['basis'],'unknown')
        self.assertEqual(result['passport']['facts']['journal_identity']['basis'],'observed')
        self.assertEqual(self.bind(None,{'A-1':report},[result]),[result])
        with self.assertRaises(ValueError):self.api.normalize_links([result],[dict(id='L-1',left='S-1',right='S-missing',claim='same_infobase')])

    def test_verified_marker_window_is_scoped_and_cannot_override_disjoint_applicability(self):
        from src.techexpert.storage import investigate
        report=investigate(ROOT/'tests/fixtures/order-load/baseline.json',self.state)
        other=investigate(ROOT/'tests/fixtures/order-load/cached.json',self.state)
        bindings=self.bind(None,{'A-1':report,'A-2':other},[
            dict(id='S-1',attachment='A-1',record_source='s1'),dict(id='S-2',attachment='A-1',record_source='s1'),dict(id='S-3',attachment='A-2',record_source='s1')])
        confirmed=self.api.normalize_links(bindings,[dict(id='L-1',left='S-1',right='S-2',claim='same_run')])[0]['check']
        self.assertEqual(confirmed['status'],'confirmed');self.assertTrue(confirmed['exact_correlation_allowed'])
        self.assertFalse(confirmed['runtime_correlation_allowed']);self.assertIn('marker_window',confirmed['scope'])
        self.assertIsNone(bindings[0]['passport']['facts']['node_identity']['value'])
        different=self.api.normalize_links(bindings,[dict(id='L-2',left='S-1',right='S-3',claim='same_run')])[0]['check']
        self.assertFalse(different['exact_correlation_allowed'])
        for value,begin,end in [(bindings[0],'10','11'),(bindings[1],'12','13')]:
            value.pop('passport');value['applicability']=dict(start='2026-11-17T'+begin+':00:00Z',end='2026-11-17T'+end+':00:00Z')
        changed=self.bind(None,{'A-1':report,'A-2':other},bindings)
        denied=self.api.normalize_links(changed,[dict(id='L-1',left='S-1',right='S-2',claim='same_run')])[0]['check']
        self.assertFalse(denied['exact_correlation_allowed']);self.assertIn('applicability_disjoint',denied['reasons'])

    def test_git_revision_equality_is_static_and_a_different_commit_is_not_runtime_correspondence(self):
        from src.techexpert.source_code import snapshot_source
        if shutil.which('git') is None:self.skipTest('Git unavailable')
        repo=self.root/'repo';repo.mkdir();empty=self.root/'git-empty-config';empty.write_text('',encoding='utf-8')
        hooks=self.root/'empty-hooks';hooks.mkdir()
        env=dict(os.environ,GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=str(empty),GIT_TERMINAL_PROMPT='0')
        command=['git','-c','user.name=SourceFixture','-c','user.email=fixture@example.test','-c','core.hooksPath='+str(hooks),
            '-c','core.attributesFile='+str(empty),'-c','core.fsmonitor=false','-c','commit.gpgsign=false','-C',str(repo)]
        def git(*args):
            result=subprocess.run(command+list(args),env=env,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr.decode('utf-8','replace'))
        git('init','--quiet');module=repo/'Module.bsl';module.write_text('Возврат 1;',encoding='utf-8')
        git('add','--','Module.bsl');git('commit','--quiet','-m','fixture1')
        first=snapshot_source(self.state,str(repo),kind='git')
        module.write_text('Возврат 2;',encoding='utf-8')
        unchanged=snapshot_source(self.state,str(repo),kind='git')
        git('add','--','Module.bsl');git('commit','--quiet','-m','fixture2')
        changed=snapshot_source(self.state,str(repo),kind='git')
        bindings=self.bind(None,{'A-1':first,'A-2':unchanged,'A-3':changed},[dict(id='S-'+str(i),attachment='A-'+str(i)) for i in (1,2,3)])
        same=self.api.normalize_links(bindings,[dict(id='L-1',left='S-1',right='S-2',claim='same_source_version')])[0]['check']
        self.assertEqual(same['status'],'confirmed');self.assertTrue(same['exact_correlation_allowed']);self.assertFalse(same['runtime_correlation_allowed'])
        self.assertIn('static_git_revision',same['scope'])
        different=self.api.normalize_links(bindings,[dict(id='L-2',left='S-1',right='S-3',claim='same_source_version')])[0]['check']
        self.assertEqual(different['status'],'conflict');self.assertFalse(different['exact_correlation_allowed'])

    def test_partial_known_bounds_prove_disjointness_in_either_order(self):
        from src.techexpert.storage import investigate
        report=investigate(ROOT/'tests/fixtures/order-load/baseline.json',self.state)
        before=dict(start=None,end='2026-11-17T11:00:00Z');after=dict(start='2026-11-17T12:00:00Z',end=None)
        for left,right in [(before,after),(after,before)]:
            with self.subTest(left=left):
                bindings=self.bind(None,{'A-1':report},[dict(id='S-1',attachment='A-1',record_source='s1',applicability=left),dict(id='S-2',attachment='A-1',record_source='s1',applicability=right)])
                check=self.api.normalize_links(bindings,[dict(id='L-1',left='S-1',right='S-2',claim='same_run')])[0]['check']
                self.assertFalse(check['exact_correlation_allowed']);self.assertIn('applicability_disjoint',check['reasons'])

    def test_selected_case_source_format_distinguishes_normalized_bsl_and_mixed_material(self):
        from src.techexpert.storage import investigate
        synthetic=investigate(ROOT/'examples/sc01/case.json',self.state)
        normalized=self.bind(None,{'A-1':synthetic},[dict(id='S-1',attachment='A-1',record_source='s1')])[0]['passport']
        self.assertEqual(normalized['type'],'normalized_events')
        self.assertEqual(normalized['capabilities']['adapter_profiles'],['normalized-events-v1'])
        report=investigate(ROOT/'tests/fixtures/order-load/baseline.json',self.state)
        source_id=next(s['id'] for s in report['sources'] if s['format']=='1c-source-text-v1')
        bsl=self.bind(self.profile('source'),{'A-1':report},[dict(id='S-1',attachment='A-1',profile_source_id='first',record_source=source_id)])[0]['passport']
        self.assertEqual(bsl['type'],'source');self.assertEqual(bsl['capabilities']['adapter_profiles'],['1c-source-text-v1'])
        self.assertEqual(bsl['facts']['recorded_run']['basis'],'unknown')
        with self.assertRaises(ValueError):self.bind(self.profile('tj'),{'A-1':report},[dict(id='S-1',attachment='A-1',profile_source_id='first',record_source=source_id)])
        tj=self.bind(self.profile('tj'),{'A-1':report},[dict(id='S-1',attachment='A-1',profile_source_id='first',record_source='s1')])[0]['passport']
        self.assertEqual(tj['type'],'tj');self.assertEqual(tj['capabilities']['adapter_profiles'],['1c-tj-text-v1'])
        self.assertEqual(tj['facts']['recorded_run']['basis'],'observed')
        auxiliary=self.bind(None,{'A-1':report},[dict(id='S-1',attachment='A-1',record_source='s2')])[0]['passport']
        self.assertEqual(auxiliary['type'],'auxiliary');self.assertEqual(auxiliary['capabilities']['adapter_profiles'],['1c-job-runtime-v1'])
        self.assertEqual(auxiliary['facts']['recorded_run']['basis'],'unknown')
        mixed=self.bind(None,{'A-1':report},[dict(id='S-1',attachment='A-1')])[0]['passport']
        self.assertEqual(mixed['type'],'mixed');self.assertGreater(len(mixed['capabilities']['adapter_profiles']),1)


class InvestigationSourceTests(PassportFixtures,unittest.TestCase):
    def managed(self,operation,key,**arguments):
        from src.techexpert import kernel
        request=self.root/(key+'.json')
        request.write_text(json.dumps(dict(schema_version=1,operation_key=key,executor_id='source-context-test',operation=operation,arguments=arguments)),encoding='utf-8')
        invocation=kernel.invoke(self.state,'run',dict(request=str(request)))
        output=io.StringIO();kernel.emit(invocation,output);return json.loads(output.getvalue())

    def prepare(self):
        from src.techexpert import investigations,profiles
        self.inv=investigations;self.profiles=profiles
        self.profiles.save_profile(self.state,self.profile(),expected_revision=0)
        doc=self.inv.create(self.state,dict(task='Одинаковые имена баз и неоднозначные журналы'))
        report=self.journal()
        changes=dict(attachments=[dict(id='A-1',kind='artifact',target_id=report['artifact_id'])],
            evidence=[dict(id='E-1',attachment='A-1',record='s1')],
            source_bindings=[dict(id='S-1',attachment='A-1',profile_source_id='first'),dict(id='S-2',attachment='A-1',profile_source_id='second')],
            source_links=[dict(id='L-1',left='S-1',right='S-2',claim='same_infobase',reported=True)],
            facts=[dict(id='F-1',text='Сопоставление записей зависит от принадлежности',evidence=['E-1'],source_links=['L-1'])])
        result=self.inv.revise(self.state,doc['investigation_id'],changes,expected_revision=1)
        return result,report

    def test_persisted_source_context_pins_the_profile_and_identifies_dependent_conclusions(self):
        doc,report=self.prepare();iid=doc['investigation_id']
        self.assertEqual(doc['schema_version'],2)
        self.assertEqual(self.inv.load(self.state,iid),doc)
        markdown=(self.inv.revision_folder(self.state,iid,2)/'report.md').read_text(encoding='utf-8')
        self.assertIn('L-1',markdown);self.assertIn('F-1',markdown)
        context=self.inv.source_context(self.state,iid)
        self.assertEqual(context['revision'],2);self.assertTrue(context['needs_clarification'])
        self.assertEqual(context['dependencies'][0]['conclusion_id'],'F-1')
        self.assertEqual(context['dependencies'][0]['unresolved_source_links'],['L-1'])
        self.profiles.save_profile(self.state,self.profile('source'),expected_revision=1)
        self.assertEqual(self.inv.source_context(self.state,iid),context)
        self.assertEqual(context['profile_revision'],1)

    def test_context_reads_saved_evidence_after_original_removal_and_rejects_damage(self):
        doc,report=self.prepare();iid=doc['investigation_id']
        before=self.inv.source_context(self.state,iid)
        shutil.rmtree(self.root/'journal')
        with patch('subprocess.Popen',side_effect=AssertionError('Context started a process')):
            self.assertEqual(self.inv.source_context(self.state,iid),before)
        (self.state/'artifacts'/report['artifact_id']/'sources/s1.bin').write_bytes(b'corrupted')
        with self.assertRaisesRegex(ValueError,'integrity'):self.inv.source_context(self.state,iid)

    def test_invalid_source_dependencies_never_commit_a_revision(self):
        doc,_=self.prepare();iid=doc['investigation_id']
        folder=self.inv.revision_folder(self.state,iid,2);before=(folder/'report.json').read_bytes()
        with self.assertRaises(ValueError):self.inv.revise(self.state,iid,dict(facts=[dict(id='F-2',text='Неразрешимая зависимость',evidence=['E-1'],source_links=['L-missing'])]),expected_revision=2)
        self.assertEqual(self.inv.load(self.state,iid),doc);self.assertEqual((folder/'report.json').read_bytes(),before)
        self.assertFalse(self.inv.revision_folder(self.state,iid,3).exists())

    def test_repinning_environment_does_not_reassign_old_source_evidence_to_new_settings(self):
        doc,_=self.prepare();iid=doc['investigation_id']
        old=doc['source_bindings'];old_bytes=(self.inv.revision_folder(self.state,iid,2)/'report.json').read_bytes()
        self.profiles.save_profile(self.state,self.profile('source'),expected_revision=1)
        revised=self.inv.revise(self.state,iid,dict(profile_revision=2),expected_revision=2)
        self.assertEqual(revised['profile_snapshot']['revision'],2)
        self.assertEqual(revised['source_bindings'],old)
        self.assertEqual(revised['source_bindings'][0]['profile_revision'],1)
        self.assertEqual(self.inv.load(self.state,iid),revised)
        self.assertEqual((self.inv.revision_folder(self.state,iid,2)/'report.json').read_bytes(),old_bytes)

    def test_global_profile_revision_is_not_limited_by_investigation_revision_count(self):
        from src.techexpert import investigations
        from src.techexpert.storage import write_json
        profile=self.profile();profile['revision']=1001
        (self.state/'profiles').mkdir(parents=True)
        write_json(self.state/'profiles/current.json',profile);write_json(self.state/'profiles/1001.json',profile)
        doc=investigations.create(self.state,dict(task='Окружение с длительной историей настроек'))
        report=self.journal()
        revised=investigations.revise(self.state,doc['investigation_id'],dict(
            attachments=[dict(id='A-1',kind='artifact',target_id=report['artifact_id'])],
            source_bindings=[dict(id='S-1',attachment='A-1',profile_source_id='first')]),expected_revision=1)
        self.assertEqual(revised['source_bindings'][0]['profile_revision'],1001)
        self.assertEqual(investigations.load(self.state,doc['investigation_id']),revised)

    def test_managed_source_context_and_program_pin_a_revision_and_verify_its_evidence_on_replay(self):
        doc,report=self.prepare();iid=doc['investigation_id']
        first=self.managed('investigation.sources','read-source-context',investigation_id=iid,revision=2)
        self.assertEqual(first['status'],'succeeded',first.get('message'))
        self.assertTrue(first['data']['needs_clarification'])
        self.assertEqual(first['snapshots'][0]['kind'],'investigations');self.assertEqual(first['snapshots'][0]['revision'],2)
        self.assertEqual(first['evidence'][0]['revision'],2)
        source='return api("investigation.sources", {"investigation_id": selected, "revision": 2})["data"]["needs_clarification"]'
        scope=dict(operations=['investigation.sources'],investigations=[dict(id=iid,revision=2)])
        program=self.managed('code.execute','source-context-program',program=source,bindings=dict(selected=iid),scope=scope)
        self.assertEqual(program['status'],'succeeded',program.get('data',{}).get('diagnostic'))
        self.assertIs(program['data']['value'],True)
        scope['investigations'][0]['revision']=1
        denied=self.managed('code.execute','wrong-context-revision',program=source,bindings=dict(selected=iid),scope=scope)
        self.assertEqual(denied['data']['diagnostic']['code'],'scope_denied');self.assertEqual(denied['data']['metrics']['calls_started'],0)
        shutil.rmtree(self.root/'journal')
        replay=self.managed('investigation.sources','read-source-context',investigation_id=iid,revision=2)
        self.assertTrue(replay['replayed']);self.assertEqual(replay['data'],first['data'])
        (self.state/'artifacts'/report['artifact_id']/'sources/s1.bin').write_bytes(b'broken')
        from src.techexpert.operations import result
        with self.assertRaisesRegex(ValueError,'integrity'):result(self.state,first['run_id'])

    def test_cli_and_setup_context_surface_only_the_source_links_used_by_a_conclusion(self):
        doc,_=self.prepare();iid=doc['investigation_id']
        result=subprocess.run([sys.executable,'-X','utf8',str(ROOT/'techexpert.py'),'--state-dir',str(self.state),
            'source-context',iid,'--revision','2'],cwd=ROOT,capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr.decode('utf-8','replace'))
        self.assertTrue(json.loads(result.stdout)['needs_clarification'])
        from src.techexpert.gui import InitHandler
        gui=InitHandler._context(doc)
        self.assertTrue(gui['source_states']['first']['needs_clarification'])
        unrelated=self.inv.revise(self.state,iid,dict(facts=[]),expected_revision=2)
        self.assertFalse(InitHandler._context(unrelated)['source_states']['first']['needs_clarification'])

    def test_managed_context_does_not_follow_a_linked_private_attachment_even_with_identical_bytes(self):
        doc,report=self.prepare();iid=doc['investigation_id']
        saved=self.state/'artifacts'/report['artifact_id']/'report.json';raw=saved.read_bytes()
        external=self.root/'external-report.json';external.write_bytes(raw)
        self.assertTrue(saved.resolve().is_relative_to(self.state.resolve()))
        saved.unlink()
        try:os.symlink(external,saved)
        except (OSError,NotImplementedError):
            saved.write_bytes(raw);self.skipTest('Local symlink creation is not available')
        result=self.managed('investigation.sources','linked-private-attachment',investigation_id=iid,revision=2)
        self.assertEqual(result['status'],'invalid_input',result.get('message'))
        self.assertIsNone(result['data'])

    def test_legacy_revision_is_not_rewritten_and_upgrades_only_on_an_explicit_edit(self):
        self.prepare()
        legacy=self.inv.create(self.state,dict(task='Старое расследование без паспортов'))
        legacy=dict(legacy,schema_version=1,investigation_id='b'*32)
        legacy.pop('source_bindings');legacy.pop('source_links');self.inv._validate(self.state,legacy)
        legacy['analysis_basis_sha256']=self.inv._basis(legacy)
        self.inv._persist(self.state,legacy)
        folder=self.inv.revision_folder(self.state,legacy['investigation_id'],1)
        before={path.name:path.read_bytes() for path in folder.iterdir() if path.is_file()}
        self.assertEqual(self.inv.load(self.state,legacy['investigation_id']),legacy)
        self.assertEqual(self.inv.source_context(self.state,legacy['investigation_id'])['status'],'legacy_unknown')
        revised=self.inv.revise(self.state,legacy['investigation_id'],dict(open_questions=['Уточнить доступные данные']),expected_revision=1)
        self.assertEqual(revised['schema_version'],2)
        self.assertEqual(before,{path.name:path.read_bytes() for path in folder.iterdir() if path.is_file()})

    def test_source_change_invalidates_new_assessment_and_public_draft_keeps_uncertainty_without_private_passports(self):
        from src.techexpert import incident_drafts
        doc,_=self.prepare();iid=doc['investigation_id']
        bindings=json.loads(json.dumps(doc['source_bindings']))
        bindings[0].pop('passport');bindings[0]['reported']=dict(infobase_identity='PRIVATE_PASSPORT_VALUE',process_identity='PRIVATE_PROCESS_OWNER',session_identity='PRIVATE_SESSION_ALIAS')
        doc=self.inv.revise(self.state,iid,dict(source_bindings=bindings,
            hypotheses=[dict(id='H-1',text='Гипотеза текущего harness',status='supported',evidence=['E-1'],source_links=['L-1'])],
            assessment=dict(summary='Объяснение harness для PRIVATE_PASSPORT_VALUE PRIVATE_PROCESS_OWNER PRIVATE_SESSION_ALIAS с зависимостью от связи',cause_state='confirmed',hypothesis_id='H-1',mechanism='Заявленный механизм',verification='Заявленная отдельная проверка',
                evidence=['E-1'],alternatives=['Другая гипотеза рассмотрена'],limitations=['Связь источников требует проверки'],references=[],
                recommendations=[dict(id='R-1',kind='diagnostic',basis=['H-1'],goal='Проверить вывод',prerequisites='Доступ к выбранным данным',expected_effect='Уточнение принадлежности',verification='Проверить идентификаторы',limitations='Не менять систему')])),expected_revision=2)
        context=self.inv.source_context(self.state,iid)
        self.assertEqual({r['conclusion_id'] for r in context['dependencies']},{'F-1','H-1','assessment','R-1'})
        before=(self.inv.revision_folder(self.state,iid,3)/'report.json').read_bytes()
        preview=incident_drafts.prepare(self.state,iid)
        for value in ('PRIVATE_PASSPORT_VALUE','PRIVATE_PROCESS_OWNER','PRIVATE_SESSION_ALIAS'):self.assertNotIn(value,json.dumps(preview,ensure_ascii=False))
        public=json.loads(next(f['text'] for f in preview['files'] if f['path']=='report.json'))
        self.assertEqual(public['source_review']['status'],'needs_clarification')
        self.assertEqual(public['source_review']['unresolved_link_count'],1)
        bindings=json.loads(json.dumps(doc['source_bindings']));bindings[0].pop('passport')
        bindings[0]['applicability']=dict(start='2026-11-17T10:00:00Z',end='2026-11-17T11:00:00Z')
        revised=self.inv.revise(self.state,iid,dict(source_bindings=bindings),expected_revision=3)
        self.assertEqual(revised['assessment_status'],'stale_due_to_revision');self.assertEqual(revised['cause_state'],'insufficient_data')
        self.assertEqual((self.inv.revision_folder(self.state,iid,3)/'report.json').read_bytes(),before)

    def test_recorded_run_identifiers_are_private_even_when_mentioned_in_public_prose(self):
        from src.techexpert import incident_drafts
        from src.techexpert.storage import investigate
        doc,_=self.prepare();case=investigate(ROOT/'tests/fixtures/order-load/baseline.json',self.state)
        identity=case['job_correlation']['native_link']['identity'];nonce=identity['nonce'];thread=identity['os_thread']
        doc=self.inv.revise(self.state,doc['investigation_id'],dict(
            attachments=doc['attachments']+[dict(id='A-2',kind='case',target_id=case['case_id'])],
            source_bindings=doc['source_bindings']+[dict(id='S-3',attachment='A-2',record_source='s1')],
            assessment=dict(summary='Наблюдавшийся идентификатор '+nonce+' и поток '+thread+' процесса 1cv8',cause_state='insufficient_data',evidence=[],limitations=['Только контрольный набор'],recommendations=[],references=[])),expected_revision=2)
        preview=incident_drafts.prepare(self.state,doc['investigation_id'])
        self.assertNotIn(nonce,json.dumps(preview,ensure_ascii=False))
        self.assertNotIn(thread,json.dumps(preview,ensure_ascii=False))
        self.assertIn('процесса 1cv8',preview['body'])
