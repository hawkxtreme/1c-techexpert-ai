import importlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys

class InvestigationTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.investigations'),'revisioned investigation state is missing')
        self.api=importlib.import_module('src.techexpert.investigations')

    def create(self,state,**extra):
        return self.api.create(state,dict(task='Фоновая загрузка заказов стала медленной',template_id='TPL-02',
            time_mode='past',scale='background',**extra))

    def test_task_alone_starts_an_unclassified_investigation_with_explicit_unknowns(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp)
            try:doc=self.api.create(state,dict(task='В 1С периодически не открывается отчёт'))
            except ValueError as exc:self.fail('Task-only start must not require a scenario classification: '+str(exc))
            self.assertEqual(doc['template']['id'],'TPL-00')
            self.assertEqual(doc['time_mode'],'unknown');self.assertEqual(doc['scale'],'unknown')
            self.assertEqual(doc['attachments'],[]);self.assertEqual(doc['cause_state'],'insufficient_data')
            self.assertEqual(self.api.load(state,doc['investigation_id']),doc)
            plan=self.api.template_plan('TPL-00',time_mode='unknown')
            self.assertEqual(plan['sources'],[]);self.assertFalse(plan['cause_preassigned'])
            self.assertFalse((state/'cases').exists());self.assertFalse((state/'artifacts').exists())

    def test_templates_keep_time_and_scale_independent_and_file_mode_excludes_sql(self):
        catalogue=self.api.templates()
        self.assertEqual({t['id'] for t in catalogue['templates']},{'TPL-'+str(i).zfill(2) for i in range(0,11)})
        plan=self.api.template_plan('TPL-01',variant='document-posting',database_mode='file',time_mode='past')
        self.assertNotIn('sql',[s['type'] for s in plan['sources']])
        self.assertIn('client',[s['type'] for s in plan['sources']])
        self.assertFalse(plan['collection_started'])
        past_client=next(c for c in plan['checks'] if c['capability']=='testpilot')
        self.assertEqual(past_client['status'],'requires_retained_client_episode')
        self.assertEqual(past_client['operations'],['client.import'])
        server=self.api.template_plan('TPL-01',database_mode='server',time_mode='current')
        self.assertIn('sql',[s['type'] for s in server['sources']])
        current_client=next(c for c in server['checks'] if c['capability']=='testpilot')
        self.assertEqual(current_client['operations'],['client.import','client.observe'])

    def test_revisions_preserve_old_report_and_reject_stale_writers(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);first=self.create(state);iid=first['investigation_id']
            self.assertEqual(first['revision'],1)
            self.assertEqual(first['execution_status'],'partial')
            self.assertEqual(first['cause_state'],'insufficient_data')
            second=self.api.revise(state,iid,dict(open_questions=['Когда был измерен нормальный запуск?']),expected_revision=1)
            self.assertEqual(second['revision'],2)
            self.assertEqual(self.api.load(state,iid,revision=1),first)
            self.assertEqual(self.api.load(state,iid),second)
            with self.assertRaisesRegex(ValueError,'revision'):self.api.revise(state,iid,{},expected_revision=1)
            with self.assertRaises(ValueError):self.api.revise(state,iid,dict(task='Overwrite original'),expected_revision=2)
            self.assertFalse((state/'cases').exists())

    def test_tool_measurement_is_extracted_from_integrity_checked_evidence(self):
        from src.techexpert.storage import ROOT,investigate
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);case=investigate(ROOT/'examples/sc01/case.json',state)
            first=self.create(state);iid=first['investigation_id']
            second=self.api.revise(state,iid,dict(
                attachments=[dict(id='A-1',kind='case',target_id=case['case_id'])],
                evidence=[dict(id='E-1',attachment='A-1',record='s1:2')],
                facts=[dict(id='F-1',text='Длительность выполнения по границам запуска',evidence=['E-1'],
                    measurement=dict(attachment='A-1',pointer='/durations_seconds/execution'))]),expected_revision=1)
            fact=second['facts'][0]
            self.assertEqual(fact['measurement']['value'],2460)
            self.assertEqual(fact['measurement']['basis'],'verified_tool_report')
            raw=state/'cases'/case['case_id']/'sources/s1.bin';raw.write_bytes(b'changed')
            with self.assertRaises(ValueError):self.api.load(state,iid)

    def test_measurement_checks_uncited_inputs_on_which_the_calculation_depends(self):
        from src.techexpert.storage import ROOT,investigate
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp)/'state';inputs=Path(temp)/'input';inputs.mkdir()
            original=json.loads((ROOT/'examples/sc01/case.json').read_text(encoding='utf-8'))
            lines=(ROOT/'examples/sc01/events.jsonl').read_bytes().splitlines(keepends=True)
            (inputs/'first.jsonl').write_bytes(b''.join(lines[:2]));(inputs/'last.jsonl').write_bytes(b''.join(lines[2:]))
            original['sources']=[dict(path=str(inputs/name),format='normalized-events-v1') for name in ('first.jsonl','last.jsonl')]
            manifest=inputs/'case.json';manifest.write_text(json.dumps(original),encoding='utf-8')
            case=investigate(manifest,state);created=self.create(state);iid=created['investigation_id']
            self.api.revise(state,iid,dict(attachments=[dict(id='A-1',kind='case',target_id=case['case_id'])],
                evidence=[dict(id='E-1',attachment='A-1',record='s1:2')],
                facts=[dict(id='F-1',text='Execution spans two inputs',evidence=['E-1'],measurement=dict(attachment='A-1',pointer='/durations_seconds/execution'))]),expected_revision=1)
            (state/'cases'/case['case_id']/'sources/s2.bin').write_bytes(b'corrupted uncited boundary')
            with self.assertRaisesRegex(ValueError,'integrity'):self.api.load(state,iid)

    def test_cause_execution_and_change_verification_have_independent_states(self):
        from src.techexpert.artifacts import save_artifact
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);artifact=save_artifact(state,'test',{},[('observed.txt',b'observed')],{'count':1})
            first=self.create(state,harness={'name':'first','version':None,'model':None});iid=first['investigation_id']
            update=dict(execution_status='completed',attachments=[dict(id='A-1',kind='artifact',target_id=artifact['artifact_id'])],
                evidence=[dict(id='E-1',attachment='A-1',record='s1')],
                hypotheses=[dict(id='H-1',text='Проверяемый механизм',status='supported',evidence=['E-1'])],
                assessment=dict(summary='Вывод текущего harness',cause_state='confirmed',hypothesis_id='H-1',
                    mechanism='Описание механизма',verification='Отдельная проверка механизма',evidence=['E-1'],alternatives=['Проверенная альтернатива'],
                    limitations=['Контрольный случай'],recommendations=[],references=[]),
                improvement=dict(applied='evidenced',comparability='comparable',effect='better',goal='not_reached',
                                 recurrence='unknown',window=None,evidence=['E-1']))
            result=self.api.revise(state,iid,update,expected_revision=1)
            self.assertEqual(result['execution_status'],'completed');self.assertEqual(result['cause_state'],'confirmed')
            self.assertEqual(result['improvement']['effect'],'better');self.assertEqual(result['improvement']['goal'],'not_reached')
            self.assertEqual(result.get('assessment_harness'),{'name':'first','version':None,'model':None})
            moved=self.api.revise(state,iid,dict(harness={'name':'second','version':None,'model':None}),expected_revision=2)
            self.assertEqual(moved['assessment_harness']['name'],'first')
            changed=self.api.revise(state,iid,dict(episode={'description':'Другой временной эпизод'}),expected_revision=3)
            self.assertEqual(changed['cause_state'],'insufficient_data')
            self.assertEqual(changed['assessment_status'],'stale_due_to_revision')
            self.assertIsNone(changed['improvement'])
            self.assertEqual(self.api.load(state,iid,revision=2)['cause_state'],'confirmed')

    def test_dangling_references_unsupported_confirmation_and_over_budget_fail_before_writing(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);first=self.create(state);iid=first['investigation_id']
            for patch in (dict(facts=[dict(id='F-1',text='claim',evidence=['E-missing'])]),
                dict(assessment=dict(summary='Unsupported',cause_state='confirmed')),
                dict(tool_runs=[dict(id='T-1',operation='read',status='completed',elapsed_seconds=-1,output_bytes=1)]),
                dict(open_questions=['x']*1001)):
                with self.subTest(patch=patch),self.assertRaises(ValueError):self.api.revise(state,iid,patch,expected_revision=1)
            self.assertEqual(self.api.load(state,iid)['revision'],1)

    def test_report_integrity_and_safe_rendering(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);first=self.create(state);iid=first['investigation_id']
            second=self.api.revise(state,iid,dict(open_questions=['<script>alert(1)</script> ![x](https://private.invalid/pixel)']),expected_revision=1)
            folder=self.api.revision_folder(state,iid,2)
            text=(folder/'report.md').read_text(encoding='utf-8')
            self.assertNotIn('<script>',text);self.assertNotIn('![x](',text)
            (folder/'report.md').write_text('tampered',encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'integrity'):self.api.load(state,iid)

    def test_cli_creates_revises_resumes_and_lists_the_shared_catalogue(self):
        repo=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);state=root/'state';request=root/'request.json';patch=root/'patch.json'
            request.write_text(json.dumps(dict(task='Загрузка замедлилась',template_id='TPL-02',time_mode='past',scale='background')),encoding='utf-8')
            patch.write_text(json.dumps(dict(execution_status='completed',open_questions=['История ожиданий недоступна'])),encoding='utf-8')
            def run(*args):
                result=subprocess.run([sys.executable,'-X','utf8',str(repo/'techexpert.py'),'--state-dir',str(state),*args],cwd=root,capture_output=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr.decode('utf-8',errors='replace')+result.stdout.decode('utf-8',errors='replace'))
                return json.loads(result.stdout)
            self.assertEqual(len(run('templates')['templates']),11)
            created=run('investigation-create',str(request));iid=created['investigation_id']
            updated=run('investigation-update',iid,str(patch),'--expected-revision','1')
            self.assertEqual(updated['revision'],2)
            loaded=run('investigation',iid);self.assertEqual(loaded['cause_state'],'insufficient_data')
            self.assertEqual(loaded['execution_status'],'completed')
            old=run('investigation',iid,'--revision','1');self.assertEqual(old['execution_status'],'partial')

    def test_recommendations_require_rollback_and_observation_verification_needs_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);created=self.create(state);iid=created['investigation_id']
            plan=dict(operations=['Проведение'],sources=['os'],metrics=['latency'],duration_seconds=300,max_bytes=1024,
                      responsible='Администратор',rollback='Вернуть настройки',verification='Проверить отсчёты',status='data_verified')
            with self.assertRaises(ValueError):self.api.revise(state,iid,dict(observation_plan=plan),expected_revision=1)
            from src.techexpert.artifacts import save_artifact
            artifact=save_artifact(state,'test',{},[('proof',b'x')],{})
            patch=dict(attachments=[dict(id='A-1',kind='artifact',target_id=artifact['artifact_id'])],
                evidence=[dict(id='E-1',attachment='A-1',record='s1')],assessment=dict(summary='Данных мало',cause_state='insufficient_data',evidence=[],
                    limitations=['Нет истории'],references=[],recommendations=[dict(id='R-1',kind='production_change',basis=['E-1'],
                    goal='Проверка',prerequisites='Окно',expected_effect='Ускорение',verification='Повтор',limitations='Нет замеров')]))
            with self.assertRaises(ValueError):self.api.revise(state,iid,patch,expected_revision=1)

    def test_interrupted_uncommitted_revision_and_active_lock_do_not_overwrite_history(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);created=self.create(state);iid=created['investigation_id']
            folder=self.api.revision_folder(state,iid,2);folder.mkdir();(folder/'report.json').write_text('{}',encoding='utf-8')
            with self.assertRaises(FileExistsError):self.api.revise(state,iid,{},expected_revision=1)
            self.assertEqual(self.api.load(state,iid)['revision'],1)
            lock=folder.parent.parent/'write.lock';lock.write_text('interrupted-owner',encoding='ascii')
            with self.assertRaisesRegex(ValueError,'writer'):self.api.revise(state,iid,{},expected_revision=1)
            self.assertEqual(lock.read_text(encoding='ascii'),'interrupted-owner')

    def test_context_changes_pin_profile_and_template_revisions_without_rewriting_the_task(self):
        from src.techexpert.profiles import save_profile
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);created=self.create(state);iid=created['investigation_id']
            profile=save_profile(state,dict(schema_version=1,name='Local',bases=[dict(id='a',name='IB',mode='file',connection='D:/IB')],sources=[]))
            changed=self.api.revise(state,iid,dict(template_id='TPL-01',variant='document-posting',time_mode='current',scale='one',profile_revision=profile['revision']),expected_revision=1)
            self.assertEqual(changed['template']['id'],'TPL-01');self.assertEqual(changed['variant']['id'],'document-posting')
            self.assertEqual(changed['time_mode'],'current');self.assertEqual(changed['task'],created['task'])
            self.assertEqual(changed['profile_snapshot']['revision'],profile['revision'])
            save_profile(state,dict(schema_version=1,name='Different',bases=[dict(id='b',name='Other',mode='server',connection='srv/other')],sources=[]))
            self.assertEqual(self.api.load(state,iid)['profile_snapshot']['name'],'Local')
            self.assertEqual(self.api.load(state,iid,revision=1)['template']['id'],'TPL-02')

    def test_periodic_incident_is_resumed_from_external_report_in_the_same_investigation(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);first=self.create(state);iid=first['investigation_id']
            plan=dict(operations=['Загрузка заказов'],sources=['tj','os'],metrics=['execution','disk_queue'],
                duration_seconds=86400,max_bytes=64*1024*1024,responsible='Администратор',rollback='Вернуть прежний logcfg',
                verification='Проверить появление записей',status='configured_reported')
            ready=self.api.revise(state,iid,dict(workflow_stage='awaiting_occurrence',observation_plan=plan,
                episode=dict(database_mode='file',recurrence_seconds=86400,requested_window_seconds=86400)),expected_revision=1)
            self.assertEqual(ready['workflow_stage'],'awaiting_occurrence')
            self.assertEqual(ready['stage_execution_status'],'completed')
            self.assertEqual(ready['execution_status'],'partial')
            self.assertEqual(ready['continuation']['trigger'],'user_or_external_occurrence_report')
            self.assertFalse(ready['continuation']['model_polling_required'])
            self.assertIsNone(ready['occurrence'])
            resumed=self.api.revise(state,iid,dict(occurrence=dict(source='user',message='Мониторинг сообщил о повторении около 12:00',
                started_at=None,ended_at=None,evidence=[])),expected_revision=2)
            self.assertEqual(resumed['investigation_id'],iid)
            self.assertEqual(resumed['workflow_stage'],'analyze_episode')
            self.assertEqual(resumed['occurrence']['status'],'reported_not_verified')
            self.assertEqual(resumed['task'],first['task'])
            self.assertEqual(self.api.load(state,iid,revision=2)['workflow_stage'],'awaiting_occurrence')
            self.assertFalse((state/'artifacts').exists())

    def test_waiting_stage_cannot_claim_preparation_or_collection_without_a_plan(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);first=self.create(state);iid=first['investigation_id']
            with self.assertRaises(ValueError):self.api.revise(state,iid,dict(workflow_stage='awaiting_occurrence'),expected_revision=1)
            with self.assertRaises(ValueError):self.api.revise(state,iid,dict(workflow_stage='analyze_episode',occurrence=dict(source='monitor',message='event',started_at='2026-11-16T12:00:00',ended_at=None,evidence=[])),expected_revision=1)

if __name__=='__main__':unittest.main()
