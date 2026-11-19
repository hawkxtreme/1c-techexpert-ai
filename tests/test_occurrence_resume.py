import io
import json
from pathlib import Path
import tempfile
import unittest

from src.techexpert import artifacts, context_disclosure, context_policy, investigation_progress
from src.techexpert import investigation_task, investigations, kernel, mcp_tools, native_jr, storage, update_state
from src.techexpert.inputs import InputError


ROOT = Path(__file__).resolve().parents[1]
WINDOW = dict(start='2026-11-16T07:05:42Z', end='2026-11-16T07:05:44Z')
NOTICE = 'Сервис мониторинга передал сообщение о повторе. synthetic-private-notice'


class OccurrenceResumeTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.state = Path(folder.name) / 'state'
        self.case = storage.investigate(ROOT/'examples/sc01/case.json', self.state)
        self.journal = native_jr.read_journal(self.state, ROOT/'tests/fixtures/native-jr',
                                            platform_version='8.3.27.1989', utc_offset='+03:00')
        self.file = artifacts.source_path(artifacts.artifact_folder(self.state, self.journal['artifact_id']),
                                          self.journal['sources'][-1], kind='native-jr')
        self.saved_bytes = self.file.read_bytes()
        doc = investigations.create(self.state, dict(task='Периодическое замедление'))
        self.iid = doc['investigation_id']
        self.old = investigations.revise(self.state, self.iid, dict(
            workflow_stage='awaiting_occurrence',
            attachments=[dict(id='A-case', kind='case', target_id=self.case['case_id']),
                         dict(id='A-jr', kind='artifact', target_id=self.journal['artifact_id'])],
            evidence=[dict(id='E-valid', attachment='A-case', record='s1:2'),
                      dict(id='E-jr', attachment='A-jr', record='s2:r1')],
            source_bindings=[dict(id='S-case', attachment='A-case'), dict(id='S-jr', attachment='A-jr')],
            source_links=[dict(id='L-sources', left='S-case', right='S-jr', claim='same_infobase')],
            facts=[dict(id='F-valid', text='Проверенное измерение', evidence=['E-valid'],
                        measurement=dict(attachment='A-case', pointer='/durations_seconds/execution')),
                   dict(id='F-related', text='Зависит от принадлежности ЖР', evidence=['E-valid'],
                        source_links=['L-sources'])],
            hypotheses=[dict(id='H-prior', text='Прежняя проверка', status='supported', evidence=['E-jr'])],
            contradictions=[dict(id='C-prior', text='Ранее проверяли вместе', evidence=['E-valid'],
                                 hypotheses=['H-prior'], status='unresolved')],
            assessment=dict(summary='Исторический вывод', cause_state='hypothesis', hypothesis_id='H-prior',
                mechanism='Гипотеза из прежнего периода', evidence=['E-jr'], limitations=[], recommendations=[], references=[]),
            tool_runs=[dict(id='T-jr', operation='jr.events', status='completed',
                            elapsed_seconds=1, output_bytes=100, attachment='A-jr')],
            observation_plan=dict(status='data_verified', collection_state='receiving_data', evidence=['E-jr'],
                operations=['Наблюдение'], sources=['Выбранный журнал'], metrics=['Количество'],
                duration_seconds=86400, max_bytes=2097152, responsible='Тестовый стенд',
                rollback='Завершить сбор', verification='Сверить записи за окно')),
            expected_revision=1)
        report = investigations.revision_folder(self.state, self.iid, 2)
        self.prior_files = {member: (report/member).read_bytes() for member in ('report.json','report.md','receipt.json')}

    def notice(self, *, evidence=()):
        return dict(source='external_monitoring', message=NOTICE,
                    started_at=WINDOW['start'], ended_at=WINDOW['end'], evidence=list(evidence))

    def protected_request(self, **overrides):
        return dict(operation_key='notice-1', text=NOTICE, context=dict(investigation_id=self.iid,
            expected_revision=2), occurrence=dict(source='external_monitoring',
                started_at=WINDOW['start'], ended_at=WINDOW['end']), **overrides)

    def test_new_occurrence_retains_the_verified_part_and_preserves_the_old_report(self):
        self.file.unlink()
        result = investigations.revise(self.state,self.iid,dict(occurrence=self.notice()),expected_revision=2)
        self.assertEqual(result['revision'],3)
        self.assertEqual(result['workflow_stage'],'analyze_episode')
        self.assertEqual(result['occurrence']['status'],'reported_not_verified')
        self.assertEqual(result['attachments'],self.old['attachments'][:1])
        self.assertEqual(result['evidence'],self.old['evidence'][:1])
        self.assertEqual(result['facts'],self.old['facts'][:1])
        self.assertEqual(result['source_bindings'],self.old['source_bindings'][:1])
        for key in ('hypotheses','contradictions','source_links'):
            self.assertEqual(result[key],[])
        self.assertEqual(result['assessment_status'],'stale_due_to_revision')
        self.assertIsNone(result['assessment'])
        self.assertEqual(result['cause_state'],'insufficient_data')
        self.assertEqual(result['observation_plan']['status'],'evidence_unavailable')
        self.assertEqual(result['observation_plan']['collection_state'],'unknown')
        self.assertEqual(result['observation_plan']['duration_seconds'],86400)
        self.assertEqual(result['budget_accounting'],self.old['budget_accounting'])
        self.assertIsNone(result['tool_runs'][0].get('attachment'))
        self.assertEqual(investigations.load(self.state,self.iid),result)
        gap, = result['source_gaps']
        self.assertEqual((gap['attachment']['id'],gap['revision'],gap['status']),('A-jr',2,'not_found'))
        self.assertEqual(gap['attachment'],self.old['attachments'][1])
        report = investigations.revision_folder(self.state,self.iid,2)
        for member, original in self.prior_files.items():
            self.assertEqual((report/member).read_bytes(),original)
        view = investigation_progress.view(self.state,self.iid)
        self.assertEqual(view['occurrence_window']['start'],'2026-11-16T07:05:42+00:00')
        self.assertEqual(view['source_gaps'],[dict(attachment='A-jr',revision=2,status='not_found')])
        self.assertNotIn(NOTICE,json.dumps(view,ensure_ascii=False))
        self.assertEqual(update_state.inspect_state(self.state)['schemata']['investigation-progress'],[2])

    def test_task_route_resumes_and_replays_then_new_verified_evidence_can_be_linked(self):
        self.file.unlink()
        action,args,request = mcp_tools.prepare('techexpert_investigation_task',self.protected_request(),'context')
        call = kernel.invoke(self.state,action,args,wire_version=mcp_tools.LEGACY,request_document=request)
        stream = io.StringIO()
        kernel.emit(call,stream)
        data = json.loads(stream.getvalue())['structuredContent']['data']
        self.assertEqual(call['exit_code'],0)
        self.assertEqual(data['recorded_revision'],3)
        self.assertNotIn(NOTICE,stream.getvalue())
        replacement = native_jr.read_journal(self.state,ROOT/'tests/fixtures/native-jr',
                                             platform_version='8.3.27.1989', utc_offset='+03:00')
        new = dict(id='A-new',kind='artifact',target_id=replacement['artifact_id'])
        current = investigations.load(self.state,self.iid)
        linked = investigations.revise(self.state,self.iid,dict(
            attachments=[*current['attachments'],new],
            evidence=[*current['evidence'],dict(id='E-new',attachment='A-new',record='s2:r1')],
            occurrence=self.notice(evidence=['E-new']) | {'link_basis':'Свежая запись в проверенном окне'}),
            expected_revision=3)
        self.assertEqual(linked['occurrence']['status'],'evidenced_by_harness')
        retry = investigation_task.record(self.state,request)['data']
        self.assertEqual((retry['revision'],retry['recorded_revision'],retry['replayed']),(4,3,True))
        policy = (self.state,self.iid,4,['jr'],4096)
        context_policy.save(*policy,context_policy.plan(*policy)['plan_sha256'])
        result = context_disclosure.read(self.state, dict(investigation_id=self.iid,revision=4,
            kind='jr-coverage',attachment='A-new'))
        self.assertEqual(result['data']['journal']['records_in_window'],4)
        self.assertEqual(update_state.inspect_state(self.state)['schemata']['investigation-task'],[2])

    def test_linked_notice_and_stale_or_reinterpreted_request_never_hide_a_missing_source(self):
        self.file.unlink()
        with self.assertRaises((OSError,InputError)):
            investigations.revise(self.state,self.iid,
                dict(occurrence=self.notice(evidence=['E-jr']) | {'link_basis':'Проверка'}), expected_revision=2)
        with self.assertRaisesRegex(InputError, 'revision'):
            investigations.revise(self.state,self.iid,dict(occurrence=self.notice()),expected_revision=1)
        self.assertEqual(investigations._read_head(self.state,self.iid)['revision'],2)
        request = self.protected_request()
        investigation_task.record(self.state,request)
        with self.assertRaisesRegex(InputError,'key conflicts'):
            investigation_task.record(self.state,dict(request,text='Другое уведомление'))

    def test_restoring_an_exact_historical_snapshot_and_relinking_resolves_the_gap(self):
        self.file.unlink()
        resumed = investigations.revise(self.state,self.iid,dict(occurrence=self.notice()),expected_revision=2)
        self.file.write_bytes(self.saved_bytes)
        linked = investigations.revise(self.state,self.iid,dict(attachments=[
            *resumed['attachments'],self.old['attachments'][1]]),expected_revision=3)
        self.assertEqual(linked.get('source_gaps',[]),[])
        self.assertEqual(linked['evidence'],resumed['evidence'])
        self.assertEqual(linked['assessment_status'],'not_provided')

    def test_changed_material_with_a_historical_id_cannot_close_the_gap(self):
        from hashlib import sha256

        self.file.unlink()
        resumed = investigations.revise(self.state,self.iid,dict(occurrence=self.notice()),expected_revision=2)
        self.file.write_bytes(self.saved_bytes)
        folder = artifacts.artifact_folder(self.state,self.journal['artifact_id'])
        changed = dict(self.journal,result=dict(self.journal['result'],consistency='stopped_writer'))
        payload = json.dumps(changed).encode('utf-8')
        receipt = json.loads((folder/'receipt.json').read_bytes())
        (folder/'report.json').write_bytes(payload)
        (folder/'receipt.json').write_text(json.dumps(dict(receipt,report_sha256=sha256(payload).hexdigest())),
                                           encoding='utf-8')
        proposed = {key:value for key,value in self.old['attachments'][1].items() if key!='report_sha256'}
        with self.assertRaisesRegex(InputError,'retained identity'):
            investigations.revise(self.state,self.iid,dict(attachments=[
                *resumed['attachments'],proposed]),expected_revision=3)
        self.assertEqual(investigations.load(self.state,self.iid),resumed)

    def test_notice_cannot_recover_a_changed_revision_or_an_unbounded_time(self):
        request = self.protected_request()
        bad = dict(request,occurrence=dict(request['occurrence'],started_at='2026-11-16T10:05:42'))
        with self.assertRaisesRegex(InputError,'offsets'):
            investigation_task.record(self.state,bad)
        previous = investigations.revision_folder(self.state,self.iid,2)
        (previous/'report.md').write_bytes(b'changed')
        with self.assertRaises(investigation_task.TaskError):
            investigation_task.record(self.state,request)
        self.assertEqual(investigations._read_head(self.state,self.iid)['revision'],2)

    def test_historical_partial_tj_is_still_readable_in_the_new_episode_window(self):
        sources = []
        for index in range(2):
            path = self.state.parent/f'tj-{index}.log'
            path.write_text('05:42.000000-10,CALL,1,SessionID=42\n',encoding='utf-8')
            sources.append(dict(path=str(path),format='1c-tj-text-v1',platform_version='8.3.27.1989',
                encoding='utf-8',placement='folders',timestamp_format='minute',rotation_hours=1,
                file_hour='2026-11-16T10:00:00+03:00'))
        manifest = self.state.parent/'native-tj.json'
        manifest.write_text(json.dumps(dict(schema=2,origin='provided',sources=sources)),encoding='utf-8')
        saved = storage.investigate(manifest,self.state)
        row = dict(id='A-mixed',kind='case',target_id=saved['case_id'])
        old = investigations.revise(self.state,self.iid,
            dict(attachments=[*self.old['attachments'],row]),expected_revision=2)
        storage.case_source_path(self.state,saved['case_id'],'s2').unlink()
        resumed = investigations.revise(self.state,self.iid,
            dict(occurrence=self.notice()),expected_revision=3)
        self.assertEqual(resumed['attachments'],old['attachments'][:2])
        self.assertEqual(resumed['source_gaps'][0]['attachment']['id'],'A-mixed')
        policy = (self.state,self.iid,4,['tj'],4096)
        context_policy.save(*policy,context_policy.plan(*policy)['plan_sha256'])
        page = context_disclosure.read(self.state,dict(attachment='A-mixed',kind='tj-coverage',
            investigation_id=self.iid,revision=3,window=WINDOW))['data']
        self.assertEqual(page['sources'][0]['records_in_window'],1)
        self.assertEqual(page['sources'][1]['availability'],'not_found')
