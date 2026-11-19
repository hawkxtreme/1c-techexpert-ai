from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import investigations, operation_state as fs, storage, update_state
from src.techexpert.inputs import InputError


class InvestigationProgressTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / 'state'
        self.first = investigations.create(self.state, dict(task='Закрытый текст задачи'))
        self.iid = self.first['investigation_id']

    def cli(self, *args, expected=0):
        proc = subprocess.run([sys.executable, '-B', '-X', 'utf8', str(storage.ROOT / 'techexpert.py'),
                               '--state-dir', str(self.state), *map(str, args)], capture_output=True, timeout=45)
        self.assertEqual(proc.returncode, expected, proc.stderr.decode('utf-8', 'replace'))
        return json.loads(proc.stdout)

    def view(self):
        from src.techexpert.investigation_progress import view
        return view(self.state, self.iid)

    def controlled_run(self, key, *, doc=None, status='running', stopped=False):
        doc = self.first if doc is None else doc
        context = dict(investigation_id=doc['investigation_id'], expected_revision=doc['revision'])
        run_id = sha256(key.encode()).hexdigest()
        folder = fs.folder(self.state, run_id)
        folder.mkdir(parents=True)
        plan = dict(schema_version=1, context=dict(**context, report_sha256=fs.digest(doc), profile_sha256=doc['profile_sha256']),
                    request=dict(operation='case.analyze', operation_key=key, context=context,
                                 arguments=dict(manifest='Закрытый путь к ТЖ')))
        fs.write(folder/'plan.json', plan)
        fs.write(folder/'plan-receipt.json', dict(sha256=fs.digest(plan)))
        identity = fs.process_identity(os.getpid())
        record = dict(schema_version=1, run_id=run_id, status=status, owner=identity, child=identity,
                      stop_verified=stopped, heartbeat_at=fs.stamp())
        fs.write(folder/'status.json',record)
        return folder, record

    def test_cli_reports_wait_and_private_reason_is_kept_in_saved_report(self):
        reply = self.cli('investigation-progress', self.iid)
        self.assertEqual(reply['data']['state'], 'awaiting_agent')
        doc = investigations.revise(self.state, self.iid, dict(stage_decision=dict(
            reason='episode_needed', detail='Закрытая причина выбора эпизода')), expected_revision=1)
        reply = self.cli('investigation-progress', self.iid)
        self.assertEqual(reply['data']['state'], 'needs_episode')
        self.assertEqual(reply['data']['reason'], 'episode_needed')
        self.assertEqual(reply['data']['last_recorded_at'], doc['created_at'])
        self.assertNotIn('Закрыт', json.dumps(reply, ensure_ascii=False))
        folder = investigations.revision_folder(self.state, self.iid, 2)
        self.assertIn('Закрытая причина', (folder/'report.md').read_text(encoding='utf-8'))
        self.assertEqual(update_state.inspect_state(self.state)['schemata']['investigation-progress'], [1])
        filled = investigations.revise(self.state, self.iid, dict(episode=dict(description='Указан эпизод')),
                                        expected_revision=2)
        self.assertNotIn('stage_decision', filled)
        self.assertEqual(self.view()['state'], 'awaiting_agent')
        self.assertEqual(investigations.load(self.state,self.iid,revision=2), doc)

    def test_revision_comparison_pages_changed_materials_facts_and_assessment(self):
        original = storage.investigate(storage.ROOT/'examples/sc01/case.json', self.state)
        new_case = storage.investigate(storage.ROOT/'tests/fixtures/order-load/cached.json', self.state)
        original_ref = dict(id='A-1', kind='case', target_id=original['case_id'])
        new_ref = dict(id='A-2', kind='case', target_id=new_case['case_id'])
        old_ref = dict(id='E-1', attachment='A-1', record='s1:2')
        new_evidence = dict(id='E-2', attachment='A-2', record='s1:1')

        def facts(ref, evidence):
            return [dict(id='F-1', text='Закрытый факт', evidence=[evidence], measurement=dict(
                         attachment=ref, pointer='/durations_seconds/execution'))]

        old = investigations.revise(self.state, self.iid, dict(attachments=[original_ref], evidence=[old_ref],
            facts=facts('A-1', 'E-1'), hypotheses=[dict(id='H-1',text='Закрытая гипотеза',status='testing',evidence=[])],
            execution_status='completed',stage_decision=dict(reason='sufficient_answer',detail='Закрытая причина остановки'),
            assessment=dict(summary='Закрытая прежняя оценка',cause_state='insufficient_data',
                            evidence=[],limitations=[],recommendations=[],references=[]),
            improvement=dict(applied='reported',comparability='unknown',effect='unknown',goal='unknown',
                             recurrence='unknown',window=None,evidence=[])),expected_revision=1)
        investigations.revise(self.state, self.iid, dict(attachments=[original_ref,new_ref],
            evidence=[old_ref,new_evidence], facts=facts('A-2','E-2'),
            hypotheses=[dict(id='H-1',text='Закрытая гипотеза',status='supported',evidence=['E-2'])]),
            expected_revision=2)
        latest = investigations.revise(self.state,self.iid,dict(
            episode=dict(description='Закрытое уточнение')),expected_revision=3)
        status = self.cli('investigation-progress',self.iid)['data']
        self.assertEqual((status['state'],status['reason']),('awaiting_agent','assessment_stale'))
        self.assertEqual(status['resume']['assessment_status'],'stale_due_to_revision')
        self.assertEqual(status['resume']['last_saved_assessment_revision'],2)
        self.assertEqual([item['id'] for item in status['resume']['attachments']],['A-1','A-2'])
        first = self.cli('investigation-progress',self.iid,'--from-revision',2,'--limit',2)['data']
        diff = first['comparison']
        self.assertEqual((diff['before_revision'],diff['after_revision']),(2,4))
        self.assertTrue(diff['analysis_basis_changed'])
        self.assertEqual(diff['assessment']['after']['status'],'stale_due_to_revision')
        self.assertEqual(diff['improvement']['before']['applied'],'reported')
        self.assertIsNone(diff['improvement']['after'])
        self.assertEqual([(row['kind'],row['id'],row['change']) for row in diff['items']],
                         [('attachment','A-2','added'),('evidence','E-2','added')])
        self.assertEqual(diff['next_offset'],2)
        self.assertNotIn('Закрыт',json.dumps(first,ensure_ascii=False))
        self.cli('investigation-progress', self.iid, '--from-revision', 2, '--offset', 2, expected=2)

        investigations.revise(self.state,self.iid,dict(open_questions=['Проверить эффект']),expected_revision=4)
        second = self.cli('investigation-progress',self.iid,'--from-revision',2,'--to-revision',4,'--offset',2)['data']
        self.assertEqual(second['revision'],5)
        self.assertEqual(second['comparison']['after_revision'],4)
        fact,hypothesis = second['comparison']['items']
        self.assertEqual(fact['id'],'F-1')
        self.assertNotEqual(old['facts'][0]['measurement']['value'], latest['facts'][0]['measurement']['value'])
        self.assertEqual(fact['before']['measurement']['attachment'], 'A-1')
        self.assertEqual(fact['after']['measurement']['attachment'], 'A-2')
        self.assertTrue(fact['measurement_value_changed'])
        self.assertEqual((hypothesis['before']['status'],hypothesis['after']['status']),('testing','supported'))
        self.assertIsNone(second['comparison']['next_offset'])
        self.assertEqual(investigations.load(self.state,self.iid,revision=2),old)
        replacement = storage.investigate(storage.ROOT/'tests/fixtures/order-load/cached.json', self.state)
        investigations.revise(self.state,self.iid,dict(
            attachments=[original_ref,dict(new_ref,target_id=replacement['case_id'])],
            evidence=[old_ref,new_evidence]),expected_revision=5)
        changed = self.cli('investigation-progress',self.iid,'--from-revision',5)['data']['comparison']
        by_id = {row['id']:row for row in changed['items']}
        self.assertTrue(by_id['F-1']['linked_basis_changed'])
        self.assertFalse(by_id['F-1']['measurement_value_changed'])
        self.assertTrue(by_id['F-1']['measurement_basis_changed'])
        self.assertTrue(by_id['H-1']['linked_basis_changed'])

    def test_confirmed_live_previous_revision_and_own_cancel_request_have_distinct_states(self):
        active, record = self.controlled_run('active')
        other = investigations.create(self.state, dict(task='Другая задача'))
        foreign, _ = self.controlled_run('foreign', doc=other)
        investigations.revise(self.state,self.iid,dict(open_questions=['Уточнить окно']),expected_revision=1)
        now = self.view()
        self.assertEqual(now['state'], 'checking')
        self.assertEqual(now['recent_checks'][0]['revision'], 1)
        self.assertEqual(now['revision'], 2)
        self.assertIn(active.name, json.dumps(now))
        self.assertNotIn(foreign.name, json.dumps(now))
        fs.write(active/'cancel.json', dict(requested_at=fs.stamp(), executor_id='operator'))
        stopping = self.view()
        self.assertEqual(stopping['state'], 'stop_requested')
        self.assertFalse(stopping['recent_checks'][0]['local_stop_verified'])
        fs.write(active/'status.json',dict(record,status='cancelled',stop_verified=True,finished_at=fs.stamp()))
        final = self.view()
        self.assertEqual(final['recent_checks'][0]['state'], 'cancelled')
        self.assertTrue(final['recent_checks'][0]['local_stop_verified'])
        self.assertEqual(final['state'], 'awaiting_agent')

    def test_heartbeat_and_incomplete_operation_registry_cannot_prove_progress(self):
        folder, record = self.controlled_run('unknown')
        with patch('src.techexpert.operation_state.inspect_process', return_value={'state':'unknown'}):
            now = self.view()
        self.assertEqual(now['state'], 'needs_data')
        self.assertEqual(now['reason'], 'operation_status_unverified')
        self.assertEqual(now['recent_checks'][0]['state'], 'unverified')
        fs.write(folder/'plan-receipt.json',dict(sha256='f'*64))
        now = self.view()
        self.assertEqual(now['operation_inventory'], 'incomplete')
        self.assertIsNone(now['active_checks'])
        self.assertEqual(now['state'], 'needs_data')

    def test_periodic_preparation_waits_and_occurrence_resumes_same_investigation(self):
        plan = dict(operations=['Импорт ТЖ'], sources=['Выбранный ТЖ'], metrics=['Длительность'],
                    duration_seconds=86400, max_bytes=1048576, responsible='Владелец источника',
                    rollback='Вернуть настройки', verification='Есть ТЖ за время эпизода',
                    status='configured_reported', collection_state='not_started')
        investigations.revise(self.state,self.iid,dict(workflow_stage='awaiting_occurrence',observation_plan=plan),
                               expected_revision=1)
        waiting = self.view()
        self.assertEqual((waiting['state'],waiting['reason'],waiting['collection_state']),
                         ('needs_data','awaiting_occurrence','not_started'))
        self.assertEqual(waiting['active_checks'], 0)
        after = investigations.revise(self.state,self.iid,dict(occurrence=dict(source='external_monitoring',
            message='Событие повторилось',started_at=None,ended_at=None,evidence=[],link_basis=None)),expected_revision=2)
        observed = self.view()
        self.assertEqual(observed['investigation_id'],self.iid)
        self.assertEqual(observed['revision'],after['revision'])
        self.assertEqual(observed['state'],'awaiting_agent')
        self.assertEqual(observed['occurrence_status'],'reported_not_verified')
        self.assertIsNone(observed['occurrence_window'])
        investigations.revise(self.state,self.iid,dict(occurrence=dict(source='external_monitoring',
            message='Уточнение времени из мониторинга',started_at='2026-11-16T12:00:00+03:00',
            ended_at='2026-11-16T09:45:00Z',evidence=[])),expected_revision=after['revision'])
        latest = self.view()
        self.assertEqual(latest['occurrence_status'],'reported_not_verified')
        self.assertEqual(latest['occurrence_window'],dict(start='2026-11-16T09:00:00+00:00',
                                                        end='2026-11-16T09:45:00+00:00'))

    def test_stop_decision_requires_consistent_outcome_and_preserves_reason(self):
        stop = dict(stage_decision=dict(reason='budget_limit', detail='Достигнут предел чтения'))
        with self.assertRaises(InputError):
            investigations.revise(self.state,self.iid,dict(stop,execution_status='completed'),expected_revision=1)
        doc = investigations.revise(self.state,self.iid,stop,expected_revision=1)
        self.assertEqual(self.view()['state'],'completed_with_limits')
        self.assertEqual(self.view()['reason'],'budget_limit')
        self.assertEqual(doc['cause_state'],'insufficient_data')
