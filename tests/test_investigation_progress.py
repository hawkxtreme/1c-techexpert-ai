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

    def test_stop_decision_requires_consistent_outcome_and_preserves_reason(self):
        stop = dict(stage_decision=dict(reason='budget_limit', detail='Достигнут предел чтения'))
        with self.assertRaises(InputError):
            investigations.revise(self.state,self.iid,dict(stop,execution_status='completed'),expected_revision=1)
        doc = investigations.revise(self.state,self.iid,stop,expected_revision=1)
        self.assertEqual(self.view()['state'],'completed_with_limits')
        self.assertEqual(self.view()['reason'],'budget_limit')
        self.assertEqual(doc['cause_state'],'insufficient_data')
