from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import capabilities, context_policy, investigations, operations, storage, update_state
from src.techexpert import operation_state as fs
from src.techexpert.inputs import InputError


class CheckHistoryTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.state = Path(folder.name) / 'state'
        self.case = storage.investigate(storage.ROOT / 'examples/sc01/case.json', self.state)
        first = investigations.create(self.state, dict(task='Проверка длительности'))
        self.iid = first['investigation_id']
        self.attachment = dict(id='A-case', kind='case', target_id=self.case['case_id'])
        self.doc = investigations.revise(self.state,self.iid,dict(attachments=[self.attachment]),expected_revision=1)

    def request(self, key, operation='case.show', *, arguments=None, **properties):
        if arguments is None:
            arguments = dict(case_id=self.case['case_id'])
        return dict(schema_version=1,operation=operation,operation_key=key,executor_id='unit-test',arguments=arguments,
                    context=dict(investigation_id=self.iid,expected_revision=self.doc['revision']),**properties)

    def no_worker(self, request):
        with patch('src.techexpert.operation_process.run',side_effect=AssertionError('repeated check launched')):
            return operations.run(self.state,request)

    def test_same_read_with_a_new_key_across_saved_revisions_points_to_previous_result(self):
        first=operations.run(self.state,self.request('first-read'))
        self.assertEqual(first['status'],'succeeded')
        self.doc=investigations.revise(self.state,self.iid,dict(open_questions=['Проверить временной интервал']),
                                       expected_revision=self.doc['revision'])
        repeated=self.no_worker(self.request('second-key'))
        previous=repeated['previous_check']
        self.assertEqual(repeated['stop_reason'],'equivalent_check_recorded')
        self.assertEqual(repeated['run_id'],sha256(b'second-key').hexdigest())
        self.assertEqual((previous['run_id'],previous['revision']),(first['run_id'],2))
        self.assertTrue(previous['result_receipt_observed'])
        self.assertIsNone(repeated['data'])
        self.assertFalse(fs.folder(self.state,repeated['run_id']).exists())
        data=operations.result(self.state,previous['run_id'])
        self.assertEqual(data['data'],first['data'])

    def test_changed_read_and_explicit_reason_can_start_after_verified_stop(self):
        initial=operations.run(self.state,self.request('initial-coverage','case.coverage'))
        self.assertEqual(initial['status'],'succeeded')
        changed=self.request('changed-events','case.coverage',arguments=dict(case_id=self.case['case_id'],required_events=['CALL']))
        self.assertEqual(operations.run(self.state,changed)['status'],'succeeded')
        explanation='Нужна контрольная повторная проверка'
        run=operations.run(self.state,self.request('reviewed-repeat','case.coverage',repeat_reason=explanation))
        self.assertEqual(run['status'],'succeeded')
        self.assertNotEqual(run['run_id'],initial['run_id'])
        self.assertEqual(fs.plan(fs.folder(self.state,run['run_id']))['request']['repeat_reason'],explanation)
        self.assertEqual(update_state.inspect_state(self.state)['schemata']['check-history'],[1])
        with self.assertRaisesRegex(InputError,'key conflict'):
            operations.run(self.state,self.request('reviewed-repeat','case.coverage',repeat_reason='Другой текст'))

    def test_control_never_restarts_while_stop_of_the_previous_check_is_unknown(self):
        first=operations.run(self.state,self.request('first-run'))
        folder=fs.folder(self.state,first['run_id'])
        current=fs.read(folder/'status.json')
        fs.write(folder/'status.json',dict(current,status='interrupted',stop_verified=False))
        reply=self.no_worker(self.request('new-key',repeat_reason='После неизвестного завершения'))
        self.assertEqual(reply['stop_reason'],'equivalent_check_unresolved')
        self.assertEqual(reply['previous_check']['run_id'],first['run_id'])
        self.assertFalse(reply['previous_check']['local_stop_verified'])

    def test_receipt_observation_does_not_replace_a_checked_replay(self):
        first=operations.run(self.state,self.request('retained-result'))
        folder=fs.folder(self.state,first['run_id'])
        output=fs.read(folder/'output.json')
        fs.write(folder/'output.json',dict(output,truncated=not output['truncated']))
        reply=self.no_worker(self.request('repeat-damaged'))
        self.assertIsNone(reply['data'])
        self.assertTrue(reply['previous_check']['result_receipt_observed'])
        with self.assertRaisesRegex(InputError,'output integrity'):
            operations.result(self.state,first['run_id'])

    def test_protected_program_compares_exact_selection_and_current_policy(self):
        parameters=(self.state,self.iid,self.doc['revision'],['case'],8192)
        context_policy.save(*parameters,context_policy.plan(*parameters)['plan_sha256'])
        program=dict(program='reply = api("context.read", {"attachment": "A-case", "kind": "case-summary"})\nreturn reply["status"]',
                     scope=dict(views=[dict(attachment='A-case',kind='case-summary')]))
        first=operations.run(self.state,self.request('protected-first','code.context',arguments=program))
        self.assertEqual(first['status'],'succeeded',first.get('stop_reason'))
        reply=self.no_worker(self.request('protected-next','code.context',arguments=program))
        self.assertEqual(reply['stop_reason'],'equivalent_check_recorded')
        self.assertIsNone(reply['data'])
        self.assertTrue(operations.result(self.state,first['run_id'])['replayed'])
        newer=(self.state,self.iid,self.doc['revision'],['case'],12288)
        context_policy.save(*newer,context_policy.plan(*newer)['plan_sha256'])
        current=operations.run(self.state,self.request('protected-new-policy','code.context',arguments=program))
        self.assertEqual(current['status'],'succeeded',current.get('stop_reason'))
        self.assertNotEqual(first['run_id'],current['run_id'])
        self.assertEqual(operations.result(self.state,first['run_id'])['stop_reason'],'context_policy_changed')

    def test_a_reason_is_for_scoped_saved_reads_and_must_be_nonempty(self):
        for request in (self.request('blank',repeat_reason='  '),
                        self.request('live','os.collect',arguments=dict(duration_seconds=1),repeat_reason='Новая проба'),
                        {key:value for key,value in self.request('unscoped',repeat_reason='Проверка').items() if key!='context'}):
            with self.subTest(request=request),self.assertRaises(InputError):
                capabilities.normalize_request(request)
