"""Approved observation windows and conservative operating-system sampler admission."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import investigations, operations, os_observation, profiles, update_state
from src.techexpert import operation_state as fs
from src.techexpert.inputs import InputError


class OSObservationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.state = Path(temp.name)/'state'
        bases = [dict(id=name,name=name,mode='file',connection='') for name in ('orders','other')]
        self.settings = dict(transport='local',duration_seconds=1,interval_seconds=1,max_bytes=1024**2,role='storage')
        sources = [dict(id=name,type='os',host='',path='',base_ids=[base],settings=self.settings)
                   for name,base in (('disk','orders'),('foreign','other'))]
        profiles.save_profile(self.state,dict(schema_version=1,name='SC-01 test',bases=bases,sources=sources),
                              expected_revision=0)
        initial = investigations.create(self.state,dict(task='Долго загружаются заказы'))
        self.iid = initial['investigation_id']
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.plan = dict(status='proposed',operations=['Загрузка заказов'],sources=['disk','foreign'],
                         metrics=['disk.queue'],responsible='локальная проверка',rollback='остановить сбор',
                         verification='сверить метрики и интервал',duration_seconds=900,max_bytes=4*1024**2,
                         start=(self.now-timedelta(seconds=60)).isoformat(),
                         end=(self.now+timedelta(seconds=840)).isoformat())
        self.doc = investigations.revise(self.state,self.iid,dict(observation_plan=self.plan),expected_revision=1)

    def context(self):
        return dict(investigation_id=self.iid,expected_revision=self.doc['revision'])

    def control(self, action, **changes):
        if action=='status':
            fields = {}
        else:
            fields = dict(base_id='orders',source_ids=['disk'],max_runs=2,max_seconds=2,max_bytes=2*1024**2)
        return os_observation.control(self.state,dict(fields,mode=action,context=self.context(),**changes))['data']

    def approve(self):
        draft = self.control('preview')
        saved = self.control('approve',proposal_sha256=draft['proposal_sha256'])
        return saved['approval_sha256']

    def collect(self, key, approval=None, *, arguments=None, source='disk'):
        request = dict(schema_version=1,operation_key=key,executor_id='tests',operation='os.collect',
                       context=self.context(),arguments=arguments or {})
        if approval is not None:
            request['observation'] = dict(approval_sha256=approval,source_id=source)
        return request

    def no_worker(self, request, diagnostic):
        with patch('src.techexpert.operation_process.run',side_effect=AssertionError('unexpected collector')):
            with self.assertRaisesRegex(InputError,diagnostic):
                operations.run(self.state,request)

    def test_preview_is_passive_and_pins_the_selected_profile_and_window(self):
        with patch('src.techexpert.operation_process.run',side_effect=AssertionError('unexpected collector')):
            draft = self.control('preview')
        self.assertEqual(draft['window'],dict(start=self.plan['start'],end=self.plan['end']))
        self.assertEqual(draft['targets'][0]['duration_seconds'],1)
        self.assertEqual(draft['targets'][0]['transport'],'local')
        self.assertFalse((self.state/'os-observations').exists())
        self.assertFalse((self.state/'operations').exists())
        with self.assertRaisesRegex(InputError,'proposal'):
            self.control('approve',proposal_sha256='0'*64)
        self.assertFalse((self.state/'os-observations').exists())
        with self.assertRaisesRegex(InputError,'selected base'):
            os_observation.control(self.state,dict(mode='preview',context=self.context(),base_id='orders',
                source_ids=['foreign'],max_runs=1,max_seconds=1,max_bytes=1024**2))

    def test_new_key_reserves_and_same_key_replays_across_ordinary_revision(self):
        approval = self.approve()
        first_request = self.collect('first-sample',approval)
        first = operations.run(self.state,first_request)
        self.assertEqual(first['status'],'succeeded',first.get('message'))
        self.assertEqual(first['observation_reservation']['approval_sha256'],approval)
        self.assertEqual(self.approve(),approval)
        self.assertEqual(self.control('status')['remaining_runs'],1)
        self.doc = investigations.revise(self.state,self.iid,dict(open_questions=['Сверить интервал']),
                                         expected_revision=self.doc['revision'])
        again = operations.run(self.state,first_request)
        self.assertTrue(again['replayed'])
        self.assertEqual(again['data']['artifact_id'],first['data']['artifact_id'])
        self.assertEqual(self.control('status')['remaining_runs'],1)
        second = operations.run(self.state,self.collect('second-sample',approval))
        self.assertEqual(second['status'],'succeeded',second.get('message'))
        self.assertNotEqual(second['data']['artifact_id'],first['data']['artifact_id'])
        self.no_worker(self.collect('third-sample',approval),'budget')
        self.assertEqual(self.control('status')['remaining_runs'],0)
        self.assertEqual(update_state.inspect_state(self.state)['schemata']['os-observation'],[1])

    def test_plan_does_not_authorize_other_routes_or_parameters(self):
        approval = self.approve()
        self.no_worker(self.collect('without-plan'),'approved observation')
        self.no_worker(self.collect('wrong-source',approval,source='foreign'),'source')
        self.no_worker(self.collect('too-long',approval,arguments=dict(duration_seconds=2)),'per-run')
        self.no_worker(self.collect('too-many-bytes',approval,arguments=dict(max_bytes=2*1024**2)),'per-run')
        self.no_worker(self.collect('override-host',approval,arguments=dict(host='elsewhere')),'argument')
        self.assertEqual(self.control('status')['remaining_runs'],2)
        self.assertFalse((self.state/'operations').exists())

    def test_expired_window_or_unknown_stop_blocks_a_new_run(self):
        approval = self.approve()
        with patch('src.techexpert.os_observation.now',return_value=self.now+timedelta(seconds=841)):
            self.no_worker(self.collect('expired',approval),'window')
        first = operations.run(self.state,self.collect('first',approval))
        self.assertEqual(first['status'],'succeeded',first.get('message'))
        target = fs.folder(self.state,first['run_id'])/'status.json'
        fs.write(target,dict(fs.read(target),status='interrupted',stop_verified=False))
        self.no_worker(self.collect('unknown-stop',approval),'completion')
        self.assertEqual(self.control('status')['remaining_runs'],1)

    def test_earlier_one_off_with_unknown_stop_blocks_approval(self):
        record = operations.run(self.state,self.collect('existing-collection',arguments=self.settings))
        self.assertEqual(record['status'],'succeeded',record.get('message'))
        path = fs.folder(self.state,record['run_id'])/'status.json'
        fs.write(path,dict(fs.read(path),status='interrupted',stop_verified=False))
        proposed = self.control('preview')
        with self.assertRaisesRegex(InputError,'completion is unverified'):
            self.control('approve',proposal_sha256=proposed['proposal_sha256'])
        self.assertFalse((self.state/'os-observations').exists())

    def test_other_local_execution_scope_and_cancelled_observation_block_new_runs(self):
        approval = self.approve()
        with patch('src.techexpert.os_observation.reader_scope.observe',return_value=dict(status='unknown')):
            self.no_worker(self.collect('other-executor',approval),'execution domain')
        self.doc = investigations.revise(self.state,self.iid,dict(observation_plan=dict(self.plan,status='cancelled')),
                                        expected_revision=self.doc['revision'])
        availability = self.control('status')
        self.assertEqual(availability['window_status'],'inactive')
        self.assertEqual(availability['eligible_source_ids'],[])
        self.no_worker(self.collect('cancelled',approval),'active observation')

    def test_worker_requires_enough_time_left_before_launch(self):
        approval = self.approve()
        first = operations.run(self.state,self.collect('record-binding',approval))
        self.assertEqual(first['status'],'succeeded',first.get('message'))
        plan = fs.plan(fs.folder(self.state,first['run_id']))
        with patch('src.techexpert.os_observation.now',return_value=self.now+timedelta(seconds=839.5)):
            with self.assertRaisesRegex(InputError,'approved observation window'):
                os_observation.execution_arguments(plan['request'],plan,first['run_id'])

    def test_verified_remote_completion_includes_a_clean_byte_limit_stop(self):
        directory = fs.private(fs.folder(self.state,'a'*64))
        for status,collection,expected in (
            ('succeeded','completed','remote_reported_completed'),
            ('partial','byte_limit','remote_reported_byte_limit'),
            ('cancelled','cancelled','remote_reported_cancelled'),
            ('partial','timeout','unverified'),
        ):
            with self.subTest(collection=collection):
                saved = dict(run_id=directory.name, status=status, stop_verified=True, child={'pid':1})
                output = dict(saved, data={'result':{'collection_status':collection}})
                fs.write(directory/'status.json', saved)
                fs.write(directory/'output.json', output)
                receipt = directory/'output-receipt.json'
                fs.write(receipt, dict(sha256=fs.digest(output)))
                self.assertEqual(os_observation._stop(directory,'ssh'), expected)
                fs.write(receipt, dict(sha256='0'*64))
                self.assertEqual(os_observation._stop(directory,'ssh'), 'unverified')

    def test_saved_run_prevents_reset_by_missing_or_older_ledger(self):
        approval = self.approve()
        ledger_path = self.state/'os-observations'/self.iid/'ledger.json'
        earlier = fs.read(ledger_path)
        request = self.collect('retained-sample',approval)
        sample = operations.run(self.state,request)
        self.assertEqual(sample['status'],'succeeded',sample.get('message'))
        fs.write(ledger_path,earlier)
        self.no_worker(self.collect('after-ledger-rollback',approval),'saved observation reservation')
        registry = ledger_path.parent
        registry.rename(registry.with_name('held-'+self.iid))
        self.no_worker(self.collect('unbound-after-ledger-loss'),'saved observation reservation')
        proof = self.control('preview')
        with self.assertRaisesRegex(InputError,'saved observation reservation'):
            self.control('approve',proposal_sha256=proof['proposal_sha256'])
        with self.assertRaisesRegex(InputError,'saved observation reservation'):
            self.control('status')
        replayed = operations.run(self.state,request)
        self.assertTrue(replayed['replayed'])
        self.assertEqual(replayed['data']['artifact_id'],sample['data']['artifact_id'])
