"""Windows endpoint ownership and the finite Testpilot subprocess contract."""
import importlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert.inputs import InputError
from src.techexpert.processes import CommandStopped
from test_client_episode import document


class TestpilotCaptureTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.testpilot_capture'),'Bounded Testpilot capture is missing')
        self.api=importlib.import_module('src.techexpert.testpilot_capture')
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path=Path(self.temp.name)
        self.state=path/'state'
        self.settings=dict(endpoint=dict(port=62353,pid=170,lifetime='134131874954012300'),
            python=str(path/'python.exe'),database_mode='file',
            navigation=dict(link='e1cib/list/Документ.Sales',ready_form='Документ.Sales.ФормаСписка'))

    def frame(self,stage='result',trace=None):
        if trace is None:
            trace=document()
            trace['action']['label']=self.settings['navigation']['link']
        return (json.dumps(dict(stage=stage,episode=trace),ensure_ascii=False)+'\n').encode('utf-8')

    def completed(self,trace=None):
        if trace is None:
            trace=document()
            trace['action']['label']=self.settings['navigation']['link']
        pending=document()
        pending['action'].update(label=trace['action']['label'],status='outcome_unknown',ready=None,returned_ns=None)
        pending['after']=None
        return self.frame('pending',pending)+self.frame(trace=trace)

    def test_normalization_refuses_network_targets_and_arbitrary_actions(self):
        for update in (
            dict(endpoint=dict(self.settings['endpoint'],port=True)),
            dict(endpoint=dict(self.settings['endpoint'],host='remote.invalid')),
            dict(endpoint=dict(self.settings['endpoint'],lifetime='')),
            dict(python='relative.exe'),
            dict(navigation=dict(link='https://example.invalid/',ready_form='OtherForm')),
            dict(navigation=dict(link='e1cib/data/Документ.Sales',ready_form='Документ.Sales.ФормаСписка')),
            dict(navigation=dict(link='e1cib/list/Документ.Sales',ready_form='Документ.Other.ФормаСписка')),
        ):
            with self.subTest(update=update),self.assertRaises(InputError):
                self.api.normalize(dict(self.settings,**update))

    def test_changed_lifetime_prevents_subprocess_and_saves_unavailable_report(self):
        with patch.object(self.api,'inspect_endpoint',return_value=dict(self.settings['endpoint'],lifetime='134131874954012301')),\
             patch.object(self.api,'run_bounded',side_effect=AssertionError('Wrong process must not start capture')):
            result=self.api.observe(self.state,**self.settings)['result']
        self.assertEqual(result['status'],'unavailable')
        self.assertFalse(result['action_may_have_run'])

    def test_driver_isolated_subprocess_uses_a_fixed_worker_and_bounded_input(self):
        def run(argv,**kwargs):
            self.assertEqual(argv[:2],[self.settings['python'],'-I'])
            self.assertTrue(argv[-1].endswith('testpilot_worker.py'))
            options=json.loads(kwargs['input_data'])
            self.assertEqual(options['navigation'],self.settings['navigation'])
            self.assertEqual(kwargs['env']['TC1C_CODE_EXECUTION'],'false')
            self.assertEqual(kwargs['env']['TC1C_QUERY_EXECUTION'],'false')
            self.assertNotIn('PYTHONPATH',kwargs['env'])
            self.assertNotIn('SQLCMDPASSWORD',kwargs['env'])
            return 0,self.completed(),b''
        with patch.object(self.api,'inspect_endpoint',return_value=self.settings['endpoint']),patch.object(self.api,'run_bounded',side_effect=run):
            result=self.api.observe(self.state,**self.settings)['result']
        self.assertEqual(result['status'],'observed')
        self.assertEqual(result['durations_seconds']['observed_ready'],.228)

    def test_loss_after_action_keeps_pending_evidence_without_restarting(self):
        pending=document()
        pending['action'].update(label=self.settings['navigation']['link'],status='outcome_unknown',returned_ns=None,ready=None)
        pending['after']=None
        stop=CommandStopped('timeout',stdout=self.frame('pending',pending)+b'{"stage":',process_started=True)
        with patch.object(self.api,'inspect_endpoint',return_value=self.settings['endpoint']),patch.object(self.api,'run_bounded',side_effect=stop) as run:
            report=self.api.observe(self.state,**self.settings)
        self.assertEqual(run.call_count,1)
        evidence=report['result']
        self.assertEqual(evidence['status'],'partial')
        self.assertEqual(evidence['action']['status'],'outcome_unknown')
        self.assertIsNone(evidence['durations_seconds']['observed_ready'])
        self.assertEqual(evidence['before']['counters']['Вызовы'],13)

    def test_changed_endpoint_after_command_or_wrong_action_refuses_ready_claim(self):
        with patch.object(self.api,'inspect_endpoint',side_effect=[self.settings['endpoint'],dict(self.settings['endpoint'],pid=171)]),\
             patch.object(self.api,'run_bounded',return_value=(0,self.completed(),b'')):
            evidence=self.api.observe(self.state,**self.settings)['result']
        self.assertNotEqual(evidence['status'],'observed')
        self.assertIsNone(evidence['durations_seconds']['observed_ready'])
        self.assertTrue(evidence['action_may_have_run'])
        with patch.object(self.api,'inspect_endpoint',return_value=self.settings['endpoint']),\
             patch.object(self.api,'run_bounded',return_value=(0,self.completed(trace=document()),b'')):
            invalid=self.api.observe(self.state,**self.settings)['result']
        self.assertNotEqual(invalid['status'],'observed')
        self.assertIsNone(invalid['durations_seconds']['observed_ready'])

    def test_one_shared_state_writer_per_port_and_no_action_without_pending_frame(self):
        from src.techexpert import operation_state as fs
        lock=fs.private(self.state/'testpilot-endpoints'/'62353')
        with fs.writer(lock),patch.object(self.api,'run_bounded',side_effect=AssertionError('Busy endpoint must not attach')):
            result=self.api.observe(self.state.parent/'owned-output',lock_state=self.state,**self.settings)['result']
        self.assertEqual(result['status'],'unavailable')
        self.assertFalse(result['action_may_have_run'])
        with patch.object(self.api,'inspect_endpoint',return_value=self.settings['endpoint']),\
             patch.object(self.api,'run_bounded',return_value=(0,self.frame(),b'')):
            result=self.api.observe(self.state,**self.settings)['result']
        self.assertEqual(result['status'],'unavailable')
        self.assertIsNone(result['durations_seconds']['observed_ready'])

    def test_cancellation_survives_loss_of_endpoint(self):
        stopped=CommandStopped('cancelled',process_started=True)
        with patch.object(self.api,'inspect_endpoint',side_effect=[self.settings['endpoint'],InputError('endpoint ended')]),\
             patch.object(self.api,'run_bounded',side_effect=stopped):
            result=self.api.observe(self.state,**self.settings)['result']
        self.assertEqual(result['status'],'cancelled')
        self.assertTrue(result['action_may_have_run'])
        self.assertIn('endpoint_or_worker_result_unverified',result['issues'])

    @unittest.skipUnless(os.name=='nt','Windows IPv4 TCP table')
    def test_port_lookup_observes_exact_owned_loopback_listener(self):
        from src.techexpert.client_endpoint import listener
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.bind(('127.0.0.1',0))
            sock.listen(1)
            self.assertEqual(listener(sock.getsockname()[1]),dict(pid=os.getpid(),address='127.0.0.1'))

    @unittest.skipUnless(os.name=='nt','Windows IPv4 TCP table')
    def test_connection_check_matches_both_established_loopback_owners(self):
        from src.techexpert import client_endpoint as windows
        from src.techexpert.operation_state import process_identity
        with socket.socket() as listener,socket.socket() as caller:
            listener.bind(('127.0.0.1',0))
            listener.listen(1)
            caller.connect(listener.getsockname())
            peer,_=listener.accept()
            with peer:
                target=dict(port=listener.getsockname()[1],pid=os.getpid(),lifetime=process_identity(os.getpid())['lifetime'])
                windows.verify_connection(target,os.getpid())
                with self.assertRaises(InputError):
                    windows.verify_connection(target,os.getpid()+1)
                with self.assertRaises(InputError):
                    windows.verify_connection(dict(target,lifetime='1'),os.getpid())

    def test_navigation_is_not_dispatched_if_established_peer_changes(self):
        from src.techexpert import testpilot_worker as worker
        trace=document()
        trace.update(session=None,before=None,after=None,action=None)
        class TestClient:
            connection_id='example'

            def call(self,name,**params):
                if name=='connect':
                    return dict(ok=True,connection_id=self.connection_id)
                if name=='get_active_window':
                    return dict(ok=True,title='Session',connection_id=self.connection_id)
                if name=='get_performance':
                    return dict(ok=True,cleared=False,indicators={},connection_id=self.connection_id)
                raise AssertionError('Navigation must not reach an unverified peer')
        with patch.object(worker,'verify_connection',side_effect=[None,InputError('peer changed')]) as verify:
            worker.attached(TestClient(),trace,self.settings)
        self.assertEqual(verify.call_count,2)
        self.assertIsNone(trace['action'])
        self.assertIn('testclient_connection_owner_unverified',trace['issues'])


if __name__=='__main__':unittest.main()
