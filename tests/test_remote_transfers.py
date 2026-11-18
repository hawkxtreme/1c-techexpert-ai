"""Offline transfer plans and source capture orchestration through a fake SFTP peer."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import remote_transfers as transfer,artifacts,investigations
from src.techexpert.inputs import InputError
from test_remote_budget import settings
from test_remote_sources import FakeSftp


class Peer(FakeSftp):
    def __init__(self,*_,**kwargs):super().__init__();self.closed=False;self.reason=None;self.stderr=b''
    def __enter__(self):return self
    def __exit__(self,*_):self.closed=True
    def metrics(self):return dict(protocol_bytes=100,sent_bytes=10,received_bytes=90,stderr_bytes=0,scope='fixture')


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.state=self.root/'state'
        inv=investigations.create(self.state,dict(task='Investigate supplied remote logs'))
        self.args=dict(settings(self.root),investigation_id=inv['investigation_id'])
        self.plan=transfer.prepare(self.state,self.state,**self.args)

    def inspect(self,run_id='1'*64):
        with patch.object(transfer,'Session',Peer),patch.object(transfer,'managed_run',return_value=run_id):
            return transfer.inspect(self.state,self.state,plan_id=self.plan['artifact_id'],source_id='tj',protocol_bytes=16384,timeout_seconds=10,limits={})

    def test_plan_is_offline_and_does_not_start_or_allocate_a_connection(self):
        self.assertEqual(self.plan['kind'],'remote_plan')
        self.assertFalse(self.plan['result']['network_started'])
        self.assertFalse((self.state/'remote-budgets').exists())

    def test_capture_has_original_node_paths_hashes_times_and_complete_bytes(self):
        catalogue=self.inspect()
        with patch.object(transfer,'Session',Peer),patch.object(transfer,'managed_run',return_value='2'*64):
            captured=transfer.capture(self.state,self.state,plan_id=self.plan['artifact_id'],source_id='tj',catalog_id=catalogue['artifact_id'],members=['m1'],protocol_bytes=32768,max_bytes=1000,timeout_seconds=10)
        self.assertTrue(captured['result']['capture_complete'])
        self.assertEqual(captured['sources'][0]['sha256'],hashlib.sha256(b'abc').hexdigest())
        self.assertEqual(captured['result']['transport']['node'],'reported')
        self.assertTrue(captured['result']['transport']['acquisition_started'])
        self.assertEqual(captured['result']['members'][0]['relative_path'],'one.log')
        self.assertFalse(captured['result']['transport']['atomic_snapshot'])

    def test_failed_transfer_retains_observation_but_no_complete_source(self):
        class Denied(Peer):
            def __enter__(self):raise InputError('SFTP status 3')
        with patch.object(transfer,'Session',Denied),patch.object(transfer,'managed_run',return_value='1'*64):
            catalogue=transfer.inspect(self.state,self.state,plan_id=self.plan['artifact_id'],source_id='tj',protocol_bytes=16384,timeout_seconds=10,limits={})
        self.assertEqual(catalogue['result']['transfer_status'],'incomplete')
        self.assertEqual(catalogue['sources'],[])
        self.assertFalse(catalogue['result']['listing_complete'])

    def test_background_limit_failure_cannot_promote_a_successful_work_value(self):
        class Overflow(Peer):
            def __exit__(self,*_):self.closed=True;self.reason='ssh_diagnostic_limit'
        with patch.object(transfer,'Session',Overflow),patch.object(transfer,'managed_run',return_value='1'*64):
            catalogue=transfer.inspect(self.state,self.state,plan_id=self.plan['artifact_id'],source_id='tj',protocol_bytes=16384,timeout_seconds=10,limits={})
        self.assertEqual(catalogue['result']['transfer_status'],'incomplete')
        self.assertFalse(catalogue['result']['listing_complete'])

    def test_changed_trust_file_prevents_connecting_and_does_not_accept_a_new_host_key(self):
        known=Path(self.args['sources'][0]['connection']['known_hosts_file']);known.write_text('changed',encoding='ascii')
        with patch.object(transfer,'Session') as peer:
            with self.assertRaisesRegex(InputError,'known_hosts'):self.inspect()
            peer.assert_not_called()

    def test_capture_cannot_switch_plan_or_source_behind_the_catalogue(self):
        catalogue=self.inspect()
        with self.assertRaises(InputError):
            transfer.capture(self.state,self.state,plan_id=self.plan['artifact_id'],source_id='not-selected',catalog_id=catalogue['artifact_id'],members=['m1'],protocol_bytes=16384,max_bytes=1000,timeout_seconds=10)

    def test_first_output_rejects_resealed_parent_request_changed_during_transfer(self):
        from src.techexpert import operations
        import json
        folder=artifacts.artifact_folder(self.state,self.plan['artifact_id']);changed=[False]
        class Changed(Peer):
            def realpath(peer,path):
                if not changed[0]:
                    changed[0]=True
                    raw=json.loads((folder/'request.json').read_text(encoding='utf-8'));raw['note']='changed during transfer'
                    artifacts.write_json(folder/'request.json',raw)
                    receipt=json.loads((folder/'receipt.json').read_text(encoding='utf-8'));receipt['request_sha256']=hashlib.sha256((folder/'request.json').read_bytes()).hexdigest()
                    artifacts.write_json(folder/'receipt.json',receipt)
                return path
        with patch.object(transfer,'Session',Changed),patch.object(transfer,'managed_run',return_value='1'*64):
            args=dict(plan_id=self.plan['artifact_id'],source_id='tj',protocol_bytes=16384,timeout_seconds=10,limits={})
            catalogue=transfer.inspect(self.state,self.state,**args)
        with self.assertRaises(InputError):operations._snapshots(self.state,'remote.inspect',args,catalogue)


if __name__=='__main__':unittest.main()
