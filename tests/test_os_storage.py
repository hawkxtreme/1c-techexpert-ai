"""Local storage observations track the selected path and preserve uncertain results."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import artifacts, context_disclosure, context_policy, investigations, operations, os_metrics, os_probe, os_storage
from src.techexpert.update_state import STATE_CONTRACT, inspect_state, supports


WINDOW = dict(start='2026-11-19T14:00:01+00:00',end='2026-11-19T14:00:04+00:00')


def sample_capture():
    return dict(schema_version=1,profile='os-metrics-v1',node='test',role='storage',scope='windows_host',
                plan=os_probe.plan(3,1),status='completed',samples=[dict(elapsed_seconds=i,
                    timestamp=f'2026-11-19T14:00:0{i}+00:00',metrics=[
                        os_probe.metric('disk.avg_queue','0',2,'requests'),
                        os_probe.metric('disk.avg_queue','1 E:',6,'requests')]) for i in (1,2,3)])


def observation(at, *, disk='0'):
    return dict(at=f'2026-11-19T14:00:0{at}+00:00',status='observed',platform='windows',
                domain_sha256='d'*64,path_identity_sha256='a'*64,mapping_sha256='b'*64,device_keys=[disk])


class OSStorageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root/'state'
        self.path = self.root/'private-base.1CD'

    def collect(self,before,after,capture=None):
        with patch.object(os_storage,'observe',side_effect=[before,after]) as watched:
            with patch.object(os_metrics,'collect',return_value=sample_capture() if capture is None else capture):
                saved=os_metrics.collect_os(self.state,dict(storage_path=str(self.path),duration_seconds=3,interval_seconds=1))
        self.assertEqual([call.args for call in watched.call_args_list],[(str(self.path),),(str(self.path),)])
        return saved

    def view(self,saved):
        task = investigations.create(self.state,dict(task='Метрики каталога базы.'))
        iid = task['investigation_id']
        doc = investigations.revise(self.state,iid,dict(attachments=[dict(id='A-os',kind='artifact',
                                     target_id=saved['artifact_id'])]),expected_revision=1)
        args = (self.state,iid,doc['revision'],['os'],8192)
        planned = context_policy.plan(*args)
        context_policy.save(*args,planned['plan_sha256'])
        result = context_disclosure.read(self.state,dict(investigation_id=iid,revision=doc['revision'],
            kind='os-window',attachment='A-os',window=WINDOW,metric_group='disk'))
        self.assertEqual(result['status'],'succeeded',result)
        self.assertNotIn(str(self.path),json.dumps(result))
        return result['data']

    def test_selected_device_is_bound_to_capture_and_ranked_in_view(self):
        saved=self.collect(observation(0),observation(4))
        summary=saved['result']['storage_binding']
        self.assertEqual(summary['status'],'same_boundary_observations')
        self.assertEqual(summary['origin'],'local_collector')
        data=self.view(saved)
        self.assertEqual(data['storage_binding']['matching_objects'],1)
        self.assertEqual(data['records'][0]['storage_match'],'recorded_device')
        self.assertEqual(data['records'][0]['metrics']['disk.avg_queue']['maximum'],2)
        self.assertEqual(data['records'][1]['metrics']['disk.avg_queue']['maximum'],6)
        self.assertEqual(data['attribution'],'not_established')
        self.assertFalse(data['can_establish_absence'])

    def test_changed_device_and_outside_capture_bounds_keep_samples_without_binding(self):
        for end, status in ((observation(4,disk='1'),'different_boundaries'),
                            (observation(2),'not_bracketed')):
            with self.subTest(status=status):
                saved=self.collect(observation(0),end)
                data=self.view(saved)
                self.assertEqual(data['storage_binding']['status'],status)
                self.assertEqual(data['storage_binding']['matching_objects'],0)
                self.assertEqual(len(data['records']),2)

    def test_import_retains_reported_origin_and_remote_target_is_refused(self):
        first=self.collect(observation(0),observation(4))
        folder=artifacts.artifact_folder(self.state,first['artifact_id'])
        copied=os_metrics.import_os(self.state,folder/'sources/s1.bin')
        self.assertEqual(self.view(copied)['storage_binding']['origin'],'reported_input')
        with self.assertRaisesRegex(ValueError,'local'):
            os_metrics.validate_request(dict(storage_path=str(self.path),transport='winrm',host='some-host'))

    def test_two_counter_instances_for_one_number_remain_ambiguous(self):
        capture=sample_capture()
        for row in capture['samples']:
            row['metrics'].append(os_probe.metric('disk.avg_queue','0 D:',8,'requests'))
        data=self.view(self.collect(observation(0),observation(4),capture))
        self.assertEqual(data['storage_binding']['ambiguous_devices'],1)
        self.assertEqual(data['storage_binding']['matching_objects'],0)
        self.assertTrue(all('storage_match' not in row for row in data['records']))

    def test_plain_profile_path_whitespace_is_not_redirected_to_a_different_path(self):
        selected=self.root/'database '
        result=os_storage.file_base_target(dict(mode='file',connection=str(selected)))
        self.assertEqual(result,None if os.name=='nt' else str(selected/'1Cv8.1CD'))

    def test_managed_direct_storage_observation_requires_its_own_reader_capability(self):
        result=operations.run(self.state,dict(schema_version=1,operation_key='storage-reader',executor_id='tests',
            operation='os.collect',arguments=dict(duration_seconds=1,interval_seconds=1,storage_path=str(self.path))))
        self.assertEqual(result['status'],'succeeded',result.get('message'))
        self.assertEqual(result['data']['result']['storage_binding']['status'],'unavailable')
        schemas=inspect_state(self.state)['schemata']
        self.assertEqual(schemas['operations'],[1])
        self.assertEqual(schemas['os-observation'],[2])
        package=dict(version='0.81.0',state_contract=STATE_CONTRACT,knowledge_schema=2)
        self.assertTrue(supports(package,schemas,os_observation_schemas=[1,2]))
        self.assertFalse(supports(package,schemas,os_observation_schemas=[1]))
