"""Keep process identity evidence tied to verified TJ and OS snapshots."""
from datetime import datetime,timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import artifacts, context_disclosure, context_policy, investigations, os_metrics, os_probe
from src.techexpert import operation_state as fs, os_process, storage, tj_process, tj_reference


WINDOW=dict(start='2026-11-19T12:00:00+00:00',end='2026-11-19T12:00:04+00:00')
CREATED='2026-11-19T11:00:00+00:00'
PRIVATE='private-live-tj-observation'


class ContextTJProcessTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.state=self.root/'state'
        elapsed=datetime.fromisoformat(CREATED)-datetime(1601,1,1,tzinfo=timezone.utc)
        lifetime=str((elapsed.days*86400+elapsed.seconds)*10**7)
        self.process=dict(pid=842317,platform='windows',domain_sha256='c'*64,lifetime=lifetime,
                          basis='windows_file_holder_at_review',file_identity_sha256='d'*64)

    def tj(self, *, replacement=False):
        path=self.root/'26111912.log'
        path.write_bytes(b'00:01.000000-10,CALL,1,Usr=private-live-tj-observation\n')
        manifest=self.root/'native.json'
        manifest.write_text(json.dumps(dict(schema=2,origin='provided',sources=[
            dict(path=str(path),format='1c-tj-text-v1',platform_version='8.3.27.1989',encoding='utf-8',
                 placement='folders',timestamp_format='minute',rotation_hours=1,file_hour='2026-11-19T12:00:00+00:00',
                 external_window=dict(WINDOW,max_retained_bytes=2000))])),encoding='utf-8')
        plan=tj_reference.plan(manifest,self.state)['plan']
        plan['method']=tj_reference.PREFIX_METHOD
        identity=tj_process.process_key(self.process['pid'],self.process['lifetime'],self.process['domain_sha256'])
        before=dict(status='observed',process_sha256=identity,base_file_sha256='d'*64,process_started_at=CREATED)
        after=dict(before,process_sha256='a'*64) if replacement else dict(before)
        observed='2026-11-19T12:01:00+00:00'
        with patch.object(fs,'stamp',return_value=observed):
            with patch.object(tj_process,'observe',side_effect=[dict(point,at=observed) for point in (before,after)]):
                case=storage.investigate(manifest,self.state,prefix_review=plan,reference_sha256=fs.digest(plan),
                                         file_process_path=str(self.root/'1Cv8.1CD'))
        path.unlink()
        return case

    def os_artifact(self, *, origin='local_collector', different_epoch=False, no_observations=False):
        target=dict(self.process)
        if different_epoch:
            target['lifetime']=str(int(target['lifetime'])-1)
        rows=[dict(timestamp=f'2026-11-19T12:00:0{i}+00:00',elapsed_seconds=i,metrics=[],
                   process_io=dict(at=f'2026-11-19T12:00:0{i}+00:00',status='observed',
                                   read_bytes=100*i,write_bytes=40*i)) for i in (0,1,2,3)]
        if no_observations:
            for row in rows:
                row['process_io']=dict(at=row['timestamp'],status='not_running')
        capture=dict(schema_version=1,profile='os-metrics-v1',scope='windows_host',role='onec',node=PRIVATE,
                     plan=os_probe.plan(3,1),status='completed',samples=rows,
                     process_observation=os_process.observation(target))
        raw=json.dumps(capture).encode()
        if origin=='reported_input':
            path=self.root/'measurements.json'
            path.write_bytes(raw)
            return os_metrics.import_os(self.state,path)
        process,_=os_process.record(capture,origin=origin)
        report=dict(os_probe.summarize(capture),process_io=process)
        return artifacts.save_artifact(self.state,'os_metrics',dict(process_target=target),[('os-metrics.json',raw)],report)

    def prepared(self, journal, os_capture):
        doc=investigations.create(self.state,dict(task='Проверить источники процесса.'))
        self.iid=doc['investigation_id']
        self.doc=investigations.revise(self.state,self.iid,dict(attachments=[
            dict(id='A-tj',kind='case',target_id=journal['case_id']),
            dict(id='A-os',kind='artifact',target_id=os_capture['artifact_id'])]),expected_revision=1)

    def allow(self,*categories):
        requests=self.state,self.iid,self.doc['revision'],categories,4096
        approved=context_policy.plan(*requests)
        context_policy.save(*requests,approved['plan_sha256'])

    def view(self):
        return context_disclosure.read(self.state,dict(investigation_id=self.iid,revision=self.doc['revision'],
            kind='os-process-at-tj',attachment='A-os',anchor_attachment='A-tj',record='s1:1',window=WINDOW))

    def test_live_tj_and_os_verify_same_process_without_assigning_event_io(self):
        case=self.tj()
        observed=self.os_artifact()
        self.prepared(case,observed)
        self.allow('os')
        self.assertEqual(self.view()['stop_reason'],'context_category_not_allowed')
        self.allow('os','tj')
        result=self.view()
        self.assertEqual(result['status'],'succeeded',result)
        data=result['data']
        self.assertEqual(data['relation']['status'],'same_observed_process')
        self.assertEqual(data['relation']['file_base'],'same_observed_file')
        self.assertFalse(data['relation']['exact_event_attribution'])
        self.assertEqual(data['anchor']['evidence']['id'],'s1:1')
        self.assertEqual(data['anchor']['source_sha256'],case['sources'][0]['sha256'])
        self.assertEqual(data['os']['process_io']['delta_bytes']['read_bytes'],300)
        payload=json.dumps(data)
        for private in (PRIVATE,str(self.root),str(self.process['pid']),self.process['lifetime'],'c'*64,'d'*64):
            self.assertNotIn(private,payload)
        storage.case_source_path(self.state,case['case_id'],'s1').write_bytes(b'changed snapshot')
        self.assertEqual(self.view()['stop_reason'],'context_evidence_unavailable')

    def test_reported_measurement_other_epoch_and_changed_holder_stay_unlinked(self):
        for origin,epoch,replacement,status in [
            ('reported_input',False,False,'os_process_unverified'),
            ('local_collector',True,False,'different_process'),
            ('local_collector',False,True,'journal_holder_unverified')]:
            with self.subTest(status=status):
                self.prepared(self.tj(replacement=replacement),self.os_artifact(origin=origin,different_epoch=epoch))
                self.allow('tj','os')
                relation=self.view()['data']['relation']
                self.assertEqual(relation['status'],status)
                self.assertEqual(relation['file_base'],'unknown')

    def test_reviewed_pid_without_process_samples_does_not_establish_relation(self):
        self.prepared(self.tj(),self.os_artifact(no_observations=True))
        self.allow('tj','os')
        data=self.view()['data']
        self.assertEqual(data['relation']['status'],'os_process_unverified')
        self.assertEqual(data['os']['process_io']['sample_statuses'],{'not_running':4})
