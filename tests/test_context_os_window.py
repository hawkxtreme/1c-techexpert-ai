"""Project saved OS counters in an evidenced time window with scoped output."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import artifacts, context_disclosure, context_policy, investigations, kernel, os_metrics, os_probe
from src.techexpert.update_state import STATE_CONTRACT, inspect_state, supports


PRIVATE = 'private-disk-or-host'
WINDOW = dict(start='2026-11-16T09:00:01Z',end='2026-11-16T09:00:04Z')


class ContextOsWindowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root/'state'
        self.iid = investigations.create(self.state,dict(task='Проверить метрики в сохранённом окне.'))['investigation_id']

    def write(self,name,value):
        path = self.root/name
        path.write_text(json.dumps(value,ensure_ascii=False),encoding='utf-8')
        return path

    def capture(self, *, timed=True, reversed_clock=False, process=False):
        queue = lambda value: os_probe.metric('disk.avg_queue',PRIVATE,value,'requests')
        rate = lambda value: os_probe.metric('disk.read_bytes_per_second',PRIVATE,value,'bytes/second')
        memory = os_probe.metric('memory.available','all',40,'bytes')
        samples = [
            [queue(98),rate(2000)],
            [queue(99),rate(3000),memory],
            [queue(3),rate(4096),os_probe.metric('disk.read_latency',PRIVATE,.004,'seconds')],
            [queue(None)],
            [queue(120),rate(9000)],
            [queue(800)]]
        rows = [dict(elapsed_seconds=index,metrics=values) for index,values in enumerate(samples)]
        if timed:
            for index,row in enumerate(rows[:-1]):
                row['timestamp'] = f'2026-11-16T12:00:0{index}+03:00'
        if reversed_clock:
            del rows[3]['timestamp']
            rows[4]['timestamp'] = rows[1]['timestamp']
        document = dict(schema_version=1,profile='os-metrics-v1',scope='windows_host',node=PRIVATE,
            observed_hostname=PRIVATE,role='storage',status='completed',started_at='2026-11-16T09:00:00Z',
            plan=os_probe.plan(5,1),samples=rows,limitations=[PRIVATE])
        if process:
            document['process_observation'] = dict(schema_version=1,platform='windows',
                                                   basis='explicit_pid',target_sha256='d'*64)
            for index,(row,count) in enumerate(zip(rows,(10,100,160,None,200,180))):
                sample = dict(at=f'2026-11-16T09:00:0{index}Z',status='not_running' if count is None else 'observed')
                if count is not None:
                    sample.update(read_bytes=count,write_bytes=count*2)
                row['process_io'] = sample
        original = self.write('capture.json',document)
        self.artifact = os_metrics.import_os(self.state,original)
        self.revision = investigations.revise(self.state,self.iid,dict(attachments=[
            dict(id='A-os',kind='artifact',target_id=self.artifact['artifact_id'])],
            occurrence=dict(source='external_monitoring',message='Проверка сохранённого эпизода.',
                            started_at=WINDOW['start'],ended_at=WINDOW['end'],evidence=[])),expected_revision=1)['revision']
        original.unlink()

    def approve(self,*categories):
        args = self.state,self.iid,self.revision,categories,4096
        preview = context_policy.plan(*args)
        context_policy.save(*args,preview['plan_sha256'])

    def view(self,kind='os-window',**args):
        response = context_disclosure.read(self.state,dict(investigation_id=self.iid,revision=self.revision,
                            kind=kind,attachment='A-os',**args))
        self.assertNotIn(PRIVATE,json.dumps(response,ensure_ascii=False))
        return response

    def test_process_window_uses_adjacent_available_samples_and_keeps_import_basis(self):
        self.capture(process=True)
        self.approve('tj')
        self.assertEqual(self.view('os-process-window')['stop_reason'],'context_category_not_allowed')
        self.approve('os')
        data = self.view('os-process-window')['data']
        self.assertEqual(data['coverage']['samples_in_window'],3)
        self.assertEqual(data['process_io']['origin'],'reported_input')
        self.assertEqual(data['process_io']['counter_scope'],'windows_process_io_transfers')
        self.assertEqual(data['process_io']['usable_intervals'],1)
        self.assertEqual(data['process_io']['sample_statuses'],dict(observed=2,not_running=1))
        self.assertEqual(data['process_io']['delta_bytes'],dict(read_bytes=60,write_bytes=120))
        self.assertEqual(data['process_io']['largest_intervals']['read_bytes']['start_pointer'],'/samples/1/process_io')
        self.assertEqual(data['process_io']['largest_intervals']['read_bytes']['end_pointer'],'/samples/2/process_io')
        self.assertEqual(data['source']['sha256'],self.artifact['sources'][0]['sha256'])
        self.assertFalse(data['can_establish_absence'])
        payload=json.dumps(data)
        self.assertNotIn('d'*64,payload)
        wider = self.view('os-process-window',window=dict(WINDOW,end='2026-11-16T09:00:06Z'))['data']
        self.assertEqual(wider['process_io']['counter_reset_intervals'],1)
        self.assertEqual(wider['process_io']['delta_bytes'],data['process_io']['delta_bytes'])
        self.assertEqual(inspect_state(self.state)['schemata']['os-observation'],[3])

    def test_os_window_keeps_only_contained_intervals_and_exact_source_reference(self):
        self.capture()
        self.approve('tj')
        with patch.object(artifacts,'source_path',side_effect=AssertionError('OS bytes read before approval')):
            self.assertEqual(self.view()['stop_reason'],'context_category_not_allowed')
        self.approve('os')
        result = self.view(metric_group='disk')
        self.assertEqual(result['status'],'succeeded',result)
        data = result['data']
        self.assertEqual(data['window_basis'],'saved_occurrence')
        self.assertEqual(data['coverage']['samples_in_window'],3)
        self.assertEqual(data['coverage']['contained_intervals'],2)
        self.assertEqual(data['coverage']['untimed_samples'],1)
        self.assertEqual(data['clock_alignment'],'not_verified')
        self.assertFalse(data['can_establish_absence'])
        self.assertEqual(data['scope'],'windows_host')
        self.assertEqual(data['role'],'storage')
        disk, = data['records']
        stats = disk['metrics']['disk.avg_queue']
        self.assertEqual((stats['known_samples'],stats['unavailable_samples'],stats['excluded_boundary_samples']), (1,1,1))
        self.assertEqual(stats['maximum'],3)
        self.assertEqual(stats['maximum_sample']['pointer'],'/samples/2/metrics/0')
        self.assertEqual(disk['metrics']['disk.read_latency']['unit'],'seconds')
        self.assertEqual(disk['metrics']['disk.read_bytes_per_second']['estimated_total'],4096)
        self.assertEqual(disk['metrics']['disk.read_bytes_per_second']['estimated_total_unit'],'bytes')
        source, = self.artifact['sources']
        self.assertEqual(data['source'],dict(id='s1',sha256=source['sha256'],byte_start=0,byte_end=source['bytes']))
        self.assertEqual(self.view(metric_group='memory')['data']['records'][0]['metrics']['memory.available']['maximum'],40)
        self.assertEqual(self.view(limit=1)['data']['next_offset'],1)

    def test_missing_clock_is_not_inferred_from_elapsed_or_capture_start(self):
        self.capture(timed=False)
        self.approve('os')
        data = self.view(metric_group='disk',window=WINDOW)['data']
        self.assertEqual(data['window_basis'],'explicit_window')
        self.assertEqual(data['records'],[])
        self.assertEqual(data['coverage']['status'],'timestamps_unavailable')
        self.assertEqual(data['coverage']['untimed_samples'],6)
        self.assertEqual(data['coverage']['observed_range'],[None,None])
        self.assertFalse(data['can_establish_absence'])

    def test_clock_reversal_across_untimed_sample_withholds_volume_estimate(self):
        self.capture(reversed_clock=True)
        self.approve('os')
        data = self.view(metric_group='disk')['data']
        self.assertEqual(data['coverage']['clock_order_issues'],1)
        rate = data['records'][0]['metrics']['disk.read_bytes_per_second']
        self.assertEqual(rate['known_samples'],1)
        self.assertEqual(rate['maximum'],4096)
        self.assertIsNone(rate['estimated_total'])

    def test_os_policy_requires_reader_before_view_and_replay_verifies_capture(self):
        self.capture()
        self.approve('tj','os')
        schemas = inspect_state(self.state)['schemata']
        self.assertEqual(schemas['context-disclosure'],[1,7])
        base = dict(version='0.79.0',state_contract=STATE_CONTRACT,knowledge_schema=2)
        self.assertFalse(supports(base,schemas,context_disclosure_schemas=[1,2,3,4,5,6]))
        self.assertTrue(supports(base,schemas,context_disclosure_schemas=[1,2,3,4,5,6,7]))
        selection = dict(attachment='A-os',kind='os-window')
        request = self.write('program.json',dict(schema_version=1,operation_key='disk-window',executor_id='tests',
            operation='code.context',context=dict(investigation_id=self.iid,expected_revision=self.revision),
            arguments=dict(program='return api("context.read", view)["data"]["coverage"]["samples_in_window"]',
                bindings=dict(view=selection),scope=dict(views=[selection]))))

        def run():
            call = kernel.invoke(self.state,'run',dict(request=str(request)))
            sink = io.StringIO()
            kernel.emit(call,sink)
            return json.loads(sink.getvalue())

        first = run()
        self.assertEqual(first['status'],'succeeded',first)
        self.assertEqual(first['data']['value'],3)
        self.assertTrue(run()['replayed'])
        self.assertEqual(inspect_state(self.state)['schemata']['context-program'],[7])
        saved = artifacts.artifact_folder(self.state,self.artifact['artifact_id'])/'sources/s1.bin'
        saved.write_bytes(b'damaged')
        replay = run()
        self.assertNotEqual(replay['status'],'succeeded')
        self.assertIsNone(replay.get('data'))
