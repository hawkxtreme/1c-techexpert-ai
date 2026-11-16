import importlib
import importlib.util
import unittest


class OsMetricsTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.os_probe'), 'OS collector is missing')
        self.probe=importlib.import_module('src.techexpert.os_probe')

    def snapshot(self,elapsed=0):
        return dict(monotonic=10+elapsed,boot_id='boot',cpu=[10+elapsed*2,0,10,80+elapsed*8,0,0,0,0,0,0],
            memory_available_bytes=100000,disks={'sda':dict(device='8:0',counters=[100+elapsed*2,0,1000+elapsed*4,100+elapsed*6,
                200+elapsed,0,2000+elapsed*2,400+elapsed*4,3,500+elapsed*2,600+elapsed*500],partition=False)},
            network={'eth0':[1000+elapsed*50,2000+elapsed*100]})

    def test_linux_queue_latency_and_rates_use_correct_units(self):
        metrics=self.probe.linux_metrics(self.snapshot(),self.snapshot(2))
        values={(r['metric'],r['instance']):r for r in metrics}
        self.assertAlmostEqual(values['disk.avg_queue','sda']['value'],.5)
        self.assertAlmostEqual(values['disk.read_latency','sda']['value'],.003)
        self.assertEqual(values['disk.read_iops','sda']['value'],2)
        self.assertEqual(values['disk.read_bytes_per_second','sda']['value'],2048)
        self.assertEqual(values['network.rx_bytes_per_second','eth0']['value'],50)
        self.assertAlmostEqual(values['cpu.busy_percent','all']['value'],20)
        self.assertEqual(values['disk.read_latency','sda']['unit'],'seconds')

    def test_warmup_resets_disappeared_devices_and_no_completed_io_remain_unknown(self):
        warm=self.probe.linux_metrics(None,self.snapshot())
        self.assertIsNone(next(x for x in warm if x['metric']=='disk.avg_queue')['value'])
        before=self.snapshot();after=self.snapshot(2)
        after['boot_id']='reboot'
        self.assertTrue(all(x['value'] is None for x in self.probe.linux_metrics(before,after) if x['metric'].endswith('iops')))
        after=self.snapshot(2);after['disks']['sda']['counters'][0]=before['disks']['sda']['counters'][0]
        self.assertIsNone(next(x for x in self.probe.linux_metrics(before,after) if x['metric']=='disk.read_latency')['value'])
        after=self.snapshot(2);after['disks']['sda']['device']='8:16'
        self.assertIsNone(next(x for x in self.probe.linux_metrics(before,after) if x['metric']=='disk.avg_queue')['value'])

    def test_defaults_limits_and_import_coverage_do_not_hide_gaps(self):
        self.assertEqual(self.probe.plan(),dict(duration_seconds=300,interval_seconds=1,max_bytes=8*1024*1024))
        for duration,interval in ((0,1),(True,1),(300,0),(300,float('nan')),(300,.1),(1,5),(3601,1)):
            with self.assertRaises(ValueError):self.probe.plan(duration,interval)
        document=dict(schema_version=1,profile='os-metrics-v1',node='host',role='onec',scope='host',
                      plan=self.probe.plan(2,1),started_at='2026-11-16T00:00:00Z',status='completed',samples=[
                          dict(elapsed_seconds=0,metrics=[dict(metric='disk.avg_queue',instance='sda',value=None,unit='requests',status='warmup')]),
                          dict(elapsed_seconds=2,metrics=[dict(metric='disk.avg_queue',instance='sda',value=3,unit='requests',status='known')])])
        summary=self.probe.summarize(document)
        self.assertEqual(summary['expected_samples'],3)
        self.assertEqual(summary['missing_samples'],1)
        self.assertEqual(summary['coverage_status'],'incomplete')
        self.assertEqual(summary['metrics'][0]['unknown'],1)
        self.assertFalse(summary['historical_incident_explained'])


if __name__=='__main__':unittest.main()
