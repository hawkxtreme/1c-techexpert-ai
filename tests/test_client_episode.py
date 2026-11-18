"""Client timings, counters and phase evidence are deliberately distinct."""
import importlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from src.techexpert.inputs import InputError


def document(origin='testpilot'):
    return dict(schema_version=1,origin=origin,driver_version='1.9.2' if origin=='testpilot' else None,
        started_at='2026-11-18T09:00:00+03:00',finished_at='2026-11-18T09:00:04+03:00',
        session=dict(id='cefc6571',platform_build='8.3.27.1989',client_type='thin',database_mode='file'),
        before=dict(at='2026-11-18T09:00:01+03:00',form_name=None,caption=None,counters={'Вызовы':13,'Длительность':.0375}),
        after=dict(at='2026-11-18T09:00:03+03:00',form_name='Документ.Sales.ФормаСписка',caption='Sales',
                   counters={'Вызовы':23,'Длительность':.0437}),
        action=dict(label='Open sales list',started_at='2026-11-18T09:00:02+03:00',
                    status='returned_ok' if origin=='testpilot' else 'reported',
                    returned_ns=135_000_000 if origin=='testpilot' else None,
                    ready_criterion='Документ.Sales.ФормаСписка' if origin=='testpilot' else 'Operator saw the form',
                    ready=dict(at='2026-11-18T09:00:02.228+03:00',elapsed_ns=228_000_000 if origin=='testpilot' else None,
                               form_name='Документ.Sales.ФормаСписка')),
        issues=[])


class ClientEpisodeTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.client_episode'),'Client evidence import is missing')
        self.api=importlib.import_module('src.techexpert.client_episode')

    def test_reports_tool_return_ready_and_counter_delta_as_different_observations(self):
        report=self.api.summarize(document(),basis='approved_live_capture')
        self.assertEqual(report['status'],'observed')
        self.assertEqual(report['timestamps']['started_at'],'2026-11-18T06:00:00+00:00')
        self.assertEqual(report['durations_seconds'],dict(tool_response=.135,observed_ready=.228,reported_wall_clock=None,
            application_write=None,refresh=None))
        counters={r['counter']:r for r in report['cumulative_indicators']}
        self.assertEqual(counters['Вызовы']['delta'],10)
        self.assertIsNone(counters['Длительность']['unit'])
        self.assertIsNone(report['cause'])
        self.assertTrue(report['requires_ai_interpretation'])

    def test_incomplete_action_preserves_counter_snapshots_without_claiming_readiness(self):
        trace=document()
        trace['action'].update(status='outcome_unknown',returned_ns=None,ready=None)
        trace['after']=None
        report=self.api.summarize(trace,basis='approved_live_capture')
        self.assertEqual(report['status'],'partial')
        self.assertIsNone(report['durations_seconds']['observed_ready'])
        self.assertEqual(report['cumulative_indicators'][0]['status'],'missing_snapshot_or_counter')

    def test_decreased_indicators_and_missing_keys_are_not_counted_as_zero(self):
        trace=document()
        trace['after']['counters']={'Вызовы':1,'Отправлено':100}
        report=self.api.summarize(trace,basis='provided_trace')
        counters={r['counter']:r for r in report['cumulative_indicators']}
        self.assertIsNone(counters['Вызовы']['delta'])
        self.assertEqual(counters['Вызовы']['status'],'decreased_or_reset')
        self.assertIsNone(counters['Отправлено']['delta'])

    def test_manual_markers_are_reported_and_supported_without_testpilot(self):
        result=self.api.summarize(document('manual'),basis='provided_trace')
        self.assertIsNone(result['durations_seconds']['observed_ready'])
        self.assertAlmostEqual(result['durations_seconds']['reported_wall_clock'],.228)
        self.assertEqual(result['ready_basis'],'operator_reported_marker')
        self.assertEqual(result['session_identity_basis'],'provided_trace')

    def test_rejects_fabricated_or_misaligned_readiness_and_unsupported_data(self):
        for change in (
            lambda d:d['action']['ready'].update(form_name='OtherForm'),
            lambda d:d['action']['ready'].update(elapsed_ns=10_000_000),
            lambda d:d['action']['ready'].update(at='2026-11-18T08:59:00Z'),
            lambda d:d['action'].update(status='outcome_unknown',returned_ns=None),
            lambda d:d['after']['counters'].update(unavailable=float('inf')),
            lambda d:d['after']['counters'].update(unavailable=True),
            lambda d:d['before'].update(at='2026-11-18T09:00:01-00:00'),
            lambda d:d['session'].update(password='unapproved-field'),
            lambda d:d.update(driver_version='not-tested'),
        ):
            doc=document();change(doc)
            with self.subTest(doc=doc),self.assertRaises(InputError):self.api.summarize(doc,basis='provided_trace')

    def test_import_binds_original_bytes_to_private_artifact(self):
        from src.techexpert.artifacts import load_artifact,artifact_folder
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'episode.json'
            raw=json.dumps(document('manual'),ensure_ascii=False).encode('utf-8')
            source.write_bytes(raw)
            report=self.api.import_episode(root/'state',source)
            self.assertEqual(report['kind'],'client_ui')
            source.unlink()
            self.assertEqual(load_artifact(root/'state',report['artifact_id']),report)
            folder=artifact_folder(root/'state',report['artifact_id'])
            self.assertEqual((folder/'sources/s1.bin').read_bytes(),raw)
            self.assertEqual(report['result']['session_identity_basis'],'provided_trace')


if __name__=='__main__':unittest.main()
