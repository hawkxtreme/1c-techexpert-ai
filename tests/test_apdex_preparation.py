"""Prepare an operational APDEX target from selected local evidence."""
import json
from pathlib import Path
import tempfile
import unittest

from src.techexpert import artifacts, context_disclosure, context_intake, context_policy, investigations
from src.techexpert import operations, source_code
from src.techexpert.inputs import InputError


START = '2026-11-16T10:00:00Z'
END = '2026-11-16T10:05:00Z'
PRIVATE = 'private-operation-context'
XML = '''<MetaDataObject xmlns="http://v8.1c.ru/8.3/MDClasses" version="2.20">
<Configuration><Properties><Name>private-operation-context</Name></Properties><ChildObjects>
<Catalog>КлючевыеОперации</Catalog><InformationRegister>ЗамерыВремени</InformationRegister>
<CommonModule>ОценкаПроизводительности</CommonModule></ChildObjects></Configuration></MetaDataObject>'''


class ApdexPreparationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / 'state'
        self.doc = investigations.create(self.state, dict(task='Prepare key operation measurements'))

    def request(self, action, key, arguments):
        return dict(schema_version=1, operation=action, operation_key=key, executor_id='test-harness',
                    arguments=arguments, context=dict(investigation_id=self.doc['investigation_id'],
                                                      expected_revision=self.doc['revision']))

    def prepare(self, key, **options):
        return self.request('apdex.prepare', key, dict(investigation_id=self.doc['investigation_id'],
            revision=self.doc['revision'], operation=PRIVATE, **options))

    def intake(self, operation, key, args):
        result = context_intake.acquire(self.state, context_intake.prepare(self.request(operation, key, args)))
        self.assertEqual(result['status'], 'succeeded', result)
        self.assertNotIn(PRIVATE, json.dumps(result))
        self.doc = investigations.load(self.state, self.doc['investigation_id'])
        return result['attachment']['id'], result['data']['material']['id']

    def test_prepares_from_configuration_and_measurements_without_inventing_a_target(self):
        export = self.root / PRIVATE
        export.mkdir()
        metadata = export / 'Configuration.xml'
        metadata.write_text(XML, encoding='utf-8')
        revision = self.doc['revision']
        iid = self.doc['investigation_id']
        comparison = (self.state, iid, revision, ['comparison'], 4096)
        context_policy.save(*comparison, context_policy.plan(*comparison)['plan_sha256'])
        cfg, source_id = self.intake('source.snapshot', 'selected-config', dict(path=str(export)))
        measurements = self.root / (PRIVATE + '.json')
        measurements.write_text(json.dumps([
            dict(id='r1', operation=PRIVATE, started_at=START, duration_seconds=3, success=True),
            dict(id='r2', operation=PRIVATE, started_at='2026-11-16T10:01:00Z', duration_seconds=7, success=True),
            dict(id='r3', operation=PRIVATE, started_at='2026-11-16T10:02:00Z', duration_seconds=None, success=False),
            dict(id='r4', operation=PRIVATE, started_at=END, duration_seconds=20, success=True),
            dict(id='r5', operation='other operation', started_at=START, duration_seconds=60, success=True),
        ]), encoding='utf-8')
        samples, artifact_id = self.intake('apdex.import', 'inventory-without-target',
            dict(measurements=str(measurements), inventory_only=True))
        imported = artifacts.load_artifact(self.state, artifact_id)['result']
        self.assertEqual(imported['operation_count'], 2)
        self.assertIsNone(imported['target_seconds'])
        self.assertIsNone(imported['score'])
        assessment = dict(summary='Cause still requires TЖ evidence', cause_state='insufficient_data',
                          evidence=[], limitations=[], recommendations=[], references=[])
        self.doc = investigations.revise(self.state, iid, dict(assessment=assessment),
                                          expected_revision=self.doc['revision'])

        base = dict(configuration=cfg, measurement_attachments=[samples], baseline_window=dict(start=START, end=END),
                    priority='high', configuration_access='unavailable')
        incomplete = operations.run(self.state, self.prepare('missing-target', **base))
        self.assertEqual(incomplete['status'], 'succeeded', incomplete)
        data = incomplete['data']['result']
        self.assertEqual(data['configuration']['status'], 'markers_declared')
        self.assertEqual(data['configuration']['runtime_availability'], 'unknown')
        self.assertEqual(data['measurements']['duration_seconds']['median'], 5)
        self.assertEqual(data['measurements']['selected'], 3)
        self.assertIsNone(data['measurements']['score_at_target'])
        self.assertIn('choose_target', data['next_actions'])
        self.assertEqual(data['configuration_responsibility'], 'administrator')

        request = self.prepare('chosen-target', **base, target_seconds=4, target_score=.8,
            boundary=dict(start='Start background operation', end='Completion with committed result'),
            target_reason=PRIVATE, verification_window=dict(start=END, end='2026-11-16T10:10:00Z'))
        prepared = context_intake.prepare(request)
        result = context_intake.acquire(self.state, prepared)
        self.assertEqual(result['status'], 'succeeded', result)
        self.assertEqual(set(result['data']), {'material'})
        self.assertNotIn(PRIVATE, json.dumps(result))
        link = result['attachment']
        linked = investigations.load(self.state, iid)
        self.assertEqual(linked['assessment'], self.doc['assessment'])
        self.assertEqual(linked['analysis_basis_sha256'], self.doc['analysis_basis_sha256'])
        selection = dict(investigation_id=iid, revision=link['revision'], attachment=link['id'], kind='apdex-setup')
        self.assertEqual(context_disclosure.read(self.state, selection)['stop_reason'], 'context_category_not_allowed')
        permission = (self.state, iid, self.doc['revision'], ['comparison', 'apdex'], 4096)
        context_policy.save(*permission, context_policy.plan(*permission)['plan_sha256'])
        opened = context_disclosure.read(self.state, selection)
        self.assertEqual(opened['status'], 'succeeded', opened)
        self.assertEqual(opened['disclosure']['category'], 'apdex')
        safe = opened['data']
        self.assertEqual(safe['measurements']['score_at_target'], .5)
        self.assertEqual(safe['goal'], dict(target_seconds=4, target_score=.8, threshold_origin='caller_selected'))
        self.assertTrue(safe['windows']['verification_selected'])
        self.assertNotIn(PRIVATE, json.dumps(opened))
        self.assertNotIn(START, json.dumps(opened))
        metadata.unlink()
        measurements.unlink()
        replay = context_intake.acquire(self.state, prepared)
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['attachment'], link)
        self.assertEqual(context_disclosure.read(self.state, selection)['data'], safe)
        saved = self.state / 'artifacts' / source_id / 'sources' / 's1.bin'
        saved.write_bytes(saved.read_bytes() + b' ')
        self.assertEqual(context_disclosure.read(self.state, selection)['stop_reason'], 'context_evidence_unavailable')
        with self.assertRaises(InputError):
            operations.result(self.state, result['run_id'])

    def test_unrelated_text_and_ambiguous_exports_are_not_capability_proof(self):
        export = self.root / 'configuration'
        export.mkdir()
        empty = XML.replace('<ChildObjects>', '<Ignored>').replace('</ChildObjects>', '</Ignored>')
        (export / 'Configuration.xml').write_text(empty, encoding='utf-8')
        reports = [source_code.snapshot_source(self.state, export)]
        nested = export / 'other'
        nested.mkdir()
        (nested / 'Configuration.xml').write_text(XML, encoding='utf-8')
        reports.append(source_code.snapshot_source(self.state, export))
        attachments = [dict(id=f'A-export-{i}', kind='artifact', target_id=report['artifact_id'])
                       for i, report in enumerate(reports)]
        self.doc = investigations.revise(self.state, self.doc['investigation_id'], dict(attachments=attachments),
                                          expected_revision=1)
        for index, status in enumerate(('markers_not_found', 'ambiguous_export')):
            with self.subTest(status=status):
                result = operations.run(self.state, self.prepare(f'config-{index}', configuration=attachments[index]['id']))
                self.assertEqual(result['status'], 'succeeded', result)
                found = result['data']['result']
                self.assertEqual(found['configuration']['status'], status)
                self.assertEqual(found['configuration']['runtime_availability'], 'unknown')
                self.assertEqual(found['measurements']['status'], 'not_selected')

        request = self.prepare('overlapping', baseline_window=dict(start=START, end=END),
                               verification_window=dict(start=START, end=END))
        prepared = operations.run(self.state, request)['data']['result']
        self.assertEqual(prepared['windows']['relation'], 'overlap')
        self.assertIn('review_window_selection', prepared['next_actions'])
