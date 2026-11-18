import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from src.techexpert.artifacts import save_artifact
from src.techexpert.investigations import create, revise
from src.techexpert.storage import ROOT, compare_cases, investigate


class InvestigationMaterialsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.state = self.root / 'private state'
        self.state.mkdir()
        first = create(self.state, {'task': 'Установить причину замедления'})
        self.iid = first['investigation_id']
        self.bundle = self.state / 'investigations' / self.iid

    def view(self, *args):
        result = subprocess.run(
            [sys.executable, '-B', '-X', 'utf8', str(ROOT / 'techexpert.py'),
             '--state-dir', str(self.state), 'investigation-materials', self.iid, *args],
            cwd=self.root, capture_output=True, encoding='utf-8', timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        return json.loads(result.stdout)

    def track(self):
        return {file: hashlib.sha256(file.read_bytes()).hexdigest()
                for file in self.state.rglob('*') if file.is_file()}

    def test_cli_counts_history_and_shared_comparison_inputs_once(self):
        manifest = ROOT / 'examples/sc01/case.json'
        before = investigate(manifest, self.state)['case_id']
        after = investigate(manifest, self.state)['case_id']
        comparison = compare_cases(self.state, [before], [after])['comparison_id']
        revise(self.state, self.iid, {
            'attachments': [
                dict(id='A-1', kind='case', target_id=before),
                dict(id='A-2', kind='comparison', target_id=comparison),
            ],
            'evidence': [dict(id='E-1', attachment='A-1', record='s1:2'),
                         dict(id='E-2', attachment='A-2', record='report')],
            'facts': [dict(id='F-1', text='Наблюдалась задержка', evidence=['E-1'])],
        }, expected_revision=1)
        revise(self.state, self.iid, dict(attachments=[], evidence=[], facts=[]), expected_revision=2)
        saved = self.track()
        result = self.view()
        self.assertEqual(result['investigation_id'], self.iid)
        self.assertEqual(result['through_revision'], 3)
        self.assertEqual(result['investigation_path'], str(self.bundle))
        self.assertEqual(result['categories']['copies']['files'], 2)
        copies = [row for row in result['entries'] if row['category'] == 'copies']
        self.assertEqual({row['product_id'] for row in copies}, {before, after})
        self.assertEqual(result['categories']['copies']['observed_bytes'],
                         2 * (ROOT / 'examples/sc01/events.jsonl').stat().st_size)
        proof = next(row for row in result['entries'] if row['category'] == 'evidence')
        self.assertEqual((proof['revision'], proof['evidence_id'], proof['product_id']), (2, 'E-1', before))
        self.assertEqual(proof['used_by'], [{'kind': 'fact', 'id': 'F-1'}])
        self.assertEqual(result['categories']['copies']['dependent_evidence'], 2)
        first_copy = self.view('--category', 'copies', '--limit', '1')
        second_copy = self.view('--category', 'copies', '--offset', '1', '--limit', '1')
        self.assertEqual(first_copy['next_offset'], 1)
        self.assertIsNone(second_copy['next_offset'])
        self.assertEqual(first_copy['categories'], second_copy['categories'])
        self.assertNotEqual(first_copy['entries'][0]['path'], second_copy['entries'][0]['path'])
        self.assertEqual(self.track(), saved)
        old = self.view('--revision', '1')
        self.assertEqual(old['categories']['copies']['files'], 0)
        self.assertEqual(old['categories']['reports']['files'], 2)
        (self.state / 'cases' / after / 'sources/s1.bin').unlink()
        evidence = {item['evidence_id']: item for item in self.view('--category', 'evidence')['entries']}
        self.assertEqual(evidence['E-1']['material_status'], 'present')
        self.assertEqual(evidence['E-2']['material_status'], 'unavailable_dependency')

    def test_missing_copies_remain_visible_without_reading_outside_state_or_exposing_content(self):
        original = self.root / 'private-token-original.txt'
        original.write_bytes(b'private-token-test-value')
        artifact = save_artifact(self.state, 'test', {'path': str(original)},
                                 [(str(original), original.read_bytes())], {'count': 1})
        aid = artifact['artifact_id']
        folder = self.state / 'artifacts' / aid
        revise(self.state, self.iid, {
            'attachments': [dict(id='A-1', kind='artifact', target_id=aid)],
            'evidence': [dict(id='E-1', attachment='A-1', record='s1')],
        }, expected_revision=1)
        (folder / 'sources' / 's1.bin').unlink()
        saved = self.track()
        result = self.view('--category', 'copies', '--limit', '1')
        self.assertEqual(result['categories']['copies']['unavailable'], 1)
        self.assertEqual(len(result['entries']), 1)
        copied = result['entries'][0]
        self.assertEqual(copied['status'], 'missing')
        self.assertIsNone(copied['bytes'])
        self.assertEqual(copied['expected_bytes'], len(original.read_bytes()))
        proof = self.view('--category', 'evidence')['entries'][0]
        self.assertTrue(proof['depends_on_copies'])
        self.assertEqual(proof['material_status'], 'unavailable_dependency')
        self.assertNotIn(original.name, json.dumps(result))
        self.assertEqual(self.track(), saved)
        self.assertEqual(original.read_bytes(), b'private-token-test-value')
        (folder / 'receipt.json').write_text('[]', encoding='utf-8')
        partial = self.view('--category', 'evidence')
        self.assertEqual(partial['issues'], {'product_record_unavailable': 1})
        self.assertIsNone(partial['entries'][0]['depends_on_copies'])
        self.assertEqual(partial['entries'][0]['material_status'], 'unavailable_dependency')

    def test_recommendation_basis_marks_direct_and_hypothesis_evidence_once(self):
        artifact = save_artifact(self.state, 'test', {}, [('observed.txt', b'observation')], {})
        revise(self.state, self.iid, {
            'attachments': [dict(id='A-1', kind='artifact', target_id=artifact['artifact_id'])],
            'evidence': [dict(id='E-1', attachment='A-1', record='s1')],
            'hypotheses': [dict(id='H-1', status='testing', text='Возможный механизм', evidence=['E-1'])],
            'assessment': dict(
                summary='Нужна ещё одна проверка', cause_state='hypothesis', hypothesis_id='H-1',
                mechanism='Механизм на проверке', evidence=['E-1'], limitations=[], references=[],
                recommendations=[dict(id='R-1', kind='diagnostic', basis=['H-1', 'E-1'], goal='Проверить',
                                      prerequisites='Снимок', expected_effect='Наблюдение',
                                      verification='Сопоставить', limitations='Один эпизод')],
            ),
        }, expected_revision=1)
        proof = self.view('--category', 'evidence')['entries'][0]
        self.assertEqual(proof['used_by'].count(dict(kind='recommendation', id='R-1')), 1)
        self.assertEqual(proof['use_count'], 3)

    @unittest.skipUnless(os.name == 'nt', 'native Windows file retirement')
    def test_reviewed_retirement_retains_history_and_reports_exact_consumers(self):
        from src.techexpert import case_retention, investigations, storage
        from src.techexpert.inputs import InputError

        manifest = ROOT / 'examples/sc01/case.json'
        before = investigate(manifest, self.state)['case_id']
        after = investigate(manifest, self.state)['case_id']
        compared = compare_cases(self.state, [before], [after])['comparison_id']
        revise(self.state, self.iid, dict(
            attachments=[dict(id='A-1', kind='case', target_id=before),
                         dict(id='A-2', kind='comparison', target_id=compared),
                         dict(id='A-3', kind='case', target_id=after)],
            evidence=[dict(id=f'E-{index}', attachment=f'A-{index}', record=record)
                      for index, record in enumerate(('s1:2', 'report', 's1:2'), 1)],
            facts=[dict(id='F-1', text='Сравнение использует снимок', evidence=['E-2']),
                   dict(id='F-2', text='Снимок после исправления', evidence=['E-3'])],
            hypotheses=[dict(id='H-1', status='testing', text='Наблюдение до исправления', evidence=['E-1'])]),
            expected_revision=1)
        target = self.state / 'cases' / before / 'sources/s1.bin'
        original = ROOT / 'examples/sc01/events.jsonl'
        original_sha = hashlib.sha256(original.read_bytes()).hexdigest()
        saved = self.track()
        preview = case_retention.preview(self.state, before, 's1')
        plan, sha = preview['plan'], preview['plan_sha256']
        impact = plan['impact']
        self.assertEqual(self.track(), saved)
        self.assertEqual(preview['logical_bytes'], target.stat().st_size)
        self.assertEqual([item['id'] for item in impact['comparisons']], [compared])
        self.assertEqual([(item['investigation_id'], item['revision']) for item in impact['investigations']], [(self.iid, 2)])
        affected = impact['investigations'][0]['evidence']
        self.assertEqual([(item['evidence_id'], item['used_by']) for item in affected], [
            ('E-1', [dict(kind='hypothesis', id='H-1')]), ('E-2', [dict(kind='fact', id='F-1')])])
        with self.assertRaisesRegex(InputError, 'plan digest'):
            case_retention.apply(self.state, plan, expected_sha256='0' * 64)
        self.assertTrue(target.exists())
        result = case_retention.apply(self.state, plan, expected_sha256=sha)
        self.assertEqual(result['status'], 'removed')
        self.assertFalse(target.exists())
        self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(), original_sha)
        self.assertTrue(all(hashlib.sha256(path.read_bytes()).hexdigest() == digest
                            for path, digest in saved.items() if path != target))
        historical = investigations.read_for_display(self.state, self.iid)
        self.assertEqual(historical['revision'], 2)
        self.assertEqual(historical['reproducibility']['status'], 'intentionally_incomplete')
        self.assertEqual(historical['reproducibility']['retired_sources'][0]['evidence'], affected)
        evidence = {item['evidence_id']: item for item in self.view('--category', 'evidence')['entries']}
        self.assertEqual(evidence['E-1']['material_status'], 'retired_dependency')
        self.assertEqual(evidence['E-2']['material_status'], 'retired_dependency')
        self.assertEqual(evidence['E-3']['material_status'], 'present')
        replacement = original.read_bytes()
        target.write_bytes(replacement)
        self.assertTrue(case_retention.apply(self.state, plan, expected_sha256=sha)['replayed'])
        self.assertEqual(target.read_bytes(), replacement)
        with self.assertRaisesRegex(InputError, 'retired case snapshot'):
            storage.read_evidence(self.state, before, 's1:2')
        revision = revise(self.state, self.iid, dict(
            attachments=[dict(id='A-3', kind='case', target_id=after)],
            evidence=[dict(id='E-3', attachment='A-3', record='s1:2')],
            facts=[dict(id='F-2', text='Снимок после исправления', evidence=['E-3'])], hypotheses=[]),
            expected_revision=2)
        self.assertEqual(investigations.load(self.state, self.iid), revision)
        self.assertEqual(investigations.read_for_display(self.state, self.iid, revision=2), historical)

    @unittest.skipUnless(os.name == 'nt', 'native Windows file retirement')
    def test_retirement_rechecks_revision_impact_and_retains_interrupted_intent(self):
        from unittest.mock import patch
        from src.techexpert import case_retention, operation_state as fs
        from src.techexpert.inputs import InputError

        case = investigate(ROOT / 'examples/sc01/case.json', self.state)['case_id']
        target = self.state / 'cases' / case / 'sources/s1.bin'
        first = case_retention.preview(self.state, case, 's1')
        revise(self.state, self.iid, dict(attachments=[dict(id='A-1', kind='case', target_id=case)]),
               expected_revision=1)
        with self.assertRaisesRegex(InputError, 'dependencies changed'):
            case_retention.apply(self.state, first['plan'], expected_sha256=first['plan_sha256'])
        self.assertTrue(target.exists())
        current = case_retention.preview(self.state, case, 's1')
        write = fs.write

        def interrupt(path, value):
            if path.name == 'receipt.json':
                raise OSError('completion receipt interrupted')
            return write(path, value)

        with patch.object(fs, 'write', side_effect=interrupt), self.assertRaises(OSError):
            case_retention.apply(self.state, current['plan'], expected_sha256=current['plan_sha256'])
        self.assertEqual(case_retention.status(self.state, case, 's1')['status'], 'outcome_unverified')
        target.write_bytes(b'new bytes')
        response = case_retention.apply(self.state, current['plan'], expected_sha256=current['plan_sha256'])
        self.assertEqual(response['status'], 'outcome_unverified')
        self.assertEqual(target.read_bytes(), b'new bytes')

    @unittest.skipUnless(os.name == 'nt', 'native Windows file retirement')
    def test_case_input_policy_is_independent_and_a_new_reference_cannot_race_removal(self):
        from unittest.mock import patch
        from src.techexpert import case_retention, retention_policy
        from src.techexpert.inputs import InputError

        case = investigate(ROOT / 'examples/sc01/case.json', self.state)['case_id']
        target = self.state / 'cases' / case / 'sources/s1.bin'
        self.assertEqual(case_retention.preview(self.state, case, 's1', use_policy=True)['status'], 'retained_by_policy')
        for index, days in enumerate((0, 31, 0)):
            retention_policy.save(self.state, dict(schema_version=1, case_input_days=days),
                                  expected_revision=index, category='case-inputs')
            self.assertTrue(target.exists())
            if index == 0:
                obsolete = case_retention.preview(self.state, case, 's1', use_policy=True)
            elif index == 1:
                with self.assertRaisesRegex(InputError, 'retention policy changed'):
                    case_retention.apply(self.state, obsolete['plan'], expected_sha256=obsolete['plan_sha256'])
        self.assertEqual(retention_policy.load(self.state)['revision'], 0)
        reviewed = case_retention.preview(self.state, case, 's1', use_policy=True)
        snapshot = case_retention.windows_native.snapshot_cleanup_file

        def overlap(path, **kwargs):
            with self.assertRaisesRegex(InputError, 'writer is active'):
                revise(self.state, self.iid, dict(attachments=[dict(id='A-1', kind='case', target_id=case)]),
                       expected_revision=1)
            return snapshot(path, **kwargs)

        with patch.object(case_retention.windows_native, 'snapshot_cleanup_file', side_effect=overlap):
            result = case_retention.apply(self.state, reviewed['plan'], expected_sha256=reviewed['plan_sha256'])
        self.assertEqual(result['status'], 'removed')
        self.assertFalse(target.exists())

    @unittest.skipUnless(os.name == 'nt', 'native Windows file retirement')
    def test_retirement_refuses_a_snapshot_selected_in_the_active_profile(self):
        from src.techexpert import case_retention, profiles
        from src.techexpert.inputs import InputError

        case = investigate(ROOT / 'examples/sc01/case.json', self.state)['case_id']
        target = self.state / 'cases' / case / 'sources/s1.bin'
        review = case_retention.preview(self.state, case, 's1')
        profiles.save_profile(self.state, dict(schema_version=1, name='Тестовый профиль',
            bases=[dict(id='base', name='Локальная база', mode='file')],
            sources=[dict(id='tj-1', type='tj', path=str(target), base_ids=['base'], settings={})]),
            expected_revision=0)
        with self.assertRaisesRegex(InputError, 'active environment source'):
            case_retention.apply(self.state, review['plan'], expected_sha256=review['plan_sha256'])
        self.assertTrue(target.exists())
        self.assertIsNone(case_retention.status(self.state, case, 's1'))
