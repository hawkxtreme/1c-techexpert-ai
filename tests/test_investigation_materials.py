import hashlib
import json
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
