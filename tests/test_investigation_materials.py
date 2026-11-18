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


class InvestigationReportRetentionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.state = Path(temp.name) / 'private'
        self.case = investigate(ROOT / 'examples/sc01/case.json', self.state)['case_id']
        self.ids = [create(self.state, {'task': 'Сохранённое расследование'})['investigation_id'] for _ in range(2)]
        for iid in self.ids:
            revise(self.state, iid, dict(attachments=[dict(id='A-1', kind='case', target_id=self.case)],
                   evidence=[dict(id='E-1', attachment='A-1', record='s1:2')]), expected_revision=1)
        self.iid = self.ids[0]
        self.root = self.state / 'investigations' / self.iid

    def test_report_cleanup_preserves_the_other_consumer_and_external_files(self):
        from src.techexpert import investigation_retention as retention, investigations, storage
        from src.techexpert.inputs import InputError

        proof = storage.read_evidence(self.state, self.case, 's1:2')
        report_files = [item for item in self.root.rglob('*') if item.is_file()]
        original_bytes = sum(item.stat().st_size for item in report_files)
        original_paths = set(self.state.rglob('*'))
        preview = retention.preview(self.state, self.iid)
        self.assertEqual(set(self.state.rglob('*')), original_paths)
        self.assertEqual(preview['logical_bytes'], original_bytes)
        self.assertEqual(preview['plan']['attached_products'], [{'kind':'case','id':self.case}])
        with self.assertRaisesRegex(InputError, 'plan digest'):
            retention.apply(self.state, preview['plan'], expected_sha256='0'*64)
        self.assertTrue(self.root.exists())
        result = retention.apply(self.state, preview['plan'], expected_sha256=preview['plan_sha256'])
        self.assertEqual(result['status'], 'removed')
        self.assertEqual(result['logical_bytes_removed'], original_bytes)
        self.assertFalse(self.root.exists())
        self.assertEqual(storage.read_evidence(self.state, self.case, 's1:2'), proof)
        self.assertEqual(investigations.load(self.state, self.ids[1])['revision'], 2)
        self.root.mkdir()
        replacement = self.root / 'personal.txt'
        replacement.write_bytes(b'reoccupied')
        self.assertTrue(retention.apply(self.state, preview['plan'], expected_sha256=preview['plan_sha256'])['replayed'])
        self.assertEqual(replacement.read_bytes(), b'reoccupied')
        with self.assertRaisesRegex(InputError, 'investigation reports were removed'):
            investigations.load(self.state, self.iid)

    def test_cli_keeps_source_review_on_live_reports_and_shows_deleted_status(self):
        def run(*parts):
            call = subprocess.run([sys.executable, '-B', '-X', 'utf8', str(ROOT/'techexpert.py'),
                '--state-dir', str(self.state), *map(str, parts)], capture_output=True, encoding='utf-8', timeout=25)
            self.assertEqual(call.returncode, 0, call.stdout + call.stderr)
            return json.loads(call.stdout)

        self.assertIn('source_review', run('investigation', self.iid))
        plan = run('investigation-cleanup-plan', self.iid)
        path = self.state.parent/'approved.json'
        path.write_text(json.dumps(plan['plan']), encoding='utf-8')
        result = run('investigation-cleanup-apply', path, '--expected-sha256', plan['plan_sha256'])
        self.assertEqual(result['status'], 'removed')
        self.assertEqual(run('investigation', self.iid)['status'], 'removed')
        self.assertEqual(run('investigation-materials', self.iid)['operation_references'], [])

    def test_cleanup_resumes_the_same_payload_after_an_interruption(self):
        from unittest.mock import patch
        from src.techexpert import investigation_retention as retention
        from src.techexpert.inputs import InputError

        preview = retention.preview(self.state, self.iid)
        remove = retention._remove_file
        calls = 0

        def interrupt(path, expected, **options):
            nonlocal calls
            calls += 1
            remove(path, expected, **options)
            if calls == 2:
                raise OSError('injected after disposal but before recording completion')

        with patch.object(retention, '_remove_file', side_effect=interrupt), self.assertRaises(OSError):
            retention.apply(self.state, preview['plan'], expected_sha256=preview['plan_sha256'])
        self.assertFalse(self.root.exists())
        self.assertEqual(retention.status(self.state, self.iid)['status'], 'cleanup_pending')
        payload = retention.registry(self.state, self.iid) / 'payload'
        self.assertFalse((payload / 'revisions/000001/receipt.json').exists())
        foreign = payload / 'unreviewed.txt'
        foreign.write_bytes(b'must stay')
        with self.assertRaisesRegex(InputError, 'unreviewed files'):
            retention.apply(self.state, preview['plan'], expected_sha256=preview['plan_sha256'])
        self.assertEqual(foreign.read_bytes(), b'must stay')
        foreign.unlink()
        result = retention.apply(self.state, preview['plan'], expected_sha256=preview['plan_sha256'])
        self.assertEqual(result['status'], 'removed')
        self.assertEqual(result['logical_bytes_removed'], preview['logical_bytes'])

    def test_missing_payload_is_distinct_from_a_verified_empty_payload(self):
        from unittest.mock import patch
        from src.techexpert import investigation_retention as retention
        from src.techexpert.inputs import InputError

        preview = retention.preview(self.state, self.iid)
        arguments = (self.state, preview['plan'])
        approval = dict(expected_sha256=preview['plan_sha256'])
        with patch.object(retention, '_remove_file', side_effect=OSError('interrupted before disposal')):
            with self.assertRaises(OSError):
                retention.apply(*arguments, **approval)
        payload = retention.registry(self.state, self.iid) / 'payload'
        displaced = self.state.parent / 'displaced-test-payload'
        payload.rename(displaced)
        with self.assertRaisesRegex(InputError, 'custody payload is missing'):
            retention.apply(*arguments, **approval)
        self.assertTrue((displaced/'head.json').is_file())
        self.assertEqual(retention.status(self.state, self.iid)['status'], 'cleanup_pending')
        displaced.rename(payload)
        seal = retention._seal

        def interrupt_completion(path, value):
            if path.name == 'receipt.json':
                raise OSError('completion interrupted')
            return seal(path, value)

        with patch.object(retention, '_seal', side_effect=interrupt_completion), self.assertRaises(OSError):
            retention.apply(*arguments, **approval)
        self.assertFalse(payload.exists())
        self.assertEqual(retention.apply(*arguments, **approval)['status'], 'removed')

    def test_unattempted_missing_member_cannot_be_counted_as_removed(self):
        from unittest.mock import patch
        from src.techexpert import investigation_retention as retention
        from src.techexpert.inputs import InputError

        preview = retention.preview(self.state, self.iid)
        approval = dict(expected_sha256=preview['plan_sha256'])
        with patch.object(retention, '_remove_file', side_effect=OSError('interrupted before disposal')):
            with self.assertRaises(OSError):
                retention.apply(self.state, preview['plan'], **approval)
        payload = retention.registry(self.state, self.iid) / 'payload'
        member = payload / 'revisions/000001/report.json'
        displaced = self.state.parent / 'displaced-report.json'
        member.rename(displaced)
        with self.assertRaisesRegex(InputError, 'unattempted report file is missing'):
            retention.apply(self.state, preview['plan'], **approval)
        self.assertTrue(displaced.is_file())
        self.assertTrue((payload/'head.json').is_file())
        self.assertEqual(retention.status(self.state, self.iid)['status'], 'cleanup_pending')

    def test_report_policy_revision_and_new_related_operation_invalidate_the_review(self):
        from src.techexpert import investigation_retention as retention, operation_state as fs, retention_policy
        from src.techexpert.inputs import InputError

        self.assertEqual(retention.preview(self.state, self.iid, use_policy=True)['status'], 'retained_by_policy')
        retention_policy.save(self.state, dict(schema_version=1, investigation_report_days=0),
                              expected_revision=0, category='reports')
        first = retention.preview(self.state, self.iid, use_policy=True)
        retention_policy.save(self.state, dict(schema_version=1, investigation_report_days=30),
                              expected_revision=1, category='reports')
        with self.assertRaisesRegex(InputError, 'retention policy changed'):
            retention.apply(self.state, first['plan'], expected_sha256=first['plan_sha256'])
        current = retention.preview(self.state, self.iid)
        key = 'related-operation'
        run_id = hashlib.sha256(key.encode()).hexdigest()
        run = fs.private(self.state/'operations'/run_id)
        request = dict(operation_key=key, operation='case.events', arguments={},
                       context=dict(investigation_id=self.iid, expected_revision=2))
        operation = dict(schema_version=1, request=request)
        fs.write(run/'plan.json', operation)
        fs.write(run/'plan-receipt.json', dict(sha256=fs.digest(operation)))
        fs.write(run/'status.json', dict(schema_version=1, run_id=run_id, status='running', stop_verified=False))
        with self.assertRaisesRegex(InputError, 'related operation'):
            retention.apply(self.state, current['plan'], expected_sha256=current['plan_sha256'])
        fs.write(run/'plan.json', dict(operation, request=dict(request, context=dict(investigation_id=self.ids[1]))))
        with self.assertRaisesRegex(InputError, 'operation relationship'):
            retention.apply(self.state, current['plan'], expected_sha256=current['plan_sha256'])
        (run/'plan.json').unlink()
        with self.assertRaisesRegex(InputError, 'operation relationship'):
            retention.apply(self.state, current['plan'], expected_sha256=current['plan_sha256'])
        self.assertTrue(self.root.exists())
        self.assertIsNone(retention.status(self.state, self.iid))
        self.assertEqual(retention_policy.load(self.state, category='case-indexes')['revision'], 0)

    def test_cleanup_admission_shares_the_writer_with_report_and_operation_admission(self):
        from src.techexpert import investigation_retention, operations
        from src.techexpert.inputs import InputError

        request = dict(schema_version=1, operation='investigation.sources', executor_id='lab',
                       operation_key='during-report-retention', arguments=dict(investigation_id=self.iid, revision=2))
        with investigation_retention.writer(self.state, self.iid, require_report=False):
            with self.assertRaisesRegex(InputError, 'writer is active'):
                revise(self.state, self.iid, {}, expected_revision=2)
            with self.assertRaisesRegex(InputError, 'writer is active'):
                operations.run(self.state, request)
        self.assertFalse((self.state/'operations').exists())
