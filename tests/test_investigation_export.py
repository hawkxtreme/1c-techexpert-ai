"""Export an exact investigation revision and replay its retained evidence offline."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import artifacts, incident_drafts, investigation_export, investigations, storage
from src.techexpert.inputs import InputError


class InvestigationExportTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.state = self.root / 'original state'
        self.doc = investigations.create(self.state, dict(task='PrivateOrders нужно проверить'))
        self.iid = self.doc['investigation_id']

    def cli(self, *args, state=None, succeeds=True):
        process = subprocess.run([sys.executable, '-B', '-X', 'utf8', str(storage.ROOT / 'techexpert.py'),
            '--state-dir', str(self.state if state is None else state), *map(str, args)], cwd=self.root,
            capture_output=True, encoding='utf-8', timeout=35)
        if succeeds:
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            return json.loads(process.stdout)
        self.assertNotEqual(process.returncode, 0, process.stdout)
        return process.stdout + process.stderr

    def attach(self, attachments, evidence):
        self.doc = investigations.revise(self.state, self.iid, dict(attachments=attachments, evidence=evidence),
                                        expected_revision=self.doc['revision'])
        return self.doc

    def plan(self, dest, mode, *options, revision=None):
        selected = self.doc['revision'] if revision is None else revision
        return self.cli('investigation-export-plan', self.iid, dest, '--revision', selected, '--content', mode, *options)

    def apply(self, dest, mode, preview, *options, succeeds=True):
        return self.cli('investigation-export', self.iid, dest, '--revision', preview['revision'], '--content', mode,
                        '--expected-sha256', preview['plan_sha256'], *options, succeeds=succeeds)

    def test_private_bundle_pins_history_and_comparison_dependencies_and_reads_without_originals(self):
        before, after = (storage.investigate(storage.ROOT / 'examples/sc01/case.json', self.state)['case_id'] for _ in range(2))
        comparison = storage.compare_cases(self.state, [before], [after])['comparison_id']
        selected = self.attach([dict(id='A-compare', kind='comparison', target_id=comparison)],
                               [dict(id='E-performance', attachment='A-compare', record='report')])
        self.attach([], [])
        policies = self.state / 'context-disclosure/policies'
        policies.mkdir(parents=True)
        (policies / 'private-local-consent.json').write_text('{"alias_key":"private-only"}', encoding='utf-8')
        dest = self.root / 'offline copy'
        preview = self.plan(dest, 'private', revision=selected['revision'])
        self.assertFalse(dest.exists())
        self.assertTrue(any(item['path'] == f'state/cases/{before}/sources/s1.bin' for item in preview['files']))
        result = self.apply(dest, 'private', preview)
        self.assertEqual(result['revision'], selected['revision'])
        self.assertFalse((dest / 'state/context-disclosure').exists())
        source = self.state / 'cases' / before / 'sources/s1.bin'
        source.unlink()
        verified = self.cli('investigation-export-verify', dest, '--expected-sha256', result['manifest_sha256'])
        self.assertTrue(verified['replay_verified'])
        self.assertEqual(investigations.load(dest / 'state', self.iid), selected)
        again = self.apply(dest, 'private', preview)
        self.assertTrue(again['replayed'])
        self.assertEqual(again['manifest_sha256'], result['manifest_sha256'])

    def test_export_binds_destination_and_current_source_bytes_and_refuses_foreign_content(self):
        item = artifacts.save_artifact(self.state, 'test', {}, [('private.txt', b'first')], {})
        identifier = item['artifact_id']
        self.attach([dict(id='A-1', kind='artifact', target_id=identifier)], [])
        dest = self.root / 'checked'
        preview = self.plan(dest, 'private')
        other = self.root / 'different target'
        self.assertIn('preview', self.apply(other, 'private', preview, succeeds=False))
        self.assertFalse(other.exists())
        source = self.state / 'artifacts' / identifier / 'sources/s1.bin'
        source.write_bytes(b'other')
        self.assertIn('integrity', self.apply(dest, 'private', preview, succeeds=False))
        self.assertFalse(dest.exists())
        source.write_bytes(b'first')
        self.apply(dest, 'private', preview)
        unlisted = dest / 'unlisted.txt'
        unlisted.write_text('foreign file', encoding='utf-8')
        self.assertIn('unlisted', self.cli('investigation-export-verify', dest, succeeds=False))
        self.assertIn('unlisted', self.apply(dest, 'private', preview, succeeds=False))
        self.assertEqual(unlisted.read_text(encoding='utf-8'), 'foreign file')

    def test_interrupted_write_retains_the_unsealed_folder_and_requires_another_destination(self):
        dest = self.root / 'interrupted copy'
        preview = self.plan(dest, 'report')
        created = investigation_export._write_new

        def interrupted(path, data):
            if path.name == 'manifest.json':
                raise OSError('simulated interruption before commit marker')
            created(path, data)

        options = dict(revision=preview['revision'], content='report', expected_sha256=preview['plan_sha256'])
        with patch.object(investigation_export, '_write_new', side_effect=interrupted), self.assertRaises(OSError):
            investigation_export.execute(self.state, self.iid, dest, **options)
        self.assertTrue((dest / 'report.md').exists())
        self.assertFalse((dest / 'manifest.json').exists())
        with self.assertRaisesRegex(InputError, 'incomplete'):
            investigation_export.verify(dest)
        with self.assertRaisesRegex(InputError, 'incomplete'):
            investigation_export.execute(self.state, self.iid, dest, **options)
        self.assertEqual(investigations.load(self.state, self.iid), self.doc)

    def test_selects_private_report_technical_metadata_and_only_reviewed_scrubbed_evidence(self):
        item = artifacts.save_artifact(self.state, 'test', {}, [('private-report.txt',
            b'contact analyst@example.test password=synthetic-password\n')], {})
        self.attach([dict(id='A-1', kind='artifact', target_id=item['artifact_id'])],
                    [dict(id='E-original', attachment='A-1', record='s1')])
        report_dir = self.root / 'reports'
        report = self.plan(report_dir, 'report')
        self.assertEqual({item['path'] for item in report['files']}, {'report.json', 'report.md'})
        self.apply(report_dir, 'report', report)
        original = investigations.revision_folder(self.state, self.iid, self.doc['revision'])
        self.assertEqual((report_dir / 'report.md').read_bytes(), (original / 'report.md').read_bytes())
        self.assertEqual(self.cli('investigation-export-verify', report_dir)['content'], 'report')

        metadata_dir = self.root / 'technical metadata'
        self.apply(metadata_dir, 'metadata', self.plan(metadata_dir, 'metadata'))
        metadata = (metadata_dir / 'technical-metadata.json').read_text(encoding='utf-8')
        self.assertEqual(json.loads(metadata)['evidence_count'], 1)
        for secret in ('PrivateOrders', 'E-original', self.iid, item['artifact_id'], 'private-report.txt'):
            self.assertNotIn(secret, metadata)

        draft = incident_drafts.prepare(self.state, self.iid, evidence_ids=['E-original'])
        args = ('--draft', draft['draft_id'])
        evidence_dir = self.root / 'pseudonymized'
        evidence = self.plan(evidence_dir, 'evidence', *args)
        changed = incident_drafts.edit(self.state, draft['draft_id'], title='Проверенная версия', body=draft['body'],
                                       expected_sha256=draft['preview_sha256'])
        self.assertNotEqual(changed['preview_sha256'], draft['preview_sha256'])
        self.assertIn('preview', self.apply(evidence_dir, 'evidence', evidence, *args, succeeds=False))
        self.assertFalse(evidence_dir.exists())
        evidence = self.plan(evidence_dir, 'evidence', *args)
        exported = self.apply(evidence_dir, 'evidence', evidence, *args)
        self.assertFalse(exported['published'])
        preview, = [entry for entry in draft['files'] if entry['path'].startswith('evidence/')]
        saved = (evidence_dir / preview['path']).read_bytes()
        self.assertEqual(saved, preview['text'].encode('utf-8'))
        self.assertEqual(evidence['files'][0]['sha256'], hashlib.sha256(saved).hexdigest())
        content = (evidence_dir / 'manifest.json').read_text(encoding='utf-8') + saved.decode('utf-8')
        for secret in ('analyst@example.test', 'synthetic-password', 'E-original', self.iid, 'issue.md'):
            self.assertNotIn(secret, content)
