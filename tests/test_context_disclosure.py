import io
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import investigations, profiles, storage
from src.techexpert.inputs import InputError


ROOT = Path(__file__).resolve().parents[1]
PRIVATE = 'synthetic-private-disclosure-marker'


class ContextDisclosureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / 'state'
        self.path = self.root / (PRIVATE + '.log')
        line = 'CALL,1,UserName=' + PRIVATE + ',SessionID=42,Context="Bearer ' + PRIVATE + '"'
        self.path.write_text('10:00.000000-10,' + line + '\n11:00.000000-30,' + line + '\n',
                             encoding='utf-8')
        manifest = self.root / 'input.json'
        manifest.write_text(json.dumps(dict(schema=2, origin='provided', sources=[dict(
            path=str(self.path), format='1c-tj-text-v1', platform_version='8.3.27.1989',
            encoding='utf-8', placement='folders', timestamp_format='minute', rotation_hours=1,
            file_hour='2026-11-15T09:00:00+03:00')])), encoding='utf-8')
        self.case = storage.investigate(manifest, self.state)
        self.profile = dict(schema_version=1, name=PRIVATE,
                            bases=[dict(id='file', name=PRIVATE, mode='file', connection=f'File="{self.root}";')],
                            sources=[])
        profiles.save_profile(self.state, self.profile, expected_revision=0)
        self.doc = self.new_investigation()

    def new_investigation(self):
        first = investigations.create(self.state, dict(task=PRIVATE))
        return investigations.revise(self.state, first['investigation_id'], dict(
            attachments=[dict(id='A-1', kind='case', target_id=self.case['case_id'])]), expected_revision=1)

    def cli(self, *arguments, document=None):
        document = document or self.doc
        run = subprocess.run([sys.executable, '-X', 'utf8', str(ROOT / 'techexpert.py'),
            '--state-dir', str(self.state), arguments[0], document['investigation_id'], '--revision',
            str(document['revision']), *arguments[1:]], capture_output=True, encoding='utf-8', timeout=35)
        self.assertNotIn(PRIVATE, run.stdout + run.stderr)
        return run.returncode, json.loads(run.stdout)

    def permit(self, *categories, document=None):
        options = [part for name in categories for part in ('--allow', name)]
        code, plan = self.cli('context-policy-plan', *options, document=document)
        self.assertEqual(code, 0, plan)
        code, receipt = self.cli('context-policy-save', *options, '--expected-sha256', plan['plan_sha256'],
                                 document=document)
        self.assertEqual(code, 0, receipt)
        return receipt

    def test_reviewed_policy_discloses_typed_tj_and_audits_without_raw_values(self):
        read = ('context-read', 'tj-events', '--attachment', 'A-1', '--limit', '1')
        code, denied = self.cli(*read)
        self.assertEqual(code, 2)
        self.assertEqual(denied['stop_reason'], 'context_policy_required')
        self.assertIsNone(denied['data'])
        self.assertFalse((self.state / 'context-disclosure').exists())
        self.permit('tj')
        self.path.unlink()
        code, first = self.cli(*read)
        self.assertEqual(code, 0, first)
        code, second = self.cli(*read, '--offset', '1')
        self.assertEqual(code, 0, second)
        one, two = [reply['data']['records'][0] for reply in (first, second)]
        self.assertEqual((one['event'], one['duration_us'], two['duration_us']), ('CALL', 10, 30))
        self.assertEqual(one['aliases']['user'], two['aliases']['user'])
        self.assertNotIn('Context', json.dumps(first))
        self.assertEqual(first['data']['next_offset'], 1)
        encoded = json.dumps(first['data'], ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode('utf-8')
        self.assertEqual(first['disclosure']['payload_sha256'], sha256(encoded).hexdigest())
        self.assertEqual(first['disclosure']['payload_bytes'], len(encoded))
        self.assertIsNone(second['data']['next_offset'])
        _, proof = self.cli('context-read', 'tj-evidence', '--attachment', 'A-1',
                            '--record', one['evidence']['id'])
        self.assertEqual(one['evidence']['byte_start'], proof['data']['proof']['byte_start'])
        self.assertNotIn('text', proof['data']['proof'])
        _, history = self.cli('context-history')
        self.assertEqual(len(history['entries']), 3)
        self.assertEqual({entry['category'] for entry in history['entries']}, {'tj'})
        self.assertTrue(all(entry['payload_bytes'] > 0 and entry['attachment'] == 'A-1'
                            for entry in history['entries']))

    def test_scope_and_revocation_apply_to_new_reads_even_when_old_output_exists(self):
        _, initial = self.cli('context-policy-plan', '--allow', 'tj')
        self.permit('tj')
        other = self.new_investigation()
        request = ('context-read', 'tj-events', '--attachment', 'A-1', '--limit', '1')
        _, original = self.cli(*request)
        _, same_profile = self.cli(*request, document=other)
        self.assertEqual(same_profile['status'], 'succeeded')
        self.assertNotEqual(original['data']['records'][0]['aliases']['user'],
                            same_profile['data']['records'][0]['aliases']['user'])
        changed = dict(self.profile, name='separate environment')
        profiles.save_profile(self.state, changed, expected_revision=1)
        third = self.new_investigation()
        _, moved = self.cli(*request, document=third)
        self.assertEqual(moved['stop_reason'], 'context_policy_required')
        self.permit()
        _, revoked = self.cli(*request)
        self.assertEqual(revoked['stop_reason'], 'context_category_not_allowed')
        code, stale = self.cli('context-policy-save', '--allow', 'tj',
                               '--expected-sha256', initial['plan_sha256'])
        self.assertEqual(code, 2, stale)
        _, after = self.cli(*request)
        self.assertEqual(after['stop_reason'], 'context_category_not_allowed')

    def test_withheld_and_unattached_reads_do_not_open_source_snapshots(self):
        from src.techexpert import context_disclosure
        identity = dict(investigation_id=self.doc['investigation_id'], revision=self.doc['revision'])
        with patch.object(storage, 'list_native_events', side_effect=AssertionError('read before approval')):
            view = context_disclosure.read(self.state, dict(identity, kind='tj-events', attachment='A-1'))
        self.assertEqual(view['stop_reason'], 'context_policy_required')
        self.permit('tj')
        with patch.object(storage, 'list_native_events', side_effect=AssertionError('read outside attachment')):
            view = context_disclosure.read(self.state, dict(identity, kind='tj-events', attachment='A-2'))
        self.assertEqual(view['stop_reason'], 'context_attachment_unavailable')
        _, history = self.cli('context-history')
        self.assertEqual(history['entries'], [])

    def test_policy_revoked_after_preparation_withholds_the_saved_payload(self):
        from src.techexpert import context_disclosure, kernel
        self.permit('tj')
        selected = dict(investigation_id=self.doc['investigation_id'], revision=self.doc['revision'],
                        kind='tj-events', attachment='A-1')
        call = kernel.invoke(self.state, 'context-read', dict(selection=context_disclosure.compact(selected)))
        self.assertEqual(call['exit_code'], 0)
        self.permit()
        receiver = io.StringIO()
        kernel.emit(call, receiver)
        gated = json.loads(receiver.getvalue())
        self.assertEqual(call['exit_code'], 2)
        self.assertEqual(gated['stop_reason'], 'context_policy_changed')
        self.assertIsNone(gated['data'])
        _, history = self.cli('context-history')
        self.assertEqual(history['entries'][0]['state'], 'prepared')

    def test_cli_reads_several_summaries_with_their_own_evidence_receipts(self):
        from src.techexpert import context_disclosure

        revision = self.doc['revision']
        self.doc = investigations.revise(self.state, self.doc['investigation_id'], dict(attachments=[
            dict(id='A-second', kind='case', target_id=self.case['case_id']),
            dict(id='A-first', kind='case', target_id=self.case['case_id']),
        ]), expected_revision=revision)
        self.permit('case')
        code, reply = self.cli('context-read', 'case-summary', '--attachment', 'A-first',
                               '--attachment', 'A-second')
        self.assertEqual(code, 0, reply)
        views = reply['data']['views']
        self.assertEqual([view['attachment'] for view in views], ['A-first', 'A-second'])
        references = {view['disclosure']['reference'] for view in views}
        self.assertEqual(len(references), 2)
        for view in views:
            proof = context_disclosure.verify_case_summary(
                self.state, view['disclosure']['reference'], self.case)
            self.assertEqual(proof['attachment'], view['attachment'])
            self.assertEqual(view['data']['native_event_count'], 2)
        payload = context_disclosure.compact(reply['data']).encode('utf8')
        self.assertEqual(reply['disclosure']['payload_bytes'], len(payload))
        self.assertEqual(reply['disclosure']['payload_sha256'], sha256(payload).hexdigest())

    def test_mcp_group_uses_the_current_policy_at_delivery(self):
        from src.techexpert import kernel, mcp_tools

        self.doc = investigations.revise(self.state, self.doc['investigation_id'], dict(attachments=[
            dict(id=label, kind='case', target_id=self.case['case_id']) for label in ('A-1', 'A-2')
        ]), expected_revision=self.doc['revision'])
        self.permit('case')
        request = dict(investigation_id=self.doc['investigation_id'], revision=self.doc['revision'],
                       kind='case-summary', attachments=['A-1', 'A-2'])
        action, arguments, _ = mcp_tools.prepare('techexpert_context_read', request, 'context')
        call = kernel.invoke(self.state, action, arguments, wire_version='2025-11-25')
        self.assertEqual(call['exit_code'], 0)
        allowed = io.StringIO()
        kernel.emit(call, allowed)
        payload = json.loads(allowed.getvalue())['structuredContent']
        self.assertEqual([row['attachment'] for row in payload['data']['views']], ['A-1', 'A-2'])
        self.permit()
        stream = io.StringIO()
        kernel.emit(call, stream)
        response = json.loads(stream.getvalue())
        self.assertTrue(response['isError'])
        self.assertEqual(response['structuredContent']['stop_reason'], 'context_policy_changed')
        self.assertIsNone(response['structuredContent']['data'])

    def test_group_respects_the_reviewed_byte_limit_and_rejects_duplicate_labels(self):
        from src.techexpert import context_disclosure, context_policy, mcp_tools

        attachments = ['A-' + str(index) for index in range(1, 9)]
        self.doc = investigations.revise(self.state, self.doc['investigation_id'], dict(attachments=[
            dict(id=label, kind='case', target_id=self.case['case_id']) for label in attachments
        ]), expected_revision=self.doc['revision'])
        approval = (self.state, self.doc['investigation_id'], self.doc['revision'], ['case'], 4096)
        context_policy.save(*approval, context_policy.plan(*approval)['plan_sha256'])
        request = dict(investigation_id=self.doc['investigation_id'], revision=self.doc['revision'],
                       kind='case-summary', attachments=attachments)
        with self.assertRaises(InputError):
            mcp_tools.prepare('techexpert_context_read', dict(request, attachments=['A-1', 'A-1']), 'context')
        options = [value for label in attachments for value in ('--attachment', label)]
        code, reply = self.cli('context-read', 'case-summary', *options)
        self.assertEqual(code, 2)
        self.assertEqual(reply['stop_reason'], 'context_output_limit')
        self.assertIsNone(reply['data'])

    def test_journal_views_seal_coordinates_and_hide_comments_and_subjects(self):
        from src.techexpert import native_jr
        journal = self.root / 'journal'
        shutil.copytree(ROOT / 'tests/fixtures/native-jr', journal)
        artifact = native_jr.read_journal(self.state, journal, platform_version='8.3.27.1989')
        doc = investigations.revise(self.state, self.doc['investigation_id'], dict(
            attachments=[dict(id='A-jr', kind='artifact', target_id=artifact['artifact_id'])]),
            expected_revision=self.doc['revision'])
        self.permit('jr', document=doc)
        journal.rename(self.root / 'older-journal')
        code, page = self.cli('context-read', 'jr-events', '--attachment', 'A-jr',
                              '--limit', '3', document=doc)
        self.assertEqual(code, 0, page)
        self.assertEqual(len(page['data']['records']), 3)
        first = page['data']['records'][0]
        self.assertEqual(first['precision_seconds'], 1)
        self.assertIsNone(first['timestamp'])
        self.assertRegex(first['event'], r'^jr_event-[a-f0-9]{24}$')
        self.assertNotIn('comment', first)
        self.assertNotIn('transaction_raw', first)
        _, evidence = self.cli('context-read', 'jr-evidence', '--attachment', 'A-jr',
                               '--record', first['evidence']['id'], document=doc)
        self.assertEqual(evidence['data']['record'], first)
        self.assertNotIn('text', evidence['data']['record'])

    def test_journal_window_uses_reviewed_policy_and_releases_only_typed_fields(self):
        from src.techexpert import native_jr
        journal = self.root / 'journal'
        shutil.copytree(ROOT / 'tests/fixtures/native-jr', journal)
        artifact = native_jr.read_journal(self.state, journal, platform_version='8.3.27.1989',utc_offset='+03:00')
        doc = investigations.revise(self.state, self.doc['investigation_id'], dict(
            attachments=[dict(id='A-jr', kind='artifact', target_id=artifact['artifact_id'])]),
            expected_revision=self.doc['revision'])
        request = ('context-read', 'jr-events', '--attachment','A-jr','--limit','3',
                   '--start','2026-11-16T07:05:42Z','--end','2026-11-16T07:05:44Z')
        code, denied = self.cli(*request, document=doc)
        self.assertEqual(code,2,denied)
        self.assertEqual(denied['stop_reason'],'context_policy_required')
        self.permit('jr', document=doc)
        code, result = self.cli(*request, document=doc)
        self.assertEqual(code,0,result)
        page = result['data']
        self.assertEqual(page['coverage']['records_in_window'],4)
        self.assertEqual(page['matched_count'],4)
        self.assertEqual(page['next_offset'],3)
        self.assertFalse(page['coverage']['can_establish_absence'])
        self.assertNotIn('_$Job$_.Start',json.dumps(page))
        for record in page['records']:
            self.assertEqual(record['timestamp'],'2026-11-16T10:05:42+03:00')
            self.assertNotIn('comment',record)
            self.assertRegex(record['evidence']['id'],r'^s2:r[1-4]$')
            self.assertLess(record['evidence']['byte_start'],record['evidence']['byte_end'])

    def test_policy_expansion_in_a_new_projection_version_requires_review(self):
        from src.techexpert import context_disclosure, context_policy
        self.permit('tj')
        selected = dict(investigation_id=self.doc['investigation_id'], revision=self.doc['revision'],
                        kind='tj-events', attachment='A-1')
        with patch.object(context_policy, 'RULE_VERSION', context_policy.RULE_VERSION + 1):
            withheld = context_disclosure.read(self.state, selected)
        self.assertEqual(withheld['stop_reason'], 'context_policy_review_required')
        self.assertIsNone(withheld['data'])
