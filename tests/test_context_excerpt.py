import io
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from src.techexpert import context_disclosure, context_policy, investigations, kernel, source_code
from src.techexpert.inputs import InputError


ROOT = Path(__file__).resolve().parents[1]
TOKEN = 'not-a-real-token-for-context-excerpt'
MAIL = 'author@example.test'
CODE = '    Кэш = Новый Соответствие;'


class ContextExcerptTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / 'state'
        folder = self.root / 'configuration'
        folder.mkdir()
        self.original = folder / 'Module.bsl'
        self.raw = ('Процедура Обработать()\r\n' + CODE + '\r\n    Token = "' + TOKEN + '";\r\n'
                    '    // ' + MAIL + '\r\nКонецПроцедуры\r\n').encode('cp1251')
        self.original.write_bytes(self.raw)
        self.artifact = source_code.snapshot_source(self.state, folder, encoding='cp1251')
        first = investigations.create(self.state, dict(task='Confirm the implementation of the change'))
        self.iid = first['investigation_id']
        self.attachments = [dict(id='A-src', kind='artifact', target_id=self.artifact['artifact_id'])]
        doc = investigations.revise(self.state, self.iid, dict(attachments=self.attachments), expected_revision=1)
        self.revision = doc['revision']
        self.policy('case')

    def policy(self, *selected):
        args = (self.state, self.iid, self.revision, list(selected), 4096)
        context_policy.save(*args, context_policy.plan(*args)['plan_sha256'])

    def cli(self, *arguments, expect=0):
        proc = subprocess.run([sys.executable, '-B', '-X', 'utf8', str(ROOT/'techexpert.py'),
            '--state-dir', str(self.state), *map(str, arguments)], capture_output=True,
            text=True, encoding='utf-8', timeout=50)
        self.assertNotIn(TOKEN, proc.stdout + proc.stderr)
        self.assertNotIn(MAIL, proc.stdout + proc.stderr)
        self.assertEqual(proc.returncode, expect, proc.stdout+proc.stderr)
        return json.loads(proc.stdout)

    def prepare(self):
        return self.cli('context-excerpt-prepare', self.iid, '--revision', self.revision,
            '--attachment', 'A-src', '--member', 'file:1', '--start', 2, '--lines', 3)

    def attach(self, item):
        self.attachments.append(item)
        doc = investigations.revise(self.state, self.iid, dict(attachments=self.attachments),
                                    expected_revision=self.revision)
        self.revision = doc['revision']
        return dict(investigation_id=self.iid, revision=self.revision,
                    kind='reviewed-excerpt', attachment=item['id'])

    def test_prepares_local_cleaned_preview_and_requires_exact_approval(self):
        prepared = self.prepare()
        self.assertNotIn(CODE, json.dumps(prepared, ensure_ascii=False))
        preview = Path(prepared['preview_path'])
        data = preview.read_bytes()
        self.assertIn(CODE, data.decode('utf-8'))
        self.assertNotIn(TOKEN, data.decode('utf-8'))
        self.assertNotIn(MAIL, data.decode('utf-8'))
        selected = self.attach(prepared['attachment'])
        denied = context_disclosure.read(self.state, selected)
        self.assertIsNone(denied['data'])
        self.assertEqual(denied['stop_reason'], 'context_excerpt_approval_required')
        self.cli('context-excerpt-approve', prepared['artifact_id'], '--expected-sha256', 'f'*64, expect=2)
        self.assertEqual(context_disclosure.history(self.state, self.iid, self.revision)['entries'], [])

        self.original.unlink()
        approval = self.cli('context-excerpt-approve', prepared['artifact_id'],
                            '--expected-sha256', prepared['review_sha256'])
        self.assertEqual(approval['attachment'], prepared['attachment'])
        self.assertNotIn(CODE, json.dumps(approval, ensure_ascii=False))
        reported = self.cli('context-read', self.iid, '--revision', self.revision,
                            'reviewed-excerpt', '--attachment', approval['attachment']['id'])
        self.assertEqual(reported['status'], 'succeeded')
        self.assertEqual(reported['data']['text'].encode('utf-8'), data)
        self.assertEqual(reported['data']['text_sha256'], sha256(data).hexdigest())
        proof = reported['data']['source']
        one, *middle, last = self.raw.splitlines(keepends=True)
        self.assertEqual((proof['byte_start'], proof['byte_end']), (len(one), len(self.raw)-len(last)))
        self.assertEqual(proof['sha256'], sha256(self.raw).hexdigest())
        self.assertEqual(proof['excerpt_sha256'], sha256(b''.join(middle)).hexdigest())
        self.assertTrue(reported['data']['untrusted_source_content'])
        self.assertEqual(reported['disclosure']['category'], 'reviewed_excerpt')

    def test_materials_counts_a_private_preview_without_returning_its_text(self):
        prepared = self.prepare()
        self.attach(prepared['attachment'])
        path = Path(prepared['preview_path'])
        report = self.cli('investigation-materials', self.iid, '--category', 'copies')
        self.assertNotIn(CODE, json.dumps(report, ensure_ascii=False))
        preview = [row for row in report['entries'] if row['product_id'] == prepared['artifact_id']]
        self.assertEqual(len(preview), 1)
        self.assertEqual((preview[0]['path'], preview[0]['status'], preview[0]['bytes']),
                         (str(path), 'present', path.stat().st_size))

    def test_prepared_response_and_program_withhold_an_unavailable_approval(self):
        setup = self.prepare()
        approved = self.cli('context-excerpt-approve', setup['artifact_id'], '--expected-sha256', setup['review_sha256'])
        selected = self.attach(approved['attachment'])
        call = kernel.invoke(self.state, 'context-read', dict(selection=context_disclosure.compact(selected)))
        self.assertEqual(call['exit_code'], 0)
        binding = dict(attachment=selected['attachment'], kind=selected['kind'])
        source = self.root/'program.json'
        request = dict(schema_version=1, operation='code.context', operation_key='reviewed-excerpt-program',
            executor_id='test', context=dict(investigation_id=self.iid, expected_revision=self.revision),
            arguments=dict(scope=dict(views=[binding]), bindings=dict(selection=binding),
                           program='return api("context.read", selection)["data"]["text"]'))
        source.write_text(json.dumps(request), encoding='utf-8')
        program = kernel.invoke(self.state, 'run', dict(request=str(source)))
        self.assertEqual(program['exit_code'], 0)
        out = io.StringIO()
        kernel.emit(program, out)
        observed = json.loads(out.getvalue())
        self.assertIn(CODE, observed['data']['value'])

        revoked = self.cli('context-excerpt-revoke', setup['artifact_id'], '--expected-sha256', setup['review_sha256'])
        self.assertEqual(revoked['status'], 'revoked')
        self.assertEqual(context_disclosure.read(self.state, selected)['stop_reason'], 'context_excerpt_revoked')
        self.cli('context-excerpt-approve', setup['artifact_id'], '--expected-sha256', setup['review_sha256'], expect=2)
        for prepared in (call,program):
            out = io.StringIO()
            kernel.emit(prepared,out)
            self.assertIsNone(json.loads(out.getvalue())['data'])
            self.assertNotIn(CODE,out.getvalue())
        again = self.cli('operation-result', observed['run_id'], expect=2)
        self.assertIsNone(again['data'])

    def test_raw_artifact_evidence_does_not_return_unreviewed_preview_text(self):
        from src.techexpert.artifacts import artifact_evidence

        prepared = self.prepare()
        with self.assertRaises(InputError):
            artifact_evidence(self.state, prepared['artifact_id'], 's1')

    def test_modified_preview_or_changed_policy_cannot_be_approved(self):
        preview = self.prepare()
        path = Path(preview['preview_path'])
        original = path.read_bytes()
        path.write_bytes(b'an edited local preview')
        confirm = ('context-excerpt-approve', preview['artifact_id'], '--expected-sha256', preview['review_sha256'])
        self.cli(*confirm, expect=2)
        path.write_bytes(original)
        self.policy('tj')
        self.cli(*confirm, expect=2)
        self.assertFalse((path.parent.parent/'review-approval.json').exists())

    def test_shared_source_does_not_grant_another_investigation_the_excerpt(self):
        preview = self.prepare()
        accepted = self.cli('context-excerpt-approve', preview['artifact_id'], '--expected-sha256', preview['review_sha256'])
        first = investigations.create(self.state, dict(task='A different investigation'))
        iid = first['investigation_id']
        doc = investigations.revise(self.state, iid, dict(attachments=[*self.attachments, accepted['attachment']]),
                                    expected_revision=1)
        args = (self.state, iid, doc['revision'], ['case'], 4096)
        context_policy.save(*args, context_policy.plan(*args)['plan_sha256'])
        other = context_disclosure.read(self.state, dict(investigation_id=iid, revision=doc['revision'],
            attachment=accepted['attachment']['id'], kind='reviewed-excerpt'))
        self.assertIsNone(other['data'])
        self.assertEqual(context_disclosure.history(self.state, iid, doc['revision'])['entries'], [])

    def test_saved_excerpt_requires_a_compatible_reader_from_the_preview_stage(self):
        from src.techexpert import update_state

        contract = dict(version='0.48.0', knowledge_schema=2, state_contract=update_state.STATE_CONTRACT)
        self.assertTrue(update_state.supports(contract, update_state.inspect_state(self.state)['schemata'],
                                             context_disclosure_schemas=[1]))
        self.prepare()
        audit = update_state.inspect_state(self.state)
        self.assertTrue(audit['metadata_complete'])
        self.assertEqual(audit['schemata']['context-disclosure'], [1, 2])
        self.assertFalse(update_state.supports(contract, audit['schemata'], context_disclosure_schemas=[1]))
        self.assertTrue(update_state.supports(contract, audit['schemata'], context_disclosure_schemas=[1, 2]))
