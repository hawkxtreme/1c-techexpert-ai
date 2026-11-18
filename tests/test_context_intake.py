from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZIP_DEFLATED, ZipFile

from src.techexpert import investigations, operations, profiles, storage


ROOT = Path(__file__).resolve().parents[1]
PRIVATE = 'private-context-intake-marker'


class ContextIntakeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / 'state'
        self.source = self.root / (PRIVATE + '.log')
        self.source.write_text('10:00.000000-10,CALL,1,Usr=' + PRIVATE + '\n', encoding='utf-8')
        self.manifest = self.root / (PRIVATE + '.json')
        self.manifest.write_text(json.dumps(dict(schema=2, origin='provided', sources=[dict(
            path=str(self.source), format='1c-tj-text-v1', platform_version='8.3.27.1989',
            encoding='utf-8', placement='folders', timestamp_format='minute', rotation_hours=1,
            file_hour='2026-11-15T09:00:00+03:00')])), encoding='utf-8')
        self.profile = dict(schema_version=1, name=PRIVATE,
                            bases=[dict(id='file', name=PRIVATE, mode='file', connection=f'File="{self.root}";')],
                            sources=[])
        profiles.save_profile(self.state, self.profile, expected_revision=0)
        self.doc = investigations.create(self.state, dict(task=PRIVATE))
        self.iid = self.doc['investigation_id']

    def request(self, operation='case.analyze', args=None, key='retained-intake'):
        return dict(schema_version=1, operation_key=key, executor_id='file-harness',
                    operation=operation, arguments=args if args is not None else dict(manifest=str(self.manifest)),
                    context=dict(investigation_id=self.iid, expected_revision=1))

    def cli(self, *args):
        run = subprocess.run([sys.executable, '-B', '-X', 'utf8', str(ROOT / 'techexpert.py'),
            '--state-dir', str(self.state), *map(str, args)], capture_output=True, encoding='utf-8', timeout=45)
        self.assertNotIn(PRIVATE, run.stdout + run.stderr)
        return run.returncode, json.loads(run.stdout)

    def write_request(self, request):
        self.spec = self.root / 'request.json'
        self.spec.write_text(json.dumps(request), encoding='utf-8')
        return self.spec

    def test_handoff_can_start_from_an_investigation_identifier_without_private_profile(self):
        code, created = self.cli('investigation-create', self.write_request(dict(task=PRIVATE)), '--handle')
        self.assertEqual(code, 0, created)
        self.assertEqual(set(created), {'investigation_id', 'revision'})
        code, known = self.cli('investigation', created['investigation_id'], '--handle')
        self.assertEqual(code, 0, known)
        self.assertEqual(known, created)
        self.assertEqual(investigations.load(self.state, created['investigation_id'])['profile_snapshot']['name'], PRIVATE)

    def test_private_first_import_links_and_replays_without_source_text(self):
        spec = self.write_request(self.request())
        code, view = self.cli('context-intake', spec)
        self.assertEqual(code, 0, view)
        self.assertEqual(view['data']['material']['kind'], 'case')
        payload = json.dumps(view['data'], ensure_ascii=False, sort_keys=True,
                             separators=(',', ':')).encode('utf-8')
        self.assertEqual(view['intake_receipt']['payload_sha256'], sha256(payload).hexdigest())
        self.assertEqual(view['intake_receipt']['payload_bytes'], len(payload))
        target = view['data']['material']['id']
        link = view['attachment']
        self.assertEqual(link['revision'], 2)
        doc = investigations.load(self.state, self.iid)
        self.assertEqual(doc['revision'], 2)
        self.assertEqual(doc['attachments'][0]['target_id'], target)
        self.assertIn(PRIVATE, storage.read_evidence(self.state, target, 's1:1')['text'])
        stored = self.state / 'operations' / view['run_id'] / 'output.json'
        self.assertNotIn(PRIVATE, stored.read_text(encoding='utf-8'))
        args = ('context-read', self.iid, '--revision', 2, 'tj-events', '--attachment', link['id'])
        _, denied = self.cli(*args)
        self.assertEqual(denied['stop_reason'], 'context_policy_required')
        _, read_permission = self.cli('context-policy-plan', self.iid, '--revision', 2, '--allow', 'tj')
        code, _ = self.cli('context-policy-save', self.iid, '--revision', 2, '--allow', 'tj',
                           '--expected-sha256', read_permission['plan_sha256'])
        self.assertEqual(code, 0)
        self.source.unlink()
        self.manifest.unlink()
        code, again = self.cli('context-intake', spec)
        self.assertEqual(code, 0, again)
        self.assertTrue(again['replayed'])
        self.assertEqual(again['attachment'], link)
        self.assertEqual(again['data'], view['data'])
        self.assertEqual(investigations.load(self.state, self.iid)['revision'], 2)
        _, old_result = self.cli('operation-result', view['run_id'])
        self.assertEqual(old_result['data'], view['data'])
        self.assertNotIn('process', old_result)
        code, allowed = self.cli(*args)
        self.assertEqual(code, 0, allowed)
        self.assertEqual(allowed['data']['records'][0]['duration_us'], 10)

    def test_later_binding_needs_the_same_environment_and_an_exact_revision(self):
        from src.techexpert import context_intake
        prepared = context_intake.prepare(self.request())
        saved = operations.run(self.state, prepared)
        self.assertEqual(saved['status'], 'succeeded')
        run = saved['run_id']
        investigations.revise(self.state, self.iid, dict(open_questions=['Уточнить время']),
                              expected_revision=1)
        code, blocked = self.cli('context-intake', self.write_request(self.request()))
        self.assertEqual(code, 1, blocked)
        self.assertEqual(blocked['attachment_status'], 'revision_conflict')
        code, attached = self.cli('context-attach', run, '--revision', 2)
        self.assertEqual(code, 0, attached)
        self.assertEqual(attached['attachment']['revision'], 3)
        _, repeated = self.cli('context-attach', run, '--revision', 2)
        self.assertEqual(attached['attachment'], repeated['attachment'])
        code, recovered = self.cli('context-intake', self.write_request(self.request()))
        self.assertEqual(code, 0, recovered)
        self.assertTrue(recovered['replayed'])
        self.assertEqual(recovered['attachment'], attached['attachment'])
        self.assertEqual(investigations.load(self.state, self.iid)['revision'], 3)
        changed = profiles.save_profile(self.state, dict(self.profile, name='Other environment'), expected_revision=1)
        investigations.revise(self.state, self.iid, dict(profile_revision=changed['revision']), expected_revision=3)
        code, denied = self.cli('context-attach', run, '--revision', 4)
        self.assertEqual(code, 1, denied)
        self.assertEqual(denied['attachment_status'], 'environment_changed')
        self.assertEqual(investigations.load(self.state, self.iid)['revision'], 4)

    def test_invalid_source_has_generic_failure_and_a_safe_resume(self):
        self.manifest.write_text(PRIVATE, encoding='utf-8')
        specification = self.write_request(self.request())
        code, result = self.cli('context-intake', specification)
        self.assertEqual(code, 2, result)
        self.assertIsNone(result['data'])
        self.assertEqual(result['stop_reason'], 'context_intake_unavailable')
        code, replay = self.cli('operation-reconcile', result['run_id'])
        self.assertEqual(code, 2, replay)
        self.assertIsNone(replay['data'])
        self.assertEqual(investigations.load(self.state, self.iid)['revision'], 1)

    def test_missing_tj_retains_the_case_with_explicit_incomplete_intake(self):
        self.source.unlink()
        code, result = self.cli('context-intake', self.write_request(self.request()))
        self.assertEqual(code, 1, result)
        self.assertEqual(result['intake_status'], 'partial')
        self.assertEqual(result['data']['sources'], [dict(id='s1',availability='not_found')])
        self.assertEqual(result['attachment_status'], 'attached')
        code, retained = self.cli('operation-result', result['run_id'])
        self.assertEqual(code, 1)
        self.assertEqual(retained['data'], result['data'])

    def test_catalogue_shows_opaque_members_and_retains_selected_zip_input(self):
        archive = self.root / (PRIVATE + '.zip')
        with ZipFile(archive, 'w', compression=ZIP_DEFLATED) as output:
            output.write(self.source, PRIVATE + '/chosen.log')
            output.writestr(PRIVATE + '/other.log', 'unused')
        request = self.request('input.inspect', dict(inputs=[dict(path=str(archive), kind='zip')]), key='zip-preview')
        code, preview = self.cli('context-intake', self.write_request(request))
        self.assertEqual(code, 0, preview)
        self.assertEqual(preview['data']['file_count'], 2)
        self.assertFalse(preview['data']['extraction_performed'])
        self.assertEqual(preview['data']['members'][0]['id'], 'm1')
        self.assertEqual(preview['data']['members'][0]['suffix_hint'], '.log')
        self.assertEqual(investigations.load(self.state, self.iid)['attachments'], [])
        doc = json.loads(self.manifest.read_bytes())
        doc['sources'][0]['path'] = 'm1'
        self.manifest.write_text(json.dumps(doc), encoding='utf-8')
        request = self.request(args=dict(manifest=str(self.manifest), input_plan=preview['data']['artifact_id']))
        code, imported = self.cli('context-intake', self.write_request(request))
        self.assertEqual(code, 0, imported)
        case_id = imported['data']['material']['id']
        self.assertIn(PRIVATE, storage.read_evidence(self.state, case_id, 's1:1')['text'])
        self.assertEqual(imported['attachment']['revision'], 2)

    def test_external_preview_shows_limits_and_exact_hash_without_file_identity(self):
        doc = json.loads(self.manifest.read_bytes())
        doc['sources'][0]['external_window'] = dict(
            start='2026-11-15T06:10:00+00:00', end='2026-11-15T06:11:00+00:00', max_retained_bytes=4096)
        self.manifest.write_text(json.dumps(doc), encoding='utf-8')
        request = self.request('source.check', dict(manifest=str(self.manifest), reference_preview=True), key='reference')
        code, output = self.cli('context-intake', self.write_request(request))
        self.assertEqual(code, 0, output)
        preview = output['data']['reference_preview']
        self.assertEqual(preview['external_bytes'], self.source.stat().st_size)
        self.assertEqual(preview['sources'][0]['window']['end'], '2026-11-15T06:11:00+00:00')
        self.assertFalse(preview['source_bytes_read'])
        self.assertFalse((self.state / 'cases').exists())
        request = self.request(args=dict(manifest=str(self.manifest), reference_sha256=preview['plan_sha256']))
        code, capture = self.cli('context-intake', self.write_request(request))
        self.assertEqual(code, 0, capture)
        self.assertEqual(capture['attachment_status'], 'attached')
        record = storage.read_evidence(self.state, capture['data']['material']['id'], 's1:1')
        self.assertEqual(record['original_location']['byte_start'], 0)

    def test_jr_import_links_a_native_artifact_without_disclosing_its_metadata_body(self):
        selected = self.root / PRIVATE
        shutil.copytree(ROOT / 'tests/fixtures/native-jr', selected)
        request = self.request('jr.import', dict(path=str(selected), platform_version='8.3.27.1989'))
        code, output = self.cli('context-intake', self.write_request(request))
        self.assertEqual(code, 0, output)
        self.assertEqual(output['data']['material']['kind'], 'artifact')
        self.assertEqual(set(output['data']), {'material'})
        self.assertEqual(output['attachment_status'], 'attached')

    def test_legacy_key_is_not_reused_as_a_protected_intake(self):
        original = operations.run(self.state, self.request())
        self.assertEqual(original['status'], 'succeeded')
        code, refused = self.cli('context-intake', self.write_request(self.request()))
        self.assertEqual(code, 2, refused)
        self.assertIsNone(refused['data'])
        code, refused = self.cli('context-attach', original['run_id'], '--revision', 1)
        self.assertEqual(code, 2, refused)
        self.assertIsNone(refused['data'])
        self.assertEqual(investigations.load(self.state, self.iid)['revision'], 1)

    def test_recovery_error_also_hides_a_sensitive_local_snapshot_path(self):
        # Put a known marker in the private state path to exercise an OS error.
        self.state = self.root / (PRIVATE + '-state')
        self.doc = investigations.create(self.state, dict(task=PRIVATE))
        self.iid = self.doc['investigation_id']
        _, view = self.cli('context-intake', self.write_request(self.request()))
        case_id = view['data']['material']['id']
        (storage.case_folder(self.state, case_id) / 'sources/s1.bin').unlink()
        (self.state / 'operations' / view['run_id'] / 'output-receipt.json').unlink()
        code, failed = self.cli('operation-reconcile', view['run_id'])
        self.assertEqual(code, 2)
        self.assertIsNone(failed['data'])
