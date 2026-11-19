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

    def configured_journals(self, *, offset='+03:00', window=True, tj_path=None, timestamp_format=None):
        from src.techexpert.profile_resources import upgrade_profile

        selected = self.root / (PRIVATE + '-jr')
        shutil.copytree(ROOT / 'tests/fixtures/native-jr', selected)
        self.source.write_text(
            '2026-11-15T09:10:00.000000-10,CALL,1,Usr=' + PRIVATE + '\n'
            '2026-11-15T09:11:00.000000-20,CALL,1,Usr=' + PRIVATE + '\n', encoding='utf-8')
        sources = [dict(id='private-tj', type='tj', path=str(tj_path or self.source), host='', base_ids=['file'],
                        settings=dict(platform_version='8.3.27.1989', utc_offset=offset)),
                   dict(id='private-jr', type='jr', path=str(selected), host='', base_ids=['file'],
                        settings=dict(platform_version='8.3.27.1989', utc_offset='+03:00'))]
        if timestamp_format is not None:
            sources[0]['settings']['timestamp_format'] = timestamp_format
        saved = profiles.save_profile(self.state, upgrade_profile(dict(self.profile, sources=sources)), expected_revision=1)
        episode = dict(start='2026-11-15T09:10:00', end='2026-11-15T09:11:00', utc_offset='+03:00') if window else {}
        self.doc = investigations.create(self.state, dict(task=PRIVATE, episode=episode))
        self.iid = self.doc['investigation_id']
        return selected, saved

    def configured_request(self, operation, key, *, revision=1, source=None, sha=None):
        args = dict(profile_journal={} if source is None else dict(source=source))
        if sha is not None:
            args['preview_sha256'] = sha
        request = self.request(operation, args, key)
        request['context']['expected_revision'] = revision
        return request

    def configured_call(self, operation, key, **selection):
        request = self.configured_request(operation, key, **selection)
        return self.cli('context-intake', self.write_request(request))

    def test_configured_sources_supply_the_saved_window_without_paths_and_replay_after_rotation(self):
        from src.techexpert.profile_resources import upgrade_profile

        selected, saved = self.configured_journals()
        profiles.save_profile(self.state, upgrade_profile(self.profile), expected_revision=saved['revision'])
        code, listed = self.configured_call('source.check', 'list-journals')
        self.assertEqual(code, 0, listed)
        self.assertEqual([(x['source'], x['kind']) for x in listed['data']['journal_sources']], [('j1', 'tj'), ('j2', 'jr')])
        code, before = self.configured_call('source.check', 'planned-tj', source='j1')
        self.assertEqual(code, 0, before)
        preview = before['data']['journal_preview']
        self.assertFalse(preview['source_bytes_read'])
        self.assertEqual(preview['window'], dict(start='2026-11-15T06:10:00+00:00', end='2026-11-15T06:11:00+00:00'))
        self.assertEqual(preview['window_basis'], 'saved_episode')
        self.assertFalse((self.state / 'cases').exists())
        capture = dict(source='j1', sha=preview['preview_sha256'])
        code, tj = self.configured_call('case.analyze', 'configured-tj', **capture)
        self.assertEqual(code, 0, tj)
        report = storage.verified_case(self.state, tj['data']['material']['id'])
        self.assertEqual(report['sources'][0]['reference_capture']['selected_records'], 1)
        self.assertEqual(tj['attachment']['revision'], 2)
        self.source.unlink()
        code, replay = self.configured_call('case.analyze', 'configured-tj', **capture)
        self.assertEqual(code, 0, replay)
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['attachment'], tj['attachment'])

        code, before = self.configured_call('source.check', 'planned-jr', source='j2', revision=2)
        self.assertEqual(code, 0, before)
        preview = before['data']['journal_preview']
        self.assertEqual(preview['kind'], 'jr')
        self.assertEqual(preview['capture_scope'], 'selected_jr_group')
        self.assertFalse(preview['source_bytes_read'])
        jr_selection = dict(source='j2', revision=2, sha=preview['preview_sha256'])
        code, jr = self.configured_call('jr.import', 'configured-jr', **jr_selection)
        self.assertEqual(code, 0, jr)
        self.assertEqual(jr['attachment']['revision'], 3)
        selected.rename(self.root / 'rotated-jr')
        code, replay = self.configured_call('jr.import', 'configured-jr', **jr_selection)
        self.assertEqual(code, 0, replay)
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['attachment'], jr['attachment'])

    def test_configured_capture_rejects_changed_file_and_unprotected_invocation(self):
        self.configured_journals()
        code, view = self.configured_call('source.check', 'approved-tj', source='j1')
        self.assertEqual(code, 0, view)
        sha = view['data']['journal_preview']['preview_sha256']
        request = self.configured_request('case.analyze', 'private-only', source='j1', sha=sha)
        code, _ = self.cli('operation-run', self.write_request(request))
        self.assertEqual(code, 2)
        with self.source.open('ab') as stream:
            stream.write(b'\n')
        code, capture = self.configured_call('case.analyze', 'changed-tj', source='j1', sha=sha)
        self.assertEqual(code, 2, capture)
        self.assertEqual(capture['stop_reason'], 'journal_preview_changed')
        self.assertFalse((self.state / 'cases').exists())

    def test_configured_preview_requires_known_source_time_and_an_episode_window(self):
        self.configured_journals(offset='', window=False)
        code, view = self.configured_call('source.check', 'missing-window', source='j2')
        self.assertEqual(code, 1, view)
        self.assertEqual(view['data']['journal_preview']['status'], 'window_required')
        request = self.configured_request('source.check', 'missing-offset', source='j1')
        request['arguments']['profile_journal']['window'] = dict(start='2026-11-15T09:10:00+03:00', end='2026-11-15T09:11:00+03:00')
        code, view = self.cli('context-intake', self.write_request(request))
        self.assertEqual(code, 1, view)
        self.assertEqual(view['data']['journal_preview']['status'], 'offset_required')
        self.assertNotIn('preview_sha256', view['data']['journal_preview'])

    def test_configured_jr_preview_is_bound_to_the_window_and_file_group(self):
        selected, _ = self.configured_journals()
        code, view = self.configured_call('source.check', 'approved-jr', source='j2')
        self.assertEqual(code, 0, view)
        sha = view['data']['journal_preview']['preview_sha256']
        request = self.configured_request('jr.import', 'other-window', source='j2', sha=sha)
        request['arguments']['profile_journal']['window'] = dict(start='2026-11-15T09:09:00+03:00', end='2026-11-15T09:11:00+03:00')
        code, refusal = self.cli('context-intake', self.write_request(request))
        self.assertEqual(code, 2, refusal)
        self.assertEqual(refusal['stop_reason'], 'journal_preview_changed')
        member = next(selected.glob('*.lgp'))
        with member.open('ab') as stream:
            stream.write(b'\n')
        code, refusal = self.configured_call('jr.import', 'changed-jr', source='j2', sha=sha)
        self.assertEqual(code, 2, refusal)
        self.assertEqual(refusal['stop_reason'], 'journal_preview_changed')
        self.assertFalse((self.state / 'artifacts').exists())

    def test_hourly_tj_selects_bounded_files_and_retains_half_open_window_across_new_year(self):
        root = self.root / (PRIVATE + '-hours')
        folder = root / '1cv8_123'
        folder.mkdir(parents=True)
        one, two = folder / '26123123.log', root / '1cv8_456_27010100.log'
        one.write_bytes(b'59:58.999999-1,CALL,1\n59:59.000000-2,CALL,1\n')
        two.write_bytes(b'00:00.000000-3,SCALL,1\n00:01.000000-4,CALL,1\n')
        for hour in range(36):
            (folder / f'2612{1 + hour // 24:02}{hour % 24:02}.log').write_bytes(b'outside the authorized window')
        self.configured_journals(tj_path=root, timestamp_format='minute')
        _, needs = self.configured_call('source.check', 'rotation-needed', source='j1')
        self.assertEqual(needs['data']['journal_preview']['status'], 'hourly_rotation_required')
        selection = dict(source='j1', timestamp_profile='hourly_minute',
                         window=dict(start='2026-12-31T20:59:59Z', end='2026-12-31T21:00:01Z'))
        code, view = self.cli('context-intake', self.write_request(self.request('source.check',
            dict(profile_journal=selection), 'two-hour-files')))
        self.assertEqual(code, 0, view)
        preview = view['data']['journal_preview']
        self.assertEqual(preview['timestamp_profile'], 'hourly_minute')
        self.assertEqual(preview['file_count'], 2)
        self.assertEqual(preview['files_outside_window'], 36)
        self.assertEqual(preview['source_bytes'], one.stat().st_size + two.stat().st_size)
        self.assertFalse(preview['source_bytes_read'])
        arguments = dict(profile_journal=selection, preview_sha256=preview['preview_sha256'])
        changed = root / '1cv8_789_27010100.log'
        changed.write_bytes(b'00:00.000000-3,SCALL,1\n')
        code, refused = self.cli('context-intake', self.write_request(self.request('case.analyze', arguments, 'changed-hour-files')))
        self.assertEqual(code, 2, refused)
        self.assertEqual(refused['stop_reason'], 'journal_preview_changed')
        changed.unlink()
        request = self.request('case.analyze', arguments, 'two-hour-window')
        code, capture = self.cli('context-intake', self.write_request(request))
        self.assertEqual(code, 0, capture)
        case_id = capture['data']['material']['id']
        report = storage.verified_case(self.state, case_id)
        self.assertEqual(len(report['sources']), 2)
        self.assertEqual({s['profile']['file_hour'] for s in report['sources']},
                         {'2026-12-31T23:00:00+03:00', '2027-01-01T00:00:00+03:00'})
        self.assertEqual([s['reference_capture']['selected_records'] for s in report['sources']], [1, 1])
        windows = storage.list_native_events(self.state, case_id)
        self.assertEqual({(r['timestamp_utc'], r['duration_us']) for r in windows['records']},
                         {('2026-12-31T20:59:59.000000+00:00', 2), ('2026-12-31T21:00:00.000000+00:00', 3)})
        one.unlink()
        two.unlink()
        code, replay = self.cli('context-intake', self.write_request(request))
        self.assertEqual(code, 0, replay)
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['attachment'], capture['attachment'])

    def test_hourly_tj_rejects_unverified_names_and_distinguishes_a_window_without_files(self):
        self.configured_journals(timestamp_format='minute')
        args = dict(profile_journal=dict(source='j1', timestamp_profile='hourly_minute'))
        code, view = self.cli('context-intake', self.write_request(self.request('source.check', args, 'bad-hour-name')))
        self.assertEqual(code, 1, view)
        self.assertEqual(view['data']['journal_preview']['status'], 'hourly_filename_required')
        self.assertNotIn('preview_sha256', view['data']['journal_preview'])

        root = self.root / 'native-hour'
        root.mkdir()
        (root/'26111608.log').write_bytes(b'00:00.000000-1,CALL,1\n')
        profile = profiles.load_profile(self.state)
        profile['sources'][0]['path'] = str(root)
        saved = profiles.save_profile(self.state, profile, expected_revision=profile['revision'])
        revised = investigations.revise(self.state, self.iid, dict(profile_revision=saved['revision']), expected_revision=1)
        selection = self.request('source.check', args, 'outside-file-hours')
        selection['context']['expected_revision'] = revised['revision']
        code, view = self.cli('context-intake', self.write_request(selection))
        self.assertEqual(code, 1, view)
        self.assertEqual(view['data']['journal_preview']['status'], 'no_hour_files_in_window')
        self.assertFalse(view['data']['journal_preview']['source_bytes_read'])

    def test_hourly_tj_valid_name_does_not_make_other_record_grammar_usable(self):
        path = self.root / '26111509.log'
        path.write_bytes(b'2026-11-15T09:10:00.000000-10,CALL,1\n')
        self.configured_journals(tj_path=path)
        args = dict(profile_journal=dict(source='j1', timestamp_profile='hourly_minute'))
        code, view = self.cli('context-intake', self.write_request(self.request('source.check', args, 'hour-profile-declared')))
        self.assertEqual(code, 0, view)
        args['preview_sha256'] = view['data']['journal_preview']['preview_sha256']
        code, capture = self.cli('context-intake', self.write_request(self.request('case.analyze', args, 'other-record-grammar')))
        self.assertEqual(code, 1, capture)
        self.assertEqual(capture['stop_reason'], 'journal_parse_failed')
        report = storage.verified_case(self.state, capture['data']['material']['id'])
        self.assertEqual(report['sources'][0]['reference_capture']['original_parse_status'], 'invalid')
        self.assertEqual(report['source_coverage']['status'], 'no_usable_tj_records_in_scope')

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
