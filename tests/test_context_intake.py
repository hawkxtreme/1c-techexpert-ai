from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from xml.sax.saxutils import quoteattr
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

    def test_retained_tj_time_correction_reanalyzes_bytes_in_a_new_revision(self):
        code, original = self.cli('context-intake', self.write_request(self.request()))
        self.assertEqual(code, 0, original)
        original_case = original['data']['material']['id']
        old_report = storage.case_folder(self.state, original_case) / 'report.json'
        previous = old_report.read_bytes()
        old_revision = investigations.load(self.state, self.iid, revision=2)
        self.source.unlink()
        self.manifest.unlink()

        selection = dict(attachment=original['attachment']['id'],
                         offsets=[dict(source_id='s1', utc_offset='+02:00')],
                         window=dict(start='2026-11-15T07:00:00Z', end='2026-11-15T08:00:00Z'))
        request = self.request(args=dict(retained_tj=selection), key='correct-retained-tj-time')
        request['context']['expected_revision'] = 2
        spec = self.write_request(request)
        code, corrected = self.cli('context-intake', spec)
        self.assertEqual(code, 0, corrected)
        self.assertEqual(corrected['attachment']['revision'], 3)
        correction = corrected['data']['time_correction']
        self.assertEqual(correction['original_case_id'], original_case)
        change, = correction['sources']
        self.assertEqual((change['before']['utc_offset'], change['after']['utc_offset']), ('+03:00', '+02:00'))
        self.assertEqual((change['before']['records_in_window'], change['after']['records_in_window']), (0, 1))
        derived = corrected['data']['material']['id']
        self.assertNotEqual(derived, original_case)
        record, = storage.list_native_events(self.state, derived)['records']
        self.assertEqual(record['timestamp_utc'], '2026-11-15T07:10:00.000000+00:00')
        old_evidence = storage.read_evidence(self.state, original_case, 's1:1')
        new_evidence = storage.read_evidence(self.state, derived, 's1:1')
        for field in ('sha256', 'line', 'byte_start', 'byte_end'):
            self.assertEqual(new_evidence[field], old_evidence[field])
        self.assertEqual(old_report.read_bytes(), previous)
        self.assertEqual(investigations.load(self.state, self.iid, revision=2), old_revision)
        self.assertEqual([item['target_id'] for item in investigations.load(self.state, self.iid)['attachments']],
                         [original_case, derived])
        replayed_code, replay = self.cli('context-intake', spec)
        self.assertEqual(replayed_code, 0, replay)
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['attachment'], corrected['attachment'])
        self.assertEqual(replay['data'], corrected['data'])
        self.assertEqual(investigations.load(self.state, self.iid)['revision'], 3)
        progress = self.cli('investigation-progress', self.iid)[1]['data']
        check = next(row for row in progress['recent_checks'] if row['run_id'] == corrected['run_id'])
        self.assertIsNone(check['captured_input_bytes'])
        self.assertEqual(check['reprocessed_input_bytes'], storage.case_source_path(self.state, derived, 's1').stat().st_size)
        from src.techexpert.update_state import inspect_state
        schemas = inspect_state(self.state)['schemata']
        self.assertEqual(schemas['operations'], [1])
        self.assertEqual(schemas['context-intake'], [1, 11])
        old_snapshot = storage.case_source_path(self.state, original_case, 's1')
        old_snapshot.write_bytes(old_snapshot.read_bytes().replace(b'-10,CALL', b'-11,CALL'))
        code, refused = self.cli('context-intake', spec)
        self.assertEqual(code, 2, refused)
        self.assertNotIn('attachment', refused)
        self.assertEqual(len(list((self.state / 'cases').iterdir())), 2)

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

    def test_reviewed_tj_prefix_retains_only_complete_window_records_after_append(self):
        path = self.root / '26111509.log'
        complete = b'09:59.999999-1,CALL,1\n10:00.000000-2,SCALL,1\n'
        tail = b'10:10.000000-3,CALL,1,Note="partial'
        path.write_bytes(complete + tail)
        self.configured_journals(tj_path=path)

        selector = dict(source='j1', timestamp_profile='hourly_minute', read_mode='fixed_prefix')
        args = dict(profile_journal=selector)
        code, preview = self.cli('context-intake', self.write_request(self.request('source.check', args, 'prefix-preview')))
        self.assertEqual(code, 0, preview)
        proposed = preview['data']['journal_preview']
        self.assertFalse(proposed['source_bytes_read'])
        self.assertEqual(proposed['capture_scope'], 'reviewed_prefix_window')
        self.assertEqual(proposed['source_bytes'], len(complete + tail))
        self.assertEqual(proposed['expected_read_bytes'], 2 * len(complete + tail))
        self.assertEqual(preview['snapshots'][0]['id'], proposed['preview_id'])

        extra = b' completed"\n10:12.000000-4,CALL,1\n'
        with path.open('ab') as stream:
            stream.write(extra)
        capture_args = dict(args, preview_id=proposed['preview_id'], preview_sha256=proposed['preview_sha256'])
        capture_request = self.request('case.analyze', capture_args, 'prefix-window')
        code, result = self.cli('context-intake', self.write_request(capture_request))
        self.assertEqual(code, 1, result)
        self.assertEqual(result['attachment_status'], 'attached')
        self.assertEqual(result['data']['prefix_captures'], [dict(source='s1', reviewed_bytes=len(complete + tail),
            unread_appended_bytes=len(extra), incomplete_tail_bytes=len(tail))])
        case_id = result['data']['material']['id']
        report = storage.verified_case(self.state, case_id)
        reference = report['sources'][0]['reference_capture']
        self.assertEqual(reference['original_sha256'], sha256(complete + tail).hexdigest())
        self.assertEqual(reference['selected_records'], 1)
        self.assertEqual(reference['incomplete_tail'], dict(byte_start=len(complete), byte_end=len(complete + tail), open_quote=True))
        self.assertEqual(storage.case_source_path(self.state, case_id, 's1').read_bytes(), b'10:00.000000-2,SCALL,1\n')
        evidence = storage.read_evidence(self.state, case_id, 's1:1')
        self.assertEqual(evidence['original_location']['basis'], 'observed_external_prefix_at_capture')
        self.assertEqual(evidence['original_location']['byte_start'], complete.index(b'10:00'))
        path.unlink()
        code, replay = self.cli('context-intake', self.write_request(capture_request))
        self.assertEqual(code, 1, replay)
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['attachment'], result['attachment'])

        selection = dict(retained_tj=dict(attachment=result['attachment']['id'],
                         offsets=[dict(source_id='s1', utc_offset='+02:00')],
                         window=dict(start='2026-11-15T07:10:00Z', end='2026-11-15T07:15:00Z')))
        request = self.request('case.analyze', selection, 'correct-prefix-time')
        request['context']['expected_revision'] = result['attachment']['revision']
        code, corrected = self.cli('context-intake', self.write_request(request))
        self.assertEqual(code, 0, corrected)
        self.assertEqual(corrected['data']['prefix_captures'], result['data']['prefix_captures'])
        change, = corrected['data']['time_correction']['sources']
        self.assertTrue(change['retained_capture_window_only'])
        self.assertEqual((change['before']['records_in_window'], change['after']['records_in_window']), (0, 1))
        derived = storage.verified_case(self.state, corrected['data']['material']['id'])
        self.assertEqual(derived['sources'][0]['reference_capture'], reference)
        saved = derived['source_coverage']['sources'][0]['reference_window']
        self.assertEqual(saved['window_basis'], 'selected_before_time_correction')
        recaptured = storage.read_evidence(self.state, derived['case_id'], 's1:1')
        self.assertEqual(recaptured['original_location'], evidence['original_location'])

    def test_retained_logcfg_supplies_parser_for_an_explicitly_selected_hourly_tj(self):
        from src.techexpert import artifacts

        destination = self.root / (PRIVATE + '-tj')
        path = destination / '1cv8_123' / '26111509.log'
        path.parent.mkdir(parents=True)
        records = b'09:59.999999-1,CALL,1\n10:00.000000-2,SCALL,1\n'
        path.write_bytes(records)
        self.configured_journals(tj_path=path, timestamp_format='minute')
        config = self.root / (PRIVATE + '-logcfg.xml')
        xml = (f'<config xmlns="http://v8.1c.ru/v8/tech-log"><log location={quoteattr(str(destination))} history="0">'
               '<event><eq property="name" value="call"/></event>'
               f'<event><eq property="name" value="SCALL"/><eq property="Usr" value="{PRIVATE}"/></event>'
               '<property name="all"/></log><defaultlog history="0"/></config>').encode()
        config.write_bytes(xml)
        inspect = self.request('source.check', dict(profile_journal=dict(source='j1', logcfg_file=str(config))), 'inspect-logcfg')
        code, view = self.cli('context-intake', self.write_request(inspect))
        self.assertEqual(code, 0, view)
        info = view['data']['logcfg']
        identifier = info['id']
        self.assertEqual(info['status'], 'matched')
        self.assertFalse(info['journal_bytes_read'])
        self.assertEqual(info['settings'], dict(format='text', placement='folders', rotation='period',
                                               rotation_hours=1, compression='none', history_hours=0))
        self.assertEqual(info['events']['names'], ['CALL'])
        self.assertEqual(info['events']['conditional_names'], ['SCALL'])
        self.assertEqual(info['timestamp_profile'], 'hourly_minute')
        self.assertEqual(info['runtime_applicability'], 'unverified')
        self.assertEqual(config.read_bytes(), xml)
        self.assertEqual(path.read_bytes(), records)
        artifact = artifacts.load_artifact(self.state, identifier)
        retained = artifacts.source_path(artifacts.artifact_folder(self.state, identifier), artifact['sources'][0])
        self.assertEqual(retained.read_bytes(), xml)
        self.assertEqual(view['snapshots'][0]['id'], identifier)
        config.unlink()

        selector = dict(source='j1', logcfg_id=identifier, read_mode='fixed_prefix')
        args = dict(profile_journal=selector)
        other = investigations.create(self.state, dict(task=PRIVATE))
        unrelated = self.request('source.check', args, 'unrelated-logcfg')
        unrelated['context']['investigation_id'] = other['investigation_id']
        code, denied = self.cli('context-intake', self.write_request(unrelated))
        self.assertEqual(code, 1, denied)
        self.assertEqual(denied['data']['journal_preview']['status'], 'logcfg_scope_mismatch')
        code, preview = self.cli('context-intake', self.write_request(self.request('source.check', args, 'logcfg-tj-preview')))
        self.assertEqual(code, 0, preview)
        plan = preview['data']['journal_preview']
        self.assertEqual(plan['timestamp_profile_basis'], 'supplied_logcfg')
        self.assertEqual({s['id'] for s in preview['snapshots']}, {identifier, plan['preview_id']})
        args.update(preview_id=plan['preview_id'], preview_sha256=plan['preview_sha256'])
        request = self.request('case.analyze', args, 'logcfg-tj-capture')
        code, capture = self.cli('context-intake', self.write_request(request))
        self.assertEqual(code, 0, capture)
        case_id = capture['data']['material']['id']
        report = storage.verified_case(self.state, case_id)
        self.assertEqual(report['logcfg_observation']['id'], identifier)
        self.assertEqual(storage.case_source_path(self.state, case_id, 's1').read_bytes(), b'10:00.000000-2,SCALL,1\n')
        path.unlink()
        code, replay = self.cli('context-intake', self.write_request(request))
        self.assertEqual(code, 0, replay)
        self.assertTrue(replay['replayed'])
        retained.write_bytes(xml + b' ')
        code, refused = self.cli('context-intake', self.write_request(request))
        self.assertEqual(code, 2, refused)
        self.assertNotIn('attachment', refused)

    def test_logcfg_process_lookup_checks_the_selected_process_without_scanning_the_host(self):
        self.configured_journals()
        args = dict(profile_journal=dict(source='j1', logcfg_process_pid=os.getpid()))
        request = self.request('source.check', args, 'lookup-client')
        code, view = self.cli('context-intake', self.write_request(request))
        self.assertEqual(code, 1, view)
        observed = view['data']['logcfg']
        expected = 'process_not_1c_client' if os.name == 'nt' else 'process_platform_unsupported'
        self.assertEqual(observed['status'], expected)
        self.assertFalse(observed['journal_bytes_read'])
        self.assertEqual(view['snapshots'], [])
        self.assertNotIn('id', observed)

    def test_logcfg_base_lookup_only_accepts_a_file_base_linked_to_the_saved_journal(self):
        self.profile['bases'].append(dict(id='other', name='Other', mode='file', connection=str(self.root / 'other')))
        self.configured_journals()
        code, listing = self.configured_call('source.check', 'list-file-base-aliases')
        self.assertEqual(code, 0, listing)
        self.assertEqual(listing['data']['journal_sources'][0]['file_bases'], ['b1'])
        expected = 'base_file_not_found' if os.name == 'nt' else 'process_platform_unsupported'
        for base, status in (('b2', 'file_base_not_linked'), ('b1', expected)):
            with self.subTest(base=base):
                args = dict(profile_journal=dict(source='j1', logcfg_base=base))
                request = self.request('source.check', args, 'logcfg-base-' + base)
                code, view = self.cli('context-intake', self.write_request(request))
                self.assertEqual(code, 1, view)
                self.assertEqual(view['data']['logcfg']['status'], status)
                self.assertFalse(view['data']['logcfg']['journal_bytes_read'])
                self.assertNotIn('id', view['data']['logcfg'])

    def test_logcfg_preview_requires_one_explicit_matching_and_supported_rule(self):
        destination = self.root / (PRIVATE + '-tj')
        path = destination / '1cv8_123' / '26111509.log'
        path.parent.mkdir(parents=True)
        self.configured_journals(tj_path=path, window=False)
        config = self.root / 'logcfg.xml'
        location = quoteattr(str(destination))
        selected = f'<log location={location} format="json" placement="plain"><event/></log>'
        unrelated = f'<log location={quoteattr(str(self.root / "unrelated"))}/>'
        prefix = '<config xmlns="http://v8.1c.ru/v8/tech-log">'
        cases = {
            'ambiguous_location': selected + f'<log location={quoteattr(str(path.parent))}/>',
            'unresolved_location': selected + '<log location="%PRIVATE%/logs"/>',
            'unmatched_location': unrelated,
            'matched': selected + unrelated,
        }
        args = dict(profile_journal=dict(source='j1', logcfg_file=str(config)))
        for expected, rules in cases.items():
            with self.subTest(expected=expected):
                config.write_text(prefix + rules + '</config>', encoding='utf8')
                _, view = self.cli('context-intake', self.write_request(self.request('source.check', args, expected)))
                self.assertEqual(view['data']['logcfg']['status'], expected)
                self.assertIsNone(view['data']['logcfg']['timestamp_profile'])
                self.assertFalse(view['data']['logcfg']['journal_bytes_read'])
        info = view['data']['logcfg']
        self.assertEqual(info['settings']['format'], 'json')
        args = dict(profile_journal=dict(source='j1', logcfg_id=info['id']))
        code, view = self.cli('context-intake', self.write_request(self.request('source.check', args, 'unsupported-logcfg')))
        self.assertEqual(code, 1, view)
        self.assertEqual(view['data']['journal_preview']['status'], 'logcfg_reader_unsupported')
        self.assertNotIn('preview_sha256', view['data']['journal_preview'])

        config.write_text(f'<!DOCTYPE config [<!ENTITY test "{PRIVATE}">]>{prefix}</config>', encoding='utf8')
        args = dict(profile_journal=dict(source='j1', logcfg_file=str(config)))
        code, view = self.cli('context-intake', self.write_request(self.request('source.check', args, 'invalid-xml')))
        self.assertEqual(code, 1, view)
        self.assertEqual(view['data']['logcfg']['status'], 'invalid_or_unsupported_xml')
        self.assertEqual(view['snapshots'], [])

    def test_native_json_logcfg_drives_fixed_prefix_and_linked_coverage(self):
        destination = self.root / (PRIVATE + '-json-tj')
        path = destination / '1cv8_123' / '26111509.log'
        path.parent.mkdir(parents=True)
        self.configured_journals(tj_path=path)
        outside = b'{"ts":"2026-11-15T09:09:59.999999","duration":"1","name":"CALL","depth":"1"}\r\n'
        inside = (f'{{"ts":"2026-11-15T09:10:00.000000","duration":"2","name":"SDBL","depth":"1",'
                  f'"Func":"Query","Func":"{PRIVATE}","OSThread":"42"}}\r\n').encode()
        original = b'\xef\xbb\xbf' + outside + inside
        path.write_bytes(original)
        config = self.root / 'logcfg.xml'
        config.write_text(
            f'<config xmlns="http://v8.1c.ru/v8/tech-log"><log location={quoteattr(str(destination))} format="json">'
            '<event><eq property="name" value="SDBL"/></event><property name="all"/></log></config>', encoding='utf8')
        args = dict(profile_journal=dict(source='j1', logcfg_file=str(config)))
        code, inspection = self.cli('context-intake', self.write_request(self.request('source.check', args, 'json-logcfg')))
        self.assertEqual(code, 0, inspection)
        info = inspection['data']['logcfg']
        self.assertEqual(info['timestamp_profile'], 'json_iso')
        config.unlink()

        args = dict(profile_journal=dict(source='j1', read_mode='fixed_prefix', logcfg_id=info['id']))
        code, view = self.cli('context-intake', self.write_request(self.request('source.check', args, 'json-prefix')))
        self.assertEqual(code, 0, view)
        preview = view['data']['journal_preview']
        self.assertEqual(preview['timestamp_profile'], 'json_iso')
        self.assertFalse(preview['source_bytes_read'])
        self.assertEqual(preview['source_bytes'], len(original))
        path.write_bytes(original + inside)
        request = self.request('case.analyze', dict(args, preview_id=preview['preview_id'],
                              preview_sha256=preview['preview_sha256']), 'json-capture')
        code, capture = self.cli('context-intake', self.write_request(request))
        self.assertEqual(code, 1, capture)
        self.assertEqual(capture['stop_reason'], 'journal_prefix_bounded')
        case_id = capture['data']['material']['id']
        self.assertEqual(storage.case_source_path(self.state, case_id, 's1').read_bytes(), inside)
        report = storage.verified_case(self.state, case_id)
        self.assertEqual(report['input_contract'], '1c-tj-json-v1')
        self.assertEqual(capture['data']['prefix_captures'][0]['unread_appended_bytes'], len(inside))
        row, = storage.list_native_events(self.state, case_id)['records']
        self.assertEqual(row['ambiguous_property_names'], ['Func'])
        self.assertEqual(row['properties'], {'OSThread': '42'})
        evidence = storage.read_evidence(self.state, case_id, 's1:1')
        self.assertEqual(evidence['original_location']['byte_start'], len(original) - len(inside))
        self.assertIn('"Func":"Query","Func":"' + PRIVATE, evidence['text'])
        path.unlink()
        self.assertEqual(self.cli('context-intake', self.write_request(request))[1]['attachment'], capture['attachment'])
        revision = capture['attachment']['revision']
        gate = (self.iid, '--revision', revision)
        code, plan = self.cli('context-policy-plan', *gate, '--allow', 'tj')
        self.assertEqual(code, 0, plan)
        code, policy = self.cli('context-policy-save', *gate, '--allow', 'tj', '--expected-sha256', plan['plan_sha256'])
        self.assertEqual(code, 0, policy)
        code, coverage = self.cli('context-read', *gate, 'tj-coverage', '--attachment', capture['attachment']['id'],
                                  '--start', preview['window']['start'], '--end', preview['window']['end'])
        self.assertIn(code, (0, 1), coverage)
        source, = coverage['data']['sources']
        self.assertEqual(source['format'], '1c-tj-json-v1')
        self.assertEqual(source['records_in_window'], 1)
        self.assertFalse(coverage['data']['can_establish_absence'])

    def test_reviewed_tj_prefix_rejects_changed_window_truncation_and_replacement(self):
        self.configured_journals()
        original = self.source.read_bytes()
        args = dict(profile_journal=dict(source='j1', read_mode='fixed_prefix'))
        code, preview = self.cli('context-intake', self.write_request(self.request('source.check', args, 'ready-prefix')))
        self.assertEqual(code, 0, preview)
        proposed = preview['data']['journal_preview']
        capture = dict(args, preview_id=proposed['preview_id'], preview_sha256=proposed['preview_sha256'])
        changed = dict(capture, profile_journal=dict(args['profile_journal'], window=dict(
            start='2026-11-15T06:10:01Z', end='2026-11-15T06:11:00Z')))
        code, denied = self.cli('context-intake', self.write_request(self.request('case.analyze', changed, 'new-window')))
        self.assertEqual(code, 2, denied)
        self.assertEqual(denied['stop_reason'], 'journal_preview_changed')
        self.source.write_bytes(original[:len(original)//2])
        code, denied = self.cli('context-intake', self.write_request(self.request('case.analyze', capture, 'truncated-prefix')))
        self.assertEqual(code, 2, denied)
        self.assertEqual(denied['stop_reason'], 'journal_prefix_truncated')
        self.source.rename(self.root / 'rotated-original.log')
        self.source.write_bytes(original + b'\n')
        code, denied = self.cli('context-intake', self.write_request(self.request('case.analyze', capture, 'replaced-prefix')))
        self.assertEqual(code, 2, denied)
        self.assertEqual(denied['stop_reason'], 'journal_prefix_replaced')
        self.assertFalse((self.state / 'cases').exists())

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
