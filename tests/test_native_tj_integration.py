import json
import os
import tempfile
import unittest
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from src.techexpert.inputs import InputError, load_manifest
from src.techexpert.storage import investigate, read_evidence, load_case


SCOPE = dict(database='orders', node='node-a', process='rphost-42', epoch='boot-a', run='job-42')
NATIVE = ('45:00.000001-2460000000,CALL,1,process=rphost,p:processName=orders,'
          'SessionID=12,Context="Загрузка, заказов\nВторая строка"\n')


def native_spec(path):
    return dict(path=str(path), format='1c-tj-text-v1', platform_version='8.3.27.1989',
                encoding='utf-8', placement='folders', timestamp_format='minute', rotation_hours=1,
                file_hour='2026-11-15T09:00:00+03:00',
                context=dict(node='node-a', process='rphost-42', epoch='boot-a'))


def write_manifest(root, sources):
    path = root / 'case.json'
    path.write_text(json.dumps(dict(schema=1, scenario='SC-01', origin='provided', selection=SCOPE,
        symptom='Загрузка заказов 45 минут вместо пяти', reported_normal_seconds=300,
        sources=sources)), encoding='utf-8')
    return path


def write_reference_manifest(root, source, window):
    path = root / 'case.json'
    path.write_text(json.dumps(dict(schema=2, origin='provided',
        sources=[dict(native_spec(source), external_window=window)])), encoding='utf-8')
    return path


class NativeIntegrationTests(unittest.TestCase):
    def test_external_window_keeps_only_complete_selected_records_and_original_positions(self):
        from hashlib import sha256
        from src.techexpert.source_coverage import inspect_case
        from src.techexpert.storage import list_native_events
        from src.techexpert.tj_reference import plan

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / 'state'
            source = root / '26111509.log'
            before = b'\xef\xbb\xbf' + b'00:02.000000-1,CALL,1,Text="before\n45:02.000000-1,EXCP,1,Text=inside-quote"\n'
            selected = NATIVE.encode('utf-8')
            between = b'32:00.000000-4,SCALL,1\n'
            later = b'45:30.000000-3,EXCP,1\r\n'
            after = b'46:00.000000-2,CALL,1\n'
            data = before + selected + between + later + after
            source.write_bytes(data)
            window = dict(start='2026-11-15T09:45:00+03:00', end='2026-11-15T09:46:00+03:00', max_retained_bytes=4096)
            manifest = write_reference_manifest(root, source, window)
            reviewed = plan(manifest, state)
            self.assertEqual(reviewed['plan']['external_bytes'], len(data))
            self.assertEqual(reviewed['plan']['max_retained_bytes'], 4096)
            self.assertEqual(reviewed['plan']['state_dir'], str(state))
            self.assertFalse(state.exists())
            result = investigate(manifest, state, reference_sha256=reviewed['plan_sha256'])
            self.assertEqual(result['native_observations']['by_event'], {'CALL': 1, 'EXCP': 1})
            saved = result['sources'][0]
            capture = saved['reference_capture']
            self.assertEqual(capture['original_sha256'], sha256(data).hexdigest())
            self.assertEqual(capture['original_bytes'], len(data))
            self.assertEqual(capture['window'], dict(start='2026-11-15T06:45:00+00:00', end='2026-11-15T06:46:00+00:00'))
            self.assertEqual(saved['size'], len(selected) + len(later))
            self.assertEqual((state / 'cases' / result['case_id'] / 'sources' / 's1.bin').read_bytes(), selected + later)
            source.rename(root / 'rotated.log')
            proof = read_evidence(state, result['case_id'], 's1:3')
            self.assertEqual(proof['original_location']['byte_start'], len(before + selected + between))
            self.assertEqual(proof['original_location']['byte_end'], len(data) - len(after))
            view = list_native_events(state, result['case_id'])
            self.assertEqual(view['records'][1]['evidence']['original_location'], proof['original_location'])
            self.assertEqual(view['reference_windows'][0]['window'], capture['window'])
            coverage = inspect_case(state, result['case_id'])
            self.assertTrue(coverage['native_snapshot_integrity_verified'])
            self.assertEqual(coverage['sources'][0]['reference_window']['window'], capture['window'])
            self.assertEqual(coverage['sources'][0]['continuity'], 'unknown')

    def test_reference_requires_a_current_preview_and_never_runs_from_ordinary_source_check(self):
        from src.techexpert.source_coverage import inspect_manifest
        from src.techexpert.tj_reference import plan

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / 'state'
            source = root / '26111509.log'
            source.write_bytes(NATIVE.encode('utf-8'))
            window = dict(start='2026-11-15T09:45:00+03:00', end='2026-11-15T10:00:00+03:00', max_retained_bytes=4096)
            manifest = write_reference_manifest(root, source, window)
            review = plan(manifest, state)
            with patch('src.techexpert.tj_reference.capture', side_effect=AssertionError('unreviewed capture')):
                with self.assertRaisesRegex(InputError, 'reference preview'):
                    investigate(manifest, state)
                coverage = inspect_manifest(manifest)
                self.assertEqual(coverage['sources'][0]['availability'], 'reference_review_required')
                with source.open('ab') as stream:
                    stream.write(b'47:00.000000-0,CALL,0\n')
                with self.assertRaisesRegex(InputError, 'reference preview changed'):
                    investigate(manifest, state, reference_sha256=review['plan_sha256'])
            self.assertFalse(state.exists())

    def test_reference_refuses_a_changed_second_read_and_an_oversized_selection(self):
        from src.techexpert import tj_reference

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / 'state'
            source = root / '26111509.log'
            source.write_bytes(NATIVE.encode('utf-8'))
            window = dict(start='2026-11-15T09:45:00+03:00', end='2026-11-15T10:00:00+03:00', max_retained_bytes=20)
            manifest = write_reference_manifest(root, source, window)
            review = tj_reference.plan(manifest, state)
            with self.assertRaisesRegex(InputError, 'exceeds the retained byte limit'):
                investigate(manifest, state, reference_sha256=review['plan_sha256'])
            window['max_retained_bytes'] = 4096
            write_reference_manifest(root, source, window)
            review = tj_reference.plan(manifest, state)
            open_source = tj_reference._open

            class DivergingRead:
                def __init__(self, path):
                    self.file = open_source(path)
                    self.repeated = False

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    self.file.close()

                def fileno(self):
                    return self.file.fileno()

                def seek(self, offset):
                    self.repeated = True
                    return self.file.seek(offset)

                def read(self, size):
                    value = self.file.read(size)
                    return (b'X' + value[1:]) if self.repeated and value else value

            with patch.object(tj_reference, '_open', side_effect=DivergingRead):
                with self.assertRaisesRegex(InputError, 'contents changed during the repeated observation'):
                    investigate(manifest, state, reference_sha256=review['plan_sha256'])
            self.assertFalse(state.exists())

    def test_reference_compares_path_and_handle_change_times_within_their_own_observations(self):
        from src.techexpert import tj_reference

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / 'state'
            source = root / '26111509.log'
            source.write_bytes(NATIVE.encode('utf-8'))
            window = dict(start='2026-11-15T09:45:00+03:00', end='2026-11-15T10:00:00+03:00', max_retained_bytes=4096)
            manifest = write_reference_manifest(root, source, window)
            observed = tj_reference._path_state(source)
            different_path_ctime = dict(observed, ctime_ns=str(int(observed['ctime_ns'])-1))
            with patch.object(tj_reference, '_path_state', return_value=different_path_ctime):
                digest = tj_reference.plan(manifest, state)['plan_sha256']
                report = investigate(manifest, state, reference_sha256=digest)
            self.assertEqual(report['sources'][0]['reference_capture']['selected_records'], 1)

    def test_managed_reference_is_an_explicit_grant_and_replays_after_rotation(self):
        from src.techexpert import capabilities, code_policy, operations
        from src.techexpert.code_values import CodeError
        from src.techexpert.tj_reference import plan

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / 'state'
            source = root / '26111509.log'
            source.write_bytes(NATIVE.encode('utf-8'))
            window = dict(start='2026-11-15T09:45:00+03:00', end='2026-11-15T10:00:00+03:00', max_retained_bytes=4096)
            manifest = write_reference_manifest(root, source, window)
            digest = plan(manifest, state)['plan_sha256']
            prepared = operations.run(state, dict(schema_version=1, operation='source.check', executor_id='reference-test',
                operation_key='preview-reference', arguments=dict(manifest=str(manifest), reference_preview=True)))
            self.assertEqual(prepared['data']['reference_preview']['plan_sha256'], digest)
            self.assertFalse(prepared['data']['reference_preview']['source_bytes_read'])
            args = dict(manifest=str(manifest), reference_sha256=digest)
            operation = dict(schema_version=1, operation='case.analyze', executor_id='reference-test',
                             operation_key='reviewed-reference', arguments=args)
            program = dict(schema_version=1, operation='code.execute', executor_id='reference-test',
                           operation_key='reference-grant', arguments=dict(program='return 0',
                               scope=dict(operations=['case.analyze'], manifests=[str(manifest)])))
            scope = capabilities.normalize_request(program)['arguments']['scope']
            with self.assertRaisesRegex(CodeError, 'External TJ review'):
                code_policy.Scope(scope, ['case.analyze']).authorize('case.analyze', args)
            program['arguments']['scope']['reference_reviews'] = [dict(manifest=str(manifest), sha256=digest)]
            granted = capabilities.normalize_request(program)['arguments']['scope']
            code_policy.Scope(granted, ['case.analyze']).authorize('case.analyze', args)
            program['arguments'].update(program='return api("case.analyze", selected)["data"]["case_id"]',
                                        bindings=dict(selected=args))
            from_program = operations.run(state, program)
            self.assertEqual(from_program['status'], 'succeeded', from_program)
            self.assertEqual(load_case(state, from_program['data']['value'])['reference_plan_sha256'], digest)
            first = operations.run(state, operation)
            self.assertEqual(first['status'], 'succeeded', first)
            self.assertEqual(first['data']['reference_plan_sha256'], digest)
            source.rename(root / 'rotated.log')
            manifest.rename(root / 'stored-request.json')
            replay = operations.run(state, operation)
            self.assertTrue(replay['replayed'])
            self.assertEqual(replay['data'], first['data'])

    def test_native_call_is_observation_not_whole_background_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / '26111509.log'
            log.write_text(NATIVE, encoding='utf-8')
            result = investigate(write_manifest(root, [native_spec(log)]), root / 'state')
            self.assertEqual(result['input_contract'], '1c-tj-text-v1')
            self.assertEqual(result['durations_seconds'], dict(queue=None, execution=None, total=None))
            self.assertEqual(result['cause_state'], 'insufficient_data')
            observed = result['native_observations']
            self.assertEqual(observed['event_count'], 1)
            self.assertEqual(observed['by_event'], {'CALL': 1})
            self.assertEqual(observed['longest_events'][0]['duration_us'], 2460000000)
            self.assertEqual(observed['job_correlation'], 'not_established')
            self.assertEqual(result['sources'][0]['parse_status'], 'parsed')
            self.assertEqual(load_case(root / 'state', result['case_id'])['case_id'], result['case_id'])

    def test_native_multiline_evidence_uses_original_snapshot_and_byte_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / '26111509.log'
            data = b'\xef\xbb\xbf' + NATIVE.replace('\n', '\r\n').encode('utf-8')
            log.write_bytes(data)
            result = investigate(write_manifest(root, [native_spec(log)]), root / 'state')
            log.write_bytes(b'rotated/truncated')
            proof = read_evidence(root / 'state', result['case_id'], 's1:1')
            self.assertIn('Вторая строка', proof['text'])
            self.assertEqual(proof['end_line'], 2)
            self.assertEqual(proof['byte_end'], len(data))
            self.assertTrue(proof['integrity_verified'])
            self.assertTrue(proof['untrusted_source_content'])
            with self.assertRaises(InputError):
                read_evidence(root / 'state', result['case_id'], 's1:2')

    def test_mixed_native_and_explicit_milestones_still_requires_correlation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / '26111509.log'
            log.write_text(NATIVE, encoding='utf-8')
            norm = root / 'events.jsonl'
            norm.write_text('\n'.join(json.dumps(dict(kind=k, timestamp=t, scope=SCOPE)) for k, t in
                [('started', '2026-11-15T09:04:00+03:00'), ('finished', '2026-11-15T09:45:00+03:00')]), encoding='utf-8')
            result = investigate(write_manifest(root, [native_spec(log),dict(path=str(norm),format='normalized-events-v1')]),root/'state')
            self.assertEqual(result['durations_seconds']['execution'], 2460)
            self.assertIsNone(result['durations_seconds']['queue'])
            self.assertEqual(result['native_observations']['job_correlation'], 'not_established')
            self.assertEqual(result['native_observations']['longest_events'][0]['evidence']['id'], 's1:1')

    def test_same_file_conflicting_profiles_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / 'renamed.txt'
            log.write_text(NATIVE, encoding='utf-8')
            one = native_spec(log)
            two = dict(one, file_hour='2026-11-15T10:00:00+03:00')
            with self.assertRaisesRegex(ValueError, 'conflicting'):
                load_manifest(write_manifest(root, [one,two]))

    def test_empty_and_invalid_native_files_have_distinct_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for data, expected in [(b'', 'empty'), (b'not a TJ\n', 'invalid')]:
                with self.subTest(expected=expected):
                    log = root / '26111509.log'
                    log.write_bytes(data)
                    result = investigate(write_manifest(root,[native_spec(log)]),root/'state')
                    self.assertEqual(result['sources'][0]['parse_status'], expected)
                    self.assertIsNone(result['durations_seconds']['total'])

    def test_identical_distinct_files_not_silently_deduplicated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            logs=[root/'one.txt',root/'two.txt']
            for log in logs:
                log.write_text(NATIVE,encoding='utf-8')
            bundle=load_manifest(write_manifest(root,[native_spec(x) for x in logs]))
            self.assertEqual(len(bundle['native_events']),2)
            self.assertNotEqual(bundle['native_events'][0]['evidence']['id'],bundle['native_events'][1]['evidence']['id'])

    def test_native_pagination_uses_snapshots_and_exact_property_filters(self):
        from src.techexpert.storage import list_native_events
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            log=root/'26111509.log'
            log.write_text(NATIVE + '46:00.000000-4,EXCP,0,SessionID=13,Descr=error\n' + NATIVE,encoding='utf-8')
            result=investigate(write_manifest(root,[native_spec(log)]),root/'state')
            log.write_bytes(b'changed')
            page=list_native_events(root/'state',result['case_id'],event='CALL',properties={'SessionID':'12'},offset=1,limit=1)
            self.assertEqual(page['matched_count'],2)
            self.assertEqual(len(page['records']),1)
            self.assertEqual(page['records'][0]['evidence']['id'],'s1:4')
            self.assertIsNone(page['next_offset'])
            self.assertTrue(page['integrity_verified'])
            self.assertEqual(page['job_correlation'],'not_established')

    def test_native_query_rejects_bad_bounds_and_unknown_source(self):
        from src.techexpert.storage import list_native_events
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            log=root/'26111509.log'
            log.write_text(NATIVE,encoding='utf-8')
            result=investigate(write_manifest(root,[native_spec(log)]),root/'state')
            for args in [dict(offset=-1),dict(limit=101),dict(limit=0),dict(source_id='s2')]:
                with self.subTest(args=args), self.assertRaises(InputError):
                    list_native_events(root/'state',result['case_id'],**args)

    def test_events_cli_returns_filtered_page_and_structured_invalid_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            log=root/'26111509.log'
            log.write_text(NATIVE,encoding='utf-8')
            result=investigate(write_manifest(root,[native_spec(log)]),root/'state')
            command=[sys.executable,str(Path(__file__).resolve().parents[1]/'techexpert.py'),
                     '--state-dir',str(root/'state'),'events',result['case_id']]
            page=subprocess.run(command+['--event','CALL','--property','SessionID=12','--limit','1'],
                                capture_output=True,encoding='utf-8',timeout=15)
            self.assertEqual(page.returncode,0,page.stdout+page.stderr)
            self.assertEqual(json.loads(page.stdout)['matched_count'],1)
            bad=subprocess.run(command+['--property','broken'],capture_output=True,encoding='utf-8',timeout=15)
            self.assertEqual(bad.returncode,2)
            self.assertEqual(json.loads(bad.stdout)['status'],'error')


class SavedTJIndexTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / 'state'
        self.originals = [self.root / name for name in ('first.txt', 'second.txt')]
        self.exact = 'Д' * 513
        self.originals[0].write_bytes((NATIVE + f'46:00.000000-4,EXCP,0,SessionID=13,Detail={self.exact}\n').encode('utf-8'))
        self.originals[1].write_bytes((NATIVE + '47:00.000000-2,EXCP,1,SessionID=13,Detail=A,Detail=B\n').encode('utf-8'))
        self.case = investigate(write_manifest(self.root, [native_spec(p) for p in self.originals]), self.state)['case_id']

    def test_indexed_pages_match_existing_route_for_exact_filters_and_multiple_sources(self):
        from src.techexpert import case_event_index, storage

        queries = ({}, dict(event='CALL', offset=1, limit=1),
                   dict(properties={'Detail': self.exact}), dict(properties={'Detail': 'A'}),
                   dict(window=dict(start='2026-11-15T06:46:00+00:00', end='2026-11-15T06:47:00+00:00')),
                   dict(offset=10**22, limit=1), dict(linked_run=True))
        baseline = [storage.list_native_events(self.state, self.case, **query) for query in queries]
        self.assertEqual(baseline[2]['matched_count'], 1)
        self.assertEqual(baseline[3]['matched_count'], 0)
        for path in self.originals:
            path.unlink()
        for source_id in ('s1', 's2'):
            prepared = case_event_index.build(self.state, self.case, source_id)
            self.assertEqual(prepared['status'], 'ready')
            self.assertTrue(case_event_index.build(self.state, self.case, source_id)['replayed'])
        with patch.object(storage, 'iter_tj', side_effect=AssertionError('used the raw scanner')):
            result = [storage.list_native_events(self.state, self.case, **query) for query in queries]
        self.assertEqual(result, baseline)
        with patch.object(case_event_index, '_query', side_effect=AssertionError('low-memory query opened SQLite')):
            self.assertEqual(storage.list_native_events(self.state, self.case, index_memory_bytes=64*1024**2), baseline[0])
        second = storage.case_source_path(self.state, self.case, 's2')
        second.write_bytes(b'truncated')
        with self.assertRaisesRegex(InputError, 'snapshot integrity'):
            storage.list_native_events(self.state, self.case, limit=1)

    def test_unusable_cache_falls_back_but_never_masks_damaged_raw_evidence(self):
        from src.techexpert import case_event_index, storage

        expected = storage.list_native_events(self.state, self.case, source_id='s1')
        prepared = case_event_index.build(self.state, self.case, 's1')
        cache = Path(prepared['path'])
        cache.write_bytes(b'broken index')
        self.assertEqual(storage.list_native_events(self.state, self.case, source_id='s1'), expected)
        rebuilt = case_event_index.build(self.state, self.case, 's1')
        self.assertNotEqual(prepared['generation'], rebuilt['generation'])
        with patch.object(case_event_index, '_query', side_effect=MemoryError):
            self.assertEqual(storage.list_native_events(self.state, self.case, source_id='s1'), expected)
        raw = storage.case_source_path(self.state, self.case, 's1')
        with raw.open('r+b') as f:
            f.seek(-2, 2)
            f.write(b'x')
        with self.assertRaisesRegex(InputError, 'snapshot integrity'):
            storage.list_native_events(self.state, self.case, source_id='s1', event='NO-MATCH', offset=99999)

    @unittest.skipUnless(os.name == 'nt', 'raw source retirement uses Windows file handles')
    def test_retirement_during_an_indexed_query_rejects_reoccupied_source(self):
        from src.techexpert import case_event_index, case_retention, storage

        case_event_index.build(self.state, self.case, 's1')
        approval = case_retention.preview(self.state, self.case, 's1')
        raw = storage.case_source_path(self.state, self.case, 's1')
        saved = raw.read_bytes()
        search = case_event_index._query

        def retire_during_lookup(*args):
            result = search(*args)
            case_retention.apply(self.state, approval['plan'], expected_sha256=approval['plan_sha256'])
            raw.write_bytes(saved)
            return result

        with patch.object(case_event_index, '_query', side_effect=retire_during_lookup):
            with self.assertRaisesRegex(InputError, 'retired case snapshot'):
                storage.list_native_events(self.state, self.case, source_id='s1')

    def test_independent_index_retention_can_remove_and_rebuild_without_losing_evidence(self):
        from src.techexpert import case_event_index, index_retention, retention_policy, storage

        original = case_event_index.build(self.state, self.case, 's1')
        proof = storage.read_evidence(self.state, self.case, 's1:1')
        self.assertEqual(index_retention.preview(self.state, self.case, 's1', use_policy=True)['status'], 'retained_by_policy')
        retention_policy.save(self.state, {'schema_version':1, 'case_index_days':0},
                              expected_revision=0, category='case-indexes')
        plan = index_retention.preview(self.state, self.case, 's1', use_policy=True)
        self.assertEqual(plan['logical_bytes'], Path(original['path']).stat().st_size)
        with self.assertRaisesRegex(InputError, 'plan digest'):
            index_retention.apply(self.state, plan['plan'], expected_sha256='0' * 64)
        result = index_retention.apply(self.state, plan['plan'], expected_sha256=plan['plan_sha256'])
        self.assertEqual(result['status'], 'removed')
        self.assertEqual(index_retention.apply(self.state, plan['plan'], expected_sha256=plan['plan_sha256'])['status'], 'already_absent')
        rebuilt = case_event_index.build(self.state, self.case, 's1')
        self.assertNotEqual(original['generation'], rebuilt['generation'])
        with self.assertRaisesRegex(InputError, 'index changed'):
            index_retention.apply(self.state, plan['plan'], expected_sha256=plan['plan_sha256'])
        self.assertEqual(storage.read_evidence(self.state, self.case, 's1:1'), proof)
        self.assertEqual(retention_policy.load(self.state, category='case-inputs')['revision'], 0)


if __name__ == '__main__':
    unittest.main()
