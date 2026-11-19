import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import context_disclosure, context_policy, investigations, kernel
from src.techexpert import native_jr, storage


ROOT = Path(__file__).resolve().parents[1]
PRIVATE = 'synthetic-private-coverage'
WINDOW = dict(start='2026-11-16T07:05:42Z', end='2026-11-16T07:05:44Z')


class ContextCoverageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / 'state'
        self.original = self.root / (PRIVATE + '.log')
        self.original.write_text(
            '05:42.000000-10,CALL,1,UserName=' + PRIVATE + ',SessionID=1\n'
            '05:43.000000-20,EXCP,1,Context=' + PRIVATE + '\n'
            '05:44.000000-30,CALL,1,UserName=' + PRIVATE + '\n', encoding='utf-8')
        second = self.root / 'other.log'
        shutil.copyfile(self.original, second)
        source = dict(format='1c-tj-text-v1', platform_version='8.3.27.1989',
                      encoding='utf-8', placement='folders', timestamp_format='minute',
                      rotation_hours=1, file_hour='2026-11-16T10:00:00+03:00')
        case = storage.investigate(self.write('case.json', dict(schema=2, origin='provided',
            sources=[dict(source, path=str(self.original), collection=dict(events=['CALL'], filters=PRIVATE)),
                     dict(source, path=str(second)), dict(source, path=str(self.root / 'missing.log'))])), self.state)
        self.case_id = case['case_id']
        folder = ROOT / 'tests/fixtures/native-jr'
        known = native_jr.read_journal(self.state, folder, platform_version='8.3.27.1989', utc_offset='+03:00')
        unknown = native_jr.read_journal(self.state, folder, platform_version='8.3.27.1989')
        first = investigations.create(self.state, dict(task=PRIVATE))
        self.iid = first['investigation_id']
        self.revision = investigations.revise(self.state, self.iid, dict(attachments=[
            dict(id='A-tj', kind='case', target_id=self.case_id),
            dict(id='A-jr', kind='artifact', target_id=known['artifact_id']),
            dict(id='A-unknown', kind='artifact', target_id=unknown['artifact_id']),
        ]), expected_revision=1)['revision']

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
        return path

    def approve(self, *categories):
        identity = (self.state, self.iid, self.revision, categories, 4096)
        preview = context_policy.plan(*identity)
        context_policy.save(*identity, preview['plan_sha256'])

    def occurrence(self, start, end):
        data = dict(source='external_monitoring', message=PRIVATE,
                    started_at=start, ended_at=end, evidence=[])
        self.revision = investigations.revise(self.state, self.iid, dict(occurrence=data),
                                              expected_revision=self.revision)['revision']

    def view(self, kind='tj-coverage', attachment='A-tj', **args):
        result = context_disclosure.read(self.state, dict(investigation_id=self.iid,
            revision=self.revision, kind=kind, attachment=attachment, **args))
        self.assertNotIn(PRIVATE, json.dumps(result))
        return result

    def test_saved_occurrence_bounds_then_explicit_fallback(self):
        self.approve('tj')
        self.occurrence(WINDOW['start'], WINDOW['start'])
        point_revision = self.revision
        self.assertEqual(self.view()['stop_reason'], 'context_window_required')
        explicit = self.view(window=WINDOW, event='SDBL')['data']
        self.assertEqual(explicit['window_basis'], 'explicit_window')
        self.assertEqual(explicit['sources'][0]['requested_event']['status'], 'not_collected_declared')
        self.occurrence(WINDOW['start'], WINDOW['end'])
        report = self.view()['data']
        first = report['sources'][0]
        self.assertEqual(report['window_basis'], 'saved_occurrence')
        self.assertEqual(report['occurrence_status'], 'reported_not_verified')
        self.assertEqual(first['records_in_window'], 2)
        self.assertEqual(first['observed_event_counts'], {'CALL': 1, 'EXCP': 1})
        self.assertEqual(first['observed_field_counts']['SessionID'], 1)
        self.assertFalse(report['can_establish_absence'])
        self.assertEqual(report['source_identity'], 'not_established')
        no_match = self.view(window=dict(start=WINDOW['end'], end='2026-11-16T07:05:45Z'))['data']
        self.assertEqual(no_match['sources'][0]['records_in_window'], 1)
        self.revision = point_revision
        self.assertEqual(self.view()['stop_reason'], 'context_window_required')

    def test_span_intersection_with_a_gap_is_distinct_from_recorded_data(self):
        self.approve('tj')
        data = self.view(window=dict(start='2026-11-16T07:05:42.250Z', end='2026-11-16T07:05:43Z'))['data']
        first = data['sources'][0]
        self.assertTrue(first['span_intersects_window'])
        self.assertEqual(first['records_in_window'], 0)
        self.assertEqual(first['assessment'], 'no_recorded_timestamps_in_window')
        self.assertEqual(data['continuity'], 'unknown')
        self.assertFalse(data['can_establish_absence'])
        self.assertEqual(self.view(limit=1, offset=1, window=WINDOW)['data']['next_offset'], 2)

    def test_lost_snapshot_does_not_discard_good_files_or_fall_back_to_original(self):
        self.approve('tj')
        storage.case_source_path(self.state, self.case_id, 's2').unlink()
        self.original.unlink()
        report = self.view(window=WINDOW)['data']
        rows = {row['source']: row for row in report['sources']}
        self.assertEqual(rows['s1']['records_in_window'], 2)
        self.assertTrue(rows['s1']['snapshot_verified'])
        self.assertEqual(rows['s2']['availability'], 'not_found')
        self.assertEqual(rows['s3']['availability'], 'not_found')
        self.assertFalse(rows['s2']['snapshot_verified'])
        self.assertEqual(rows['s3']['availability_basis'], 'capture_attempt')
        for problem, expected in ((PermissionError(PRIVATE), 'access_denied'),
                                  (OSError(PRIVATE), 'read_error')):
            with self.subTest(expected=expected):
                with patch('src.techexpert.context_coverage._tj_source', side_effect=problem):
                    report = self.view(window=WINDOW)['data']
                self.assertEqual(report['sources'][0]['availability'], expected)

    def test_journal_counts_use_only_saved_time_and_hide_records(self):
        self.approve('jr')
        self.occurrence(WINDOW['start'], WINDOW['end'])
        known = self.view('jr-coverage', 'A-jr')['data']
        unknown = self.view('jr-coverage', 'A-unknown')['data']
        self.assertEqual(known['journal']['records_in_window'], 4)
        self.assertNotIn('_$Job$_.Start', json.dumps(known))
        self.assertNotIn('records', known)
        self.assertEqual(unknown['journal']['assessment'], 'time_zone_unknown')
        self.assertIsNone(unknown['journal']['records_in_window'])
        self.assertFalse(unknown['can_establish_absence'])

    def test_journal_near_tj_requires_both_categories_and_keeps_half_open_evidence(self):
        anchor = dict(anchor_attachment='A-tj', record='s1:2', within_seconds=1)
        self.approve('jr')
        with patch.object(storage, 'load_case', side_effect=AssertionError('read before policy')):
            denied = self.view('jr-near-tj', 'A-jr', **anchor)
        self.assertEqual(denied['stop_reason'], 'context_category_not_allowed')
        self.approve('tj', 'jr')
        result = self.view('jr-near-tj', 'A-jr', limit=1, **anchor)
        self.assertEqual(result['status'], 'succeeded', result)
        data = result['data']
        self.assertEqual(data['anchor']['evidence']['id'],'s1:2')
        self.assertEqual(data['anchor']['timestamp_utc'],'2026-11-16T07:05:43+00:00')
        self.assertEqual(data['window']['end'],'2026-11-16T07:05:44+00:00')
        self.assertEqual(data['matched_count'],4)
        self.assertEqual(data['next_offset'],1)
        self.assertEqual(data['records'][0]['recorded_delta_seconds'],-1)
        self.assertEqual(data['records'][0]['evidence']['id'],'s2:r1')
        self.assertEqual(result['disclosure']['anchor']['source_id'],self.case_id)
        self.assertFalse(data['source_relation']['exact_correlation_allowed'])
        self.assertEqual(data['clock_alignment'],'not_verified')
        self.assertNotIn('_$Job$_.Start',json.dumps(result))
        following = self.view('jr-near-tj','A-jr',offset=1,**anchor)['data']
        self.assertEqual(len(following['records']),3)
        self.assertIsNone(following['next_offset'])
        unknown = self.view('jr-near-tj','A-unknown',**anchor)['data']
        self.assertEqual(unknown['coverage']['status'],'time_zone_unknown')
        self.assertIsNone(unknown['coverage']['records_in_window'])
        self.assertFalse(unknown['can_establish_absence'])

    def test_journal_candidate_retains_conflicting_passports_and_records(self):
        revision = investigations.revise(self.state,self.iid,dict(source_bindings=[
            dict(id='S-tj',attachment='A-tj',record_source='s1',reported=dict(infobase_identity=PRIVATE+'1')),
            dict(id='S-jr',attachment='A-jr',reported=dict(infobase_identity=PRIVATE+'2'))],
            source_links=[dict(id='L-pair',left='S-tj',right='S-jr',claim='same_infobase',reported=True)]),
            expected_revision=self.revision)
        self.revision = revision['revision']
        self.approve('tj','jr')
        result = self.view('jr-near-tj','A-jr',anchor_attachment='A-tj',record='s1:2',within_seconds=2,limit=1)
        data = result['data']
        self.assertEqual(data['matched_count'],5)
        self.assertEqual(data['source_relation']['status'],'conflict')
        self.assertIn('different_infobase_claims',data['source_relation']['reasons'])
        self.assertEqual(data['source_relation']['saved_links'][0]['id'],'L-pair')
        self.assertEqual(data['source_relation']['tj_passport'],'S-tj')
        self.assertEqual(data['source_relation']['jr_passport'],'S-jr')
        self.assertFalse(data['source_relation']['exact_correlation_allowed'])
        self.assertEqual(investigations.load(self.state,self.iid,revision=self.revision),revision)

    def test_journal_candidate_program_pins_both_attachments_and_reader(self):
        from src.techexpert.update_state import inspect_state

        self.approve('tj','jr')
        selection = dict(kind='jr-near-tj',attachment='A-jr',anchor_attachment='A-tj',
                         record='s1:2',within_seconds=1,limit=1)
        full = dict(selection,investigation_id=self.iid,revision=self.revision)
        self.assertEqual(kernel.invoke(self.state,'context-read',dict(selection=context_disclosure.compact(full)))['exit_code'],0)
        scope = [{key: selection[key] for key in ('kind','attachment','anchor_attachment')}]
        program = 'return api("context.read", selected)["data"]["records"][0]["evidence"]["id"]'
        request = dict(schema_version=1,operation_key='near-journal',executor_id='tests',operation='code.context',
                       arguments=dict(program=program,bindings=dict(selected=selection),scope=dict(views=scope)),
                       context=dict(investigation_id=self.iid,expected_revision=self.revision))

        def run(value):
            path = self.write('near-program.json',value)
            call = kernel.invoke(self.state,'run',dict(request=str(path)))
            stream = io.StringIO()
            kernel.emit(call,stream)
            return json.loads(stream.getvalue())

        without_anchor = dict(request,operation_key='wrong-near-journal',arguments=dict(request['arguments'],
                              scope=dict(views=[dict(kind='jr-near-tj',attachment='A-jr')])))
        self.assertNotEqual(run(without_anchor)['status'],'succeeded')
        initial = run(request)
        self.assertEqual(initial['status'],'succeeded',initial)
        self.assertEqual(initial['data']['value'],'s2:r1')
        self.assertTrue(run(request)['replayed'])
        schemas = inspect_state(self.state)['schemata']
        self.assertIn(6,schemas['context-disclosure'])
        self.assertIn(6,schemas['context-program'])
        storage.case_source_path(self.state,self.case_id,'s1').write_bytes(b'damaged')
        denied = run(request)
        self.assertNotEqual(denied['status'],'succeeded')
        self.assertIsNone(denied.get('data'))

    def test_protected_coverage_of_unsupported_attachment_is_metadata_only(self):
        from src.techexpert import artifacts
        candidate = artifacts.save_artifact(self.state, 'sample', {}, [], {})
        self.revision = investigations.revise(self.state, self.iid, dict(attachments=[
            dict(id='A-candidate', kind='artifact', target_id=candidate['artifact_id'])]),
            expected_revision=self.revision)['revision']
        self.approve('jr')
        with patch.object(native_jr, '_parse_saved', side_effect=AssertionError('read unsupported sources')):
            report = self.view('jr-coverage', 'A-candidate', window=WINDOW)['data']
        self.assertEqual(report['status'], 'unsupported_format')
        self.assertIsNone(report.get('journal'))

    def test_only_reviewed_views_can_scan_and_program_replay_checks_good_bytes(self):
        from src.techexpert.update_state import inspect_state

        with patch.object(storage, 'load_case', side_effect=AssertionError('scan before policy')):
            self.assertEqual(self.view(window=WINDOW)['stop_reason'], 'context_policy_required')
        self.approve('tj')
        self.occurrence(WINDOW['start'], WINDOW['end'])
        storage.case_source_path(self.state, self.case_id, 's2').unlink()
        program = '''coverage = api("context.read", {"attachment": "A-tj", "kind": "tj-coverage"})["data"]
return {"found": coverage["sources"][0]["records_in_window"], "missing": coverage["sources"][1]["availability"]}
'''
        request = self.write('program.json', dict(schema_version=1, operation_key='coverage-resume',
            executor_id='tests', operation='code.context', arguments=dict(program=program,
                scope=dict(views=[dict(attachment='A-tj', kind='tj-coverage')])),
            context=dict(investigation_id=self.iid, expected_revision=self.revision)))

        def run():
            call = kernel.invoke(self.state, 'run', dict(request=str(request)))
            stream = io.StringIO()
            kernel.emit(call, stream)
            return json.loads(stream.getvalue())

        first = run()
        self.assertEqual(first['status'], 'succeeded', first)
        self.assertEqual(first['data']['value'], dict(found=2, missing='not_found'))
        self.assertTrue(run()['replayed'])
        self.assertEqual(inspect_state(self.state)['schemata']['context-program'], [3])
        storage.case_source_path(self.state, self.case_id, 's1').write_bytes(b'changed')
        denied = run()
        self.assertIsNone(denied.get('data'))
        self.assertNotEqual(denied['status'], 'succeeded')

    def test_saved_cli_coverage_requires_a_compatible_reader(self):
        from src.techexpert.update_state import STATE_CONTRACT, inspect_state, supports

        self.approve('tj')
        selection = dict(investigation_id=self.iid, revision=self.revision, kind='tj-coverage',
                         attachment='A-tj', window=WINDOW)
        arguments = dict(selection=context_disclosure.compact(selection))
        call = kernel.invoke(self.state, 'context-read', arguments)
        self.assertEqual(call['exit_code'], 0)
        observed = inspect_state(self.state)
        self.assertEqual(observed['activity'], 'idle_observed')
        self.assertEqual(observed['schemata']['context-disclosure'], [1, 3])
        metadata = dict(version='0.56.0', state_contract=STATE_CONTRACT, knowledge_schema=2)
        self.assertFalse(supports(metadata, observed['schemata'], context_disclosure_schemas=[1, 2]))
        self.assertTrue(supports(metadata, observed['schemata'], context_disclosure_schemas=[1, 2, 3]))
