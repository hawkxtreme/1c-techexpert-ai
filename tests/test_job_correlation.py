"""Synthetic adverse cases model the observed controlled file-mode contract."""
import copy
import importlib
import importlib.util
import unittest
from datetime import datetime, timezone


JOB = '11111111-1111-4111-8111-111111111111'
NONCE = '22222222-2222-4222-8222-222222222222'
SESSION = '33333333-3333-4333-8333-333333333333'
OTHER_JOB = '44444444-4444-4444-8444-444444444444'
OTHER_NONCE = '55555555-5555-4555-8555-555555555555'
OTHER_SESSION = '66666666-6666-4666-8666-666666666666'
FILE = r'C:\controlled\ib'
EPOCH = datetime(1, 1, 1, tzinfo=timezone.utc)


def clock(value):
    stamp = datetime.fromisoformat(value)
    delta = stamp - EPOCH
    return dict(observed_utc_ms=delta.days * 86400000 + delta.seconds * 1000 + delta.microseconds // 1000,
                clock_epoch='0001-01-01T00:00:00Z', clock_precision='milliseconds',
                observed_utc_seconds=stamp.isoformat(timespec='seconds').replace('+00:00', 'Z'))


def documents():
    common = dict(schema=1, origin='controlled_real_background_job', nonce=NONCE, job_uuid=JOB)
    connection = f'File="{FILE}";'
    final = dict(job_uuid=JOB, job_state_code='completed', job_state='localized display ignored',
                 completed=True, job_key='shared-key-not-run-identity',
                 job_begin_platform_date='2026-11-16T08:55:36',
                 job_end_platform_date='2026-11-16T08:55:38', platform_date_precision='seconds',
                 **clock('2026-11-16T05:55:38.794+00:00'))
    controller = dict(common, connection_string=connection, status='completed', final_job_snapshot=final)
    enter = dict(common, stage='body_enter', session_id=2, session_info_number=2, connection_id=2,
                 connection_string=connection, job_begin_platform_date='2026-11-16T08:55:36',
                 platform_date_precision='seconds', **clock('2026-11-16T05:55:36.780+00:00'))
    leave = dict(common, stage='body_exit', session_id=2, connection_id=2, body_observed_elapsed_ms=2011,
                 **clock('2026-11-16T05:55:38.791+00:00'))
    return [dict(role=role, data=data, platform_utc_offset='+03:00',
                 evidence=dict(id=f's{i}:1', source=f's{i}', sha256=str(i) * 64, line=1))
            for i, (role, data) in enumerate((('controller', controller), ('worker_enter', enter), ('worker_exit', leave)), 1)]


def native(event, seconds, **properties):
    return dict(event=event, timestamp_utc=f'2026-11-16T05:55:{seconds}+00:00',
                duration_us=0, properties=dict(process='1cv8', OSThread='222', **properties))


def marker(stage, job=JOB, nonce=NONCE):
    return f'SELECT\n"SC01LIFECYCLE:{stage}:{nonce}:{job}"\n'


def located(rows):
    for index, row in enumerate(rows, 1):
        position = dict(line=index, end_line=index, byte_start=(index - 1) * 100, byte_end=index * 100)
        row.update(position)
        row['evidence'] = dict(id=f's4:{index}', source='s4', sha256='a' * 64, **position)
    return rows


def events():
    session = dict(Appl='BackgroundJob', IB=FILE, Nmb='2', ID=SESSION)
    rows = [native('SESN', '36.765000', Func='Start', **session),
            native('CALL', '36.770000'),
            native('SDBL', '36.781000', Sdbl=marker('body_enter')),
            native('CALL', '37.000000'),
            native('CALL', '37.500000'),
            native('SDBL', '38.781000', Sdbl=marker('body_exit')),
            native('SESN', '38.781040', Func='Attach', **session),
            native('SESN', '38.781050', Func='Finish', **session)]
    rows[4]['properties']['OSThread'] = 'other-thread'
    return located(rows)


class JobCorrelationTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.job_correlation'),
                             'The controlled lifecycle correlator is not implemented yet')
        self.correlate = importlib.import_module('src.techexpert.job_correlation').correlate_job

    def run_case(self, docs=None, rows=None, selection=None):
        return self.correlate(documents() if docs is None else docs,
                              events() if rows is None else rows,
                              dict(run=JOB) if selection is None else selection)

    def test_exact_chain_links_only_same_thread_between_markers(self):
        result = self.run_case()
        self.assertEqual(result['status'], 'established')
        link = result['native_link']
        self.assertEqual([x['id'] for x in link['linked_evidence']], ['s4:3', 's4:4', 's4:6'])
        self.assertEqual(link['linked_count'], 3)
        self.assertEqual(link['identity']['job_uuid'], JOB)
        self.assertEqual(link['identity']['session_number'], 2)
        self.assertEqual(link['identity']['session_uuid'], SESSION)
        for field in ('node', 'process_id', 'epoch'):
            self.assertIsNone(link['identity'][field])
        self.assertEqual(link['body']['observed_elapsed_ms'], 2011)
        self.assertAlmostEqual(link['session']['recorded_seconds'], 2.01605)

    def test_lifecycle_seconds_and_bounds_are_separate_from_session_and_body(self):
        life = self.run_case()['job_lifecycle']
        self.assertEqual(life['status'], 'established')
        self.assertEqual(life['state'], 'completed')
        self.assertEqual(life['execution_seconds'], 2)
        self.assertEqual(life['precision_seconds'], 1)
        self.assertEqual(life['execution_bounds_seconds'], [1, 3])
        self.assertIsNone(life['queue_seconds'])
        self.assertIsNone(life['total_seconds'])

    def test_nested_clock_observations_do_not_prove_synchronization(self):
        link = self.run_case()['native_link']
        self.assertEqual(link['clock_alignment']['status'], 'not_verified')
        self.assertTrue(link['clock_alignment']['containment_at_1ms_resolution'])

    def test_observed_run3_clock_disagreement_does_not_erase_exact_identity(self):
        # Synthetic identifiers; clock values reproduce the observed run3 ordering.
        docs, rows = documents(), events()
        docs[0]['data']['final_job_snapshot'].update(clock('2026-11-16T05:55:38.941+00:00'))
        docs[1]['data'].update(clock('2026-11-16T05:55:36.925+00:00'))
        docs[2]['data'].update(clock('2026-11-16T05:55:38.938+00:00'), body_observed_elapsed_ms=2013)
        for index,seconds in ((0,'36.921128'),(2,'36.936035'),(5,'38.952004'),(6,'38.952014'),(7,'38.952015')):
            rows[index]['timestamp_utc'] = f'2026-11-16T05:55:{seconds}+00:00'
        result = self.run_case(docs,rows)
        link = result['native_link']
        self.assertEqual(result['status'], 'established')
        self.assertEqual(result['job_lifecycle']['execution_seconds'], 2)
        self.assertEqual(link['clock_alignment']['status'], 'not_verified')
        self.assertFalse(link['clock_alignment']['containment_at_1ms_resolution'])
        self.assertAlmostEqual(link['clock_alignment']['marker_enter_minus_runtime_enter_ms'], 11.035)
        self.assertAlmostEqual(link['clock_alignment']['marker_exit_minus_runtime_exit_ms'], 14.004)
        self.assertEqual(link['body']['observed_elapsed_ms'], 2013)
        self.assertIn('cross_clock_order_disagreement', [item['code'] for item in link['limitations']])
        self.assertIn('synchronization_not_verified', link['body']['clock_basis'])

    def test_native_clock_shift_preserves_identity_but_never_verifies_alignment(self):
        rows = events()
        for row in rows:
            row['timestamp_utc'] = row['timestamp_utc'].replace('T05:', 'T06:')
        result = self.run_case(rows=rows)
        self.assertEqual(result['status'], 'established')
        self.assertFalse(result['native_link']['clock_alignment']['containment_at_1ms_resolution'])
        self.assertEqual(result['native_link']['clock_alignment']['status'], 'not_verified')
        self.assertEqual(result['job_lifecycle']['execution_seconds'], 2)

    def test_localized_state_and_completed_bool_do_not_choose_canonical_state(self):
        docs = documents()
        del docs[0]['data']['final_job_snapshot']['job_state_code']
        result = self.run_case(docs)
        self.assertEqual(result['job_lifecycle']['status'], 'not_established')
        self.assertIsNone(result['job_lifecycle']['execution_seconds'])
        self.assertEqual(result['native_link']['status'], 'established')

    def test_failed_lifecycle_can_be_known_without_exit_or_native_link(self):
        docs = documents()[:2]
        docs[0]['data']['final_job_snapshot']['job_state_code'] = 'failed'
        result = self.run_case(docs, [])
        self.assertEqual(result['job_lifecycle']['status'], 'established')
        self.assertEqual(result['job_lifecycle']['state'], 'failed')
        self.assertEqual(result['job_lifecycle']['execution_seconds'], 2)
        self.assertEqual(result['native_link']['status'], 'not_established')

    def test_active_has_no_execution_or_end_and_terminal_requires_end(self):
        for state in ('active', 'completed'):
            docs = documents()
            final = docs[0]['data']['final_job_snapshot']
            final['job_state_code'] = state
            del final['job_end_platform_date']
            result = self.run_case(docs)
            self.assertIsNone(result['job_lifecycle']['execution_seconds'])
            self.assertEqual(result['job_lifecycle']['status'], 'established' if state == 'active' else 'not_established')

    def test_reversed_platform_dates_or_active_with_end_are_conflicting(self):
        for changes in ({'job_end_platform_date':'2026-11-16T08:55:35'}, {'job_state_code':'active'}):
            docs = documents()
            docs[0]['data']['final_job_snapshot'].update(changes)
            self.assertEqual(self.run_case(docs)['job_lifecycle']['status'], 'conflicting')

    def test_offset_is_required_and_checked_against_utc_body(self):
        docs = documents()
        del docs[0]['platform_utc_offset']
        self.assertEqual(self.run_case(docs)['job_lifecycle']['status'], 'not_established')
        docs = documents()
        for doc in docs:
            doc['platform_utc_offset'] = '+02:00'
        self.assertEqual(self.run_case(docs)['job_lifecycle']['status'], 'conflicting')

    def test_observed_hostname_conflict_rejects_same_host_profile(self):
        docs = documents()
        docs[0]['data']['computer_name'] = 'HOST_A'
        docs[0]['data']['final_job_snapshot']['computer_name'] = 'HOST_A'
        docs[1]['data']['computer_name'] = 'HOST_B'
        docs[2]['data']['computer_name'] = 'HOST_B'
        result = self.run_case(docs)
        self.assertEqual(result['job_lifecycle']['status'], 'conflicting')
        self.assertEqual(result['native_link']['status'], 'conflicting')

    def test_unverified_native_process_is_not_promoted_by_file_connection(self):
        for process in ('rphost', '1cv8c'):
            rows = events()
            for row in rows:
                row['properties']['process'] = process
            with self.subTest(process=process):
                self.assertNotEqual(self.run_case(rows=rows)['status'], 'established')

    def test_duplicate_roles_or_different_runtime_identity_are_conflicting(self):
        scenarios = []
        docs = documents(); docs.append(copy.deepcopy(docs[0])); scenarios.append(docs)
        for field, value in (('job_uuid', OTHER_JOB), ('nonce', OTHER_NONCE),
                             ('session_info_number', 3), ('connection_string', 'File="C:\\other";')):
            docs = documents(); docs[1]['data'][field] = value; scenarios.append(docs)
        docs = documents(); docs[2]['data']['session_id'] = 3; scenarios.append(docs)
        for docs in scenarios:
            with self.subTest(docs=docs):
                self.assertEqual(self.run_case(docs)['status'], 'conflicting')

    def test_selection_run_is_actual_job_uuid_and_other_labels_are_not_evidence(self):
        self.assertNotEqual(self.run_case(selection=dict(run=OTHER_JOB))['status'], 'established')
        result = self.run_case(selection=dict(run=JOB, database='invented', node='invented', process='invented', epoch='invented'))
        self.assertEqual(result['status'], 'established')
        self.assertNotEqual(result['native_link']['identity']['database_file'], 'invented')
        self.assertIsNone(result['native_link']['identity']['node'])

    def test_duplicate_markers_are_conflicting_even_with_same_contents(self):
        rows = events(); rows.append(copy.deepcopy(rows[2]))
        self.assertEqual(self.run_case(rows=rows)['status'], 'conflicting')

    def test_marker_grammar_is_whole_sdbl_not_context_or_substring(self):
        for change in ('context', 'prefix', 'suffix', 'literal_backslash', 'wrong_nonce'):
            rows = events()
            props = rows[2]['properties']
            if change == 'context':
                props['Context'] = props.pop('Sdbl')
            elif change == 'prefix':
                props['Sdbl'] = 'noise' + props['Sdbl']
            elif change == 'suffix':
                props['Sdbl'] += 'noise'
            elif change == 'literal_backslash':
                props['Sdbl'] = props['Sdbl'].replace('\n', '\\n')
            else:
                props['Sdbl'] = marker('body_enter', nonce=OTHER_NONCE)
            with self.subTest(change=change):
                self.assertNotEqual(self.run_case(rows=rows)['status'], 'established')

    def test_exact_marker_query_accepts_crlf_line_endings(self):
        rows = events()
        for index in (2, 5):
            rows[index]['properties']['Sdbl'] = rows[index]['properties']['Sdbl'].replace('\n', '\r\n')
        self.assertEqual(self.run_case(rows=rows)['status'], 'established')

    def test_marker_source_hash_process_and_thread_must_match(self):
        for kind, field, value in (('evidence','source','s5'), ('evidence','sha256','b' * 64),
                                   ('properties','process','rphost'), ('properties','OSThread','333')):
            rows = events(); rows[5][kind][field] = value
            with self.subTest(field=field):
                self.assertEqual(self.run_case(rows=rows)['status'], 'conflicting')

    def test_session_database_number_uuid_and_appl_are_required(self):
        for field, value in (('IB', r'C:\other'), ('Nmb','3'), ('ID',OTHER_SESSION), ('Appl','1CV8')):
            rows = events(); rows[7]['properties'][field] = value
            with self.subTest(field=field):
                self.assertNotEqual(self.run_case(rows=rows)['status'], 'established')

    def test_session_number_reuse_or_overlapping_session_is_not_time_matched(self):
        for reuse in (True, False):
            rows = events()
            extra = native('SESN', '37.200000', Func='Start', Appl='BackgroundJob', IB=FILE,
                           Nmb='2' if reuse else '3', ID=OTHER_SESSION)
            rows.insert(4, extra)
            self.assertEqual(self.run_case(rows=located(rows))['status'], 'conflicting')

    def test_sequential_other_job_and_shared_job_key_do_not_poison_selected_run(self):
        rows = events()
        other = dict(Appl='BackgroundJob', IB=FILE, Nmb='3', ID=OTHER_SESSION)
        rows.extend([native('SESN','40.000000',Func='Start',**other),
                     native('SDBL','40.100000',Sdbl=marker('body_enter',OTHER_JOB,OTHER_NONCE)),
                     native('SDBL','41.100000',Sdbl=marker('body_exit',OTHER_JOB,OTHER_NONCE)),
                     native('SESN','41.200000',Func='Finish',**other)])
        self.assertEqual(self.run_case(rows=located(rows))['status'], 'established')

    def test_marker_time_outside_native_session_remains_conflicting(self):
        rows = events(); rows[5]['timestamp_utc'] = '2026-11-16T05:55:39.000000+00:00'
        self.assertEqual(self.run_case(rows=rows)['status'], 'conflicting')

    def test_out_of_range_utc_conversion_is_not_an_uncaught_exception(self):
        rows = events(); rows[2]['timestamp_utc'] = '0001-01-01T00:00:00+23:00'
        self.assertNotEqual(self.run_case(rows=rows)['status'], 'established')

    def test_record_session_conflict_inside_marker_window_invalidates_link(self):
        rows = events(); rows[3]['properties']['SessionID'] = '3'
        self.assertEqual(self.run_case(rows=rows)['status'], 'conflicting')

    def test_hash_conflict_same_source_is_not_ignored(self):
        rows = events(); rows[3]['evidence']['sha256'] = 'b' * 64
        self.assertEqual(self.run_case(rows=rows)['status'], 'conflicting')

    def test_ambiguous_marker_or_session_key_is_not_silently_picked(self):
        for index, key in ((2,'Sdbl'),(0,'Nmb'),(2,'OSThread')):
            rows = events(); value = rows[index]['properties'][key]
            rows[index]['properties'][key] = [value, value]
            with self.subTest(index=index,key=key):
                self.assertNotEqual(self.run_case(rows=rows)['status'], 'established')

    def test_removed_ambiguous_ownership_property_is_not_treated_as_absent(self):
        for key, values in (('SessionID',['2','3']), ('IB',[FILE,r'C:\other']),
                            ('process',['1cv8','rphost']), ('OSThread',['222','333'])):
            rows = events()
            rows[3]['properties'].pop(key, None)
            rows[3]['ambiguous_properties'] = {key: values}
            with self.subTest(key=key):
                self.assertEqual(self.run_case(rows=rows)['status'], 'conflicting')

    def test_competing_session_with_ambiguous_thread_cannot_disappear(self):
        rows = events()
        other = native('SESN','37.200000',Func='Start',Appl='BackgroundJob',IB=FILE,Nmb='3',ID=OTHER_SESSION)
        del other['properties']['OSThread']
        other['ambiguous_properties'] = {'OSThread':['222','333']}
        rows.insert(4,other)
        self.assertEqual(self.run_case(rows=located(rows))['status'], 'conflicting')

    def test_session_with_missing_context_inside_window_cannot_disappear(self):
        for key in ('process','OSThread'):
            rows = events()
            other = native('SESN','37.200000',Func='Start',Appl='BackgroundJob',IB=FILE,Nmb='3',ID=OTHER_SESSION)
            del other['properties'][key]
            rows.insert(4,other)
            with self.subTest(key=key):
                self.assertNotEqual(self.run_case(rows=located(rows))['status'], 'established')

    def test_malformed_session_attach_uuid_and_boolean_schema_do_not_crash_or_establish(self):
        rows = events(); rows[6]['properties']['ID'] = []
        self.assertNotEqual(self.run_case(rows=rows)['status'], 'established')
        docs = documents(); docs[0]['data']['schema'] = True
        self.assertNotEqual(self.run_case(docs)['status'], 'established')

    def test_shared_predicate_matches_all_bounded_records_beyond_preview(self):
        helper = importlib.import_module('src.techexpert.job_correlation').record_matches_link
        rows = events(); rows[3:4] = [native('CALL','37.000000') for _ in range(250)]
        rows = located(rows)
        link = self.run_case(rows=rows)['native_link']
        self.assertEqual(sum(helper(row,link) for row in rows), 252)
        for change in ('source', 'sha256', 'position', 'SessionID', 'ambiguous'):
            row = copy.deepcopy(rows[3])
            if change in ('source','sha256'):
                row['evidence'][change] = 's9' if change == 'source' else 'b' * 64
            elif change == 'position':
                row['byte_start'] = 0
                row['evidence']['byte_start'] = 0
            elif change == 'SessionID':
                row['properties']['SessionID'] = '3'
            else:
                row['ambiguous_properties'] = {'SessionID':['2','3']}
            with self.subTest(change=change):
                self.assertFalse(helper(row,link))
        self.assertFalse(helper(rows[3],dict(link,status='not_established')))

    def test_bad_evidence_or_missing_runtime_clock_cannot_establish(self):
        docs = documents(); docs[1]['evidence']['sha256'] = 'not a hash'
        self.assertNotEqual(self.run_case(docs)['status'], 'established')
        docs = documents(); del docs[1]['data']['clock_epoch']
        self.assertNotEqual(self.run_case(docs)['status'], 'established')

    def test_link_output_is_bounded_and_inputs_are_not_mutated(self):
        rows = events()
        rows[3:4] = [native('CALL','37.000000') for _ in range(250)]
        rows = located(rows)
        docs = documents(); before = copy.deepcopy((docs, rows))
        result = self.run_case(docs, rows)
        self.assertEqual((docs, rows), before)
        link = result['native_link']
        self.assertEqual(link['status'], 'established')
        self.assertEqual(link['linked_count'], 252)
        self.assertEqual(len(link['linked_evidence']), 200)
        self.assertTrue(link['linked_evidence_truncated'])

    def test_input_work_limits_are_explicit(self):
        with self.assertRaises(ValueError):
            self.run_case(docs=documents() * 11)
        with self.assertRaises(ValueError):
            self.run_case(rows=[{}] * 100001)


if __name__ == '__main__':
    unittest.main()
