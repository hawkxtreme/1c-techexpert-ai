"""Public, sanitized excerpts from two controlled platform background jobs."""
import copy
import hashlib
import json
import unittest
from pathlib import Path

from src.techexpert.inputs import load_manifest
from src.techexpert.job_correlation import correlate_job
from src.techexpert.native_tj import parse_tj, validate_profile


FIXTURES = Path(__file__).parent / 'fixtures' / 'job-lifecycle'
PUBLIC_BASE = r'C:\controlled\sc01-ib'
COMPLETED = 'c5f11c18-514d-449a-b3d8-7ba5d23c3b39'
FAILED = 'a1982c27-3c0b-4311-ac53-254753e9239a'
COMPLETED_NONCE = '54a79e26-cfed-4aae-8d24-20cac3a50d59'
FAILED_NONCE = '5f21a00a-0283-41c3-9eb8-f03afcd75ffa'
SHARED_KEY = 'SC01LIFECYCLE:3bdc62ce-94b7-4d4c-b0e1-f5c595aa7413'
SOURCE_HASH = '57cc91c77c7073a13f3c1cd03dcaffa23e2705113b5bdd3927a7e37d68dbeddf'
NATIVE_HASH = '4faad2503dca1eebe3af03855aabf26666b5ae749134989128bb0afad5dc3c13'
SOURCE_RANGES = [
    (608, 839, 839, 132879, 133096),
    (654, 969, 973, 146688, 147174),
    (655, 974, 976, 147174, 147557),
    (656, 977, 980, 147557, 148054),
    (657, 981, 985, 148054, 148538),
    (664, 994, 994, 149793, 150017),
    (671, 1021, 1021, 155163, 155380),
    (681, 1042, 1046, 158400, 158886),
    (688, 1067, 1067, 161353, 161577),
]


def read_json(name):
    return json.loads((FIXTURES / name).read_text(encoding='utf-8'))


def digest(value):
    return hashlib.sha256(value).hexdigest()


def correlate(bundle):
    return correlate_job(bundle['lifecycle_documents'], bundle['native_events'],
                         bundle['manifest']['selection'])


class JobFixtureTests(unittest.TestCase):
    def test_passport_labels_sanitization_and_hashes_every_published_input(self):
        passport = read_json('passport.json')
        self.assertEqual(passport['provenance'], 'sanitized_real_capture')
        self.assertIs(passport['byte_identical_to_original'], False)
        self.assertTrue(passport['capture']['not_a_reproduction_of_45_minute_incident'])
        names = {p.name for p in FIXTURES.iterdir() if p.is_file()}
        self.assertEqual(set(passport['files']), names - {'passport.json'})
        for name, expected in passport['files'].items():
            with self.subTest(file=name):
                raw = (FIXTURES / name).read_bytes()
                self.assertEqual(len(raw), expected['bytes'])
                self.assertEqual(digest(raw), expected['sha256'])
        source = passport['native_excerpt']['source']
        self.assertEqual((source['sha256'], source['bytes']), (SOURCE_HASH, 190355))
        self.assertEqual(source['parsed_records'], 805)
        self.assertEqual(source['parse_status'], 'partial')
        self.assertEqual([x['code'] for x in source['limitations']], ['ambiguous_property'])
        self.assertEqual(passport['files']['native.txt']['sha256'], NATIVE_HASH)
        self.assertEqual(len(passport['runtime_documents']), 5)
        for document in passport['runtime_documents']:
            source = document['source']
            self.assertRegex(source['sha256'], r'^[0-9a-f]{64}$')
            self.assertEqual((source['byte_start'], source['byte_end']), (0, source['bytes']))
            self.assertTrue(document['transformations'])

    def test_native_ranges_preserve_complete_contiguous_body_excerpt(self):
        passport = read_json('passport.json')['native_excerpt']
        raw = (FIXTURES / 'native.txt').read_bytes()
        spec = read_json('completed.json')['sources'][0]
        parsed = parse_tj(raw, validate_profile(spec, FIXTURES / 'native.txt'))
        self.assertEqual(parsed['status'], 'parsed')
        self.assertEqual(parsed['limitations'], [])
        self.assertEqual(len(parsed['records']), 9)
        self.assertEqual(len(passport['records']), 9)
        for mapping, record, expected in zip(passport['records'], parsed['records'], SOURCE_RANGES):
            with self.subTest(source_record=expected[0]):
                source = mapping['source']
                self.assertEqual((mapping['source_record_index_0'], source['line'],
                                  source['end_line'], source['byte_start'], source['byte_end']), expected)
                published = mapping['published']
                for field in ('line', 'end_line', 'byte_start', 'byte_end'):
                    self.assertEqual(published[field], record[field])
                self.assertEqual(digest(raw[record['byte_start']:record['byte_end']]), published['sha256'])
                self.assertIsNone(record['start_timestamp_utc'])
        window = passport['contiguous_completed_body_window']
        self.assertEqual(window['source_record_indices_0'], [654, 655, 656, 657])
        self.assertEqual(window['published_record_indices_0'], [1, 2, 3, 4])
        for left, right in zip(passport['records'][1:4], passport['records'][2:5]):
            self.assertEqual(left['source']['byte_end'], right['source']['byte_start'])
            self.assertEqual(left['published']['byte_end'], right['published']['byte_start'])
        sessions = [r['properties'] for r in parsed['records'] if r['event'] == 'SESN']
        self.assertEqual([(p['Nmb'], p['Func']) for p in sessions],
                         [('2', 'Start'), ('2', 'Finish'), ('3', 'Start'), ('3', 'Finish')])
        self.assertEqual({p['IB'] for p in sessions}, {PUBLIC_BASE})

    def test_manifests_use_only_observed_run_selection_and_relative_paths(self):
        for case, job, roles in [('completed', COMPLETED, ['controller', 'worker_enter', 'worker_exit']),
                                 ('failed', FAILED, ['controller', 'worker_enter'])]:
            with self.subTest(case=case):
                manifest = read_json(case + '.json')
                self.assertEqual(manifest['selection'], {'run': job})
                self.assertEqual(manifest['origin'], 'provided')
                self.assertEqual(manifest['correlation_profile'], '1c-file-job-markers-v1')
                self.assertEqual([s['role'] for s in manifest['sources'][1:]], roles)
                for source in manifest['sources']:
                    path = Path(source['path'])
                    self.assertFalse(path.is_absolute())
                    self.assertEqual(path.name, source['path'])
                    self.assertTrue((FIXTURES / path).is_file())
                    self.assertEqual(source['platform_version'], '8.3.27.1989')
                native = manifest['sources'][0]
                self.assertEqual((native['encoding'], native['placement'], native['timestamp_format'],
                                  native['utc_offset']), ('utf-8', 'plain', 'iso', '+03:00'))
                bundle = load_manifest(FIXTURES / (case + '.json'))
                self.assertEqual(bundle['limitations'], [])
                self.assertEqual(len(bundle['native_events']), 9)
                self.assertEqual(len(bundle['lifecycle_documents']), len(roles))

    def test_original_run_identity_state_and_missing_failed_exit_are_preserved(self):
        for case, job, nonce, session in [('completed', COMPLETED, COMPLETED_NONCE, 2),
                                          ('failed', FAILED, FAILED_NONCE, 3)]:
            controller = read_json(case + '-controller.json')
            enter = read_json(case + '-worker-enter.json')
            final = controller['final_job_snapshot']
            self.assertEqual((controller['schema'], controller['origin']),
                             (1, 'controlled_real_background_job'))
            self.assertEqual((controller['job_uuid'], enter['job_uuid'], final['job_uuid']), (job,) * 3)
            self.assertEqual((controller['nonce'], enter['nonce']), (nonce, nonce))
            self.assertEqual((controller['requested_job_key'], enter['job_key'], final['job_key']),
                             (SHARED_KEY,) * 3)
            self.assertEqual(final['job_state_code'], case)
            self.assertEqual((enter['session_id'], enter['session_info_number']), (session, session))
            self.assertEqual(enter['connection_id'], 2)
            self.assertEqual(enter['connection_string'], 'File="' + PUBLIC_BASE + '";')
        self.assertFalse((FIXTURES / 'failed-worker-exit.json').exists())
        native = (FIXTURES / 'native.txt').read_text(encoding='utf-8')
        self.assertNotIn('SC01LIFECYCLE:body_exit:' + FAILED_NONCE, native)

    def test_completed_job_links_only_four_body_records_with_independent_times(self):
        result = correlate(load_manifest(FIXTURES / 'completed.json'))
        lifecycle, link = result['job_lifecycle'], result['native_link']
        self.assertEqual((lifecycle['status'], lifecycle['state']), ('established', 'completed'))
        self.assertEqual(lifecycle['execution_seconds'], 2)
        self.assertEqual(lifecycle['precision_seconds'], 1)
        self.assertEqual(lifecycle['execution_bounds_seconds'], [1, 3])
        self.assertIsNone(lifecycle['queue_seconds'])
        self.assertIsNone(lifecycle['total_seconds'])
        self.assertEqual(link['status'], 'established')
        self.assertEqual(link['identity']['job_uuid'], COMPLETED)
        self.assertEqual(link['identity']['session_number'], 2)
        self.assertEqual(link['identity']['session_uuid'], '11c14f70-203c-4ec7-ab99-c2f116bb0240')
        self.assertEqual(link['body']['observed_elapsed_ms'], 2008)
        self.assertAlmostEqual(link['session']['recorded_seconds'], 2.015984, places=6)
        self.assertEqual(link['linked_count'], 4)
        self.assertEqual([x['id'] for x in link['linked_evidence']], ['s1:2', 's1:7', 's1:10', 's1:14'])
        for field in ('node', 'process_id', 'epoch'):
            self.assertIsNone(link['identity'][field])

    def test_failed_state_is_known_while_missing_body_exit_prevents_native_link(self):
        result = correlate(load_manifest(FIXTURES / 'failed.json'))
        lifecycle, link = result['job_lifecycle'], result['native_link']
        self.assertEqual((lifecycle['status'], lifecycle['state']), ('established', 'failed'))
        self.assertEqual(lifecycle['job_uuid'], FAILED)
        self.assertEqual(lifecycle['execution_seconds'], 2)
        self.assertIsNone(lifecycle['queue_seconds'])
        self.assertIsNone(lifecycle['total_seconds'])
        self.assertEqual(link['status'], 'not_established')
        self.assertEqual(link['linked_evidence'], [])
        self.assertIn('missing_worker_body_boundary', [x['code'] for x in link['limitations']])

    def test_same_key_does_not_allow_worker_from_the_other_real_job(self):
        completed = load_manifest(FIXTURES / 'completed.json')
        failed = load_manifest(FIXTURES / 'failed.json')
        mixed = copy.deepcopy(completed)
        wrong_enter = next(d for d in failed['lifecycle_documents'] if d['role'] == 'worker_enter')
        mixed['lifecycle_documents'] = [wrong_enter if d['role'] == 'worker_enter' else d
                                         for d in mixed['lifecycle_documents']]
        result = correlate(mixed)
        self.assertEqual(result['native_link']['status'], 'conflicting')
        self.assertEqual(result['job_lifecycle']['status'], 'conflicting')
        self.assertIn('runtime_job_identity_conflict',
                      [x['code'] for x in result['native_link']['limitations']])

    def test_fixture_contains_only_the_public_path_and_host_alias(self):
        def check_names(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == 'computer_name':
                        self.assertEqual(item, 'controlled-host')
                    check_names(item)
            elif isinstance(value, list):
                for item in value:
                    check_names(item)

        for path in FIXTURES.iterdir():
            if not path.is_file():
                continue
            with self.subTest(file=path.name):
                text = path.read_bytes().decode('utf-8')
                decoded_slashes = text.replace('\\\\', '\\').replace(PUBLIC_BASE, '')
                self.assertNotRegex(decoded_slashes, r'(?<![A-Za-z0-9_])[A-Za-z]:[\\/]')
                self.assertNotRegex(decoded_slashes, r'(?i)([\\/]Users[\\/]|\.local[\\/]|file://)')
                if path.suffix == '.json':
                    check_names(json.loads(text))


if __name__ == '__main__':
    unittest.main()
