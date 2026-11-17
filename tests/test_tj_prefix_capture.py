"""Controlled append/mutation fixtures, not live-platform compatibility proof."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert.inputs import InputError, SnapshotReadError, load_manifest
from src.techexpert import storage, source_coverage

ROW = '04:05.123456-7,NEW_EVENT,0,Context="Начало,\r\nконец"\r\n'.encode()
PROFILE = dict(format='1c-tj-text-v1', platform_version='8.3.27.1989', encoding='utf-8', placement='folders',
               timestamp_format='minute', file_hour='2026-11-16T09:00:00+03:00', rotation_hours=1)


class ChangingReader:
    def __init__(self, stream, action, when='read'):
        self.stream = stream
        self.action = action
        self.when = when
        self.done = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stream.close()

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def read(self, count):
        data = self.stream.read(count)
        if self.when == 'read' and not self.done:
            self.done = True
            self.action()
        return data

    def seek(self, *args):
        result = self.stream.seek(*args)
        if self.when == 'seek' and not self.done:
            self.done = True
            self.action()
        return result


class TJPrefixCaptureTests(unittest.TestCase):
    def setUp(self):
        self.api = importlib.import_module('src.techexpert.tj_capture')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / '26111609.log'
        self.log.write_bytes(ROW)

    def changing(self, action, when='read'):
        original = self.api._open
        return patch.object(self.api, '_open', side_effect=lambda path: ChangingReader(original(path), action, when))

    def test_append_is_excluded_from_fixed_prefix_and_next_capture_reads_it(self):
        def append():
            with self.log.open('ab') as stream:
                stream.write(ROW)
        with self.changing(append):
            data, acquisition = self.api.read_prefix(self.log)
        self.assertEqual(data, ROW)
        self.assertEqual(acquisition['method'], 'tj-prefix-v1')
        self.assertEqual(acquisition['byte_start'], 0)
        self.assertEqual(acquisition['byte_end'], len(ROW))
        self.assertEqual(acquisition['sha256'], hashlib.sha256(ROW).hexdigest())
        self.assertEqual(acquisition['excluded_appended_bytes'], len(ROW))
        self.assertTrue(acquisition['append_observed'])
        self.assertFalse(acquisition['atomic_snapshot'])
        self.assertEqual(acquisition['framing']['terminated_prefix_bytes'], len(ROW))
        second, later = self.api.read_prefix(self.log)
        self.assertEqual(second, ROW * 2)
        self.assertNotEqual(later['snapshot_id'], acquisition['snapshot_id'])

    def test_open_does_not_prefetch_beyond_the_requested_fixed_prefix(self):
        with self.api._open(self.log) as stream:
            self.assertEqual(stream.read(1), ROW[:1])
            self.assertEqual(os.lseek(stream.fileno(), 0, os.SEEK_CUR), 1)

    def test_unchanged_prefix_has_same_snapshot_id_but_distinct_capture_interval(self):
        first, one = self.api.read_prefix(self.log)
        second, two = self.api.read_prefix(self.log)
        self.assertEqual(first, second)
        self.assertEqual(one['snapshot_id'], two['snapshot_id'])
        self.assertIn('started_at', one)
        self.assertIn('finished_at', one)
        self.assertEqual(one['file_identity'], two['file_identity'])
        self.assertTrue(all(isinstance(value, str) for value in one['file_identity'].values()))

    def test_equal_text_from_different_real_files_has_distinct_snapshot_identity(self):
        other = self.root / 'other.log'
        other.write_bytes(ROW)
        _, one = self.api.read_prefix(self.log)
        _, two = self.api.read_prefix(other)
        self.assertEqual(one['sha256'], two['sha256'])
        self.assertNotEqual(one['snapshot_id'], two['snapshot_id'])

    def test_reads_are_chunk_bounded_and_do_not_chase_an_active_appender(self):
        initial = ROW * 2000
        self.log.write_bytes(initial)
        sizes = []
        original = self.api._open
        class Appending(ChangingReader):
            def read(reader, count):
                sizes.append(count)
                with self.log.open('ab') as writer:
                    writer.write(ROW)
                return reader.stream.read(count)
        with patch.object(self.api, '_open', side_effect=lambda path: Appending(original(path), lambda: None)):
            data, acquired = self.api.read_prefix(self.log)
        self.assertEqual(data, initial)
        self.assertTrue(sizes and max(sizes) <= 65536)
        self.assertEqual(acquired['byte_end'], len(initial))
        self.assertGreater(acquired['excluded_appended_bytes'], 0)

    @unittest.skipIf(os.name == 'nt', 'POSIX FIFO fixture')
    def test_fifo_is_rejected_before_a_blocking_open(self):
        fifo = self.root / 'named-pipe.log'
        os.mkfifo(fifo)
        with patch.object(self.api, '_open', side_effect=AssertionError('FIFO opened')):
            with self.assertRaises(InputError):
                self.api.read_prefix(fifo)

    def test_quoted_multiline_and_partial_utf8_tail_are_retained_with_exact_bounds(self):
        tail = b'04:06.000000-0,NEW_EVENT,0,Context="' + 'Недописано\nещё'.encode()[:-1]
        self.log.write_bytes(b'\xef\xbb\xbf' + ROW + tail)
        data, acquisition = self.api.read_prefix(self.log)
        frame = acquisition['framing']
        self.assertEqual(data, self.log.read_bytes())
        self.assertEqual(frame['terminated_prefix_bytes'], 3 + len(ROW))
        self.assertEqual(frame['incomplete_tail'], dict(byte_start=3 + len(ROW), byte_end=len(data), bytes=len(tail),
            sha256=hashlib.sha256(tail).hexdigest(), open_quote=True))
        self.assertTrue(frame['complete_scan'])

    def test_empty_and_bom_only_prefix_are_distinct_bounded_snapshots(self):
        for raw in (b'', b'\xef\xbb\xbf'):
            with self.subTest(raw=raw):
                self.log.write_bytes(raw)
                data, acquisition = self.api.read_prefix(self.log)
                self.assertEqual(data, raw)
                self.assertEqual(acquisition['framing']['terminated_prefix_bytes'], len(raw))
                self.assertIsNone(acquisition['framing']['incomplete_tail'])

    def test_same_size_prefix_rewrite_between_passes_is_refused_without_retry(self):
        replacement = b'X' * len(ROW)
        with self.changing(lambda: self.log.write_bytes(replacement), 'seek') as opened:
            with self.assertRaises(SnapshotReadError) as failure:
                self.api.read_prefix(self.log)
        self.assertEqual(failure.exception.code, 'prefix_changed')
        self.assertEqual(opened.call_count, 1)

    def test_observed_truncation_is_refused(self):
        with self.changing(lambda: self.log.write_bytes(b'')):
            with self.assertRaises(SnapshotReadError) as failure:
                self.api.read_prefix(self.log)
        self.assertEqual(failure.exception.code, 'source_truncated')

    def test_replaced_path_does_not_promote_old_handle_bytes(self):
        def replace():
            replacement = self.root / 'replacement.log'
            replacement.write_bytes(ROW)
            if os.name == 'nt':
                from src.techexpert.windows_native import replace_shared_metadata
                replace_shared_metadata(replacement, self.log)
            else:
                os.replace(replacement, self.log)
        with self.changing(replace):
            with self.assertRaises(SnapshotReadError) as failure:
                self.api.read_prefix(self.log)
        self.assertEqual(failure.exception.code, 'source_replaced')

    def test_links_and_nonregular_paths_are_refused(self):
        with self.assertRaises(InputError):
            self.api.read_prefix(self.root)
        link = self.root / 'linked.log'
        try:
            link.symlink_to(self.log)
        except OSError:
            self.skipTest('symlink privilege unavailable')
        with self.assertRaises(InputError):
            self.api.read_prefix(link)

    def test_read_and_framing_budgets_are_enforced_without_suffix_claim(self):
        with self.assertRaises(SnapshotReadError) as failure:
            self.api.read_prefix(self.log, max_bytes=len(ROW) - 1)
        self.assertEqual(failure.exception.code, 'byte_limit')
        self.log.write_bytes(ROW * 3)
        _, acquisition = self.api.read_prefix(self.log, max_records=1)
        frame = acquisition['framing']
        self.assertFalse(frame['complete_scan'])
        self.assertEqual(frame['terminated_prefix_bytes'], len(ROW))
        self.assertIsNone(frame['incomplete_tail'])
        self.assertEqual(frame['unframed_bytes'], len(ROW) * 2)


class TJPrefixManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / '26111609.log'
        self.log.write_bytes(ROW + b'04:06.000000-0,NEW_EVENT,0,Context="partial')

    def manifest(self, sources=None):
        path = self.root / 'case.json'
        path.write_text(json.dumps(dict(schema=1, scenario='SC-01', origin='provided',
            selection=dict(database='reported', node='reported', process='reported', epoch='reported', run='reported'),
            sources=sources if sources is not None else [dict(PROFILE, path=str(self.log), read_mode='tj-prefix-v1')])), encoding='utf-8')
        return path

    def test_explicit_prefix_mode_retains_raw_tail_and_only_complete_events(self):
        result = storage.investigate(self.manifest(), self.root / 'state')
        source = result['sources'][0]
        self.assertEqual(source['acquisition']['method'], 'tj-prefix-v1')
        self.assertEqual(source['parsed_event_count'], 1)
        self.assertEqual(source['acquisition']['framing']['terminated_prefix_bytes'], len(ROW))
        retained = storage.case_folder(self.root / 'state', result['case_id']) / 'sources/s1.bin'
        self.assertEqual(retained.read_bytes(), self.log.read_bytes())
        self.assertEqual(result['durations_seconds'], dict(queue=None, execution=None, total=None))
        self.assertEqual(result['cause_state'], 'insufficient_data')
        self.assertFalse(source['acquisition']['atomic_snapshot'])

    def test_prefix_mode_is_exposed_by_explicit_check_and_saved_case_coverage(self):
        manifest = self.manifest()
        checked = source_coverage.inspect_manifest(manifest)
        self.assertEqual(checked['sources'][0]['acquisition']['method'], 'tj-prefix-v1')
        self.assertFalse((self.root / 'state').exists())
        result = storage.investigate(manifest, self.root / 'state')
        self.log.unlink()
        saved = source_coverage.inspect_case(self.root / 'state', result['case_id'])
        self.assertEqual(saved['sources'][0]['acquisition'], result['sources'][0]['acquisition'])
        self.assertFalse(saved['can_establish_absence'])
        self.assertEqual(saved['sources'][0]['continuity'], 'unknown')

    def test_read_mode_is_native_only_and_rejects_unknown_values_before_source_open(self):
        variants = [dict(PROFILE, path='missing.log', read_mode='tail'),
                    dict(path='missing.jsonl', format='normalized-events-v1', read_mode='tj-prefix-v1'),
                    dict(PROFILE, path='missing.log', read_mode=[]) ]
        for source in variants:
            with self.subTest(source=source), self.assertRaisesRegex(InputError, 'read.mode|read mode'):
                load_manifest(self.manifest([source]))

    def test_same_path_with_different_read_modes_is_not_silently_deduplicated(self):
        sources = [dict(PROFILE, path=str(self.log)), dict(PROFILE, path=str(self.log), read_mode='tj-prefix-v1')]
        with self.assertRaisesRegex(InputError, 'conflicting'):
            load_manifest(self.manifest(sources))

    def test_equal_text_events_are_not_deduplicated_by_payload_or_snapshot_hash(self):
        other = self.root / 'other.log'
        other.write_bytes(ROW)
        self.log.write_bytes(ROW * 2)
        sources = [dict(PROFILE, path=str(path), read_mode='tj-prefix-v1') for path in (self.log, other)]
        result = storage.investigate(self.manifest(sources), self.root / 'state')
        self.assertEqual(result['native_observations']['event_count'], 3)
        self.assertEqual([source['parsed_event_count'] for source in result['sources']], [2, 1])

    def test_source_failure_does_not_hide_independent_stable_source(self):
        api = importlib.import_module('src.techexpert.tj_capture')
        second = self.root / 'other.log'
        second.write_bytes(ROW)
        sources = [dict(PROFILE, path=str(self.log), read_mode='tj-prefix-v1'), dict(PROFILE, path=str(second))]
        with patch.object(api, 'read_prefix', side_effect=SnapshotReadError('changed prefix', 'prefix_changed')):
            result = storage.investigate(self.manifest(sources), self.root / 'state')
        self.assertEqual(result['source_acquisition'][0]['availability'], 'prefix_changed')
        self.assertEqual([s['id'] for s in result['sources']], ['s2'])
        self.assertEqual(result['native_observations']['event_count'], 1)


if __name__ == '__main__':
    unittest.main()
