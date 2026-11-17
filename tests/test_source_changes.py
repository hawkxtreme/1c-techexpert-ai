"""Compare retained sources without requiring a completed job or reading originals."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from src.techexpert import artifacts, storage, input_intake
from src.techexpert.inputs import InputError
from test_tj_prefix_capture import PROFILE, ROW

DOMAIN = dict(status='observed', profile='local-reader-domain-v1',
              platform='windows' if os.name == 'nt' else 'linux', id='a' * 64)
TAIL = '04:06.000000-0,NEW_EVENT,0,Context="неполный'.encode()


class SourceChangeTests(unittest.TestCase):
    def setUp(self):
        self.api = importlib.import_module('src.techexpert.source_changes')
        self.reader = importlib.import_module('src.techexpert.reader_scope')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'state'
        self.log = self.root / 'original.log'
        self.counter = 0

    def manifest(self, source, **context):
        self.counter += 1
        path = self.root / ('case-' + str(self.counter) + '.json')
        document = dict(schema=1, scenario='SC-01', origin='provided',
            selection={key: 'reported' for key in ('database', 'node', 'process', 'epoch', 'run')}, sources=[source])
        document.update(context)
        path.write_text(json.dumps(document), encoding='utf-8')
        return path

    def case(self, raw=ROW, *, path=None, domain=DOMAIN, prefix=True, **profile):
        path = self.log if path is None else path
        if raw is not None:
            path.write_bytes(raw)
        source = dict(PROFILE, path=str(path), **profile)
        if prefix:
            source['read_mode'] = 'tj-prefix-v1'
        with patch.object(self.reader, 'observe', return_value=domain):
            result = storage.investigate(self.manifest(source), self.state)
        return dict(kind='case', id=result['case_id'], source_id='s1')

    def value(self, before, after):
        return self.api.compare(self.state, before, after)

    def change_report(self, ref, change):
        folder = storage.case_folder(self.state, ref['id'])
        report = storage.load_case(self.state, ref['id'])
        change(report)
        storage.write_json(folder / 'report.json', report)
        receipt = json.loads((folder / 'receipt.json').read_text())
        receipt['report_sha256'] = hashlib.sha256((folder / 'report.json').read_bytes()).hexdigest()
        storage.write_json(folder / 'receipt.json', receipt)

    def test_same_retained_source_is_duplicate_material_without_merging_events(self):
        ref = self.case(ROW * 2)
        self.log.unlink()
        value = self.value(ref, ref)
        self.assertEqual(value['observation']['relation'], 'same_retained_source')
        self.assertEqual(value['byte_relation'], 'identical')
        self.assertTrue(value['input_duplicate']['duplicate'])
        self.assertEqual(value['counts']['unique_input_bytes_after'], 0)
        self.assertFalse(value['counts']['events_deduplicated'])
        self.assertIsNone(value['suggested_after_range'])
        self.assertEqual(len(value['dependencies']), 1)

    def test_prefix_extension_reopens_an_old_incomplete_frame_without_rewriting_cases(self):
        old_bytes = ROW + TAIL
        before = self.case(old_bytes)
        old_folder = storage.case_folder(self.state, before['id'])
        old_files = {str(p): p.read_bytes() for p in old_folder.rglob('*') if p.is_file()}
        suffix = ' завершён"\r\n'.encode() + ROW
        after = self.case(old_bytes + suffix)
        self.log.unlink()
        value = self.value(before, after)
        self.assertEqual(value['observation']['relation'], 'prefix_extended')
        self.assertEqual(value['byte_relation'], 'extended_prefix')
        self.assertEqual(value['common_prefix_bytes'], len(old_bytes))
        self.assertEqual(value['suggested_after_range']['byte_start'], len(ROW))
        self.assertEqual(value['framing']['tail_transition']['status'], 'frame_completed')
        self.assertIsNone(value['framing']['tail_transition']['valid_event'])
        self.assertFalse(value['counts']['events_deduplicated'])
        self.assertEqual(old_files, {str(p): p.read_bytes() for p in old_folder.rglob('*') if p.is_file()})
        self.assertIsNone(storage.load_case(self.state, after['id'])['durations_seconds']['execution'])

    def test_still_incomplete_tail_is_not_promoted_to_an_event(self):
        before = self.case(ROW + TAIL)
        after = self.case(ROW + TAIL + b' more')
        value = self.value(before, after)
        self.assertEqual(value['framing']['tail_transition']['status'], 'still_incomplete')
        self.assertEqual(value['suggested_after_range']['byte_start'], len(ROW))
        self.assertIsNone(value['framing']['tail_transition']['valid_event'])

    def test_plain_extension_starts_at_the_previous_complete_prefix(self):
        before = self.case(ROW)
        after = self.case(ROW * 2)
        value = self.value(before, after)
        self.assertEqual(value['suggested_after_range']['byte_start'], len(ROW))
        self.assertEqual(value['suggested_after_range']['byte_end'], len(ROW) * 2)

    def test_shortening_and_rewrite_are_distinct_observations(self):
        before = self.case(ROW * 2)
        after = self.case(ROW)
        value = self.value(before, after)
        self.assertEqual(value['observation']['relation'], 'prefix_shortened')
        self.assertEqual(value['byte_relation'], 'shortened_prefix')
        changed = self.case(ROW.replace(b'NEW_EVENT', b'OTHER_EVT'))
        value = self.value(after, changed)
        self.assertEqual(value['observation']['relation'], 'prefix_rewritten')
        self.assertEqual(value['suggested_after_range']['byte_start'], 0)
        self.assertEqual(value['observation']['lifetime_continuity'], 'not_proven')

    def test_same_path_with_a_different_observed_file_is_replacement_not_proven_rotation(self):
        before = self.case()
        replacement = self.root / 'replacement.log'
        replacement.write_bytes(ROW)
        os.replace(replacement, self.log)
        after = self.case(None)
        value = self.value(before, after)
        self.assertEqual(value['observation']['relation'], 'path_replaced')
        self.assertFalse(value['observation']['rotation_proven'])
        self.assertIsNone(value['input_duplicate']['duplicate'])
        self.assertEqual(value['suggested_after_range']['byte_start'], 0)

    def test_equal_text_in_distinct_files_is_not_collapsed(self):
        before = self.case(ROW * 2)
        after = self.case(ROW * 2, path=self.root / 'another.log')
        value = self.value(before, after)
        self.assertEqual(value['byte_relation'], 'identical')
        self.assertEqual(value['observation']['relation'], 'distinct_observed_files')
        self.assertIsNone(value['input_duplicate']['duplicate'])
        self.assertIsNone(value['counts']['unique_input_bytes_after'])
        self.assertEqual(value['suggested_after_range'], dict(byte_start=0, byte_end=len(ROW) * 2, basis='full_current_source'))
        self.assertFalse(value['counts']['events_deduplicated'])

    def test_windows_case_different_names_do_not_imply_replacement(self):
        scope = dict(DOMAIN, platform='windows')
        before = self.case(domain=scope)
        after = self.case(path=self.root / 'other.log', domain=scope)
        self.change_report(before, lambda doc: doc['sources'][0].update(path='C:/Logs/One.log'))
        self.change_report(after, lambda doc: doc['sources'][0].update(path='C:/Logs/one.log'))
        self.assertEqual(self.value(before, after)['observation']['relation'], 'distinct_observed_files')

    def test_early_framing_stop_releases_the_stream_without_waiting_for_cyclic_gc(self):
        import gc
        import io
        import weakref
        from src.techexpert.native_tj_stream import summarize_frames
        class Tracked(io.BytesIO):
            pass
        enabled = gc.isenabled()
        gc.disable()
        try:
            raw = ROW * 3000
            stream = Tracked(raw)
            handle = weakref.ref(stream)
            summary = summarize_frames(stream, size=len(raw), max_records=1)
            self.assertFalse(summary['complete_scan'])
            del stream
            self.assertIsNone(handle())
        finally:
            if enabled:
                gc.enable()

    def test_renamed_file_is_only_a_different_path_for_the_observed_identity(self):
        before = self.case()
        other = self.root / 'rotated.log'
        os.rename(self.log, other)
        after = self.case(None, path=other)
        value = self.value(before, after)
        self.assertEqual(value['observation']['relation'], 'same_observed_identity_different_path')
        self.assertFalse(value['observation']['rotation_proven'])

    def test_legacy_and_different_reader_domains_do_not_infer_a_lifetime(self):
        for second_domain, prefix, expected in [(DOMAIN, False, 'unknown_origin'),
                (dict(DOMAIN, id='b' * 64), True, 'different_reader_domains')]:
            with self.subTest(expected=expected):
                before = self.case()
                after = self.case(ROW * 2, domain=second_domain, prefix=prefix)
                value = self.value(before, after)
                self.assertEqual(value['observation']['relation'], expected)
                self.assertEqual(value['common_prefix_bytes'], len(ROW))
                self.assertEqual(value['suggested_after_range']['byte_start'], 0)
                self.assertIsNone(value['input_duplicate']['duplicate'])

    def test_reversed_capture_order_does_not_become_a_truncation_claim(self):
        first = self.case()
        second = self.case(ROW * 2)
        value = self.value(second, first)
        self.assertEqual(value['byte_relation'], 'shortened_prefix')
        self.assertEqual(value['observation']['relation'], 'order_unknown')

    def test_same_catalogue_member_reimport_is_duplicate_input_but_new_clock_requires_reanalysis(self):
        self.log.write_bytes(ROW)
        plan = input_intake.inspect(self.state, [dict(path=str(self.log), kind='file')])
        before = input_intake.analyze(self.state, self.state, self.manifest(dict(PROFILE, path='m1')), plan['artifact_id'])
        changed_profile = dict(PROFILE, file_hour='2026-11-16T09:00:00+04:00')
        after = input_intake.analyze(self.state, self.state, self.manifest(dict(changed_profile, path='m1')), plan['artifact_id'])
        left, right = [dict(kind='case', id=item['case_id'], source_id='s1') for item in (before, after)]
        self.log.unlink()
        value = self.value(left, right)
        self.assertEqual(value['observation']['relation'], 'same_catalogue_member')
        self.assertTrue(value['input_duplicate']['duplicate'])
        self.assertFalse(value['interpretation']['same'])
        self.assertEqual(value['suggested_after_range']['byte_start'], 0)
        self.assertIn(plan['artifact_id'], {item['id'] for item in value['dependencies']})
        (self.state / 'artifacts' / plan['artifact_id'] / 'report.json').write_bytes(b'corrupt parent')
        with self.assertRaises(InputError):
            self.value(left, right)

    def test_artifact_sources_share_the_byte_comparison_without_native_format_claims(self):
        a = artifacts.save_artifact(self.state, 'provided_bytes', {}, [('a.bin', ROW)], {})
        b = artifacts.save_artifact(self.state, 'provided_bytes', {}, [('b.bin', ROW)], {})
        left, right = [dict(kind='artifact', id=item['artifact_id'], source_id='s1') for item in (a, b)]
        value = self.value(left, right)
        self.assertEqual(value['byte_relation'], 'identical')
        self.assertEqual(value['observation']['relation'], 'unknown_origin')
        self.assertIsNone(value['input_duplicate']['duplicate'])
        self.assertEqual(value['framing']['after']['status'], 'not_applicable')
        self.assertTrue(value['requires_ai_interpretation'])

    def test_same_zip_member_is_verified_from_retained_bytes_and_pins_its_catalogue(self):
        archive = self.root / 'provided.zip'
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as zipped:
            zipped.writestr('node/client.log', ROW)
        plan = input_intake.inspect(self.state, [dict(path=str(archive), kind='zip')])
        references = []
        for _ in range(2):
            report = input_intake.analyze(self.state, self.state, self.manifest(dict(PROFILE, path='m1')), plan['artifact_id'])
            references.append(dict(kind='case', id=report['case_id'], source_id='s1'))
        archive.unlink()
        value = self.value(*references)
        self.assertTrue(value['input_duplicate']['duplicate'])
        self.assertIsNone(value['suggested_after_range'])
        self.assertEqual(len(value['dependencies']), 3)
        self.assertEqual(value['before']['crc32'], __import__('zlib').crc32(ROW))

    def test_same_input_with_a_different_selected_episode_requires_full_reanalysis(self):
        self.log.write_bytes(ROW)
        plan = input_intake.inspect(self.state, [dict(path=str(self.log), kind='file')])
        references = []
        for run in ('episode-a', 'episode-b'):
            selection = {key: 'reported' for key in ('database', 'node', 'process', 'epoch', 'run')}
            selection['run'] = run
            report = input_intake.analyze(self.state, self.state,
                self.manifest(dict(PROFILE, path='m1'), selection=selection), plan['artifact_id'])
            references.append(dict(kind='case', id=report['case_id'], source_id='s1'))
        value = self.value(*references)
        self.assertTrue(value['input_duplicate']['duplicate'])
        self.assertFalse(value['interpretation']['same'])
        self.assertIn('context', value['interpretation']['changed_fields'])
        self.assertEqual(value['suggested_after_range']['byte_start'], 0)

    def test_changed_original_parse_budget_requires_reanalysis_of_identical_bytes(self):
        before = self.case()
        after = self.case()
        self.change_report(before, lambda doc: doc['sources'][0].update(record_budget=0, parse_status='not_parsed'))
        value = self.value(before, after)
        self.assertFalse(value['interpretation']['same'])
        self.assertIn('record_budget', value['interpretation']['changed_fields'])
        self.assertEqual(value['suggested_after_range']['byte_start'], 0)

    def test_metric_artifact_catalogue_bindings_are_also_verified(self):
        from src.techexpert.input_adapters import import_selected
        from test_input_adapter_intake import os_document
        archive = self.root / 'metrics.zip'
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as zipped:
            zipped.writestr('os.json', json.dumps(os_document()))
        plan = input_intake.inspect(self.state, [dict(path=str(archive), kind='zip')])
        args = dict(measurements=str(archive), input_plan=plan['artifact_id'], members=['m1'])
        references = []
        for _ in range(2):
            report = import_selected('os.import', args, self.state, self.state)
            references.append(dict(kind='artifact', id=report['artifact_id'], source_id='s1'))
        archive.unlink()
        value = self.value(*references)
        self.assertTrue(value['input_duplicate']['duplicate'])
        self.assertEqual(value['observation']['relation'], 'same_catalogue_member')
        self.assertEqual(value['framing']['before']['status'], 'not_applicable')

    def test_bad_refs_and_unknown_source_are_rejected_without_original_path_access(self):
        good = self.case()
        self.log.unlink()
        for bad in [dict(good, kind='path'), dict(good, kind=[]), dict(good, id='../bad'), dict(good, source_id='../../x'), dict(good, source_id='s99')]:
            with self.subTest(bad=bad), self.assertRaises(InputError):
                self.value(good, bad)

    def test_invalid_monotonic_interval_does_not_establish_capture_order(self):
        before = self.case()
        after = self.case(ROW * 2)
        folder = storage.case_folder(self.state, before['id'])
        report = storage.load_case(self.state, before['id'])
        acquisition = report['sources'][0]['acquisition']
        acquisition['started_monotonic_ns'] = str(int(acquisition['finished_monotonic_ns']) + 1)
        storage.write_json(folder / 'report.json', report)
        receipt = json.loads((folder / 'receipt.json').read_text())
        receipt['report_sha256'] = hashlib.sha256((folder / 'report.json').read_bytes()).hexdigest()
        storage.write_json(folder / 'receipt.json', receipt)
        self.assertEqual(self.value(before, after)['observation']['relation'], 'order_unknown')

    def test_boolean_capture_boundary_is_not_accepted_as_an_integer(self):
        before = self.case(b'')
        after = self.case(ROW)
        self.change_report(before, lambda doc: doc['sources'][0]['acquisition'].update(byte_start=False))
        with self.assertRaises(InputError):
            self.value(before, after)

    def test_empty_to_nonempty_snapshot_does_not_invent_an_old_event(self):
        before = self.case(b'')
        after = self.case(ROW)
        value = self.value(before, after)
        self.assertEqual(value['byte_relation'], 'extended_prefix')
        self.assertEqual(value['common_prefix_bytes'], 0)
        self.assertEqual(value['suggested_after_range']['byte_start'], 0)

    def test_a_changed_saved_suffix_after_an_early_difference_still_fails_integrity(self):
        a = artifacts.save_artifact(self.state, 'provided_bytes', {}, [('a', b'a' * 200000)], {})
        b = artifacts.save_artifact(self.state, 'provided_bytes', {}, [('b', b'b' * 200000)], {})
        left, right = [dict(kind='artifact', id=item['artifact_id'], source_id='s1') for item in (a, b)]
        target = self.state / 'artifacts' / b['artifact_id'] / 'sources/s1.bin'
        original = self.api.open_verified_snapshot
        def changed(*args, **kwargs):
            if Path(args[0]) == target:
                with target.open('r+b') as stream:
                    stream.seek(190000)
                    stream.write(b'changed')
            return original(*args, **kwargs)
        with patch.object(self.api, 'open_verified_snapshot', side_effect=changed), self.assertRaises(InputError):
            self.value(left, right)


if __name__ == '__main__':
    unittest.main()
