"""A reviewed one-shot OS plan can be handed off and returned as an offline snapshot."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import os
from pathlib import Path
import platform
import socket
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import capabilities, operation_state as fs, os_operator, update_state
from src.techexpert.inputs import InputError
from src.techexpert.os_metrics import import_os


class OperatorPlanTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        self.state = self.root / 'state'
        self.ticket = self.root / 'plan.json'
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.request = dict(schema_version=1, target=dict(platform=platform.system().lower(), hostname=socket.gethostname()),
                            window=dict(start=(self.now-timedelta(seconds=10)).isoformat(),
                                        end=(self.now+timedelta(minutes=15)).isoformat()),
                            collection=dict(role='storage'))

    def save(self):
        preview = os_operator.prepare(self.request)
        digest = preview['ticket_sha256']
        return os_operator.prepare(self.request, output=self.ticket, expected_sha256=digest)

    def test_cross_platform_preview_does_not_read_the_target_or_write_a_plan(self):
        self.request['target'] = dict(platform='windows', hostname='STORAGE-NODE')
        self.request['collection']['file_base'] = r'F:\1C Bases\Orders'
        with patch('src.techexpert.os_storage.observe', side_effect=AssertionError('unexpected storage access')):
            preview = os_operator.prepare(self.request)
            chosen = preview['ticket']['collection']
            self.assertEqual((chosen['duration_seconds'], chosen['interval_seconds']), (300, 1))
            self.assertEqual(preview['ticket']['target']['hostname'], 'storage-node')
            self.assertEqual(chosen['file_base'], r'F:\1C Bases\Orders')
            self.assertFalse(self.ticket.exists())
            with self.assertRaisesRegex(InputError, 'reviewed plan digest'):
                os_operator.prepare(self.request, output=self.ticket, expected_sha256='0'*64)
        self.assertFalse(self.ticket.exists())
        self.assertFalse(self.state.exists())
        self.request['collection']['file_base'] = r'\\server\share\Orders'
        with self.assertRaisesRegex(InputError, 'local filesystem path'):
            os_operator.prepare(self.request)

    def test_wrong_hash_node_or_window_never_launches(self):
        saved = self.save()
        digest = saved['ticket_sha256']
        with patch('src.techexpert.kernel.invoke', side_effect=AssertionError('unexpected collector')):
            with self.assertRaisesRegex(InputError, 'reviewed plan digest'):
                os_operator.run(self.state, self.ticket, expected_sha256='0'*64)
            with patch('src.techexpert.os_operator.socket.gethostname', return_value='another-host'):
                with self.assertRaisesRegex(InputError, 'target node'):
                    os_operator.run(self.state, self.ticket, expected_sha256=digest)
            with patch('src.techexpert.os_observation.now', return_value=self.now-timedelta(minutes=1)):
                with self.assertRaisesRegex(InputError, 'collection window'):
                    os_operator.run(self.state, self.ticket, expected_sha256=digest)
            with patch('src.techexpert.os_observation.now', return_value=self.now+timedelta(hours=1)):
                with self.assertRaisesRegex(InputError, 'collection window'):
                    os_operator.run(self.state, self.ticket, expected_sha256=digest)
            saved['ticket']['collection']['duration_seconds'] = 4
            fs.write(self.ticket, dict(ticket=saved['ticket'], ticket_sha256=digest))
            with self.assertRaisesRegex(InputError, 'reviewed plan digest'):
                os_operator.run(self.state, self.ticket, expected_sha256=digest)
        self.assertFalse(self.state.exists())

    def test_reviewed_reader_accepts_utf8_lf_and_crlf_installations(self):
        version = self.root / 'probe.py'
        version.write_bytes(b'# sampler\n')
        with patch.object(os_operator, 'PROBE', version):
            original = os_operator.prepare(self.request)['ticket_sha256']
            version.write_bytes(b'# sampler\r\n')
            self.assertEqual(os_operator.prepare(self.request)['ticket_sha256'], original)
            version.write_bytes(b'# changed sampler\n')
            self.assertNotEqual(os_operator.prepare(self.request)['ticket_sha256'], original)

    def test_managed_import_keeps_the_explicit_returned_digest(self):
        arguments = dict(measurements=str(self.root / 'returned.json'), expected_sha256='a'*64)
        request = dict(schema_version=1, operation='os.import', executor_id='operator-test',
                       operation_key='returned-measurements', arguments=arguments)
        self.assertEqual(capabilities.normalize_request(request)['arguments'], arguments)

    def test_return_file_does_not_replace_a_concurrent_writer(self):
        destination = self.root / 'measurements.json'
        sync = os.fsync

        def competing_writer(descriptor):
            sync(descriptor)
            destination.write_bytes(b'other result')

        with patch.object(os_operator.os, 'fsync', side_effect=competing_writer):
            with self.assertRaisesRegex(InputError, 'saved measurement bytes'):
                os_operator._return_file(destination, b'captured result')
        self.assertEqual(destination.read_bytes(), b'other result')

    def test_update_scan_sees_an_operator_writer_before_the_collector_starts(self):
        stage = fs.private(self.state / 'os-operator' / ('a'*64))
        with fs.writer(stage):
            result = update_state.inspect_state(self.state)
        self.assertEqual(result['activity'], 'active', result)
        self.assertIn(dict(kind='os-operator', id='a'*64, status='active'), result['problems'])

    def test_completed_run_replays_after_window_and_preserves_returned_bytes(self):
        base = self.root / '1Cv8.1CD'
        base.write_bytes(b'Storage mapping test file. No database connection.')
        self.request['collection'].update(duration_seconds=1, interval_seconds=1, max_bytes=1024**2, file_base=str(base))
        preview = self.save()
        digest = preview['ticket_sha256']
        first = os_operator.run(self.state, self.ticket, expected_sha256=digest)
        self.assertEqual(first['status'], 'succeeded', first)
        self.assertEqual(first['run_id'], preview['run_id'])
        self.assertFalse(first['replayed'])
        measurement = Path(first['measurements']['path'])
        raw = measurement.read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), first['measurements']['sha256'])
        self.assertEqual(fs.read(measurement)['observed_hostname'], socket.gethostname())
        inspection = update_state.inspect_state(self.state)
        self.assertEqual(inspection['activity'], 'idle_observed', inspection)
        self.assertEqual(inspection['schemata']['os-observation'], [1, 2, 4])
        with patch('src.techexpert.os_observation.now', return_value=self.now+timedelta(hours=1)):
            replay = os_operator.run(self.state, self.ticket, expected_sha256=digest)
            self.assertEqual(replay['run_id'], first['run_id'])
            self.assertEqual(replay['measurements'], first['measurements'])
            self.assertTrue(replay['replayed'])
            self.assertEqual(measurement.read_bytes(), raw)
            measurement.write_bytes(raw+b' ')
            with self.assertRaisesRegex(InputError, 'saved measurement bytes'):
                os_operator.run(self.state, self.ticket, expected_sha256=digest)

        returned = self.root / 'returned.json'
        returned.write_bytes(raw)
        intake = self.root / 'investigator'
        with self.assertRaisesRegex(InputError, 'measurement SHA-256'):
            import_os(intake, returned, expected_sha256='0'*64)
        self.assertFalse(intake.exists())
        imported = import_os(intake, returned, expected_sha256=first['measurements']['sha256'])
        self.assertEqual(imported['sources'][0]['sha256'], first['measurements']['sha256'])
        self.assertEqual(imported['result']['storage_binding']['origin'], 'reported_input')
        self.assertEqual(imported['result']['plan']['duration_seconds'], 1)
