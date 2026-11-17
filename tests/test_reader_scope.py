"""A reader namespace is observed metadata, never physical host authentication."""
import importlib
import os
import unittest
from unittest.mock import patch


class ReaderScopeTests(unittest.TestCase):
    def setUp(self):
        self.api = importlib.import_module('src.techexpert.reader_scope')

    def test_native_scope_is_bounded_stable_and_does_not_return_raw_identifiers(self):
        one, two = self.api.observe(), self.api.observe()
        self.assertEqual(one, two)
        self.assertEqual(one['profile'], 'local-reader-domain-v1')
        self.assertEqual(one['status'], 'observed')
        self.assertRegex(one['id'], '^[a-f0-9]{64}$')
        self.assertEqual(one['platform'], 'windows' if os.name == 'nt' else 'linux')
        self.assertNotIn('boot_id', one)
        self.assertNotIn('hostname', one)

    def test_unavailable_os_visibility_is_unknown_and_not_a_hostname_fallback(self):
        with patch.object(self.api, '_native', side_effect=OSError('unavailable')):
            value = self.api.observe()
        self.assertEqual(value['status'], 'unknown')
        self.assertIsNone(value['id'])

    def test_zero_empty_or_oversized_os_data_does_not_become_a_shared_identity(self):
        for raw in (b'', b'\0' * 24, b'x' * 1000):
            with self.subTest(raw_length=len(raw)), patch.object(self.api, '_native', return_value=raw):
                self.assertEqual(self.api.observe()['status'], 'unknown')


if __name__ == '__main__':
    unittest.main()
