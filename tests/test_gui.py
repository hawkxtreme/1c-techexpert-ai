import http.client
from html.parser import HTMLParser
import importlib
import importlib.util
import json
import tempfile
import threading
import unittest
from pathlib import Path


class GuiHTTPTests(unittest.TestCase):
    def test_new_checks_require_auth_and_local_preflight_has_no_side_effects(self):
        status,_,_=self.request('POST','/api/check',self.profile,token=False)
        self.assertEqual(status,401)
        status,_,body=self.request('POST','/api/check',self.profile)
        self.assertEqual(status,200)
        result=json.loads(body)
        self.assertFalse(result['connected'])
        self.assertFalse(result['collection_started'])
        self.assertFalse(self.state_dir.exists())
        status,_,_=self.request('POST','/api/ras',{'endpoint':'localhost:1545','executable':'cmd.exe'})
        self.assertEqual(status,400)

    def test_manual_base_selector_contains_file_server_unknown(self):
        class SelectParser(HTMLParser):
            active = False
            values = None
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == 'select':
                    self.active = attrs.get('id') == 'manual-mode'
                elif tag == 'option' and self.active:
                    self.values.append(attrs.get('value'))
            def handle_endtag(self, tag):
                if tag == 'select':
                    self.active = False
        status, _, body = self.request('GET', '/', token=False, origin=False)
        self.assertEqual(status, 200)
        parser = SelectParser()
        parser.values = []
        parser.feed(body.decode('utf-8'))
        self.assertCountEqual(parser.values, ['file', 'server', 'unknown'])

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.gui'),
                             'The local init HTTP boundary is not implemented yet')
        self.gui = importlib.import_module('src.techexpert.gui')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state_dir = Path(self.temp.name) / 'state'
        self.server = self.gui.create_server(self.state_dir, ttl=10)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server, self.server, self.thread)
        self.origin = 'http://127.0.0.1:' + str(self.server.server_port)
        self.profile = {
            'schema_version': 1, 'name': 'Local test',
            'bases': [{'id': 'file-1', 'name': 'Accounting', 'mode': 'file',
                       'connection': str(Path(self.temp.name) / 'Accounting')}],
            'sources': [{'id': 'tj-1', 'type': 'tj', 'path': str(Path(self.temp.name) / 'logs'),
                         'host': '', 'base_ids': ['file-1']}],
        }

    @staticmethod
    def stop_server(server, thread):
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    def request(self, method, route, body=None, *, token=True, origin=True, headers=None):
        options = {'Origin': self.origin} if origin else {}
        if token:
            options['Authorization'] = 'Bearer ' + self.server.token
        if body is not None:
            options['Content-Type'] = 'application/json'
            if not isinstance(body, (str, bytes)):
                body = json.dumps(body).encode('utf-8')
        options.update(headers or {})
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        try:
            connection.request(method, route, body=body, headers=options)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def assert_no_profile(self):
        status, _, body = self.request('GET', '/api/profile')
        self.assertEqual(status, 200)
        self.assertIsNone(json.loads(body))

    def test_loopback_and_page_do_not_expose_token(self):
        self.assertEqual(self.server.server_address[0], '127.0.0.1')
        status, headers, body = self.request('GET', '/', token=False, origin=False)
        self.assertEqual(status, 200)
        self.assertNotIn(self.server.token.encode(), body)
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
        self.assertIn('no-store', headers['Cache-Control'])

    def test_doctor_reports_this_helpers_state_directory(self):
        status,_,body=self.request('GET','/api/doctor')
        self.assertEqual(status,200)
        self.assertEqual(Path(json.loads(body)['state_dir']),self.state_dir.resolve())
        self.assertFalse(self.state_dir.exists())

    def test_missing_or_wrong_token_cannot_read_profile(self):
        for headers in ({}, {'Authorization': 'Bearer incorrect'}):
            with self.subTest(headers=headers):
                status, _, _ = self.request('GET', '/api/profile', token=False, headers=headers)
                self.assertEqual(status, 401)

    def test_query_token_is_not_an_authentication_route(self):
        status, _, _ = self.request('GET', '/api/profile?token=' + self.server.token, token=False)
        self.assertIn(status, (400, 401))

    def test_foreign_host_is_rejected_even_with_token(self):
        status, _, _ = self.request('POST', '/api/profile', self.profile,
                                    headers={'Host': 'attacker.example'})
        self.assertEqual(status, 403)
        self.assert_no_profile()

    def test_foreign_or_absent_origin_cannot_save(self):
        for origin in ('https://attacker.example', 'null', None):
            with self.subTest(origin=origin):
                headers = {'Origin': origin} if origin is not None else {}
                status, _, _ = self.request('POST', '/api/profile', self.profile,
                                            origin=False, headers=headers)
                self.assertEqual(status, 403)
        self.assert_no_profile()

    def test_cross_origin_read_is_rejected(self):
        status, _, _ = self.request('GET', '/api/profile',
                                    headers={'Origin': 'http://attacker.example'})
        self.assertEqual(status, 403)

    def test_non_json_cannot_save(self):
        status, _, _ = self.request('POST', '/api/profile', json.dumps(self.profile),
                                    headers={'Content-Type': 'text/plain'})
        self.assertEqual(status, 415)
        self.assert_no_profile()

    def test_malformed_or_oversized_json_does_not_save(self):
        for body, expected in (('{broken', 400), ('x' * 70000, 413), ('[]', 400)):
            with self.subTest(expected=expected, size=len(body)):
                status, _, _ = self.request('POST', '/api/profile', body)
                self.assertEqual(status, expected)
        self.assert_no_profile()

    def test_save_validation_does_not_overwrite_previous_profile(self):
        status, _, saved = self.request('POST', '/api/profile', self.profile)
        self.assertEqual(status, 200)
        bad = json.loads(json.dumps(self.profile))
        bad['sources'][0]['type'] = 'sql'
        bad['sources'][0]['host'] = 'not-contacted.example'
        status, _, _ = self.request('POST', '/api/profile', bad)
        self.assertEqual(status, 400)
        status, _, loaded = self.request('GET', '/api/profile')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(loaded), json.loads(saved))

    def test_authorized_save_and_load_return_backend_revision(self):
        status, _, raw = self.request('POST', '/api/profile', self.profile)
        self.assertEqual(status, 200)
        saved = json.loads(raw)
        self.assertTrue(saved['revision'])
        self.assertEqual(saved['bases'][0]['mode'], 'file')
        self.assertEqual(saved['sources'][0]['status'], 'not_checked')
        status, _, raw = self.request('GET', '/api/profile', origin=False)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw), saved)

    def test_starter_import_reads_only_explicit_file(self):
        starter = Path(self.temp.name) / 'ibases.v8i'
        starter.write_text('[Accounting]\nConnect=File="C:\\Data\\Accounting";\n', encoding='utf-8-sig')
        status, _, raw = self.request('POST', '/api/starter', {'path': str(starter)})
        self.assertEqual(status, 200)
        bases = json.loads(raw)
        self.assertEqual(len(bases), 1)
        self.assertEqual(bases[0]['mode'], 'file')
        self.assert_no_profile()

    def test_ttl_ends_server_lifetime(self):
        server = self.gui.create_server(self.state_dir, ttl=0.15)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.stop_server, server, thread)
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive(), 'The helper must terminate when its token expires')


if __name__ == '__main__':
    unittest.main()
