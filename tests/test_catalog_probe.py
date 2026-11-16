import importlib
import importlib.util
import json
import socket
import time
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

JOB='11111111-1111-4111-8111-111111111111'
NONCE='22222222-2222-4222-8222-222222222222'
REQUEST='33333333-3333-4333-8333-333333333333'
BATCH='44444444-4444-4444-8444-444444444444'

class CatalogProbeTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.catalog_probe'))
        self.module=importlib.import_module('src.techexpert.catalog_probe')

    def request(self, probe, *, sku='SKU003', request_id=REQUEST, nonce=NONCE):
        req=urllib.request.Request(f'http://127.0.0.1:{probe.port}/catalog/{sku}', headers={
            'X-SC01-Job':JOB,'X-SC01-Nonce':nonce,'X-SC01-Request':request_id,'X-SC01-Batch':BATCH})
        return urllib.request.urlopen(req,timeout=3)

    def test_real_http_response_and_independent_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            probe=self.module.CatalogProbe(root,delay_ms=1,max_requests=1,ttl_seconds=3)
            thread=threading.Thread(target=probe.serve);thread.start()
            try:
                with self.request(probe) as response:
                    value=json.load(response)
                self.assertEqual(value,dict(sku='SKU003',price=115,catalog_revision='sc01-catalog-v1',request_id=REQUEST))
            finally:
                probe.stop();thread.join(4)
            self.assertFalse(thread.is_alive())
            record=json.loads((root/(JOB+'.json')).read_text(encoding='utf-8'))
            self.assertEqual(record['origin'],'controlled_loopback_http_service')
            self.assertEqual(record['catalog']['SKU003'],115)
            self.assertEqual(record['job_uuid'],JOB)
            self.assertEqual(len(record['requests']),1)
            call=record['requests'][0]
            self.assertEqual(call['request_id'],REQUEST)
            self.assertEqual(call['nonce'],NONCE)
            self.assertTrue(call['completed'])
            self.assertGreaterEqual(call['elapsed_us'],1000)
            self.assertEqual(call['elapsed_us'],(call['finished_monotonic_ns']-call['started_monotonic_ns'])//1000)
            self.assertEqual(record['host'],'127.0.0.1')

    def test_duplicate_request_and_mixed_nonce_are_rejected_without_overwriting_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            probe=self.module.CatalogProbe(root,delay_ms=0,max_requests=3,ttl_seconds=3)
            thread=threading.Thread(target=probe.serve);thread.start()
            try:
                self.request(probe).close()
                for kw in ({},{'request_id':'55555555-5555-4555-8555-555555555555','nonce':BATCH}):
                    with self.assertRaises(urllib.error.HTTPError) as caught:
                        self.request(probe,**kw)
                    self.assertEqual(caught.exception.code,409)
                    caught.exception.close()
            finally:
                probe.stop();thread.join(4)
            record=json.loads((root/(JOB+'.json')).read_text(encoding='utf-8'))
            self.assertEqual(len(record['requests']),1)
            state=json.loads((root/'service.json').read_text(encoding='utf-8'))
            self.assertEqual(state['rejected_requests'],2)

    def test_invalid_sku_and_missing_identity_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            probe=self.module.CatalogProbe(Path(tmp),delay_ms=0,max_requests=2,ttl_seconds=3)
            thread=threading.Thread(target=probe.serve);thread.start()
            try:
                with self.assertRaises(urllib.error.HTTPError) as first: self.request(probe,sku='../outside')
                first.exception.close()
                with self.assertRaises(urllib.error.HTTPError) as second:
                    urllib.request.urlopen(f'http://127.0.0.1:{probe.port}/catalog/SKU000',timeout=3)
                second.exception.close()
            finally:
                probe.stop();thread.join(4)
            self.assertFalse((Path(tmp)/(JOB+'.json')).exists())

    def test_expiration_stops_without_any_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            probe=self.module.CatalogProbe(Path(tmp),delay_ms=0,max_requests=1,ttl_seconds=0.1)
            thread=threading.Thread(target=probe.serve);thread.start();thread.join(2)
            self.assertFalse(thread.is_alive())
            state=json.loads((Path(tmp)/'service.json').read_text(encoding='utf-8'))
            self.assertEqual(state['stop_reason'],'ttl')

    def test_nonempty_output_and_invalid_limits_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for kw in (dict(delay_ms=-1),dict(delay_ms=True),dict(max_requests=0),dict(ttl_seconds=301)):
                with self.assertRaises(ValueError): self.module.CatalogProbe(root,**kw)
            (root/'keep').write_text('existing',encoding='utf-8')
            with self.assertRaises(ValueError): self.module.CatalogProbe(root)
            self.assertEqual((root/'keep').read_text(encoding='utf-8'),'existing')

    def test_absolute_ttl_closes_trickled_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            probe=self.module.CatalogProbe(Path(tmp),ttl_seconds=0.15)
            thread=threading.Thread(target=probe.serve);thread.start()
            with socket.create_connection(('127.0.0.1',probe.port),timeout=1) as client:
                client.sendall(b'GET / HTTP/1.0\r\nX-Slow: ')
                until=time.monotonic()+0.6
                while thread.is_alive() and time.monotonic()<until:
                    try:client.sendall(b'x')
                    except OSError:break
                    time.sleep(0.025)
                thread.join(0.4)
                stopped=not thread.is_alive()
            probe.stop();thread.join(3)
            self.assertTrue(stopped,'trickled headers extended absolute service TTL')
            self.assertEqual(json.loads((Path(tmp)/'service.json').read_text())['stop_reason'],'ttl')

    def test_stop_interrupts_incomplete_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            probe=self.module.CatalogProbe(Path(tmp),ttl_seconds=3)
            thread=threading.Thread(target=probe.serve);thread.start()
            with socket.create_connection(('127.0.0.1',probe.port),timeout=1) as client:
                client.sendall(b'GET / HTTP/1.0\r\nX-Slow: ')
                until=time.monotonic()+1
                while not probe.requests and time.monotonic()<until:time.sleep(0.01)
                probe.stop();thread.join(0.6)
                stopped=not thread.is_alive()
            thread.join(3)
            self.assertTrue(stopped,'stop waited for an untrusted client')

    def test_unsupported_method_consumes_request_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            probe=self.module.CatalogProbe(Path(tmp),max_requests=1,ttl_seconds=3)
            thread=threading.Thread(target=probe.serve);thread.start()
            req=urllib.request.Request(f'http://127.0.0.1:{probe.port}/',method='PUT')
            with self.assertRaises(urllib.error.HTTPError) as caught:urllib.request.urlopen(req,timeout=1)
            caught.exception.close()
            thread.join(0.6);stopped=not thread.is_alive()
            probe.stop();thread.join(3)
            self.assertTrue(stopped)
            state=json.loads((Path(tmp)/'service.json').read_text())
            self.assertEqual((state['total_requests'],state['rejected_requests']),(1,1))

if __name__=='__main__': unittest.main()
