"""Native saved queries retain integrity without a file/event-sized buffer."""
import gc
import hashlib
import json
from pathlib import Path
import tempfile
import tracemalloc
import unittest
from unittest.mock import patch

from src.techexpert import storage
from src.techexpert.inputs import InputError
from test_native_tj_stream import GOOD,PROFILE


class StreamedCaseQueryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.state=Path(self.temp.name)/'state';self.case_id='a'*32
        self.folder=self.state/'cases'/self.case_id;self.folder.joinpath('sources').mkdir(parents=True);self.snapshot=self.folder/'sources/s1.bin'

    def prepare(self,data,budget=100000):
        self.snapshot.write_bytes(data);manifest=b'{"schema":1}\n';(self.folder/'manifest.json').write_bytes(manifest)
        report=dict(schema_version=1,case_id=self.case_id,sources=[dict(id='s1',format='1c-tj-text-v1',sha256=hashlib.sha256(data).hexdigest(),size=len(data),profile=PROFILE,record_budget=budget)])
        storage.write_json(self.folder/'report.json',report);storage.write_json(self.folder/'receipt.json',dict(report_sha256=hashlib.sha256((self.folder/'report.json').read_bytes()).hexdigest(),manifest_sha256=hashlib.sha256(manifest).hexdigest()))

    def no_native_bulk_read(self):
        real=storage.read_snapshot
        def read(path,*args,**kwargs):
            if Path(path)==self.snapshot:raise AssertionError('Native snapshot loaded as one bytes object')
            return real(path,*args,**kwargs)
        return patch.object(storage,'read_snapshot',side_effect=read)

    def test_native_page_and_evidence_do_not_load_the_snapshot_at_once(self):
        self.prepare(GOOD*3)
        with self.no_native_bulk_read():
            page=storage.list_native_events(self.state,self.case_id,offset=1,limit=1)
            proof=storage.read_evidence(self.state,self.case_id,'s1:2')
            verified=storage.verified_case(self.state,self.case_id)
        self.assertEqual(page['matched_count'],3);self.assertEqual(page['next_offset'],2)
        self.assertEqual(page['records'][0]['evidence']['byte_start'],len(GOOD))
        self.assertEqual(proof['byte_start'],len(GOOD));self.assertTrue(proof['integrity_verified']);self.assertEqual(verified['case_id'],self.case_id)

    def test_page_memory_is_bounded_independently_of_total_record_payload(self):
        row=b'04:05.123456-0,UNKNOWN_EVENT,0,Context="'+b'x'*2048+b'"\n'
        self.prepare(row*1200);gc.collect();tracemalloc.start()
        try:
            result=storage.list_native_events(self.state,self.case_id,event='UNKNOWN_EVENT',limit=1)
            _,peak=tracemalloc.get_traced_memory()
        finally:tracemalloc.stop()
        self.assertEqual(result['matched_count'],1200);self.assertEqual(len(result['records']),1)
        self.assertLess(peak,2*1024*1024,'Native query retained source/event-sized allocations: '+str(peak))

    def test_corrupt_bytes_beyond_requested_page_are_never_ignored(self):
        self.prepare(GOOD*20,budget=1)
        with self.snapshot.open('r+b') as stream:stream.seek(-2,2);stream.write(b'X')
        for method,args in ((storage.list_native_events,dict(limit=1)),(storage.read_evidence,dict(evidence_id='s1:1'))):
            with self.subTest(method=method.__name__),self.assertRaises(InputError):method(self.state,self.case_id,**args)

    def test_change_while_reading_is_refused_before_returning_a_page(self):
        self.prepare(GOOD*4);real=Path.open;snapshot=self.snapshot;changed=[]
        class Reader:
            def __init__(self,stream):self.stream=stream
            def __enter__(self):return self
            def __exit__(self,*args):self.stream.close()
            def fileno(self):return self.stream.fileno()
            def read(self,size):
                data=self.stream.read(size)
                if not changed:
                    with real(snapshot,'ab') as writer:writer.write(b'new bytes')
                    changed.append(True)
                return data
        def opening(path,*args,**kwargs):
            stream=real(path,*args,**kwargs)
            return Reader(stream) if path==snapshot and args and args[0]=='rb' else stream
        with patch.object(Path,'open',opening),self.assertRaises(InputError):storage.list_native_events(self.state,self.case_id,limit=1)
        self.assertTrue(changed)

    def test_multiline_evidence_still_uses_original_complete_byte_range(self):
        first='04:05.123456-0,CALL,0,Context="Начало,\r\nконец"\r\n'.encode();self.prepare(b'\xef\xbb\xbf'+first+GOOD)
        proof=storage.read_evidence(self.state,self.case_id,'s1:1')
        self.assertEqual((proof['byte_start'],proof['byte_end'],proof['end_line']),(3,3+len(first),2))
        self.assertIn('Начало,\r\nконец',proof['text'])
        with self.assertRaises(InputError):storage.read_evidence(self.state,self.case_id,'s1:2')

    def test_linked_runtime_reference_cannot_escape_the_source_directory(self):
        self.prepare(GOOD);(self.folder/'outside.bin').write_bytes(GOOD)
        report=json.loads((self.folder/'report.json').read_text(encoding='utf-8'));report['sources'][0].update(id='../outside',format='1c-job-runtime-v1')
        storage.write_json(self.folder/'report.json',report);receipt=json.loads((self.folder/'receipt.json').read_text(encoding='utf-8'));receipt['report_sha256']=hashlib.sha256((self.folder/'report.json').read_bytes()).hexdigest();storage.write_json(self.folder/'receipt.json',receipt)
        with self.assertRaises(InputError):storage.list_native_events(self.state,self.case_id,linked_run=True)
