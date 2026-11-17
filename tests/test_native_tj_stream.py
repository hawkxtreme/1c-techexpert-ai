"""Chunked native text framing keeps exact evidence and conservative boundaries."""
import hashlib
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from src.techexpert import native_tj as api

PROFILE=dict(format='1c-tj-text-v1',platform_version='8.3.27.1989',encoding='utf-8',placement='folders',timestamp_format='minute',file_hour='2026-11-16T09:00:00+03:00',rotation_hours=1)
GOOD=b'04:05.123456-250000,SCALL,2,level=INFO,process=rphost\n'


class BoundedReader(io.BytesIO):
    def __init__(self,data,chunk):super().__init__(data);self.chunk=chunk;self.bytes_read=0;self.requests=[]
    def read(self,size=-1):
        if not 1<=size<=self.chunk:raise AssertionError('Unbounded input read')
        self.requests.append(size);value=super().read(size);self.bytes_read+=len(value);return value
    def seek(self,*args):raise AssertionError('Parser sought in its input')
    def tell(self):raise AssertionError('Parser needs no input cursor API')


class NativeTJStreamTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(callable(getattr(api,'iter_tj',None)),'Native TJ has no streaming iterator')
        self.profile=api.validate_profile(PROFILE,'26111609.log')

    def scan(self,data,chunk=7,**limits):
        reader=BoundedReader(data,chunk);scan=api.iter_tj(reader,self.profile,chunk_size=chunk,**limits)
        records=list(scan);return records,scan.summary,reader

    def test_every_boundary_preserves_bom_utf8_quotes_multiline_and_unknown_event(self):
        first=('04:05.123456-7,NEW_EVENT,0,"Ключ\r\nимя"="Привет,""строка""\r\n'
               '04:06.000000-0,FAKE,0,k=v\r\nend",path=C:\\Temp\\one\r\n').encode()
        data=b'\xef\xbb\xbf'+first+GOOD
        for chunk in (1,2,3,4,7,16,64,4096):
            with self.subTest(chunk=chunk):
                records,summary,reader=self.scan(data,chunk)
                self.assertEqual(summary['status'],'parsed');self.assertEqual(summary['records_seen'],2)
                self.assertEqual([r['event'] for r in records],['NEW_EVENT','SCALL'])
                self.assertEqual(records[0]['properties']['Ключ\r\nимя'],'Привет,"строка"\r\n04:06.000000-0,FAKE,0,k=v\r\nend')
                self.assertEqual(tuple(records[0][k] for k in ('byte_start','byte_end','line','end_line')),(3,3+len(first),1,4))
                self.assertEqual((records[1]['byte_start'],records[1]['line']),(3+len(first),5))
                self.assertIsNone(records[0]['start_timestamp_utc']);self.assertNotIn('kind',records[0]);self.assertEqual(reader.bytes_read,len(data))

    def test_summary_is_unavailable_until_exhaustion_and_raw_bytes_match_the_record(self):
        scan=api.iter_tj(BoundedReader(GOOD+GOOD,8),self.profile,chunk_size=8)
        with self.assertRaises(ValueError):_ = scan.summary
        self.assertEqual(next(scan)['byte_start'],0);self.assertEqual(scan.raw_record,GOOD)
        with self.assertRaises(ValueError):_ = scan.summary
        self.assertEqual(next(scan)['byte_start'],len(GOOD));self.assertEqual(list(scan),[])
        self.assertEqual(scan.summary['status'],'parsed')

    def test_oversized_multiline_payload_is_not_used_to_recover_fake_headers(self):
        oversized=b'04:05.123456-0,CALL,0,k="'+b'x'*200+b'\n'+GOOD+b'"\n'
        rows,summary,_=self.scan(oversized+GOOD,1,max_record_bytes=80)
        self.assertEqual([r['event'] for r in rows],['SCALL']);self.assertEqual(rows[0]['byte_start'],len(oversized))
        self.assertEqual(summary['records_seen'],2);self.assertEqual(summary['limitations'][0]['code'],'record_too_large')

    def test_open_quote_and_unterminated_tail_never_become_records(self):
        for tail in (GOOD[:-1],b'04:05.123456-0,CALL,0,k="open\n'+GOOD):
            with self.subTest(tail=tail):
                rows,summary,_=self.scan(GOOD+tail,2);self.assertEqual(len(rows),1);self.assertEqual(summary['status'],'partial')
                self.assertIn(summary['limitations'][-1]['code'],('truncated_record','ambiguous_record_boundary'))

    def test_invalid_utf8_and_bom_damage_have_ranges_without_source_text(self):
        bad=b'04:05.123456-0,CALL,0,k=PRIVATE_BAD_\xff\n'
        rows,summary,_=self.scan(bad+GOOD+b'\xef\xbb\xbf'+GOOD,3)
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['byte_start'],len(bad))
        self.assertEqual([r['code'] for r in summary['limitations']],['invalid_utf8','unexpected_bom'])
        self.assertEqual(summary['limitations'][0]['byte_end'],len(bad));self.assertNotIn('PRIVATE_BAD',str(summary))

    def test_record_budget_counts_bad_attempts_and_drains_without_parsing_more(self):
        data=b'bad\nbad\n'+GOOD
        rows,summary,reader=self.scan(data,4,max_records=2)
        self.assertEqual(rows,[]);self.assertEqual(summary['records_seen'],2);self.assertEqual(reader.bytes_read,len(data))
        self.assertEqual(summary['limitations'][-1],dict(code='record_limit',message='Record-attempt budget reached; remaining bytes were not parsed.',byte_start=8))

    def test_scan_byte_budget_reads_only_one_lookahead_byte(self):
        with patch.object(api,'MAX_INPUT_BYTES',len(GOOD)+10):
            rows,summary,reader=self.scan(GOOD*4,7)
        self.assertEqual(len(rows),1);self.assertLessEqual(reader.bytes_read,len(GOOD)+11)
        self.assertIn('input_byte_limit',[r['code'] for r in summary['limitations']])

    def test_empty_and_bom_only_remain_empty_with_zero_attempt_budget(self):
        for data in (b'',b'\xef\xbb\xbf'):
            for budget in (0,1):
                with self.subTest(data=data,budget=budget):
                    rows,summary,_=self.scan(data,1,max_records=budget);self.assertEqual(rows,[]);self.assertEqual(summary['status'],'empty')

    def test_invalid_limits_fail_before_any_stream_read(self):
        for limits in (dict(chunk_size=0),dict(chunk_size=True),dict(chunk_size=65537),dict(max_records=-1),dict(max_record_bytes=False)):
            reader=BoundedReader(GOOD,7)
            with self.subTest(limits=limits),self.assertRaises(ValueError):api.iter_tj(reader,self.profile,**limits)
            self.assertEqual(reader.bytes_read,0)

    def test_read_error_never_exposes_a_completed_summary(self):
        class Broken(BoundedReader):
            def read(self,size=-1):
                if self.bytes_read>=len(GOOD):raise OSError('controlled read failure')
                return super().read(size)
        scan=api.iter_tj(Broken(GOOD*2,len(GOOD)),self.profile,chunk_size=len(GOOD))
        self.assertEqual(next(scan)['byte_start'],0)
        with self.assertRaises(OSError):list(scan)
        with self.assertRaises(ValueError):_ = scan.summary

    def test_diagnostics_remain_bounded(self):
        _,summary,_=self.scan(b'bad\n'*1000,13)
        self.assertEqual(summary['records_seen'],1000);self.assertLessEqual(len(summary['limitations']),200)
        self.assertEqual(summary['limitations'][-1]['code'],'additional_limitations')

    def test_bundled_published_fixture_keeps_its_prechange_result(self):
        data=(Path(__file__).resolve().parents[1]/'tests/fixtures/native-tj/folders-minute.txt').read_bytes()
        for chunk in (1,17,65536):
            with self.subTest(chunk=chunk):
                rows,summary,_=self.scan(data,chunk)
                digest=hashlib.sha256(json.dumps(dict(records=rows,**summary),ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                self.assertEqual(digest,'f8075c89e6e36c3780cdf6ea5742e339665f2eca8d0d17b02dc1accba390c16d')

    def test_short_reads_need_no_seek_or_full_requested_chunk(self):
        class Short(BoundedReader):
            def read(self,size=-1):return super().read(min(size,2))
        scan=api.iter_tj(Short(b'\xef\xbb\xbf'+GOOD,65536),self.profile)
        self.assertEqual(next(scan)['byte_start'],3);self.assertEqual(list(scan),[]);self.assertEqual(scan.summary['status'],'parsed')

    def test_invalid_binary_reader_results_never_produce_a_completed_scan(self):
        for value in (None,'text',b'x'*65537):
            class Reader:
                def read(self,size):return value
            with self.subTest(kind=type(value).__name__):
                scan=api.iter_tj(Reader(),self.profile)
                with self.assertRaises(ValueError):list(scan)
                with self.assertRaises(ValueError):_ = scan.summary
