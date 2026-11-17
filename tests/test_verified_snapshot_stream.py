"""Full digest and file stability remain mandatory after an early consumer stop."""
import hashlib
from pathlib import Path
import tempfile
import tracemalloc
import unittest
from unittest.mock import patch

from src.techexpert import inputs


class VerifiedSnapshotStreamTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(callable(getattr(inputs,'open_verified_snapshot',None)),'No verified streaming snapshot reader')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.path=Path(self.temp.name)/'snapshot.bin'
        self.data=b'original bytes\n'*10000;self.path.write_bytes(self.data);self.digest=hashlib.sha256(self.data).hexdigest()

    def test_early_consumer_still_hashes_the_complete_snapshot_with_bounded_reads(self):
        real=Path.open;requests=[];counts=[];path=self.path
        class Reader:
            def __init__(self,stream):self.stream=stream
            def __enter__(self):return self
            def __exit__(self,*args):self.stream.close()
            def fileno(self):return self.stream.fileno()
            def read(self,size):
                if not 1<=size<=65536:raise AssertionError('Unbounded snapshot read')
                requests.append(size);data=self.stream.read(size);counts.append(len(data));return data
        def opening(target,*args,**kwargs):
            stream=real(target,*args,**kwargs);return Reader(stream) if target==path else stream
        with patch.object(Path,'open',opening):
            with inputs.open_verified_snapshot(path,self.digest,expected_size=len(self.data)) as reader:self.assertEqual(reader.read(3),b'ori')
        self.assertEqual(sum(counts),len(self.data));self.assertLessEqual(max(requests),65536)

    def test_corruption_after_first_requested_bytes_is_refused_on_exit(self):
        with self.assertRaises(inputs.InputError):
            with inputs.open_verified_snapshot(self.path,self.digest) as reader:
                self.assertEqual(reader.read(3),b'ori')
                with self.path.open('r+b') as writer:writer.seek(-2,2);writer.write(b'X')

    def test_size_hash_and_limit_conflicts_never_yield_a_verified_reader(self):
        for changes in (dict(expected_sha256='x'*64),dict(expected_size=len(self.data)+1),dict(max_bytes=2),dict(expected_size=True)):
            args=dict(expected_sha256=self.digest);args.update(changes)
            with self.subTest(changes=changes),self.assertRaises(inputs.InputError):
                with inputs.open_verified_snapshot(self.path,**args):self.fail('Invalid snapshot was opened')

    def test_small_metadata_does_not_allocate_its_entire_allowed_byte_limit(self):
        self.path.write_bytes(b'{"schema":1}')
        tracemalloc.start()
        try:
            self.assertEqual(inputs.read_snapshot(self.path,16*1024*1024),b'{"schema":1}')
            _,peak=tracemalloc.get_traced_memory()
        finally:tracemalloc.stop()
        self.assertLess(peak,1024*1024,'Small metadata allocated a full allowed input buffer: '+str(peak))
