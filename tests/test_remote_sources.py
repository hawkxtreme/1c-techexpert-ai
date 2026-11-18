"""Stable read-only remote catalogue/capture checks, independent from log format."""
import hashlib
from pathlib import Path
import stat
import tempfile
import unittest

from src.techexpert import remote_sources as sources
from src.techexpert.inputs import InputError


class FakeSftp:
    def __init__(self):
        self.files={'/logs/one.log':b'abc','/logs/sub/two.log':b'hello'}
        self.links=set();self.changed=False;self.handles={};self.calls=[];self.on_read=None

    def realpath(self,path):return path
    def lstat(self,path):
        if path in self.links:return dict(permissions=stat.S_IFLNK|0o777,size=1,mtime=1)
        if path in ('/','/logs','/logs/sub'):return dict(permissions=stat.S_IFDIR|0o700,size=0,mtime=1)
        if path not in self.files:raise InputError('SFTP status 2')
        return dict(permissions=stat.S_IFREG|0o600,size=len(self.files[path]),mtime=1)
    def open(self,path):self.calls.append(('open',path));self.handles[path]=path;return path
    def fstat(self,handle):return self.lstat(handle)
    def opendir(self,path):self.calls.append(('opendir',path));return ['dir',path,False]
    def readdir(self,handle):
        if handle[2]:return None
        handle[2]=True
        paths=['/logs/one.log','/logs/sub'] if handle[1]=='/logs' else ['/logs/sub/two.log']
        return [dict(name=p.rsplit('/',1)[-1],attributes=self.lstat(p)) for p in paths]
    def read(self,handle,offset,count):
        if self.on_read:self.on_read(self,handle,offset)
        data=self.files[handle][offset:offset+count]
        return data or None
    def close_handle(self,handle):pass


class RemoteSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.client=FakeSftp()

    def inspect(self,**limits):return sources.inspect_tree(self.client,'/logs',**limits)

    def test_catalogue_reports_metadata_without_opening_files_or_interpreting_format(self):
        catalogue=self.inspect()
        self.assertTrue(catalogue['listing_complete'])
        self.assertEqual([m['relative_path'] for m in catalogue['members']],['one.log','sub/two.log'])
        self.assertFalse(any(op=='open' for op,_ in self.client.calls))
        self.assertEqual(catalogue['collection_coverage'],'unknown')

    def test_capture_repeats_complete_bytes_and_retains_private_raw_files(self):
        catalogue=self.inspect()
        result=sources.capture_files(self.client,'/logs',catalogue['members'],self.root/'work')
        self.assertEqual([r['sha256'] for r in result],[hashlib.sha256(b'abc').hexdigest(),hashlib.sha256(b'hello').hexdigest()])
        self.assertTrue(all(Path(r['path']).is_file() and r['complete'] for r in result))
        self.assertTrue(all(not r['atomic_snapshot'] for r in result))

    def test_symlink_root_and_member_are_never_followed(self):
        self.client.links.add('/logs')
        with self.assertRaises(InputError):self.inspect()
        self.client.links={'/logs/one.log'}
        catalogue=self.inspect()
        self.assertEqual(catalogue['excluded'][0]['reason'],'unsupported_file_type')
        self.assertEqual(len(catalogue['members']),1)

    def test_limits_return_explicit_partial_catalogue_without_complete_coverage_claim(self):
        catalogue=self.inspect(max_files=1)
        self.assertFalse(catalogue['listing_complete'])
        self.assertTrue(catalogue['truncated'])
        self.assertEqual(len(catalogue['members']),1)

    def test_changed_file_and_missing_second_read_are_not_complete_sources(self):
        catalogue=self.inspect()
        self.client.files['/logs/one.log']=b'changed'
        with self.assertRaisesRegex(InputError,'changed'):sources.capture_files(self.client,'/logs',catalogue['members'],self.root/'changed')
        self.client=FakeSftp();reads=[0]
        def mutate(client,path,offset):
            if path=='/logs/one.log' and offset==0:
                reads[0]+=1
                if reads[0]==2:client.files[path]=b'xyz'
        self.client.on_read=mutate
        with self.assertRaisesRegex(InputError,'changed'):sources.capture_files(self.client,'/logs',catalogue['members'],self.root/'rewritten')
        self.assertTrue(list((self.root/'rewritten').rglob('*.bin')))

    def test_escaping_and_oversized_metadata_are_not_guessed_or_opened(self):
        catalogue=self.inspect();member=dict(catalogue['members'][0],relative_path='../outside')
        with self.assertRaises(InputError):sources.capture_files(self.client,'/logs',[member],self.root/'escape')
        self.client.files['/logs/one.log']=b'x'*20
        catalogue=self.inspect(max_file_bytes=10)
        self.assertFalse(catalogue['members'][0]['importable'])
        with self.assertRaises(InputError):sources.capture_files(self.client,'/logs',[catalogue['members'][0]],self.root/'large')


if __name__=='__main__':unittest.main()
