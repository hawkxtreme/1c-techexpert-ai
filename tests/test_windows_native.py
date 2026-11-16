import importlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest


@unittest.skipUnless(os.name=='nt','Windows native runtime profile only')
class WindowsNativeTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.windows_native'),'owned native runner is missing')
        self.api=importlib.import_module('src.techexpert.windows_native')

    def test_literal_argv_capture_and_completed_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);result=self.api.run([sys.executable,'-c','import sys;print(sys.argv[1])','a;$(whoami)'],cwd=root,guard=lambda:None,timeout=5)
            self.assertEqual(result['status'],'completed');self.assertEqual(result['exit_code'],0)
            self.assertTrue(result['tree_finished']);self.assertEqual((root/'stdout.bin').read_text().strip(),'a;$(whoami)')

    def test_managed_start_records_identity_before_resume_and_has_a_job_memory_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);started=[]
            def before_resume(pid):
                self.assertFalse((root/'started').exists());started.append(pid)
            result=self.api.run([sys.executable,'-c','from pathlib import Path;Path("started").write_text("ok")'],
                cwd=root,guard=lambda:None,timeout=5,on_started=before_resume,memory_bytes=1024**3)
            self.assertEqual(started,[result['pid']]);self.assertEqual(result['exit_code'],0)
            self.assertTrue(result['tree_finished']);self.assertGreater(result['resource_usage']['peak_job_memory_bytes'],0)

    def test_mutable_state_reader_allows_atomic_replacement_and_keeps_its_open_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);path=root/'state.json';path.write_bytes(b'old')
            with self.api.open_shared_read(path) as reader:
                replacement=root/'replacement';replacement.write_bytes(b'new');self.api.replace_shared_metadata(replacement,path)
                self.assertEqual(reader.read(),b'old')
            self.assertEqual(path.read_bytes(),b'new')

    def test_metadata_replacement_does_not_bypass_an_ordinary_blocking_reader(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);path=root/'state.json';replacement=root/'replacement'
            path.write_bytes(b'old');replacement.write_bytes(b'new')
            with path.open('rb'):
                with self.assertRaises(OSError):self.api.replace_shared_metadata(replacement,path)
            self.assertEqual(path.read_bytes(),b'old');self.assertEqual(replacement.read_bytes(),b'new')

    def test_timeout_terminates_only_the_owned_job(self):
        with tempfile.TemporaryDirectory() as temp:
            result=self.api.run([sys.executable,'-c','import time;time.sleep(20)'],cwd=Path(temp),guard=lambda:None,timeout=.2)
            self.assertEqual(result['stop_reason'],'timeout');self.assertTrue(result['tree_finished'])

    def test_parent_exit_does_not_leave_a_writing_descendant(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            child='import pathlib,time; p=pathlib.Path("heartbeat");\nwhile True:p.write_text(str(time.time()));time.sleep(.05)'
            parent='import subprocess,sys,time;subprocess.Popen([sys.executable,"-c",'+repr(child)+']);time.sleep(.2)'
            result=self.api.run([sys.executable,'-c',parent],cwd=root,guard=lambda:None,timeout=5)
            self.assertEqual(result['stop_reason'],'descendants_after_parent_exit');self.assertTrue(result['tree_finished'])
            before=(root/'heartbeat').read_bytes();time.sleep(.15);self.assertEqual((root/'heartbeat').read_bytes(),before)

    def test_owner_crash_immediately_after_create_has_no_unassigned_suspended_orphan(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);nested=root/'nested';nested.mkdir();helper=root/'crash-after-create.py'
            repo=Path(__file__).resolve().parents[1]
            code='''import os,sys
from pathlib import Path
sys.path.insert(0,REPO)
from src.techexpert import windows_native as native
real=native._kernel()
def created(*args):
    result=real.CreateProcessW(*args)
    if result:
        Path("create-returned").write_bytes(b"owned test fault")
        os._exit(73)
    return result
class Proxy:
    def __getattr__(self,name):return created if name=="CreateProcessW" else getattr(real,name)
native._kernel=lambda:Proxy()
native.run([sys.executable,"-c","import time;time.sleep(30)"],cwd=Path("nested"),guard=lambda:None,timeout=35)
'''.replace('REPO',repr(str(repo)))
            helper.write_text(code,encoding='utf-8')
            # The outer owned Job contains the fault injector and provides safe
            # cleanup even against the old unassigned-child bug; no found PID kill.
            result=self.api.run([sys.executable,str(helper)],cwd=root,guard=lambda:None,timeout=5)
            self.assertTrue((root/'create-returned').exists());self.assertEqual(result['exit_code'],73)
            self.assertTrue(result['tree_finished'])
            self.assertIsNone(result['stop_reason'],'inner owner crash left a suspended child for the outer Job to clean up')

    def test_guard_failure_stops_the_job(self):
        with tempfile.TemporaryDirectory() as temp:
            def stop():raise ValueError('owned output budget exceeded')
            result=self.api.run([sys.executable,'-c','import time;time.sleep(20)'],cwd=Path(temp),guard=stop,timeout=5)
            self.assertEqual(result['stop_reason'],'guard_failed');self.assertTrue(result['tree_finished'])

    def test_copy_limits_and_windows_version_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'original.bin';source.write_bytes(b'controlled source');os.utime(source,(1600000000,1600000000))
            result=self.api.copy_locked(source,root/'copy.bin',max_bytes=100,deadline=time.monotonic()+5,space_floor=0)
            self.assertEqual((root/'copy.bin').read_bytes(),source.read_bytes());self.assertEqual(result['bytes'],len(source.read_bytes()))
            self.assertEqual(result['source_identity'],self.api.file_identity(source),'locked-handle identity differs from planned path identity')
            with self.assertRaises(ValueError):self.api.copy_locked(source,root/'oversized.bin',max_bytes=1,deadline=time.monotonic()+5,space_floor=0)
            self.assertTrue(self.api.file_version(Path(sys.executable)).startswith('3.'))

    def test_copy_refuses_existing_writer_without_creating_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'source';source.write_bytes(b'private')
            with source.open('r+b'):
                with self.assertRaisesRegex(ValueError,'writers|close'):self.api.copy_locked(source,root/'copy',max_bytes=100,deadline=time.monotonic()+5,space_floor=0)
            self.assertFalse((root/'copy').exists())

    def test_private_directory_has_protected_owner_admin_system_access(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/'new-private';folder.mkdir()
            protect=getattr(self.api,'protect_directory',None);self.assertIsNotNone(protect,'private copy directory access is not restricted')
            policy=protect(folder)
            self.assertTrue(policy['protected']);self.assertEqual(set(policy['allow']),{'owner','administrators','system'})
            self.assertEqual(self.api.directory_policy(folder),policy)


if __name__=='__main__':unittest.main()
