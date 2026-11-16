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
