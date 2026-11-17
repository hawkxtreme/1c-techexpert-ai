"""Live owned-tree scans may retry movement, never ignore incomplete evidence."""
import os
import errno
import hashlib
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src.techexpert import operation_state as fs
from src.techexpert.inputs import InputError


class LiveInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name);self.state=self.home/'state';self.key='live-inventory-test';self.root=self.state/'operations'/hashlib.sha256(self.key.encode()).hexdigest();self.root.mkdir(parents=True);(self.root/'baseline.bin').write_bytes(b'base')

    def product(self):
        from src.techexpert.artifacts import save_artifact
        plan=dict(schema_version=1,request=dict(operation_key=self.key));fs.write(self.root/'plan.json',plan);fs.write(self.root/'plan-receipt.json',dict(sha256=fs.digest(plan)))
        report=save_artifact(self.root/'work-state','apdex',{},[('fixture',b'bounded source')],dict(score=.75))
        worker=dict(schema_version=1,status='succeeded',targets=[dict(kind='artifacts',id=report['artifact_id'])],data=report)
        fs.write(self.root/'worker-result.json',worker);fs.write(self.root/'worker-receipt.json',dict(sha256=fs.digest(worker)))
        destination=self.state/'artifacts'/report['artifact_id'];destination.parent.mkdir()
        return self.root/'work-state/artifacts'/report['artifact_id'],destination

    def promote(self,source,destination):
        self.assertTrue(source.resolve().is_relative_to(self.home.resolve()))
        self.assertTrue(destination.parent.resolve().is_relative_to(self.home.resolve()))
        os.rename(source,destination)

    def test_product_promotion_restarts_the_complete_scan_without_double_counting(self):
        source,destination=self.product();receipt=(source/'receipt.json').read_bytes();real_walk=os.walk;moved=False
        def walk(*args,**kwargs):
            nonlocal moved
            for current,dirs,files in real_walk(*args,**kwargs):
                if Path(current)==source and not moved:
                    self.promote(source,destination);moved=True
                yield current,dirs,files
        with patch.object(fs.os,'walk',side_effect=walk):result=fs.inventory(self.root)
        actual=fs.inventory(self.root)
        self.assertTrue(moved);self.assertGreaterEqual(result['bytes'],4)
        self.assertEqual(result['bytes'],actual['bytes']);self.assertEqual(result['files'],actual['files']);self.assertEqual(result['scan_retries'],1)
        self.assertEqual((destination/'receipt.json').read_bytes(),receipt)

    def test_repeated_disappearance_fails_with_unknown_usage_instead_of_partial_totals(self):
        source,destination=self.product();self.promote(source,destination)
        error=FileNotFoundError(errno.ENOENT,'moving member',str(source/'receipt.json'))
        with patch.object(fs.os,'walk',side_effect=error) as walker:
            with self.assertRaisesRegex((InputError,OSError),'unstable|changing|moving'):fs.inventory(self.root)
            self.assertEqual(walker.call_count,3)

    def test_missing_member_with_source_still_present_is_not_a_promotion(self):
        source,destination=self.product()
        error=FileNotFoundError(errno.ENOENT,'missing member',str(source/'receipt.json'))
        with patch.object(fs.os,'walk',side_effect=error) as walker:
            with self.assertRaises(FileNotFoundError):fs.inventory(self.root)
            self.assertEqual(walker.call_count,1)

    def test_changed_promoted_report_cannot_authorize_a_retry(self):
        source,destination=self.product();self.promote(source,destination)
        report=fs.read(destination/'report.json');report['summary']={'score':1};fs.write(destination/'report.json',report)
        error=FileNotFoundError(errno.ENOENT,'missing member',str(source/'receipt.json'))
        with patch.object(fs.os,'walk',side_effect=error) as walker:
            with self.assertRaisesRegex(InputError,'disagrees'):fs.inventory(self.root)
            self.assertEqual(walker.call_count,1)

    def test_unsealed_worker_cannot_authorize_a_retry(self):
        source,destination=self.product();self.promote(source,destination)
        fs.write(self.root/'worker-receipt.json',dict(sha256='0'*64))
        error=FileNotFoundError(errno.ENOENT,'missing member',str(source/'receipt.json'))
        with patch.object(fs.os,'walk',side_effect=error) as walker:
            with self.assertRaisesRegex(InputError,'integrity'):fs.inventory(self.root)
            self.assertEqual(walker.call_count,1)

    def test_permission_failure_is_not_retried_or_reported_as_zero(self):
        with patch.object(fs.os,'walk',side_effect=PermissionError('metadata denied')) as walker:
            with self.assertRaises(PermissionError):fs.inventory(self.root)
            self.assertEqual(walker.call_count,1)

    def test_missing_root_does_not_become_a_successful_empty_scan(self):
        with self.assertRaises((InputError,OSError)):fs.inventory(self.home/'absent')

    def test_replaced_root_between_attempts_is_rejected(self):
        source,destination=self.product();original=Path.lstat;changed=False
        def lstat(path,*args,**kwargs):
            info=original(path,*args,**kwargs)
            if changed and path==self.root:return SimpleNamespace(st_mode=info.st_mode,st_dev=info.st_dev,st_ino=info.st_ino+1,st_file_attributes=getattr(info,'st_file_attributes',0))
            return info
        def disappear(*args,**kwargs):
            nonlocal changed
            self.promote(source,destination);changed=True;raise FileNotFoundError(errno.ENOENT,'moving member',str(source/'receipt.json'))
        with patch.object(Path,'lstat',lstat),patch.object(fs.os,'walk',side_effect=disappear) as walker:
            with self.assertRaisesRegex(InputError,'identity|replaced'):fs.inventory(self.root)
            self.assertEqual(walker.call_count,1)

    def test_reparse_root_after_a_retry_stays_rejected(self):
        source,destination=self.product();original=Path.lstat;changed=False
        def lstat(path,*args,**kwargs):
            if changed and path==self.root:return SimpleNamespace(st_mode=stat.S_IFDIR,st_file_attributes=0x400)
            return original(path,*args,**kwargs)
        def disappear(*args,**kwargs):
            nonlocal changed
            self.promote(source,destination);changed=True;raise FileNotFoundError(errno.ENOENT,'moving member',str(source/'receipt.json'))
        with patch.object(Path,'lstat',lstat),patch.object(fs.os,'walk',side_effect=disappear) as walker:
            with self.assertRaisesRegex(InputError,'linked'):fs.inventory(self.root)
            self.assertEqual(walker.call_count,1)
