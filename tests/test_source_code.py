import importlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class SourceCodeTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.source_code'), 'source snapshot/search is missing')
        self.api=importlib.import_module('src.techexpert.source_code')

    def test_catalog_snapshot_survives_edits_and_returns_exact_lines(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'src';source.mkdir()
            (source/'Module.bsl').write_text('// header\nЗапрос.Выполнить();\n',encoding='utf-8-sig')
            (source/'Configuration.xml').write_text('<Configuration><Properties><Version>1.0</Version></Properties></Configuration>',encoding='utf-8')
            report=self.api.snapshot_source(root/'state',source)
            (source/'Module.bsl').write_text('changed',encoding='utf-8')
            found=self.api.search_source(root/'state',report['artifact_id'],'Выполнить')
            self.assertEqual(found['matches'][0]['line'],2)
            read=self.api.read_source(root/'state',report['artifact_id'],'Module.bsl',start=2,limit=1)
            self.assertEqual(read['lines'][0]['text'],'Запрос.Выполнить();')
            self.assertTrue(read['integrity_verified'])
            self.assertEqual(report['result']['working_version_match'],'unknown')

    def test_git_snapshots_commit_not_mutable_worktree(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'repo';source.mkdir()
            def git(*args):
                return subprocess.run(['git','-c','core.hooksPath=/dev/null','-C',str(source),*args],check=True,capture_output=True)
            git('init','-q');(source/'Module.bsl').write_text('original\n',encoding='utf-8')
            git('add','Module.bsl');git('-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','test fixture')
            (source/'Module.bsl').write_text('changed\n',encoding='utf-8')
            report=self.api.snapshot_source(root/'state',source,kind='git')
            self.assertEqual(self.api.read_source(root/'state',report['artifact_id'],'Module.bsl')['lines'][0]['text'],'original')
            self.assertFalse(report['result']['origin']['working_tree_included'])

    def test_git_snapshot_does_not_execute_configured_clean_filters(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'repo';source.mkdir();marker=root/'filter-ran'
            def git(*args):return subprocess.run(['git','-C',str(source),*args],check=True,capture_output=True)
            git('init','-q');(source/'M.bsl').write_text('original',encoding='utf-8')
            git('add','M.bsl');git('-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','fixture')
            script=root/'filter.py'
            script.write_text('import pathlib,sys\npathlib.Path('+repr(str(marker))+').write_text("ran")\nsys.stdout.write(sys.stdin.read())\n',encoding='utf-8')
            command='"'+Path(sys.executable).as_posix()+'" "'+script.as_posix()+'"'
            git('config','filter.probe.clean',command)
            (source/'.gitattributes').write_text('*.bsl filter=probe\n',encoding='utf-8')
            (source/'M.bsl').write_text('modified',encoding='utf-8')
            self.api.snapshot_source(root/'state',source,kind='git')
            self.assertFalse(marker.exists(),'read-only source snapshot executed a Git clean filter')

    def test_archive_ref_and_snapshot_path_cannot_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);archive=root/'sources.zip';archive.write_bytes(b'archive')
            with self.assertRaises(ValueError):self.api.snapshot_source(root/'state',archive)
            with self.assertRaises(ValueError):self.api.snapshot_source(root/'state',root,kind='git',ref='--upload-pack=bad')
            source=root/'code';source.mkdir();(source/'M.bsl').write_text('source',encoding='utf-8')
            report=self.api.snapshot_source(root/'state',source)
            with self.assertRaises(ValueError):self.api.read_source(root/'state',report['artifact_id'],'../M.bsl')

    def test_promisor_repository_is_rejected_before_lazy_fetch(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'repo';source.mkdir()
            subprocess.run(['git','-C',str(source),'init','-q'],check=True,capture_output=True)
            subprocess.run(['git','-C',str(source),'config','remote.origin.promisor','true'],check=True,capture_output=True)
            with self.assertRaisesRegex(ValueError,'partial|promisor'):
                self.api.snapshot_source(root/'state',source,kind='git')


if __name__=='__main__':unittest.main()
