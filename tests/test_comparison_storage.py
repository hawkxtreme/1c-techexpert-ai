import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_comparison import series
from src.techexpert.inputs import InputError
from src.techexpert.storage import write_json

ROOT=Path(__file__).resolve().parents[1]


def saved_series(state):
    before,after=series()
    data=b'controlled test evidence\n'
    digest=hashlib.sha256(data).hexdigest()
    def replace_refs(value):
        if isinstance(value,dict):
            if 'sha256' in value:value['sha256']=digest
            for v in value.values():replace_refs(v)
        elif isinstance(value,list):
            for v in value:replace_refs(v)
    for report in before+after:
        report['schema_version']=1
        replace_refs(report)
        folder=state/'cases'/report['case_id'];(folder/'sources').mkdir(parents=True)
        for source in report['sources']:
            source['sha256']=digest
            (folder/'sources'/(source['id']+'.bin')).write_bytes(data)
        (folder/'manifest.json').write_bytes(b'{}')
        write_json(folder/'report.json',report)
        write_json(folder/'receipt.json',dict(report_sha256=hashlib.sha256((folder/'report.json').read_bytes()).hexdigest(),
                   manifest_sha256=hashlib.sha256(b'{}').hexdigest()))
    return [x['case_id'] for x in before],[x['case_id'] for x in after]


class ComparisonStorageTests(unittest.TestCase):
    def setUp(self):
        self.storage=importlib.import_module('src.techexpert.storage')
        self.assertTrue(hasattr(self.storage,'compare_cases'))

    def test_comparison_saved_with_readable_report_and_resumes(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp);before,after=saved_series(state)
            report=self.storage.compare_cases(state,before,after)
            self.assertEqual(report['status'],'verified')
            self.assertEqual(self.storage.load_comparison(state,report['comparison_id']),report)
            markdown=(state/'comparisons'/report['comparison_id']/'report.md').read_text(encoding='utf-8')
            self.assertIn(before[0],markdown)
            self.assertIn('matches_expected',markdown)
            self.assertIn('improved',markdown)

    def test_changed_case_source_prevents_comparing_and_resuming(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp);before,after=saved_series(state)
            report=self.storage.compare_cases(state,before,after)
            (state/'cases'/before[0]/'sources/s1.bin').write_bytes(b'changed')
            with self.assertRaises(InputError):self.storage.compare_cases(state,before,after)
            with self.assertRaises(InputError):self.storage.load_comparison(state,report['comparison_id'])

    def test_cli_compare_and_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp);before,after=saved_series(state)
            command=[sys.executable,str(ROOT/'techexpert.py'),'--state-dir',str(state)]
            process=subprocess.run(command+['compare','--before',*before,'--after',*after],capture_output=True,encoding='utf-8',timeout=15)
            self.assertEqual(process.returncode,0,process.stdout+process.stderr)
            report=json.loads(process.stdout)
            self.assertEqual(report['status'],'verified')
            resume=subprocess.run(command+['comparison',report['comparison_id']],capture_output=True,encoding='utf-8',timeout=15)
            self.assertEqual(resume.returncode,0,resume.stdout+resume.stderr)
            self.assertEqual(json.loads(resume.stdout),report)

    def test_comparison_hash_is_of_the_report_used_for_calculation(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp);before,after=saved_series(state)
            folder=state/'cases'/after[0]
            original_hash=hashlib.sha256((folder/'report.json').read_bytes()).hexdigest()
            calculate=self.storage.compare_reports
            def concurrent_change(*args):
                result=calculate(*args)
                value=json.loads((folder/'report.json').read_text())
                value['concurrent_change']='different report after calculation'
                write_json(folder/'report.json',value)
                receipt=json.loads((folder/'receipt.json').read_text())
                receipt['report_sha256']=hashlib.sha256((folder/'report.json').read_bytes()).hexdigest()
                write_json(folder/'receipt.json',receipt)
                return result
            with patch.object(self.storage,'compare_reports',side_effect=concurrent_change):
                report=self.storage.compare_cases(state,before,after)
            saved=next(x for x in report['input_reports'] if x['case_id']==after[0])
            self.assertEqual(saved['sha256'],original_hash)
            with self.assertRaises(InputError):self.storage.load_comparison(state,report['comparison_id'])

if __name__=='__main__':unittest.main()
