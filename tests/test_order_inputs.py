import json
from pathlib import Path
import tempfile
import unittest

from src.techexpert.inputs import load_manifest,InputError
from src.techexpert.storage import investigate,read_evidence

JOB='11111111-1111-4111-8111-111111111111'

class OrderInputsTests(unittest.TestCase):
    def prepare(self,root,kind,data,*,enabled=True):
        source=root/'input';source.write_bytes(data)
        manifest=dict(schema=1,scenario='SC-01',origin='provided',selection={'run':JOB},
            correlation_profile='1c-file-job-markers-v1',sources=[dict(path=str(source),format=kind)])
        if enabled:manifest['workload_profile']='sc01-order-load-v1'
        path=root/'manifest.json';path.write_text(json.dumps(manifest),encoding='utf-8')
        return path

    def test_auxiliary_sources_require_explicit_workload_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for kind in ('sc01-orders-csv-v1','sc01-http-service-v1','sc01-run-capture-v1','1c-source-text-v1'):
                with self.subTest(format=kind):
                    data=b'order_id,sku,qty\nA,SKU000,1\n' if 'csv' in kind else b'{"schema":1}\n'
                    if kind=='1c-source-text-v1':data='Процедура Test()\nКонецПроцедуры\n'.encode('utf-8')
                    bundle=load_manifest(self.prepare(root,kind,data))
                    source=bundle['sources'][0]
                    self.assertEqual(source['data'],data)
                    self.assertEqual(source['evidence']['id'],'s1:1')
                    self.assertEqual(source['evidence']['byte_end'],len(data))
                    with self.assertRaises(InputError):load_manifest(self.prepare(root,kind,data,enabled=False))

    def test_auxiliary_json_duplicate_keys_not_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            result=load_manifest(self.prepare(root,'sc01-run-capture-v1',b'{"schema":1,"schema":2}'))
            self.assertEqual(result['sources'][0]['parse_status'],'invalid')

    def test_whole_json_auxiliary_evidence_and_text_lines_are_immutable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            path=self.prepare(root,'sc01-run-capture-v1',b'{\n"schema":1,\n"job_uuid":"'+JOB.encode()+b'"\n}\n')
            report=investigate(path,root/'state')
            proof=read_evidence(root/'state',report['case_id'],'s1:1')
            self.assertEqual(json.loads(proof['text'])['job_uuid'],JOB)
            self.assertEqual(proof['end_line'],4)
            with self.assertRaises(InputError):read_evidence(root/'state',report['case_id'],'s1:2')
            path=self.prepare(root,'1c-source-text-v1',b'first\nsecond\n')
            report=investigate(path,root/'state')
            (root/'input').write_bytes(b'changed')
            self.assertEqual(read_evidence(root/'state',report['case_id'],'s1:2')['text'],'second')

if __name__=='__main__':unittest.main()
