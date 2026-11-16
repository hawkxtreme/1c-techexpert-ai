import json
import tempfile
import unittest
from pathlib import Path

from src.techexpert.inputs import load_manifest, InputError

JOB='42ae85ca-6be6-4985-8748-cffdc32da157'


def runtime_spec(path):
    return dict(path=str(path),format='1c-job-runtime-v1',role='controller',
                platform_version='8.3.27.1989',platform_utc_offset='+03:00')


def manifest(root,sources,**changes):
    data=dict(schema=1,scenario='SC-01',origin='provided',correlation_profile='1c-file-job-markers-v1',
              selection=dict(run=JOB),sources=sources)
    data.update(changes)
    p=root/'case.json'
    p.write_text(json.dumps(data),encoding='utf-8')
    return p


class JobInputTests(unittest.TestCase):
    def test_runtime_snapshot_has_whole_document_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            source=root/'runtime.json'
            source.write_text(json.dumps(dict(schema=1,job_uuid=JOB,evidence={'id':'fake'}),indent=2),encoding='utf-8')
            bundle=load_manifest(manifest(root,[runtime_spec(source)]))
            self.assertEqual(len(bundle['lifecycle_documents']),1)
            doc=bundle['lifecycle_documents'][0]
            self.assertEqual(doc['role'],'controller')
            self.assertEqual(doc['evidence']['id'],'s1:1')
            self.assertEqual(doc['evidence']['byte_end'],source.stat().st_size)
            self.assertEqual(doc['platform_utc_offset'],'+03:00')
            self.assertNotIn('database',bundle['manifest']['selection'])

    def test_duplicate_json_ids_are_not_silently_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            source=root/'runtime.json'
            source.write_text('{"schema":1,"job_uuid":"one","job_uuid":"two"}',encoding='utf-8')
            bundle=load_manifest(manifest(root,[runtime_spec(source)]))
            self.assertEqual(bundle['lifecycle_documents'],[])
            self.assertEqual(bundle['sources'][0]['parse_status'],'invalid')
            self.assertTrue(any(x['code']=='invalid_runtime_document' for x in bundle['limitations']))

    def test_same_runtime_path_conflicting_roles_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            source=root/'runtime.json'
            source.write_text('{"schema":1}',encoding='utf-8')
            with self.assertRaisesRegex(InputError,'conflicting'):
                load_manifest(manifest(root,[runtime_spec(source),dict(runtime_spec(source),role='worker_enter')]))

    def test_invalid_profile_selector_offset_and_mixed_contract_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            spec=runtime_spec(root/'missing.json')
            for changes in [dict(correlation_profile='unknown'),dict(selection={'run':'not-a-uuid'}),
                            dict(selection={'run':JOB,'node':'guess'})]:
                with self.subTest(changes=changes),self.assertRaises(InputError):
                    load_manifest(manifest(root,[spec],**changes))
            for extra in [dict(role='unknown'),dict(platform_utc_offset='+03:60'),dict(platform_version='8.3.28')]:
                with self.subTest(extra=extra),self.assertRaises(InputError):
                    load_manifest(manifest(root,[dict(spec,**extra)]))
            with self.assertRaises(InputError):
                load_manifest(manifest(root,[dict(path='normal.jsonl',format='normalized-events-v1')]))


if __name__=='__main__':
    unittest.main()
