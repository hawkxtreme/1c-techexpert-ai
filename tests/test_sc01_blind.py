"""A held-out diagnosis must precede access to source or corrected captures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('sc01_blind',ROOT/'scripts/sc01_blind.py')


class BlindPreparationTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SPEC.origin and Path(SPEC.origin).is_file(),'blind preparation tool is missing')
        self.tool=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(self.tool)

    def manifest(self, name):
        return ROOT/'tests/fixtures/order-load'/(name+'.json')

    def test_prepared_toolkit_runs_its_own_catalogues_and_readiness_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=Path(tmp)/'trial'
            self.tool.prepare(ROOT,run,[self.manifest('baseline')],[self.manifest('cached')])
            kit=run/'diagnosis';state=kit/'state';results={}
            for command in ('templates','readiness','capabilities','knowledge'):
                args=[command]+(['фоновое задание'] if command=='knowledge' else [])
                child=subprocess.run([sys.executable,'-B','-X','utf8',str(kit/'techexpert.py'),'--state-dir',str(state),*args],
                    cwd=kit,capture_output=True,timeout=20)
                self.assertEqual(child.returncode,0,command+': '+(child.stdout+child.stderr).decode('utf-8','replace'))
                results[command]=json.loads(child.stdout)
            self.assertEqual(len(results['templates']['templates']),11)
            self.assertTrue(results['readiness']['capabilities']['run_synthetic_demo'])
            self.assertEqual(len(results['capabilities']['operations']),37)
            self.assertTrue(results['knowledge']['matches'])
            self.assertFalse(state.exists(),'Kit catalogue inspection started investigation state')
            self.assertEqual(len(list((kit/'skills').glob('*/SKILL.md'))),18)
            self.assertTrue((kit/'answer-schema.json').is_file(),'The prompt promises an absent response schema')

    def test_diagnosis_has_unmodified_observations_without_solution_or_future(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=Path(tmp)/'trial'
            receipt=self.tool.prepare(ROOT,run,[self.manifest('baseline')],[self.manifest('cached')])
            kit=run/'diagnosis'
            intake=json.loads((kit/'intake.json').read_text(encoding='utf-8'))
            self.assertEqual(len(intake['cases']),1)
            manifest=json.loads((kit/intake['cases'][0]).read_text(encoding='utf-8'))
            self.assertNotIn('1c-source-text-v1',[s['format'] for s in manifest['sources']])
            self.assertEqual(manifest['selection']['run'],json.loads(self.manifest('baseline').read_text())['selection']['run'])
            future_job=json.loads(self.manifest('cached').read_text())['selection']['run']
            for path in kit.rglob('*'):
                if path.is_file():
                    self.assertNotIn(future_job.encode(),path.read_bytes(),str(path))
            for entry in receipt['diagnosis_sources']:
                target=kit/entry['path']
                self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(),entry['original_sha256'])
            self.assertFalse((kit/'README.md').exists())
            self.assertFalse((kit/'knowledge/cases/SC01-order-load.md').exists())
            self.assertFalse((run/'verification').exists())
            self.assertEqual((kit/'.agents/skills/techexpert/SKILL.md').read_bytes(),(ROOT/'.agents/skills/techexpert/SKILL.md').read_bytes())
            for text in ((kit/'prompt.txt').read_text(encoding='utf-8'),(kit/'skills/investigate/SKILL.md').read_text(encoding='utf-8')):
                self.assertNotIn('cached',text.casefold())
                self.assertNotIn('кэш',text.casefold())
            from src.techexpert.storage import investigate
            report=investigate(kit/intake['cases'][0],Path(tmp)/'state')
            self.assertEqual(report['order_load']['status'],'partial')
            self.assertEqual(report['order_load']['capture_validation']['status'],'not_verified')
            self.assertEqual(report['order_load']['external_calls']['count'],200)
            self.assertEqual(report['order_load']['result_validation']['status'],'matches_expected')

    def test_release_requires_frozen_substantive_diagnosis_and_preserves_raw_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=Path(tmp)/'trial'
            self.tool.prepare(ROOT,run,[self.manifest('baseline')],[self.manifest('cached')])
            answer=Path(tmp)/'answer.json'
            answer.write_text('{}',encoding='utf-8')
            with self.assertRaises(ValueError):self.tool.release(run,answer)
            self.assertFalse((run/'verification').exists())
            kit=run/'diagnosis';intake=json.loads((kit/'intake.json').read_text(encoding='utf-8'))
            child=subprocess.run([sys.executable,'-B',str(kit/'techexpert.py'),'--state-dir',str(kit/'state'),
                'analyze',str(kit/intake['cases'][0])],cwd=kit,capture_output=True,timeout=20)
            self.assertEqual(child.returncode,0,child.stderr);case=json.loads(child.stdout)
            response=dict(status='hypothesis',cause_hypothesis='A supported mechanism',
                evidence=[dict(case_id=case['case_id'],id='s1:1',observation='Measured interval')],
                proposed_change='A concrete intervention',limitations=['not yet verified'])
            answer.write_text(json.dumps(response),encoding='utf-8')
            released=self.tool.release(run,answer)
            self.assertEqual(released['frozen_diagnosis_sha256'],hashlib.sha256(answer.read_bytes()).hexdigest())
            stage=kit/'verification'
            intake=json.loads((stage/'intake.json').read_text(encoding='utf-8'))
            self.assertEqual((len(intake['before']),len(intake['after'])),(1,1))
            for name in intake['before']+intake['after']:
                manifest=json.loads((kit/name).read_text(encoding='utf-8'))
                self.assertIn('1c-source-text-v1',[s['format'] for s in manifest['sources']])
            answer.write_text('changed',encoding='utf-8')
            self.assertEqual(json.loads((stage/'previous-answer.json').read_text())['proposed_change'],'A concrete intervention')
            with self.assertRaises(ValueError):self.tool.release(run,answer)

    def test_reuse_or_changed_prepared_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=Path(tmp)/'trial'
            self.tool.prepare(ROOT,run,[self.manifest('baseline')],[self.manifest('cached')])
            with self.assertRaises(ValueError):self.tool.prepare(ROOT,run,[self.manifest('baseline')],[self.manifest('cached')])
            (run/'diagnosis/skills/investigate/SKILL.md').write_text('changed',encoding='utf-8')
            with self.assertRaises(ValueError):self.tool.verify_prepared(run)

    def test_later_original_change_cannot_replace_the_frozen_trial_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=Path(tmp)/'trial'
            later=Path(tmp)/'later.json'
            source=json.loads(self.manifest('cached').read_text(encoding='utf-8'))
            for spec in source['sources']:
                spec['path']=str((self.manifest('cached').parent/spec['path']).resolve())
            later.write_text(json.dumps(source),encoding='utf-8')
            self.tool.prepare(ROOT,run,[self.manifest('baseline')],[later])
            later.write_text(json.dumps(source)+' ',encoding='utf-8')
            answer=Path(tmp)/'answer.json'
            answer.write_text(json.dumps(dict(status='insufficient_data',cause_hypothesis=None,proposed_change=None,evidence=[],
                limitations=['Plumbing-only fixture'],next_steps=['Inspect the additional retained data'])),encoding='utf-8')
            released=self.tool.release(run,answer)
            self.assertFalse(released['original_inputs_read'])
            self.assertTrue((run/'diagnosis/verification').is_dir())


if __name__=='__main__':unittest.main()
