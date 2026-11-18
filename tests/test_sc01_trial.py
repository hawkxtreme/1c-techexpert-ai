"""Held-out material survives original loss and preserves one participant state."""
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


class TrialTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('trial_cli',ROOT/'scripts/sc01_blind.py')
        self.api=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.api)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name);self.trial=self.folder/'trial'
        self.before=ROOT/'tests/fixtures/order-load/baseline.json';self.after=ROOT/'tests/fixtures/order-load/cached.json'

    def prepare(self,before=None,after=None):
        value=self.api.prepare(ROOT,self.trial,[before or self.before],[after or self.after])
        self.assertEqual(value.get('schema'),2,'The controller does not retain versioned private inputs')
        return value

    def cli(self,*args):
        kit=self.trial/'diagnosis'
        p=subprocess.run([sys.executable,'-B','-X','utf8',str(kit/'techexpert.py'),'--state-dir',str(kit/'state'),*map(str,args)],
                         cwd=kit,capture_output=True,timeout=30)
        self.assertEqual(p.returncode,0,(p.stdout+p.stderr).decode('utf-8','replace'))
        return json.loads(p.stdout)

    def answer(self,*,insufficient=False):
        if insufficient:
            doc=dict(status='insufficient_data',cause_hypothesis=None,proposed_change=None,evidence=[],
                     limitations=['This is a plumbing-only answer fixture, not a model diagnosis'],next_steps=['Inspect the newly supplied records'])
        else:
            kit=self.trial/'diagnosis';intake=json.loads((kit/'intake.json').read_text(encoding='utf-8'))
            case=self.cli('analyze',kit/intake['cases'][0]);self.case=case
            doc=dict(status='hypothesis',cause_hypothesis='Provisional interpretation of supplied observations',
                proposed_change='A bounded control measurement',evidence=[dict(case_id=case['case_id'],id='s1:1',observation='Read supplied source')],
                limitations=['Plumbing-only answer fixture, not a model diagnosis'])
        path=self.folder/'answer.json';path.write_text(json.dumps(doc,ensure_ascii=False),encoding='utf-8')
        return path

    def test_one_workspace_retains_state_and_old_case_evidence(self):
        self.prepare();answer=self.answer();kit=self.trial/'diagnosis'
        before=(kit/'state'/'cases'/self.case['case_id']/'report.json').read_bytes()
        released=self.api.release(self.trial,answer)
        self.assertEqual(released['workspace'],str(kit))
        self.assertEqual(released['prompt'],'verification/prompt.txt')
        self.assertFalse((self.trial/'verification').exists(),'Disclosure started an unrelated workspace')
        self.assertEqual((kit/'state'/'cases'/self.case['case_id']/'report.json').read_bytes(),before)
        self.assertEqual(self.cli('show',self.case['case_id'])['case_id'],self.case['case_id'])
        self.assertTrue(self.cli('evidence',self.case['case_id'],'s1:1')['integrity_verified'])
        intake=json.loads((kit/'verification/intake.json').read_text(encoding='utf-8'))
        cases=[self.cli('analyze',kit/path) for path in intake['before']+intake['after']]
        comparison=self.cli('compare','--before',cases[0]['case_id'],'--after',cases[1]['case_id'])
        self.assertEqual(comparison['performance']['status'],'inconclusive')
        self.assertEqual(self.api.status(self.trial)['release_status'],'released')

    def test_disclosure_reads_private_snapshots_after_originals_disappear(self):
        source=self.folder/'originals';source.mkdir();paths=[]
        for name in ('baseline','cached'):
            file=ROOT/'tests/fixtures/order-load'/(name+'.json');doc=json.loads(file.read_text(encoding='utf-8'))
            one=source/name;one.mkdir()
            for i,item in enumerate(doc['sources']):
                member=one/('input-'+str(i)+'.bin');member.write_bytes((file.parent/item['path']).resolve().read_bytes());item['path']=member.name
            manifest=one/'manifest.json';manifest.write_text(json.dumps(doc),encoding='utf-8');paths.append(manifest)
        self.prepare(*paths);answer=self.answer(insufficient=True)
        for group in source.iterdir():
            for file in group.iterdir():file.unlink()
            group.rmdir()
        result=self.api.release(self.trial,answer)
        self.assertEqual(result['release_status'],'released')
        self.assertFalse(result['original_inputs_read'])
        self.assertEqual(self.api.status(self.trial)['material_integrity'],'verified')

    def test_changed_private_capture_is_refused_without_disclosure(self):
        self.prepare();answer=self.answer(insufficient=True)
        capture=next((self.trial/'private-inputs').rglob('input-01.bin'));raw=capture.read_bytes();capture.write_bytes(raw[:-1]+b'X')
        with self.assertRaisesRegex(ValueError,'capture|integrity|snapshot'):
            self.api.release(self.trial,answer)
        self.assertFalse((self.trial/'diagnosis/verification').exists())

    def test_extra_static_tool_and_changed_prompt_are_not_silently_trusted(self):
        self.prepare();kit=self.trial/'diagnosis';extra=kit/'skills/investigate/extra.md';extra.write_text('injected')
        with self.assertRaisesRegex(ValueError,'prepared|inventory|input'):self.api.verify_prepared(self.trial)
        extra.unlink();self.api.verify_prepared(self.trial)
        (kit/'prompt.txt').write_text('changed')
        with self.assertRaisesRegex(ValueError,'prepared|inventory|input'):self.api.verify_prepared(self.trial)

    def test_honest_insufficient_answer_and_exact_frozen_response_survive_edits(self):
        self.prepare();answer=self.answer(insufficient=True);raw=answer.read_bytes()
        result=self.api.release(self.trial,answer)
        answer.write_bytes(b'changed after disclosure')
        saved=self.trial/'diagnosis/verification/previous-answer.json'
        self.assertEqual(saved.read_bytes(),raw)
        self.assertEqual(result['frozen_diagnosis_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertFalse(result['causal_truth_judged'])
        with self.assertRaisesRegex(ValueError,'already|released'):self.api.release(self.trial,answer)

    def test_answer_raw_length_limit_is_enforced_before_disclosure(self):
        self.prepare();answer=self.answer(insufficient=True);base=json.loads(answer.read_text(encoding='utf-8'))
        raw_head=(self.trial/'head.json').read_bytes()
        for field in ('cause_hypothesis','proposed_change','limitations','next_steps','evidence'):
            with self.subTest(field=field):
                doc=deepcopy(base);too_long='x'+' '*8192
                if field in ('limitations','next_steps'):doc[field]=[too_long]
                elif field=='evidence':doc[field]=[dict(case_id='a'*32,id='s1:1',observation=too_long)]
                else:doc[field]=too_long
                answer.write_text(json.dumps(doc),encoding='utf-8')
                with self.assertRaisesRegex(ValueError,'answer|interpretation|evidence'):
                    self.api.release(self.trial,answer)
                self.assertEqual((self.trial/'head.json').read_bytes(),raw_head)
                self.assertFalse((self.trial/'diagnosis/verification').exists())
                self.assertFalse((self.trial/'frozen-diagnosis.json').exists())
        from scripts.sc01_trial import _answer
        base['next_steps']=['x'+' '*8191]
        self.assertEqual(_answer(json.dumps(base).encode()),base)
        base['next_steps']=[' '*8192]
        with self.assertRaisesRegex(ValueError,'text list'):_answer(json.dumps(base).encode())

    def test_invalid_control_json_returns_structured_error_without_rewriting(self):
        self.prepare();answer=self.answer(insufficient=True)
        def invoke(command):
            args=['--response',str(answer)] if command=='release' else []
            result=subprocess.run([sys.executable,'-B','-X','utf8',str(ROOT/'scripts/sc01_blind.py'),command,'--output',str(self.trial),*args],
                cwd=self.folder,capture_output=True,timeout=30)
            self.assertEqual(result.returncode,2,(result.stdout+result.stderr).decode('utf-8','replace'))
            doc=json.loads(result.stdout);self.assertEqual(doc['code'],'trial_input_or_state_error')
            self.assertEqual(result.stderr,b'')
        def reject(file,commands):
            original=file.read_bytes()
            for invalid in (None,[],False,'invalid',{},dict(sha256=[]),dict(sha256='0'*64,extra=True),dict(stage=[]),dict(stage='prepared',extra=True)):
                with self.subTest(file=file.name,value=invalid):
                    raw=json.dumps(invalid).encode();file.write_bytes(raw)
                    try:
                        for command in commands:
                            invoke(command);self.assertEqual(file.read_bytes(),raw)
                    finally:file.write_bytes(original)
        reject(self.trial/'head.json',('status','release'))
        reject(self.trial/'preparation-receipt.json',('status','release'))
        self.assertEqual(json.loads((self.trial/'head.json').read_text())['stage'],'prepared')
        self.assertFalse((self.trial/'diagnosis/verification').exists())
        self.api.release(self.trial,answer)
        immutable={p:p.read_bytes() for p in (self.trial/'head.json',self.trial/'release.json',self.trial/'frozen-diagnosis.json')}
        reject(self.trial/'release-receipt.json',('status',))
        self.assertEqual({p:p.read_bytes() for p in immutable},immutable)
        self.assertEqual(self.api.status(self.trial)['release_status'],'released')

    def test_wrong_case_reference_is_not_an_actual_participant_result(self):
        self.prepare();answer=self.answer();doc=json.loads(answer.read_text(encoding='utf-8'))
        doc['evidence'][0]['case_id']='a'*32;answer.write_text(json.dumps(doc),encoding='utf-8')
        with self.assertRaises((ValueError,OSError)):self.api.release(self.trial,answer)
        self.assertFalse((self.trial/'diagnosis/verification').exists())

    def test_verified_case_summary_can_support_diagnosis_without_an_unrelated_record(self):
        from src.techexpert import context_disclosure, context_policy, investigations, operation_state as fs

        self.prepare();answer=self.answer()
        state=self.trial/'diagnosis/state';cid=self.case['case_id']
        iid=investigations.create(state, dict(task='Review the retained case measurements'))['investigation_id']
        revision=investigations.revise(state,iid,dict(attachments=[dict(id='A-1',kind='case',target_id=cid)]),
            expected_revision=1)['revision']
        approval=(state,iid,revision,['case'],8192)
        context_policy.save(*approval,context_policy.plan(*approval)['plan_sha256'])
        ready=context_disclosure.read(state,dict(investigation_id=iid,revision=revision,attachment='A-1',kind='case-summary'))
        entry=ready['disclosure'];reference=f"view:{iid}:{entry['id']}"
        doc=json.loads(answer.read_bytes());doc['evidence'][0]['id']=reference;fs.write(answer,doc)
        path=state/'context-disclosure/history'/iid/(entry['id']+'.json')
        original=path.read_bytes()
        falsified=dict(entry,payload_sha256='a'*64)
        fs.write(path,dict(entry=falsified,sha256=fs.digest(falsified)))
        with self.assertRaises(ValueError):self.api.release(self.trial,answer)
        self.assertEqual(self.api.status(self.trial)['release_status'],'withheld')
        fs.write(path,json.loads(original))

        result=self.api.release(self.trial,answer)
        self.assertEqual(result['release_status'],'released')
        proof,=result['evidence_verified_at_release']
        self.assertEqual(proof['id'],reference)
        self.assertEqual(proof['proof']['payload_sha256'],entry['payload_sha256'])
        self.assertEqual(context_disclosure.history(state,iid,revision)['total'],1)
        self.assertEqual(entry['reference'],reference)
        revoke=(state,iid,revision,[],8192)
        context_policy.save(*revoke,context_policy.plan(*revoke)['plan_sha256'])
        with self.assertRaisesRegex(ValueError,'policy changed'):
            context_disclosure.verify_case_summary(state,reference,self.case)

    def test_interrupted_disclosure_retains_work_and_does_not_restart(self):
        self.prepare();answer=self.answer(insufficient=True)
        from scripts import sc01_trial
        with patch.object(sc01_trial,'materialize',side_effect=OSError('injected output failure')):
            with self.assertRaisesRegex(OSError,'injected'):self.api.release(self.trial,answer)
        state=self.api.status(self.trial)
        self.assertEqual(state['release_status'],'releasing')
        self.assertTrue((self.trial/'diagnosis/verification').exists())
        with self.assertRaisesRegex(ValueError,'partial|releasing|already'):self.api.release(self.trial,answer)

    def test_controller_writer_and_legacy_format_are_not_bypassed(self):
        self.prepare();answer=self.answer(insufficient=True)
        from src.techexpert import operation_state as fs
        with fs.writer(self.trial):
            with self.assertRaisesRegex(ValueError,'writer'):self.api.release(self.trial,answer)
        other=self.folder/'old';other.mkdir();(other/'preparation.json').write_text('{"schema":1}')
        with self.assertRaisesRegex(ValueError,'legacy|schema'):self.api.status(other)

    def test_second_stage_answer_is_mutable_output_and_schema_separates_effect(self):
        self.prepare();self.api.release(self.trial,self.answer(insufficient=True))
        stage=self.trial/'diagnosis/verification'
        (stage/'answer.json').write_text('{"plumbing_only":true}')
        try:state=self.api.status(self.trial)
        except ValueError as exc:self.fail('The participant cannot save its requested second-stage answer: '+str(exc))
        self.assertEqual(state['material_integrity'],'verified')
        schema=json.loads((stage/'answer-schema.json').read_text(encoding='utf-8'))
        for field in ('status','cause_state','comparison_id','effect','business_result','goal','recurrence','evidence','limitations'):
            self.assertIn(field,schema['properties'])
        (stage/'prompt.txt').write_text('changed immutable instruction')
        with self.assertRaisesRegex(ValueError,'integrity'):self.api.status(self.trial)

    def test_total_capture_budget_is_checked_before_creating_a_trial(self):
        from scripts import sc01_trial
        with patch.object(sc01_trial,'MAX_INPUT_BYTES',1):
            with self.assertRaisesRegex(ValueError,'byte limit'):
                self.api.prepare(ROOT,self.trial,[self.before],[self.after])
        self.assertFalse(self.trial.exists())

    def test_projection_does_not_hide_substantive_dependencies_or_conflicts(self):
        from scripts.sc01_kit import _knowledge
        raw=json.loads((ROOT/'knowledge/index.json').read_text(encoding='utf-8'))
        index,pruned=_knowledge({'knowledge/index.json':json.dumps(raw).encode()})
        self.assertEqual(len(index['cards']),4);self.assertTrue(pruned)
        copied=deepcopy(raw)
        next(card for card in copied['cards'] if card['id']=='SC01-TIME')['depends_on']=['SC01-ORDER-LOAD']
        with self.assertRaisesRegex(ValueError,'depends'):_knowledge({'knowledge/index.json':json.dumps(copied).encode()})
        raw['open_conflicts']=[dict(id='CONFLICT-test',cards=['SC01-TIME','SC01-ORDER-LOAD'],summary='Must remain visible')]
        with self.assertRaisesRegex(ValueError,'conflict'):_knowledge({'knowledge/index.json':json.dumps(raw).encode()})

    def test_inventory_budget_counts_empty_directories(self):
        from scripts import sc01_trial
        tree=self.folder/'tree';tree.mkdir();(tree/'one').mkdir();(tree/'two').mkdir()
        with patch.object(sc01_trial,'MAX_FILES',1):
            with self.assertRaisesRegex(ValueError,'limit'):sc01_trial.inventory(tree)

    def test_clean_package_can_prepare_and_disclose_without_checkout_imports(self):
        from scripts.package_plugin import build
        import zipfile
        archive=self.folder/'plugin.zip';build(archive)
        bundle=self.folder/'bundle'
        with zipfile.ZipFile(archive) as z:z.extractall(bundle)
        selected=[]
        for case in ('baseline','cached'):selected.append(bundle/'tests/fixtures/order-load'/(case+'.json'))
        def invoke(*args):
            p=subprocess.run([sys.executable,'-B','-X','utf8',str(bundle/'scripts/sc01_blind.py'),*map(str,args)],
                cwd=self.folder,capture_output=True,timeout=30)
            self.assertEqual(p.returncode,0,(p.stdout+p.stderr).decode('utf-8','replace'))
            return json.loads(p.stdout)
        prepared=invoke('prepare','--output',self.trial,'--before',selected[0],'--after',selected[1])
        self.assertEqual(prepared['status'],'prepared');self.assertFalse((self.trial/'diagnosis/state').exists())
        released=invoke('release','--output',self.trial,'--response',self.answer(insufficient=True))
        self.assertEqual(released['status'],'released');self.assertEqual(invoke('status','--output',self.trial)['status'],'released')


if __name__=='__main__':unittest.main()
