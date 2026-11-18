"""Verification reads sealed measurements and keeps the five outcomes independent."""
import json
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import artifacts, investigations, operations
from src.techexpert.inputs import InputError


class FixVerificationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root/'state'
        self.attachments = []

    def measurements(self, label, day, durations, *, import_target=3, failed=()):
        rows = [dict(id=f'{label}-{index}',operation='OrderLoad',started_at=f'2026-11-{day}T10:{index:02d}:00Z',
                     success=index not in failed,duration_seconds=elapsed) for index,elapsed in enumerate(durations)]
        source = self.root/(label+'.json')
        source.write_text(json.dumps(rows),encoding='utf-8')
        result = artifacts.import_apdex(self.state,source,import_target)
        self.attachments.append(dict(id='A-'+label,kind='artifact',target_id=result['artifact_id']))
        return source,result['artifact_id']

    def investigation(self):
        created = investigations.create(self.state,dict(task='Check order loading after a change.'))
        iid = created['investigation_id']
        assessment = dict(summary='Cause still needs separate observations.',cause_state='insufficient_data',
                          evidence=[],limitations=[],recommendations=[],references=[])
        return investigations.revise(self.state,iid,dict(attachments=self.attachments,assessment=assessment),expected_revision=1)

    def request(self, document, **changes):
        arguments = dict(investigation_id=document['investigation_id'],revision=document['revision'],
            measure='Change in order loading',operation='OrderLoad',control='Repeat the selected workload.',
            applied='reported',minimum_observations=2,goal=dict(kind='apdex',value=.8,target_seconds=1),
            before=dict(attachments=['A-before']),after=dict(attachments=['A-after']))
        arguments.update(changes)
        return dict(schema_version=1,operation_key='verified-fix',executor_id='test-harness',
                    operation='fix.verify',arguments=arguments)

    def test_shared_apdex_target_and_scoped_recurrence_replay_from_retained_bytes(self):
        before,_ = self.measurements('before',16,[5,2],import_target=10)
        after,after_id = self.measurements('after',17,[1,2],import_target=6)
        followup,_ = self.measurements('later',18,[2,9,13])
        doc = self.investigation()
        window = dict(start='2026-11-18T10:00:00Z',end='2026-11-18T10:02:00Z')
        request = self.request(doc,observation=dict(attachments=['A-later'],window=window,threshold_seconds=4))
        completed = operations.run(self.state,request)
        self.assertEqual(completed['status'],'succeeded',completed)
        result = completed['data']['result']
        self.assertEqual(result['application']['status'],'reported')
        self.assertEqual(result['before']['value'],.25)
        self.assertEqual(result['after']['value'],.75)
        self.assertEqual(result['effect']['observed_direction'],'better')
        self.assertEqual(result['effect']['status'],'unknown')
        self.assertEqual(result['goal']['status'],'not_reached')
        self.assertEqual(result['recurrence']['status'],'observed')
        self.assertEqual(result['recurrence']['breaches'],1)
        self.assertEqual(result['recurrence']['evidence'][0]['row_index'],2)
        self.assertIsNone(result['recurrence']['complete_coverage'])
        self.assertNotIn(str(self.root),json.dumps(completed['data']))

        for path in (before,after,followup):
            path.unlink()
        replay = operations.run(self.state,request)
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['data'],completed['data'])
        artifact = completed['data']['artifact_id']
        linked = investigations.revise(self.state,doc['investigation_id'],dict(attachments=doc['attachments']+[
            dict(id='A-verification',kind='artifact',target_id=artifact)],
            evidence=[dict(id='E-verification',attachment='A-verification',record='report')]),expected_revision=2)
        self.assertEqual(linked['evidence'][0]['proof']['method'],'fix-verification-v1')
        self.assertIn('цель — не достигнута',investigations.render(linked))
        self.assertEqual(linked['assessment'],doc['assessment'])
        self.assertEqual(linked['analysis_basis_sha256'],doc['analysis_basis_sha256'])

        saved = self.state/'artifacts'/after_id/'sources/s1.bin'
        saved.write_bytes(saved.read_bytes()+b' ')
        with self.assertRaises(InputError):
            operations.result(self.state,completed['run_id'])
        with self.assertRaises(InputError):
            investigations.load(self.state,doc['investigation_id'],revision=3)

    def test_current_target_without_baseline_and_clear_sample_without_continuity(self):
        self.measurements('after',17,[1,1])
        self.measurements('later',18,[1,None])
        doc = self.investigation()
        request = self.request(doc,before=dict(attachments=[]),goal=dict(kind='duration',value=1),
            observation=dict(attachments=['A-later'],window=dict(start='2026-11-18T10:00:00Z',
                end='2026-11-18T11:00:00Z'),threshold_seconds=4))
        completed = operations.run(self.state,request)
        self.assertEqual(completed['status'],'succeeded',completed)
        result = completed['data']['result']
        self.assertEqual(result['effect']['status'],'unknown')
        self.assertEqual(result['goal']['status'],'reached')
        self.assertEqual(result['recurrence']['status'],'unknown')
        self.assertEqual(result['recurrence']['unknown_duration'],1)
        self.assertIsNone(result['recurrence']['complete_coverage'])

    def test_apdex_counts_a_failure_with_no_elapsed_time_and_checks_program_scope(self):
        self.measurements('after',17,[1,None],failed=(1,))
        doc = self.investigation()
        selected = self.request(doc,before=dict(attachments=[]),goal=dict(kind='apdex',value=.5,target_seconds=1))['arguments']
        code = 'result = api("fix.verify", selected)["data"]["result"]\nreturn {"goal":result["goal"]["status"],"after":result["after"]["value"]}'
        request = dict(schema_version=1,executor_id='test-harness',operation='code.execute',operation_key='verify-denied',
                       arguments=dict(program=code,bindings=dict(selected=selected),scope=dict(operations=['fix.verify'])))
        denied = operations.run(self.state,request)
        self.assertEqual(denied['data']['diagnostic']['code'],'scope_denied')
        self.assertEqual(denied['data']['metrics']['calls_started'],0)
        request['operation_key'] = 'verify-allowed'
        request['arguments']['scope']['investigations'] = [dict(id=doc['investigation_id'],revision=doc['revision'])]
        allowed = operations.run(self.state,request)
        self.assertEqual(allowed['status'],'succeeded',allowed)
        self.assertEqual(allowed['data']['value'],dict(goal='reached',after=.5))

    def test_shared_sample_needs_disjoint_windows_and_claimed_fix_needs_evidence(self):
        self.measurements('after',17,[2,1])
        doc = self.investigation()
        request = self.request(doc,before=dict(attachments=['A-after']))
        result = operations.run(self.state,request)
        self.assertEqual(result['status'],'invalid_input')
        self.assertIn('disjoint',result['message'])
        with self.assertRaisesRegex(InputError,'selected investigation evidence'):
            operations.run(self.state,self.request(doc,applied='evidenced'))

    def test_duration_goal_requires_confirmed_completion(self):
        from src.techexpert import fix_verification, sample_description

        source_hash = 'a'*64
        metric = dict(name='execution',status='known',unit='seconds',value=2,evidence=['s1:1'])
        for state,outcome,expected in (('canceled','failed','not_reached'),
                                       ('unknown','unknown','unknown'),('completed','success','reached')):
            with self.subTest(state=state):
                report = dict(metrics=[metric],durations_seconds=dict(execution=2),job_correlation=dict(
                    job_lifecycle=dict(status='established',state=state,execution_seconds=2,execution_bounds_seconds=[1,3])))
                resource = dict(report=report,ref=dict(kind='case',id='1'*32),summary=dict(
                    sources=[dict(source_id='s1',sha256=source_hash,bytes=10)]))
                with patch('src.techexpert.storage.read_evidence',return_value=dict(sha256=source_hash,line=1)):
                    row = sample_description._case_row(self.state,resource)
                self.assertEqual(row['outcome'],outcome)
                goal = dict(kind='duration',value=5)
                data = fix_verification._Measurements(goal,'after',None)
                data.observe(row,report)
                observed = data.summary(statistics=dict(median=2),sources=['A-after'])
                self.assertEqual(fix_verification._goal(observed,goal,1)['status'],expected)

    def test_claimed_operation_context_must_match_selected_revision(self):
        self.measurements('after',17,[1,1])
        doc = self.investigation()
        request = self.request(doc,before=dict(attachments=[]))
        other = investigations.create(self.state,dict(task='Another investigation.'))
        request['context'] = dict(investigation_id=other['investigation_id'],expected_revision=1)
        with self.assertRaisesRegex(InputError,'exact investigation revision'):
            operations.run(self.state,request)

    def test_known_admissible_breach_survives_an_unplaced_or_conflicting_row(self):
        from src.techexpert import fix_verification

        goal = dict(kind='duration',value=5)
        summary = fix_verification._Measurements(goal,'after','2026-11-17T10:00:00Z')
        row = dict(kind='artifact',id='1'*32,evidence=[],outcome='success',value_seconds=9)
        summary.observe(dict(row,reason='unknown_operation_start'),{})
        summary.observe(dict(row,started_at='2026-11-17T09:00:00Z'),{})
        data = summary.summary(statistics=dict(median=9),sources=['A-after'])
        self.assertEqual(fix_verification._goal(data,goal,1)['status'],'unknown')
        summary.observe(dict(row,started_at='2026-11-17T10:00:00Z'),{})
        data = summary.summary(statistics=dict(median=9),sources=['A-after'])
        self.assertEqual(fix_verification._goal(data,goal,1)['status'],'not_reached')

    def test_comparison_used_for_application_keeps_transitive_case_impact(self):
        from test_comparison_storage import saved_series
        from src.techexpert import case_impact, storage

        before,after = saved_series(self.state)
        selected = [before[0],after[0]]
        for identifier in selected:
            folder = self.state/'cases'/identifier
            path = folder/'report.json'
            report = json.loads(path.read_bytes())
            for source in report['sources']:
                source['size'] = (folder/'sources'/(source['id']+'.bin')).stat().st_size
            storage.write_json(path,report)
            receipt = json.loads((folder/'receipt.json').read_bytes())
            receipt['report_sha256'] = sha256(path.read_bytes()).hexdigest()
            storage.write_json(folder/'receipt.json',receipt)
        comparison = storage.compare_cases(self.state,before[:1],after[:1])
        attachment = dict(id='A-comparison',kind='comparison',target_id=comparison['comparison_id'])
        created = investigations.create(self.state,dict(task='Verify the reported change.'))
        iid = created['investigation_id']
        doc = investigations.revise(self.state,iid,dict(attachments=[attachment],evidence=[
            dict(id='E-applied',attachment='A-comparison',record='report')]),expected_revision=1)
        request = self.request(doc,before=dict(attachments=[]),after=dict(attachments=[]),
                               applied='evidenced',application_evidence=['E-applied'])
        completed = operations.run(self.state,request)
        self.assertEqual(completed['status'],'succeeded',completed.get('message'))
        data = completed['data']
        self.assertEqual({item['id'] for item in data['result']['dependencies'] if item['kind']=='cases'},set(selected))
        investigations.revise(self.state,iid,dict(attachments=[dict(id='A-check',kind='artifact',target_id=data['artifact_id'])],
            evidence=[dict(id='E-check',attachment='A-check',record='report')]),expected_revision=2)
        case,digest = storage.load_case(self.state,before[0],with_digest=True)
        impacted = case_impact.observed(self.state,case,digest,'s1')['investigations']
        latest = next(item for item in impacted if item['investigation_id']==iid and item['revision']==3)
        self.assertEqual(latest['attachments'],['A-check'])
        self.assertEqual(latest['evidence'][0]['evidence_id'],'E-check')

    def test_replacing_a_verification_evidence_does_not_keep_an_old_assessment_bound_to_its_id(self):
        self.measurements('after',17,[1,1])
        doc = self.investigation()
        first = self.request(doc,before=dict(attachments=[]),goal=dict(kind='duration',value=2))
        second = self.request(doc,before=dict(attachments=[]),goal=dict(kind='duration',value=.5))
        second['operation_key'] = 'verification-second-target'
        artifacts = [operations.run(self.state,spec)['data']['artifact_id'] for spec in (first,second)]
        proof = [dict(id='E-check',attachment='A-check',record='report')]
        def attach(target):
            return doc['attachments']+[dict(id='A-check',kind='artifact',target_id=target)]
        iid = doc['investigation_id']
        selected = investigations.revise(self.state,iid,dict(attachments=attach(artifacts[0]),evidence=proof,
            assessment=dict(doc['assessment'],evidence=['E-check'])),expected_revision=2)
        self.assertEqual(selected['assessment']['evidence'],['E-check'])
        changed = investigations.revise(self.state,iid,dict(attachments=attach(artifacts[1]),evidence=proof),expected_revision=3)
        self.assertNotEqual(changed['evidence'][0]['proof']['sha256'],selected['evidence'][0]['proof']['sha256'])
        self.assertIsNone(changed['assessment'])
        self.assertEqual(changed['assessment_status'],'stale_due_to_revision')
        self.assertEqual(investigations.load(self.state,iid,revision=3),selected)
