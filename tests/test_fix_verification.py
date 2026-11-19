"""Verification reads sealed measurements and keeps the five outcomes independent."""
import json
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import artifacts, investigations, operations, storage
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

    def test_case_apdex_uses_the_same_target_and_keeps_comparability_and_correctness_separate(self):
        from src.techexpert import context_intake, investigation_materials
        from src.techexpert.update_state import inspect_state

        fixtures = Path(__file__).parent / 'fixtures/order-load'
        for name, label in [('baseline', 'before'), ('cached', 'after'), ('cached', 'after-copy')]:
            case = storage.investigate(fixtures / (name + '.json'), self.state)
            self.attachments.append(dict(id='A-' + label, kind='case', target_id=case['case_id']))
        doc = self.investigation()
        goal = dict(kind='apdex', value=.9, target_seconds=4)
        request = self.request(doc, goal=goal, minimum_observations=1)
        completed = operations.run(self.state, request)
        self.assertEqual(completed['status'], 'succeeded', completed)
        result = completed['data']['result']
        self.assertEqual((result['before']['value'], result['after']['value']), (.5, 1))
        self.assertEqual(result['goal']['status'], 'reached')
        self.assertEqual(result['effect']['observed_direction'], 'better')
        self.assertEqual(result['effect']['status'], 'unknown')
        self.assertEqual(result['comparability']['status'], 'unknown')
        self.assertEqual(result['result_correctness'], 'not_verified')
        self.assertEqual(result['recurrence']['status'], 'unknown')

        intake = dict(request, operation_key='linked-case-apdex', context=dict(
            investigation_id=doc['investigation_id'], expected_revision=doc['revision']))
        attached = context_intake.acquire(self.state, context_intake.prepare(intake))
        self.assertEqual(attached['attachment_status'], 'attached')
        linked = investigations.load(self.state, doc['investigation_id'])
        self.assertIn('После изменения APDEX 1.0 по 1 наблюдениям.', investigations.render(linked))
        self.assertEqual(linked['assessment'], doc['assessment'])
        self.assertIn(2, inspect_state(self.state)['schemata']['fix-verification'])
        materials = investigation_materials.view(self.state, doc['investigation_id'], category='evidence')
        evidence, = materials['entries']
        self.assertEqual(evidence['evidence_id'], attached['attachment']['evidence_id'])
        self.assertTrue(evidence['depends_on_copies'])
        self.assertEqual(materials['categories']['copies']['dependent_evidence'], 1)

        duplicate = self.request(doc, goal=goal, after=dict(attachments=['A-after', 'A-after-copy']))
        duplicate['operation_key'] += '-duplicate'
        result = operations.run(self.state, duplicate)['data']['result']
        self.assertEqual(result['after']['counts']['duplicate_observations'], 1)
        self.assertIsNone(result['after']['value'])
        self.assertEqual(result['goal']['status'], 'unknown')

        overlap = self.request(doc, goal=goal, before=dict(attachments=['A-after-copy']))
        overlap['operation_key'] += '-overlap'
        result = operations.run(self.state, overlap)
        self.assertEqual(result['status'], 'invalid_input', result)
        self.assertIn('same verified execution evidence', result['message'])

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

    def test_protected_verification_links_and_discloses_only_reviewed_measurements(self):
        import io

        from src.techexpert import context_disclosure, context_intake, context_policy, kernel, mcp_tools
        from src.techexpert.update_state import inspect_state

        private = 'private-verification-label'
        before, _ = self.measurements('before', 16, [5, 2])
        after, after_id = self.measurements('after', 17, [1, 2])
        later, _ = self.measurements('later', 18, [9, None])
        doc = self.investigation()
        iid, revision = doc['investigation_id'], doc['revision']
        request = self.request(doc, measure=private, conditions=dict(workload=private), observation=dict(
            attachments=['A-later'], window=dict(start='2026-11-18T10:00:00Z', end='2026-11-18T11:00:00Z'),
            threshold_seconds=4))
        with self.assertRaises(InputError):
            context_intake.prepare(request)
        with self.assertRaisesRegex(InputError, 'exact investigation revision'):
            context_intake.prepare(dict(request, context=dict(investigation_id=iid, expected_revision=1)))
        self.assertFalse((self.state / 'operations').exists())

        tool_args = {key: value for key, value in request.items() if key != 'schema_version'}
        call_args = dict(tool_args, context=dict(investigation_id=iid, expected_revision=revision))
        action, _, prepared = mcp_tools.prepare('techexpert_context_intake', call_args, 'context')
        self.assertEqual(action, 'context-intake')
        acquired = context_intake.acquire(self.state, prepared)
        self.assertEqual(acquired['status'], 'succeeded', acquired)
        self.assertEqual(set(acquired['data']), {'material'})
        self.assertNotIn(private, json.dumps(acquired))
        link = acquired['attachment']
        self.assertEqual(link['revision'], revision + 1)
        linked = investigations.load(self.state, iid)
        evidence = linked['evidence'][0]
        self.assertEqual((evidence['id'], evidence['attachment'], evidence['record']),
                         (link['evidence_id'], link['id'], 'report'))
        self.assertEqual(evidence['proof']['method'], 'fix-verification-v1')
        self.assertEqual(evidence['proof']['revision'], revision)
        self.assertEqual(linked['assessment'], doc['assessment'])
        self.assertEqual(linked['analysis_basis_sha256'], doc['analysis_basis_sha256'])
        self.assertEqual(inspect_state(self.state)['schemata']['context-intake'], [2])

        selection = dict(investigation_id=iid, revision=link['revision'], attachment=link['id'], kind='fix-summary')
        with patch.object(artifacts, 'load_artifact', side_effect=AssertionError('opened before policy')):
            self.assertEqual(context_disclosure.read(self.state, selection)['stop_reason'], 'context_policy_required')
            approval = (self.state, iid, revision, ['case'], 4096)
            context_policy.save(*approval, context_policy.plan(*approval)['plan_sha256'])
            self.assertEqual(context_disclosure.read(self.state, selection)['stop_reason'], 'context_category_not_allowed')
        approval = (self.state, iid, revision, ['case', 'comparison'], 4096)
        context_policy.save(*approval, context_policy.plan(*approval)['plan_sha256'])

        def emit(call):
            stream = io.StringIO()
            kernel.emit(call, stream)
            self.assertNotIn(private, stream.getvalue())
            return json.loads(stream.getvalue())

        direct = emit(kernel.invoke(self.state, 'context-read', dict(selection=context_disclosure.compact(selection))))
        self.assertEqual(direct['status'], 'succeeded', direct)
        self.assertEqual(direct['disclosure']['category'], 'comparison')
        self.assertEqual(direct['disclosure']['source_report_sha256'], evidence['proof']['sha256'])
        data = direct['data']
        self.assertEqual(data['application']['status'], 'reported')
        self.assertEqual(data['comparability']['status'], 'unknown')
        self.assertEqual(data['effect']['observed_direction'], 'better')
        self.assertEqual(data['effect']['status'], 'unknown')
        self.assertEqual(data['goal']['status'], 'not_reached')
        self.assertEqual(data['after']['value'], .75)
        self.assertEqual(data['recurrence']['status'], 'observed')
        self.assertEqual(data['recurrence']['unknown_duration'], 1)
        self.assertIsNone(data['recurrence']['complete_coverage'])
        self.assertNotIn('2026-11-18T', json.dumps(data))

        view = dict(attachment=link['id'], kind='fix-summary')
        program = ('summary = api("context.read", ' + json.dumps(view) + ')["data"]\n'
                   'return {"goal": summary["goal"]["status"], "score": summary["after"]["value"]}')
        spec = self.root / 'program.json'
        spec.write_text(json.dumps(dict(schema_version=1, operation='code.context', operation_key='fix-summary',
            executor_id='test-harness', context=dict(investigation_id=iid, expected_revision=link['revision']),
            arguments=dict(program=program, scope=dict(views=[view])))), encoding='utf-8')

        def run_program():
            return emit(kernel.invoke(self.state, 'run', dict(request=str(spec))))

        projected = run_program()
        self.assertEqual(projected['status'], 'succeeded', projected)
        self.assertEqual(projected['data']['value'], dict(goal='not_reached', score=.75))
        observed = inspect_state(self.state)
        self.assertEqual(observed['activity'], 'idle_observed')
        self.assertEqual(observed['schemata']['context-disclosure'], [1, 4])
        self.assertEqual(observed['schemata']['context-program'], [4])

        for source in (before, after, later):
            source.unlink()
        replay = context_intake.acquire(self.state, prepared)
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['attachment'], link)
        self.assertEqual(investigations.load(self.state, iid)['revision'], link['revision'])
        self.assertTrue(run_program()['replayed'])
        saved = self.state / 'artifacts' / after_id / 'sources' / 's1.bin'
        saved.write_bytes(saved.read_bytes() + b' ')
        self.assertEqual(context_disclosure.read(self.state, selection)['stop_reason'], 'context_evidence_unavailable')
        self.assertIsNone(run_program().get('data'))

    def test_protected_verification_can_attach_after_an_intervening_revision(self):
        from src.techexpert import context_intake

        self.measurements('after', 17, [1, 2])
        doc = self.investigation()
        iid, revision = doc['investigation_id'], doc['revision']
        request = self.request(doc, before=dict(attachments=[]))
        prepared = context_intake.prepare(dict(request, context=dict(investigation_id=iid, expected_revision=revision)))
        saved = operations.run(self.state, prepared)
        self.assertEqual(saved['status'], 'succeeded', saved)
        intervening = investigations.revise(self.state, iid, dict(open_questions=['Private clarification']),
                                            expected_revision=revision)
        conflict = context_intake.acquire(self.state, prepared)
        self.assertEqual(conflict['attachment_status'], 'revision_conflict')
        attached = context_intake.attach(self.state, saved['run_id'], intervening['revision'])
        self.assertEqual(attached['attachment_status'], 'attached', attached)
        link = attached['attachment']
        self.assertEqual(link['revision'], intervening['revision'] + 1)
        current = investigations.load(self.state, iid)
        self.assertEqual(current['open_questions'], intervening['open_questions'])
        self.assertEqual(current['evidence'][0]['proof']['revision'], revision)
        self.assertEqual(current['evidence'][0]['id'], link['evidence_id'])
        self.assertEqual(context_intake.attach(self.state, saved['run_id'], intervening['revision'])['attachment'], link)
        self.assertEqual(context_intake.acquire(self.state, prepared)['attachment'], link)

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
