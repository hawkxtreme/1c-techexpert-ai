import io
import json
from pathlib import Path
import tempfile
import unittest

from src.techexpert import context_disclosure, context_policy, investigations, kernel, storage


PRIVATE = 'sensitive-value-in-context-program-fixture'
PROGRAM = '''offset = 0
count = 0
total = 0
while True:
    page = api("context.read", {"kind": "tj-events", "attachment": "A-1", "offset": offset, "limit": 1})["data"]
    for row in page["records"]:
        count = count + 1
        total = total + row["duration_us"]
    offset = page["next_offset"]
    if offset is None:
        break
return {"count": count, "total_us": total}
'''


class ContextProgramTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / 'state'
        self.original = self.root / (PRIVATE + '.log')
        self.original.write_text(
            '10:00.000000-10,CALL,1,UserName=' + PRIVATE + ',Context=private text\n'
            '11:00.000000-30,CALL,1,UserName=' + PRIVATE + '\n', encoding='utf-8')
        manifest = self.root / 'source.json'
        self.write(manifest, dict(schema=2, origin='provided', sources=[dict(
            path=str(self.original), format='1c-tj-text-v1', platform_version='8.3.27.1989',
            encoding='utf-8', placement='folders', timestamp_format='minute', rotation_hours=1,
            file_hour='2026-11-15T09:00:00+03:00')]))
        self.case = storage.investigate(manifest, self.state)
        first = investigations.create(self.state, dict(task=PRIVATE))
        self.iid = first['investigation_id']
        doc = investigations.revise(self.state, self.iid, dict(attachments=[
            dict(id='A-1', kind='case', target_id=self.case['case_id']),
            dict(id='A-2', kind='case', target_id=self.case['case_id']),
        ]), expected_revision=1)
        self.revision = doc['revision']

    def write(self, file, data):
        file.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
        return file

    def approve(self, categories=('tj',), max_bytes=4096):
        arguments = (self.state, self.iid, self.revision, list(categories), max_bytes)
        preview = context_policy.plan(*arguments)
        return context_policy.save(*arguments, preview['plan_sha256'])

    def prepare(self, source=PROGRAM, *, key='context-scope', resources=None, wire_version=None):
        arguments = dict(program=source, scope=dict(views=[dict(attachment='A-1', kind='tj-events')]))
        if resources is not None:
            arguments['resources'] = resources
        request = dict(schema_version=1, operation_key=key, executor_id='tests', operation='code.context',
                       arguments=arguments, context=dict(investigation_id=self.iid, expected_revision=self.revision))
        name = self.write(self.root / ('request-' + key + '.json'), request)
        return kernel.invoke(self.state, 'run', dict(request=str(name)), wire_version=wire_version)

    def emit(self, call):
        stream = io.StringIO()
        kernel.emit(call, stream)
        self.assertNotIn(PRIVATE, stream.getvalue())
        return json.loads(stream.getvalue())

    def test_combines_the_same_allowed_pages_and_replays_without_new_reads(self):
        self.approve()
        direct = context_disclosure.read(self.state, dict(investigation_id=self.iid, revision=self.revision,
            attachment='A-1', kind='tj-events', limit=2))
        result = self.emit(self.prepare())
        self.assertEqual(result['status'], 'succeeded', result)
        self.assertEqual(result['data']['value'], dict(count=2, total_us=sum(
            item['duration_us'] for item in direct['data']['records'])))
        self.assertEqual(result['data']['metrics']['calls_started'], 2)
        self.assertEqual(len(result['snapshots']), 1)
        self.assertEqual(len(list((self.state / 'operations').iterdir())), 1)
        before = context_disclosure.history(self.state, self.iid, self.revision)
        self.original.unlink()
        another = self.emit(self.prepare())
        self.assertTrue(another['replayed'])
        self.assertEqual(another['data']['value'], result['data']['value'])
        self.assertEqual(context_disclosure.history(self.state, self.iid, self.revision), before)

    def test_comparison_explains_recurrence_limit_even_when_a_program_selects_only_effect(self):
        from test_comparison_storage import saved_series

        before, after = saved_series(self.state)
        comparison = storage.compare_cases(self.state, before, after)
        view = dict(attachment='A-comparison', kind='comparison')
        doc = investigations.revise(self.state, self.iid, dict(attachments=[
            dict(id=view['attachment'], kind='comparison', target_id=comparison['comparison_id'])]),
            expected_revision=self.revision)
        self.revision = doc['revision']
        self.approve(('comparison',))
        selection = context_disclosure.compact(dict(view, investigation_id=self.iid, revision=self.revision))
        source = 'sample = api("context.read", ' + json.dumps(view) + ')["data"]\nreturn sample["performance"]["status"]'
        request = self.write(self.root / 'comparison-program.json', dict(schema_version=1, operation='code.context',
            operation_key='comparison-effect', executor_id='tests',
            context=dict(investigation_id=self.iid, expected_revision=self.revision),
            arguments=dict(program=source, scope=dict(views=[view]))))

        cli = self.emit(kernel.invoke(self.state, 'context-read', dict(selection=selection)))
        mcp = self.emit(kernel.invoke(self.state, 'context-read', dict(selection=selection), wire_version='2025-11-25'))
        program = self.emit(kernel.invoke(self.state, 'run', dict(request=str(request)), wire_version='2025-11-25'))
        projected = program['structuredContent']
        self.assertEqual(projected['status'], 'succeeded', projected)
        self.assertEqual(projected['data']['value'], 'improved')
        history = context_disclosure.history(self.state, self.iid, self.revision)
        replay = self.emit(kernel.invoke(self.state, 'result', dict(run_id=projected['run_id'])))
        self.assertTrue(replay['replayed'])
        self.assertEqual(context_disclosure.history(self.state, self.iid, self.revision), history)
        for entrypoint, reply in (('cli', cli), ('mcp', mcp['structuredContent']),
                                  ('program', projected), ('program replay', replay)):
            with self.subTest(entrypoint=entrypoint):
                self.assertEqual(reply['status'], 'succeeded', reply)
                self.assertIn('Recurrence is unknown', ' '.join(reply['limitations']))

    def test_policy_is_required_and_scope_cannot_be_expanded_inside_program(self):
        denied = self.emit(self.prepare())
        self.assertEqual(denied['data']['diagnostic']['code'], 'context_policy_required')
        self.assertEqual(denied['data']['metrics']['calls_started'], 0)
        self.approve()
        for index, source in enumerate((
            'return api("case.evidence", {"case_id": "not-approved", "evidence_id": "s1:1"})',
            'return api("context.read", {"attachment": "A-2", "kind": "tj-events"})',
            'return api("context.read", {"attachment": "A-1", "kind": "tj-events", "revision": 1})',
        )):
            result = self.emit(self.prepare(source, key='refuse-' + str(index)))
            self.assertEqual(result['status'], 'invalid_input', result)
            self.assertEqual(result['data']['metrics']['calls_started'], 0)
        self.assertEqual(context_disclosure.history(self.state, self.iid, self.revision)['entries'], [])

    def test_current_policy_gates_sealed_cli_and_replay_results(self):
        self.approve()
        prepared = self.prepare()
        self.assertEqual(prepared['exit_code'], 0)
        self.approve(())
        revoked = self.emit(prepared)
        self.assertEqual(revoked['stop_reason'], 'context_policy_changed')
        self.assertIsNone(revoked['data'])
        repeated = self.emit(self.prepare())
        self.assertIsNone(repeated['data'])
        self.assertEqual(repeated['stop_reason'], 'context_policy_changed')
        replay = self.emit(kernel.invoke(self.state, 'result', dict(run_id=revoked['run_id'])))
        self.assertEqual(replay['stop_reason'], 'context_policy_changed')
        self.assertIsNone(replay['data'])

    def test_program_output_and_api_call_budgets_are_independent(self):
        self.approve()
        blocked = self.emit(self.prepare('return "x" * 5000', key='too-large'))
        self.assertEqual(blocked['data']['diagnostic']['code'], 'context_output_limit')
        self.assertIsNone(blocked['data']['value'])
        limited = self.emit(self.prepare(key='too-many', resources=dict(max_calls=1)))
        self.assertEqual(limited['status'], 'partial', limited)
        self.assertEqual(limited['data']['diagnostic']['code'], 'call_limit')
        self.assertEqual(limited['data']['metrics']['calls_started'], 1)

    def test_inspection_omits_program_text_and_damaged_views_block_replay(self):
        self.approve()
        source = '# ' + PRIVATE + '\n' + PROGRAM
        saved = self.emit(self.prepare(source))
        run_id = saved['run_id']
        request = self.write(self.root / 'inspect.json', dict(schema_version=1, operation_key='inspect-context',
            executor_id='tests', operation='code.inspect', arguments=dict(run_id=run_id)))
        checked = self.emit(kernel.invoke(self.state, 'run', dict(request=str(request))))
        self.assertEqual(checked['status'], 'succeeded', checked)
        self.assertTrue(checked['data']['protected_context'])
        self.assertEqual(checked['data']['program'], '')
        self.assertEqual(len(checked['data']['calls']), 2)

        before = context_disclosure.history(self.state, self.iid, self.revision)
        view = self.state / 'operations' / run_id / 'context-view-001.json'
        view.write_text(PRIVATE, encoding='utf-8')
        for call in (kernel.invoke(self.state, 'result', dict(run_id=run_id)), self.prepare(source)):
            blocked = self.emit(call)
            self.assertEqual(blocked['status'], 'invalid_input', blocked)
            self.assertIsNone(blocked['data'])
        self.assertEqual(context_disclosure.history(self.state, self.iid, self.revision), before)

    def test_mcp_partial_reply_is_withheld_in_both_representations(self):
        self.approve()
        prepared = self.prepare(key='partial-mcp', resources=dict(max_calls=1), wire_version='2025-11-25')
        partial = self.emit(prepared)['structuredContent']
        self.assertEqual(partial['status'], 'partial', partial)
        self.assertEqual(len(partial['data']['calls']), 2)
        self.approve(())
        blocked = self.emit(prepared)
        self.assertTrue(blocked['isError'])
        structured = blocked['structuredContent']
        self.assertEqual(json.loads(blocked['content'][0]['text']), structured)
        self.assertEqual(structured['run_id'], partial['run_id'])
        self.assertEqual(structured['operation'], 'code.context')
        self.assertEqual(structured['stop_reason'], 'context_policy_changed')
        self.assertIsNone(structured['data'])
