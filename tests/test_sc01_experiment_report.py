"""Offline accounting for the planned SC-01 comparison."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.sc01_experiment_report import summarize
from src.techexpert.inputs import InputError


class SC01ExperimentReportTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        self.schedule = self.root / 'schedule.json'
        self.receipts = self.root / 'receipts.json'
        self.write_json(self.schedule, {
            'schema_version': 1,
            'schedule': [
                dict(case='SC-01', series=series, repeat=repeat, position=position, method=method)
                for series in ('first_start', 'prepared_start')
                for repeat in range(1, 6)
                for position, method in enumerate(('cli', 'direct_mcp', 'code_mode'), 1)
            ],
        })

    def write_json(self, path, data):
        path.write_text(json.dumps(data), encoding='utf-8')

    def results(self, *attempts):
        self.write_json(self.receipts, dict(
            schema_version=1, schedule_sha256=hashlib.sha256(self.schedule.read_bytes()).hexdigest(),
            codex_cli_version='0.164.0', attempts=list(attempts),
        ))
        return summarize(self.schedule, self.receipts)

    def trace(self, name, thread, usage=None, tail=b''):
        events = [
            dict(type='thread.started', thread_id=thread),
            dict(type='turn.started'),
            dict(type='item.started', item=dict(type='command_execution', id='item_0')),
            dict(type='item.completed', item=dict(type='command_execution', id='item_0')),
        ]
        if usage is not None:
            events.append(dict(type='turn.completed', usage=usage))
        raw = b''.join(json.dumps(event).encode() + b'\n' for event in events) + tail
        (self.root / name).write_bytes(raw)
        return dict(path=name, sha256=hashlib.sha256(raw).hexdigest())

    def attempt(self, repeat, logs, *, outcome='completed', reviewed=True):
        quality = dict(verdict='pass', review_sha256='a' * 64) if reviewed else None
        return dict(series='first_start', method='cli', repeat=repeat,
                    outcome=outcome, elapsed_ms=1000, logs=logs, quality=quality)

    def first_cli(self, report):
        return next(group for group in report['groups']
                    if group['series'] == 'first_start' and group['method'] == 'cli')

    def app_server_trace(self, name, thread, second='completed', *, second_total=150, second_kind='commandExecution'):
        events = [dict(method='thread/started', params=dict(thread=dict(id=thread)))]
        for turn, total, kind in (('turn-1', 100, 'mcpToolCall'), ('turn-2', second_total, second_kind)):
            identity = dict(threadId=thread, turnId=turn)
            events.append(dict(method='turn/started', params=dict(threadId=thread, turn=dict(id=turn, status='inProgress'))))
            item = dict(type=kind, id='same-local-item-id', status='inProgress')
            events.append(dict(method='item/started', params=dict(**identity, item=item)))
            if total is not None:
                usage = dict(totalTokens=total, inputTokens=total-12, cachedInputTokens=4,
                             outputTokens=12, reasoningOutputTokens=2)
                events.append(dict(method='thread/tokenUsage/updated', params=dict(**identity, tokenUsage=dict(total=usage))))
            if turn == 'turn-2' and second == 'unterminated':
                break
            terminal = dict(item, status='completed')
            if kind == 'commandExecution':
                terminal['exitCode'] = 3
            elif kind == 'dynamicToolCall':
                terminal['success'] = False
            else:
                terminal['result'] = dict(isError=False)
            notice = dict(method='item/completed', params=dict(**identity, item=terminal))
            events.extend((notice, notice))
            events.append(dict(method='turn/completed', params=dict(threadId=thread,
                turn=dict(id=turn, status=second if turn=='turn-2' else 'completed'))))
        raw = b''.join(json.dumps(event).encode() + b'\n' for event in events)
        (self.root / name).write_bytes(raw)
        return dict(path=name,sha256=hashlib.sha256(raw).hexdigest(),format='codex_app_server_v2')

    def test_all_planned_slots_are_retained_when_no_results_are_available(self):
        report = summarize(self.schedule)
        self.assertEqual(len(report['attempts']), 30)
        self.assertTrue(all(attempt['outcome'] == 'not_recorded' for attempt in report['attempts']))
        self.assertTrue(all(group['planned'] == 5 for group in report['groups']))
        self.assertIsNone(self.first_cli(report)['metrics']['total_tokens']['observed_total'])

    def test_resume_counts_latest_cumulative_usage_and_includes_failed_attempt_cost(self):
        full = dict(input_tokens=300, cached_input_tokens=200, output_tokens=80, reasoning_output_tokens=30)
        early = dict(input_tokens=100, cached_input_tokens=70, output_tokens=25, reasoning_output_tokens=10)
        start = self.trace('start.jsonl', 'one', early)
        resume = self.trace('resume.jsonl', 'one', full)
        rows = [self.attempt(1, [start, resume])]
        for repeat in range(2, 6):
            log = self.trace(f'{repeat}.jsonl', f'thread-{repeat}', early)
            rows.append(self.attempt(repeat, [log], outcome='failed', reviewed=False))
        report = self.results(*rows)
        first = report['attempts'][0]
        self.assertEqual(first['usage']['total_tokens'], 380)
        self.assertEqual(first['logs'][0]['observed_items']['command_execution'], 1)
        group = self.first_cli(report)
        self.assertEqual(group['outcomes'], {'completed': 1, 'failed': 4})
        self.assertEqual(group['metrics']['total_tokens']['observed_total'], 880)
        self.assertEqual(group['tokens_per_reported_success'], 880)
        self.assertIsNone(group['metrics']['cache_write_input_tokens']['observed_total'])

    def test_incomplete_or_default_usage_stays_unknown_with_observed_prefix_preserved(self):
        early = dict(input_tokens=100, output_tokens=25)
        start = self.trace('start.jsonl', 'one', early)
        broken = self.trace('resume.jsonl', 'one', tail=b'{"type":"item.')
        default = self.trace('empty-usage.jsonl', 'two', dict(input_tokens=0, output_tokens=0, cached_input_tokens=0))
        report = self.results(
            self.attempt(1, [start, broken], outcome='interrupted', reviewed=False),
            self.attempt(2, [default], reviewed=False),
        )
        first = report['attempts'][0]
        self.assertIsNone(first['usage']['total_tokens'])
        self.assertEqual(first['logs'][0]['cumulative_usage']['total_tokens'], 125)
        self.assertEqual(first['logs'][1]['status'], 'malformed')
        # Schedule order puts the CLI slot for repeat two after the first three methods.
        second = report['attempts'][3]
        self.assertEqual(second['logs'][0]['status'], 'completed')
        self.assertIsNone(second['usage']['input_tokens'])
        self.assertIsNone(self.first_cli(report)['tokens_per_reported_success'])

    def test_wrong_snapshot_or_cross_attempt_thread_is_rejected(self):
        usage = dict(input_tokens=1, output_tokens=1)
        one = self.trace('first.jsonl', 'one', usage)
        two = self.trace('second.jsonl', 'one', usage)
        with self.assertRaisesRegex(InputError, 'thread reused'):
            self.results(self.attempt(1, [one]), self.attempt(2, [two]))
        with (self.root / one['path']).open('ab') as stream:
            stream.write(b'\n')
        with self.assertRaisesRegex(InputError, 'trace integrity'):
            self.results(self.attempt(1, [one]))

    def test_resumed_turn_returning_only_the_restored_usage_does_not_cover_both_phases(self):
        usage = dict(input_tokens=100, output_tokens=25)
        start = self.trace('first.jsonl', 'one', usage)
        resume = self.trace('resume.jsonl', 'one', usage)
        row = self.results(self.attempt(1, [start, resume]))['attempts'][0]
        self.assertIsNone(row['usage']['total_tokens'])
        self.assertEqual(row['logs'][1]['cumulative_usage']['total_tokens'], 125)

    def test_overlong_trace_member_is_rejected_before_resolving_ancestors(self):
        nested = '/'.join(['directory'] * 30 + ['trace.jsonl'])
        with self.assertRaisesRegex(InputError, 'trace path limit'):
            self.results(self.attempt(1, [dict(path=nested, sha256='a' * 64)]))

    def test_native_two_turn_trace_counts_cumulative_usage_and_tools_once(self):
        trace = self.app_server_trace('native.jsonl', 'native-thread')
        report = self.results(self.attempt(1, [trace]))
        attempt = report['attempts'][0]
        self.assertEqual(attempt['usage']['total_tokens'], 150)
        self.assertEqual(attempt['usage']['reasoning_output_tokens'], 2)
        self.assertIsNone(attempt['usage']['cache_write_input_tokens'])
        self.assertEqual(attempt['logs'][0]['observed_turns'], 2)
        self.assertEqual(attempt['logs'][0]['observed_items'],
                         dict(command_execution=1,mcp_tool_call=1,dynamic_tool_call=0))
        self.assertEqual(attempt['logs'][0]['observed_failed_items']['command_execution'], 1)
        self.assertEqual(self.first_cli(report)['metrics']['observed_mcp_tool_calls']['observed_total'], 1)
        self.assertEqual(report['token_scope'], 'reported_cumulative_codex_app_server_0.164.0_thread')

    def test_native_incomplete_or_missing_final_usage_does_not_complete_cost(self):
        first = self.app_server_trace('interrupted.jsonl', 'interrupted-thread', 'unterminated')
        second = self.app_server_trace('missing.jsonl', 'missing-thread', second_total=None)
        third = self.app_server_trace('regressed.jsonl', 'regressed-thread', second_total=80)
        report = self.results(self.attempt(1, [first], outcome='interrupted', reviewed=False),
                              self.attempt(2, [second]), self.attempt(3, [third]))
        by_repeat = {row['repeat']:row for row in report['attempts'] if row['method']=='cli' and row['series']=='first_start'}
        self.assertEqual(by_repeat[1]['logs'][0]['status'], 'interrupted')
        self.assertEqual(by_repeat[1]['logs'][0]['cumulative_usage']['total_tokens'], 150)
        self.assertEqual(by_repeat[1]['logs'][0]['observed_unfinished_items']['command_execution'], 1)
        self.assertEqual(by_repeat[2]['logs'][0]['cumulative_usage']['total_tokens'], 100)
        self.assertEqual(by_repeat[3]['logs'][0]['cumulative_usage']['total_tokens'], 100)
        self.assertTrue(all(row['usage']['total_tokens'] is None for row in by_repeat.values()))

    def test_native_session_cannot_be_combined_with_another_log_for_one_attempt(self):
        native = self.app_server_trace('native.jsonl', 'native-thread')
        cli = self.trace('command.jsonl', 'native-thread', dict(input_tokens=3,output_tokens=1))
        with self.assertRaisesRegex(InputError, 'one native App Server transcript'):
            self.results(self.attempt(1, [native,cli]))

    def test_native_foreign_thread_usage_cannot_complete_an_attempt(self):
        ref = self.app_server_trace('foreign.jsonl', 'good-thread')
        path = self.root / ref['path']
        raw = path.read_bytes().replace(
            b'"threadId": "good-thread", "turnId": "turn-2", "tokenUsage"',
            b'"threadId": "other-thread", "turnId": "turn-2", "tokenUsage"')
        self.assertNotEqual(raw, path.read_bytes())
        path.write_bytes(raw)
        ref['sha256'] = hashlib.sha256(raw).hexdigest()
        result = self.results(self.attempt(1, [ref]))['attempts'][0]
        self.assertEqual(result['logs'][0]['status'], 'malformed')
        self.assertEqual(result['logs'][0]['cumulative_usage']['total_tokens'], 100)
        self.assertIsNone(result['usage']['total_tokens'])

    def test_native_dynamic_tool_can_return_unsuccessful_terminal_result(self):
        trace = self.app_server_trace('dynamic.jsonl', 'dynamic-thread', second_kind='dynamicToolCall')
        result = self.results(self.attempt(1,[trace]))['attempts'][0]['logs'][0]
        self.assertEqual(result['observed_items']['dynamic_tool_call'], 1)
        self.assertEqual(result['observed_failed_items']['dynamic_tool_call'], 1)
