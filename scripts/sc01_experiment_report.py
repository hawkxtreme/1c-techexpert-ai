"""Summarize the private SC-01 schedule and saved Codex 0.164.0 JSONL.

Each receipt covers one scheduled attempt. Its logs are ordered captures of a
fresh thread and any resumes of that thread. Review verdicts and elapsed time
are supplied by the experiment operator. This tool runs offline.

The receipts JSON contains schema_version=1, schedule_sha256, codex_cli_version
and attempts. Each attempt contains series, repeat, method, outcome, elapsed_ms
and logs (path relative to the receipts file and sha256). A log with format
codex_app_server_v2 contains the complete native App Server session for that
attempt. The default format is codex_cli. Quality is optional and contains a
reported verdict (pass or fail) and review_sha256 when supplied.
"""
import argparse
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import re
import stat
from statistics import median
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.sc01_trial import _relative
from src.techexpert.inputs import InputError, json_value, read_snapshot
from src.techexpert.operation_state import safe

SERIES = ('first_start', 'prepared_start')
METHODS = ('cli', 'direct_mcp', 'code_mode')
OUTCOMES = ('completed', 'failed', 'interrupted', 'limit_exceeded')
USAGE_FIELDS = ('input_tokens', 'cached_input_tokens', 'cache_write_input_tokens',
                'output_tokens', 'reasoning_output_tokens')
TOKEN_METRICS = (*USAGE_FIELDS, 'total_tokens')
ITEM_TYPES = ('command_execution', 'mcp_tool_call')
CLI_TRACE = 'codex_cli'
APP_SERVER_TRACE = 'codex_app_server_v2'
APP_SERVER_ITEMS = dict(commandExecution='command_execution', mcpToolCall='mcp_tool_call',
                        dynamicToolCall='dynamic_tool_call')
APP_SERVER_USAGE = dict(input_tokens='inputTokens', cached_input_tokens='cachedInputTokens',
                        cache_write_input_tokens='cacheWriteInputTokens', output_tokens='outputTokens',
                        reasoning_output_tokens='reasoningOutputTokens')
APP_SERVER_NOTICES = ('thread/started', 'turn/started', 'turn/completed', 'thread/tokenUsage/updated',
                      'item/started', 'item/completed')
MAX_TRACE_BYTES = 8 * 1024**2
MAX_ALL_TRACES_BYTES = 128 * 1024**2


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _file(path, limit):
    path = safe(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise InputError('an ordinary snapshot file is required')
    return read_snapshot(path, limit)


def _read_document(path):
    raw = _file(path, 128 * 1024)
    doc = json_value(raw.decode('utf-8-sig'), reject_duplicates=True)
    if not isinstance(doc, dict) or type(doc.get('schema_version')) is not int or doc['schema_version'] != 1:
        raise InputError('expected a schema_version 1 experiment document')
    return doc, _sha(raw)


def _slot(row):
    if not isinstance(row, dict):
        raise InputError('expected a scheduled attempt object')
    series, repeat, method = (row.get(key) for key in ('series', 'repeat', 'method'))
    if series not in SERIES or type(repeat) is not int or not 1 <= repeat <= 5 or method not in METHODS:
        raise InputError('invalid SC-01 attempt slot')
    return series, repeat, method


def _schedule(doc):
    rows = doc.get('schedule')
    if not isinstance(rows, list) or len(rows) != len(SERIES) * len(METHODS) * 5:
        raise InputError('SC-01 requires 30 scheduled slots')
    entries = {}
    positions = set()
    for row in rows:
        series, repeat, method = slot = _slot(row)
        position = row.get('position')
        if (row.get('case') != 'SC-01' or slot in entries or type(position) is not int
                or not 1 <= position <= 3 or (series, repeat, position) in positions):
            raise InputError('each SC-01 repeat needs all three methods and unique positions')
        positions.add((series, repeat, position))
        entries[slot] = dict(series=series, repeat=repeat, method=method, position=position)
    return entries


def _usage(value):
    missing = dict.fromkeys(TOKEN_METRICS)
    if not isinstance(value, dict):
        return missing
    fields = {key: value.get(key) for key in USAGE_FIELDS}
    if any(number is not None and (type(number) is not int or not 0 <= number < 2**63)
           for number in fields.values()):
        return missing
    inputs, outputs, cached = (fields[key] for key in ('input_tokens', 'output_tokens', 'cached_input_tokens'))
    if not any(fields.values()) or inputs is not None and cached is not None and cached > inputs:
        return missing
    # Prompt-cache and reasoning details are already reported alongside the main totals.
    return dict(fields, total_tokens=inputs + outputs if inputs is not None and outputs is not None else None)


def _trace(raw):
    thread = None
    started = False
    status = 'interrupted'
    usage = dict.fromkeys(TOKEN_METRICS)
    items = {name: set() for name in ITEM_TYPES}
    try:
        for line in io.BytesIO(raw):
            event = json_value(line.decode('utf-8'), reject_duplicates=True)
            if not isinstance(event, dict) or not isinstance(event.get('type'), str):
                raise InputError('invalid JSONL event')
            kind = event['type']
            if kind == 'thread.started':
                thread_id = event.get('thread_id')
                if thread is not None or not isinstance(thread_id, str) or not re.fullmatch('[A-Za-z0-9-]{1,128}', thread_id):
                    raise InputError('invalid or repeated JSONL thread')
                thread = thread_id
            elif kind == 'turn.started':
                if thread is None or started:
                    raise InputError('invalid or repeated JSONL turn')
                started = True
            elif kind in ('turn.completed', 'turn.failed'):
                if not started or status != 'interrupted':
                    raise InputError('unexpected JSONL terminal event')
                status = 'completed' if kind == 'turn.completed' else 'failed'
                usage = _usage(event.get('usage')) if status == 'completed' else usage
            elif kind in ('item.started', 'item.updated', 'item.completed'):
                item = event.get('item')
                if not started or status != 'interrupted' or not isinstance(item, dict) or not isinstance(item.get('type'), str):
                    raise InputError('invalid JSONL item')
                if item['type'] in items:
                    identity = item.get('id')
                    if not isinstance(identity, str) or not 1 <= len(identity) <= 128:
                        raise InputError('invalid JSONL item identity')
                    items[item['type']].add(identity)
    except (ValueError, RecursionError):
        status = 'malformed'
    if not started and status != 'malformed':
        status = 'start_unobserved'
    return dict(thread=thread, status=status, cumulative_usage=usage, observed_turns=int(started),
                observed_items={name: len(seen) for name, seen in items.items()})


def _identity(value):
    if not isinstance(value, str) or not re.fullmatch('[A-Za-z0-9-]{1,128}', value):
        raise InputError('invalid App Server thread or turn identity')
    return value


def _native_usage(value):
    if isinstance(value, dict):
        observed = _usage({key: value.get(name) for key, name in APP_SERVER_USAGE.items()})
        if (type(value.get('totalTokens')) is int and value['totalTokens'] == observed['total_tokens']
            and (observed['reasoning_output_tokens'] is None
                 or observed['reasoning_output_tokens'] <= observed['output_tokens'])):
            return observed
    return None


def _decreased(before, after):
    return any(before[key] is not None and after[key] is not None and after[key] < before[key]
               for key in TOKEN_METRICS)


def _native_item_failed(item, kind):
    if item.get('status') in ('failed', 'declined'):
        return True
    if kind == 'command_execution':
        code = item.get('exitCode')
        return type(code) is int and code != 0
    if kind == 'mcp_tool_call':
        result = item.get('result')
        return item.get('error') is not None or isinstance(result, dict) and result.get('isError') is True
    return item.get('success') is False


def _app_server_trace(raw):
    thread = None
    active = None
    turns = {}
    usage = dict.fromkeys(TOKEN_METRICS)
    last_known = usage.copy()
    turn_usage = None
    opening_total = 0
    complete_usage = True
    items = {name: {} for name in APP_SERVER_ITEMS.values()}
    malformed = False
    try:
        for line in io.BytesIO(raw):
            event = json_value(line.decode('utf-8'), reject_duplicates=True)
            if not isinstance(event, dict):
                raise InputError('invalid App Server event')
            method = event.get('method')
            if method not in APP_SERVER_NOTICES:
                continue
            params = event['params']
            if method == 'thread/started':
                if thread is not None:
                    raise InputError('an attempt must have one App Server thread')
                thread = _identity(params['thread']['id'])
                continue
            if thread is None or params['threadId'] != thread:
                raise InputError('foreign App Server event')
            if method == 'turn/started':
                identifier = _identity(params['turn']['id'])
                if active is not None or identifier in turns or params['turn']['status'] != 'inProgress':
                    raise InputError('unexpected App Server turn start')
                active = identifier
                turns[active] = 'interrupted'
                opening_total = usage['total_tokens'] or 0
                turn_usage = None
                continue
            if method == 'turn/completed':
                terminal = params['turn']['status']
                if active is None or params['turn']['id'] != active or terminal not in ('completed', 'failed', 'interrupted'):
                    raise InputError('unexpected App Server turn completion')
                turns[active] = terminal
                complete_usage = complete_usage and turn_usage is not None and turn_usage['total_tokens'] > opening_total
                active = None
                continue
            if active is None or params['turnId'] != active:
                raise InputError('event outside its App Server turn')
            if method == 'thread/tokenUsage/updated':
                turn_usage = _native_usage(params['tokenUsage']['total'])
                if turn_usage is not None and _decreased(last_known, turn_usage):
                    complete_usage = False
                    turn_usage = None
                if turn_usage is not None:
                    usage = turn_usage
                    last_known.update({name: count for name, count in usage.items() if count is not None})
                continue
            item = params['item']
            kind = APP_SERVER_ITEMS.get(item['type'])
            if kind is None:
                continue
            identifier = item['id']
            if not isinstance(identifier, str) or not 1 <= len(identifier) <= 128:
                raise InputError('invalid App Server tool item identity')
            # Each turn can emit a start and repeat a terminal notification for the same call.
            key = active, identifier
            seen = items[kind]
            if method == 'item/started':
                seen.setdefault(key, None)
            else:
                if item.get('status') not in ('completed', 'failed', 'declined'):
                    raise InputError('unexpected App Server tool completion')
                failed = _native_item_failed(item, kind)
                if seen.get(key) not in (None, failed):
                    raise InputError('conflicting App Server tool result')
                seen[key] = failed
    except (ValueError, KeyError, TypeError, RecursionError):
        malformed = True
    status = ('malformed' if malformed else 'start_unobserved' if not turns else
              'interrupted' if 'interrupted' in turns.values() else
              'failed' if 'failed' in turns.values() else 'completed')
    return dict(thread=thread, status=status, cumulative_usage=usage,
                usage_complete=status=='completed' and complete_usage, observed_turns=len(turns),
                observed_items={name: len(seen) for name, seen in items.items()},
                observed_failed_items={name: sum(value is True for value in seen.values()) for name, seen in items.items()},
                observed_unfinished_items={name: sum(value is None for value in seen.values()) for name, seen in items.items()})


def _attempt_usage(logs):
    unknown = dict.fromkeys(TOKEN_METRICS)
    if not logs or any(log['status'] != 'completed' or log['thread'] != logs[0]['thread']
                       or not log.get('usage_complete', True) for log in logs):
        return unknown
    # Codex CLI 0.164.0 emits thread totals. Summing two resumes would count the prefix twice.
    totals = [log['cumulative_usage']['total_tokens'] for log in logs]
    # A resume can replay the last saved totals before any new measurement.
    if any(before is None or after is None or before >= after for before, after in zip(totals, totals[1:])):
        return unknown
    result = dict(logs[-1]['cumulative_usage'])
    for field in TOKEN_METRICS:
        observed = [log['cumulative_usage'][field] for log in logs]
        known = [value for value in observed if value is not None]
        if known != sorted(known):
            return unknown
    return result


def _read_attempts(path, schedule_sha, slots):
    doc, doc_sha = _read_document(path)
    if doc.get('schedule_sha256') != schedule_sha or doc.get('codex_cli_version') != '0.164.0':
        raise InputError('receipts require the exact schedule and Codex CLI 0.164.0')
    rows = doc.get('attempts')
    if not isinstance(rows, list) or len(rows) > len(slots):
        raise InputError('expected at most one receipt per scheduled slot')
    results = {}
    paths = set()
    threads = {}
    remaining = MAX_ALL_TRACES_BYTES
    for row in rows:
        slot = _slot(row)
        outcome, elapsed, quality, refs = (row.get(key) for key in ('outcome', 'elapsed_ms', 'quality', 'logs'))
        if (slot not in slots or slot in results or outcome not in OUTCOMES
                or elapsed is not None and (type(elapsed) is not int or not 0 <= elapsed < 2**63)
                or not isinstance(refs, list) or len(refs) > 8):
            raise InputError('invalid or duplicate SC-01 attempt receipt')
        if quality is not None and (
                not isinstance(quality, dict) or set(quality) != {'verdict', 'review_sha256'}
                or quality['verdict'] not in ('pass', 'fail')
                or not isinstance(quality['review_sha256'], str)
                or not re.fullmatch('[a-f0-9]{64}', quality['review_sha256'])
                or quality['verdict'] == 'pass' and outcome != 'completed'):
            raise InputError('invalid independent review reference')
        logs = []
        for ref in refs:
            if not isinstance(ref, dict) or set(ref) not in ({'path', 'sha256'}, {'path', 'sha256', 'format'}):
                raise InputError('trace requires a path and SHA-256')
            trace_format = ref.get('format', CLI_TRACE)
            if trace_format not in (CLI_TRACE, APP_SERVER_TRACE):
                raise InputError('unsupported Codex trace format')
            if trace_format == APP_SERVER_TRACE and len(refs) != 1:
                raise InputError('an attempt requires one native App Server transcript without other logs')
            name = ref['path']
            if not isinstance(name, str) or not 1 <= len(name) <= 512 or name.count('/') > 12 or '\x00' in name:
                raise InputError('trace path limit exceeded')
            member = _relative(path.parent, name)
            if member.suffix != '.jsonl' or member in paths:
                raise InputError('each trace requires a distinct relative JSONL path')
            raw = _file(member, min(MAX_TRACE_BYTES, remaining))
            digest = _sha(raw)
            if digest != ref['sha256']:
                raise InputError('trace integrity mismatch')
            remaining -= len(raw)
            paths.add(member)
            log = _app_server_trace(raw) if trace_format == APP_SERVER_TRACE else _trace(raw)
            thread = log['thread']
            if thread is not None and threads.setdefault(thread, slot) != slot:
                raise InputError('Codex thread reused across attempts')
            logs.append(dict(log, format=trace_format, path=name, sha256=digest, bytes=len(raw)))
        results[slot] = dict(outcome=outcome, elapsed_ms=elapsed, quality=quality,
                             usage=_attempt_usage(logs), logs=logs)
    return results, doc_sha


def _metric(values):
    known = [value for value in values if value is not None]
    if not known:
        return dict(observed=0, observed_total=None, minimum=None, median=None, maximum=None)
    return dict(observed=len(known), observed_total=sum(known), minimum=min(known),
                median=median(known), maximum=max(known))


def _observed_calls(row, field, kind):
    counts = [log.get(field, {}).get(kind) for log in row['logs'] if log['observed_turns']]
    known = [count for count in counts if count is not None]
    return sum(known) if known else None


def _group(series, method, rows):
    planned = len(rows)
    metrics = {'elapsed_ms': _metric([row['elapsed_ms'] for row in rows])}
    metrics.update({key: _metric([row['usage'][key] for row in rows]) for key in TOKEN_METRICS})
    for kind in APP_SERVER_ITEMS.values():
        metrics['observed_'+kind+'s'] = _metric([_observed_calls(row, 'observed_items', kind) for row in rows])
        metrics['observed_failed_'+kind+'s'] = _metric([_observed_calls(row, 'observed_failed_items', kind) for row in rows])
        metrics['observed_unfinished_'+kind+'s'] = _metric([_observed_calls(row, 'observed_unfinished_items', kind) for row in rows])
    outcomes = Counter(row['outcome'] for row in rows)
    quality = Counter(row['quality']['verdict'] if row['quality'] else 'unreviewed' for row in rows)
    coverage = sum(row['outcome'] not in ('completed', 'not_recorded') or row['quality'] is not None for row in rows)
    successes = quality['pass']
    budget = metrics['total_tokens']
    ratio = budget['observed_total'] / successes if successes and coverage == planned and budget['observed'] == planned else None
    return dict(series=series, method=method, planned=planned,
                recorded=planned - outcomes['not_recorded'], outcomes=dict(outcomes),
                reported_quality=dict(quality), metrics=metrics, tokens_per_reported_success=ratio)


def summarize(schedule_path, receipts_path=None):
    doc, schedule_sha = _read_document(schedule_path)
    slots = _schedule(doc)
    results, receipts_sha = ({}, None) if receipts_path is None else _read_attempts(Path(receipts_path), schedule_sha, slots)
    empty = dict(outcome='not_recorded', elapsed_ms=None, quality=None, usage=dict.fromkeys(TOKEN_METRICS), logs=[])
    attempts = [dict(slot, **results.get(key, empty)) for key, slot in slots.items()]
    groups = [_group(series, method, [row for row in attempts if (row['series'], row['method']) == (series, method)])
              for series in SERIES for method in METHODS]
    formats = sorted({log['format'] for row in attempts for log in row['logs']})
    token_scope = ('reported_cumulative_codex_cli_0.164.0_thread' if APP_SERVER_TRACE not in formats else
                   'reported_cumulative_codex_app_server_0.164.0_thread' if formats == [APP_SERVER_TRACE] else
                   'reported_cumulative_codex_0.164.0_thread_mixed_trace_formats')
    return dict(schema_version=1, case='SC-01', schedule_sha256=schedule_sha,
                receipts_sha256=receipts_sha, token_scope=token_scope, trace_formats=formats,
                review_evidence_verified=False, provider_cost=None, groups=groups, attempts=attempts)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('schedule', type=Path, help='private experiment schedule JSON')
    parser.add_argument('--receipts', type=Path, help='optional recorded attempt receipts with hashed JSONL snapshots')
    args = parser.parse_args()
    try:
        result = summarize(args.schedule, args.receipts)
    except (OSError, ValueError, RecursionError) as exc:
        print(json.dumps(dict(error=str(exc)), ensure_ascii=True), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
