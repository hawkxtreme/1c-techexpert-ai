"""Summarize the private SC-01 schedule and saved Codex CLI 0.164.0 JSONL.

Each receipt covers one scheduled attempt. Its logs are ordered captures of a
fresh thread and any resumes of that thread. Review verdicts and elapsed time
are supplied by the experiment operator. This tool runs offline.

The receipts JSON contains schema_version=1, schedule_sha256, codex_cli_version
and attempts. Each attempt contains series, repeat, method, outcome, elapsed_ms
and logs (path relative to the receipts file and sha256). Quality is optional
and contains verdict (pass or fail) and review_sha256 when supplied.
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
    return dict(thread=thread, status=status, cumulative_usage=usage,
                observed_items={name: len(seen) for name, seen in items.items()})


def _attempt_usage(logs):
    unknown = dict.fromkeys(TOKEN_METRICS)
    if not logs or any(log['status'] != 'completed' or log['thread'] != logs[0]['thread'] for log in logs):
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
            if not isinstance(ref, dict) or set(ref) != {'path', 'sha256'}:
                raise InputError('trace requires a path and SHA-256')
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
            log = _trace(raw)
            thread = log['thread']
            if thread is not None and threads.setdefault(thread, slot) != slot:
                raise InputError('Codex thread reused across attempts')
            logs.append(dict(log, path=name, sha256=digest, bytes=len(raw)))
        results[slot] = dict(outcome=outcome, elapsed_ms=elapsed, quality=quality,
                             usage=_attempt_usage(logs), logs=logs)
    return results, doc_sha


def _metric(values):
    known = [value for value in values if value is not None]
    if not known:
        return dict(observed=0, observed_total=None, minimum=None, median=None, maximum=None)
    return dict(observed=len(known), observed_total=sum(known), minimum=min(known),
                median=median(known), maximum=max(known))


def _group(series, method, rows):
    planned = len(rows)
    metrics = {'elapsed_ms': _metric([row['elapsed_ms'] for row in rows])}
    metrics.update({key: _metric([row['usage'][key] for row in rows]) for key in TOKEN_METRICS})
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
    return dict(schema_version=1, case='SC-01', schedule_sha256=schedule_sha,
                receipts_sha256=receipts_sha, token_scope='reported_cumulative_codex_cli_0.164.0_thread',
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
