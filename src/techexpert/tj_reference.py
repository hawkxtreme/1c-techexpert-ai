"""Retain a verified recorded-time window of an explicitly selected local TJ."""

from bisect import bisect_right
from collections import Counter
from datetime import datetime
import hashlib
import os
from pathlib import Path
import re

from . import operation_state as fs
from .input_files import chain
from .inputs import InputError, MAX_EVENTS, MAX_FILE_BYTES, MAX_RECORD_BYTES, MAX_TOTAL_BYTES, read_manifest
from .native_tj import MAX_REFERENCE_SCAN_BYTES, iter_tj
from .source_coverage import validate_request
from .tj_capture import _identity, _open


METHOD = 'tj-reference-window-v1'
MAX_SPANS = 2048


def window_spec(value):
    if type(value) is not dict or set(value) != {'start', 'end', 'max_retained_bytes'}:
        raise InputError('external_window requires start, end and max_retained_bytes')
    bound = value['max_retained_bytes']
    if type(bound) is not int or not 1 <= bound <= MAX_FILE_BYTES:
        raise InputError('external TJ retention limit must be 1 through 16 MiB')
    return dict(window=validate_request(window={key: value[key] for key in ('start', 'end')})['window'],
                max_retained_bytes=bound)


def _file_state(info):
    return dict(identity=_identity(info), bytes=info.st_size, mtime_ns=str(info.st_mtime_ns),
                ctime_ns=str(info.st_ctime_ns))


def _path_state(path):
    return dict(_file_state(path.lstat()), path_chain_sha256=fs.digest(chain(path)))


def build_review(path, raw, manifest, state):
    """Read metadata only. Bind the request, source identities and storage limit."""
    items = []
    identities = set()
    for number, source in enumerate(manifest['sources'], 1):
        if 'external_window' not in source:
            continue
        original = Path(source['path'])
        if not original.is_absolute():
            original = path.parent / original
        original = fs.safe(original)
        observation = _path_state(original)
        identity = observation['identity']['device'], observation['identity']['inode']
        if identity in identities:
            raise InputError('a reference preview requires distinct external TJ files')
        identities.add(identity)
        items.append(dict(id=f's{number}', path=str(original), observation=observation,
                          **window_spec(source['external_window'])))
    if not items:
        return None
    size = sum(item['observation']['bytes'] for item in items)
    retained = sum(item['max_retained_bytes'] for item in items)
    if size > MAX_REFERENCE_SCAN_BYTES or retained > MAX_TOTAL_BYTES:
        raise InputError('reference preview exceeds the total external scan or retained byte limit')
    return dict(schema_version=1, method=METHOD, state_dir=str(fs.safe(state)), manifest_path=str(path),
                manifest_sha256=hashlib.sha256(raw).hexdigest(), external_bytes=size,
                expected_read_bytes=2*size, max_scan_records=MAX_EVENTS, max_retained_bytes=retained, sources=items,
                ordinary_source_count=len(manifest['sources'])-len(items))


def plan(manifest_path, state):
    path, raw, manifest = read_manifest(manifest_path)
    if manifest['schema'] != 2:
        raise InputError('external_window requires the native TJ schema=2 manifest')
    review = build_review(path, raw, manifest, state)
    if review is None:
        raise InputError('manifest has no external_window sources to preview')
    return dict(status='ready', plan=review, plan_sha256=fs.digest(review),
                source_bytes_read=False, bytes_saved=False)


class _HashReader:
    def __init__(self, stream, size, should_stop):
        self.stream = stream
        self.remaining = size
        self.digest = hashlib.sha256()
        self.should_stop = should_stop

    def read(self, size):
        if self.should_stop and self.should_stop():
            raise InputError('external TJ read stopped by the operation boundary')
        if self.remaining == 0:
            return b''
        block = self.stream.read(min(size, self.remaining))
        if not block:
            raise InputError('external TJ became shorter than the reviewed length')
        self.remaining -= len(block)
        self.digest.update(block)
        return block


def _add_span(spans, record, start, end, line):
    if spans and spans[-1]['original_end'] == record['byte_start']:
        spans[-1].update(retained_end=end, original_end=record['byte_end'])
        return
    if len(spans) >= MAX_SPANS:
        raise InputError('external TJ window has too many disjoint ranges; narrow the window')
    spans.append(dict(retained_start=start, retained_end=end, retained_line=line,
                      original_start=record['byte_start'], original_end=record['byte_end'],
                      original_line=record['line']))


def _check(stream, initial):
    if _file_state(os.fstat(stream.fileno())) != initial:
        raise InputError('external TJ changed during capture')


def capture(path, reviewed, profile, *, max_retained, max_records, should_stop=None):
    """Scan and hash a fixed stable file twice, retaining only selected frames."""
    expected = reviewed['observation']
    started = fs.stamp()
    if _path_state(path) != expected:
        raise InputError('external TJ changed since the reference preview')
    size = expected['bytes']
    start, end = (datetime.fromisoformat(reviewed['window'][key]) for key in ('start', 'end'))
    limit = min(reviewed['max_retained_bytes'], max_retained)
    kept = bytearray()
    spans = []
    count, line = 0, 1
    with _open(path) as stream:
        initial = _file_state(os.fstat(stream.fileno()))
        # Windows may report different ctime values for path and handle queries.
        if any(initial[key] != expected[key] for key in ('identity', 'bytes', 'mtime_ns')):
            raise InputError('external TJ handle differs from the reviewed path')
        first = _HashReader(stream, size, should_stop)
        scan = iter_tj(first, profile, max_records=max_records, max_record_bytes=MAX_RECORD_BYTES,
                       max_input_bytes=max(1, size))
        for record in scan:
            if not start <= datetime.fromisoformat(record['timestamp_utc']) < end:
                continue
            raw = scan.raw_record
            if len(kept) + len(raw) > limit:
                raise InputError('selected external TJ window exceeds the retained byte limit; narrow the window')
            position = len(kept)
            kept.extend(raw)
            _add_span(spans, record, position, len(kept), line)
            line += record['end_line'] - record['line'] + 1
            count += 1
        summary = scan.summary
        issues = Counter()
        for issue in summary['limitations']:
            if issue['code'] == 'additional_limitations':
                issues.update(issue['counts_by_code'])
            else:
                issues[issue['code']] += 1
        if first.remaining or {'record_limit', 'input_byte_limit'}.intersection(issues):
            raise InputError('external TJ scan did not finish within its record or byte limit')
        _check(stream, initial)
        stream.seek(0)
        second = _HashReader(stream, size, should_stop)
        while second.read(65536):
            pass
        _check(stream, initial)
        if first.digest.digest() != second.digest.digest() or _path_state(path) != expected:
            raise InputError('external TJ contents changed during the repeated observation')
    return bytes(kept), dict(method=METHOD, window=reviewed['window'], original_bytes=size,
        original_sha256=first.digest.hexdigest(), file_identity=expected['identity'],
        selected_records=count, records_scanned=summary['records_seen'], original_parse_status=summary['status'],
        original_scan_issues=dict(issues), spans=spans, started_at=started, finished_at=fs.stamp(),
        original_rechecked_on_replay=False,
        atomic_snapshot=False, clock_alignment='not_verified', collection_coverage='unknown')


def validate_saved(source):
    meta = source['reference_capture']
    if type(meta) is not dict or meta.get('method') != METHOD:
        raise InputError('unsupported saved external TJ descriptor')
    size, count, scanned, spans = (meta.get(key) for key in ('original_bytes', 'selected_records', 'records_scanned', 'spans'))
    if (type(size) is not int or not 0 <= size <= MAX_REFERENCE_SCAN_BYTES
            or type(count) is not int or type(scanned) is not int or not 0 <= count <= scanned <= MAX_EVENTS
            or count != source.get('record_budget') or count != source.get('parsed_event_count')
            or type(meta.get('original_sha256')) is not str or not re.fullmatch('[a-f0-9]{64}', meta['original_sha256'])
            or type(spans) is not list or len(spans) > min(count, MAX_SPANS)
            or not meta.get('window') or validate_request(window=meta['window'])['window'] != meta['window']):
        raise InputError('invalid saved external TJ descriptor')
    retained, previous_end = 0, 0
    line, original_line = 0, 0
    fields = {'retained_start', 'retained_end', 'retained_line', 'original_start', 'original_end', 'original_line'}
    for span in spans:
        if (type(span) is not dict or set(span) != fields or any(type(value) is not int for value in span.values())
                or span['retained_start'] != retained or span['retained_end'] <= retained
                or not previous_end <= span['original_start'] < span['original_end'] <= size
                or span['original_end'] - span['original_start'] != span['retained_end'] - retained
                or span['retained_line'] <= line or span['original_line'] <= original_line):
            raise InputError('invalid saved external TJ byte ranges')
        retained, previous_end = span['retained_end'], span['original_end']
        line, original_line = span['retained_line'], span['original_line']
    if retained != source.get('size') or bool(retained) != bool(count):
        raise InputError('saved external TJ ranges do not cover the retained bytes')


def has_saved_reference(report):
    sources = report.get('sources')
    selected = [source for source in sources if type(source) is dict and 'reference_capture' in source] if type(sources) is list else []
    if 'reference_plan_sha256' not in report and not selected:
        return False
    digest = report.get('reference_plan_sha256')
    if not selected or len(sources) > 32 or type(digest) is not str or not re.fullmatch('[a-f0-9]{64}', digest):
        raise InputError('saved case has no valid external TJ reference review')
    for source in selected:
        validate_saved(source)
    return True


def view(source):
    capture = source['reference_capture']
    return dict(source=source['id'], retained_bytes=source['size'],
                **{key: capture[key] for key in ('method', 'window', 'original_bytes', 'original_sha256',
                    'selected_records', 'records_scanned', 'original_parse_status', 'original_scan_issues',
                    'original_rechecked_on_replay', 'collection_coverage')})


def original_location(source, record):
    capture = source['reference_capture']
    spans = capture['spans']
    position = bisect_right(spans, record['byte_start'], key=lambda span: span['retained_start'])
    if not position:
        raise InputError('retained TJ record has no verified original range')
    span = spans[position - 1]
    if not span['retained_start'] <= record['byte_start'] < record['byte_end'] <= span['retained_end']:
        raise InputError('retained TJ record crosses an original range boundary')
    byte_delta = span['original_start'] - span['retained_start']
    line_delta = span['original_line'] - span['retained_line']
    return dict(byte_start=record['byte_start'] + byte_delta, byte_end=record['byte_end'] + byte_delta,
                line=record['line'] + line_delta, end_line=record['end_line'] + line_delta,
                sha256=capture['original_sha256'], basis='observed_external_file_at_capture')
