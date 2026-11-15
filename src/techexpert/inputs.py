"""Bounded immutable input capture with explicit format and provenance."""
import hashlib
import io
import json
import os
from pathlib import Path

from .analysis import SCOPE_KEYS

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_RECORD_BYTES = 256 * 1024
MAX_EVENTS = 100_000


class InputError(ValueError):
    pass


def read_snapshot(path, max_bytes=MAX_FILE_BYTES):
    path = Path(path)
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        if before.st_size > max_bytes:
            raise InputError('input exceeds byte limit')
        data = stream.read(max_bytes + 1)
        after = os.fstat(stream.fileno())
    if len(data) > max_bytes:
        raise InputError('input exceeds byte limit')
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or len(data) != before.st_size:
        raise InputError('input changed while reading; provide a stable snapshot')
    return data


def json_value(data):
    def no_constant(value):
        raise InputError(f'invalid JSON number: {value}')
    return json.loads(data, parse_constant=no_constant)


def load_manifest(path):
    path = Path(path).resolve()
    try:
        raw = read_snapshot(path, 1024 * 1024)
        manifest = json_value(raw.decode('utf-8-sig'))
    except (OSError, UnicodeError, ValueError) as exc:
        raise InputError(f'Cannot read case manifest: {exc}') from exc
    if not isinstance(manifest, dict) or manifest.get('schema') != 1 or manifest.get('scenario') != 'SC-01':
        raise InputError('expected schema=1 and scenario=SC-01')
    if manifest.get('origin') not in ('synthetic', 'provided'):
        raise InputError('origin must explicitly be synthetic or provided')
    selection = manifest.get('selection')
    if not isinstance(selection, dict) or any(not isinstance(selection.get(k), str) or not selection[k] for k in SCOPE_KEYS):
        raise InputError('selection requires database, node, process, epoch and run')
    specs = manifest.get('sources')
    if not isinstance(specs, list) or not 1 <= len(specs) <= 32:
        raise InputError('sources must contain 1..32 explicit files')
    events, sources, limits, seen, total = [], [], [], set(), 0
    records_seen, omitted_details = 0, 0
    for source_number, spec in enumerate(specs, 1):
        if not isinstance(spec, dict) or spec.get('format') != 'normalized-events-v1':
            raise InputError('supported input: normalized-events-v1; this is not native TJ/JR')
        if not isinstance(spec.get('path'), str) or not spec['path']:
            raise InputError('source path required')
        source_path = Path(spec['path'])
        if not source_path.is_absolute():
            source_path = path.parent / source_path
        source_path = source_path.resolve()
        identity = os.path.normcase(str(source_path))
        if identity in seen:
            continue
        seen.add(identity)
        source_id = f's{source_number}'
        try:
            data = read_snapshot(source_path, min(MAX_FILE_BYTES, MAX_TOTAL_BYTES-total))
            total += len(data)
        except (OSError, InputError) as exc:
            limits.append(dict(code='source_unavailable', source=source_id, detail=str(exc)))
            continue
        digest = hashlib.sha256(data).hexdigest()
        sources.append(dict(id=source_id, path=str(source_path), sha256=digest, size=len(data),
                            format='normalized-events-v1', data=data))
        for number, line in enumerate(io.BytesIO(data), 1):
            records_seen += 1
            if records_seen > MAX_EVENTS:
                limits.append(dict(code='record_limit', source=source_id, line=number))
                break
            if not line.strip():
                continue
            if len(line) > MAX_RECORD_BYTES:
                limits.append(dict(code='record_limit', source=source_id, line=number))
                break
            evidence = dict(id=f'{source_id}:{number}', source=source_id, line=number, sha256=digest)
            try:
                value = json_value(line.decode('utf-8-sig' if number == 1 else 'utf-8'))
                if not isinstance(value, dict) or not isinstance(value.get('kind'), str) or len(value['kind'])>64:
                    raise ValueError('event object and kind required')
            except (UnicodeError, ValueError):
                if len(limits) < 200:
                    limits.append(dict(code='invalid_record', source=source_id, line=number))
                else:
                    omitted_details += 1
                continue
            # Input-supplied evidence never overrides the captured source location.
            value['evidence'] = evidence
            events.append(value)
    if omitted_details:
        limits.append(dict(code='additional_invalid_records', count=omitted_details))
    return dict(manifest=manifest, manifest_sha256=hashlib.sha256(raw).hexdigest(),
                manifest_data=raw, events=events, sources=sources, limitations=limits)
