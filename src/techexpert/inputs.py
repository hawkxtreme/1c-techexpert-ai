"""Bounded immutable input capture with explicit format and provenance."""
import hashlib
import io
import json
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path

from .analysis import SCOPE_KEYS
from .native_tj import validate_profile, parse_tj

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_RECORD_BYTES = 256 * 1024
MAX_EVENTS = 100_000
AUXILIARY_FORMATS = frozenset(('sc01-orders-csv-v1', 'sc01-http-service-v1',
                               'sc01-run-capture-v1', '1c-source-text-v1'))
WHOLE_JSON_FORMATS = frozenset(('1c-job-runtime-v1', 'sc01-http-service-v1', 'sc01-run-capture-v1'))


class InputError(ValueError):
    pass


class SnapshotReadError(InputError):
    def __init__(self,message,code):
        super().__init__(message)
        self.code=code


def read_snapshot(path, max_bytes=MAX_FILE_BYTES, *, share_delete=False):
    path = Path(path)
    if share_delete and os.name=='nt':
        from .windows_native import open_shared_read
        opened=open_shared_read(path)
    else:opened=path.open('rb')
    with opened as stream:
        before = os.fstat(stream.fileno())
        if before.st_size > max_bytes:
            raise SnapshotReadError('input exceeds byte limit','byte_limit')
        data = stream.read(min(max_bytes+1,before.st_size+1))
        after = os.fstat(stream.fileno())
    if len(data) > max_bytes:
        raise SnapshotReadError('input exceeds byte limit','byte_limit')
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or len(data) != before.st_size:
        raise SnapshotReadError('input changed while reading; provide a stable snapshot','changed_during_read')
    return data


class _VerifiedSnapshotRead:
    def __init__(self,stream,digest,size,max_bytes):
        self.stream=stream;self.digest=digest;self.max_bytes=max_bytes;self.before=os.fstat(stream.fileno())
        self.count=0;self.hash=hashlib.sha256();self.eof=False
        if (not stat.S_ISREG(self.before.st_mode) or self.before.st_size>max_bytes
            or size is not None and self.before.st_size!=size):raise InputError('evidence snapshot integrity mismatch')

    def read(self,size):
        if type(size) is not int or not 1<=size<=65536:raise InputError('snapshot reads require a bounded positive size')
        if self.eof:return b''
        data=self.stream.read(size)
        if not isinstance(data,bytes) or len(data)>size:raise InputError('evidence snapshot integrity mismatch')
        self.count+=len(data)
        if self.count>self.max_bytes:raise InputError('evidence snapshot integrity mismatch')
        self.hash.update(data);self.eof=not data
        return data

    def verify(self):
        while not self.eof:self.read(65536)
        after=os.fstat(self.stream.fileno())
        if ((self.before.st_size,self.before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns)
            or self.count!=self.before.st_size or self.hash.hexdigest()!=self.digest):raise InputError('evidence snapshot integrity mismatch')


@contextmanager
def open_verified_snapshot(path,expected_sha256,*,expected_size=None,max_bytes=MAX_FILE_BYTES):
    """Read the whole retained snapshot digest without materializing its bytes.

    Consumers may stop early, but the context drains and verifies all remaining
    bytes before returning their result. This does not make a live source stable.
    """
    if (not isinstance(expected_sha256,str) or not re.fullmatch('[a-f0-9]{64}',expected_sha256)
        or type(max_bytes) is not int or not 0<=max_bytes<=MAX_FILE_BYTES
        or expected_size is not None and (type(expected_size) is not int or not 0<=expected_size<=max_bytes)):
        raise InputError('invalid verified snapshot limits or identity')
    with Path(path).open('rb') as stream:
        reader=_VerifiedSnapshotRead(stream,expected_sha256,expected_size,max_bytes)
        try:yield reader
        finally:reader.verify()


def json_value(data, *, reject_duplicates=False):
    def no_constant(value):
        raise InputError(f'invalid JSON number: {value}')
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise InputError('duplicate JSON property')
            result[key] = value
        return result
    return json.loads(data, parse_constant=no_constant, object_pairs_hook=unique_keys if reject_duplicates else None)


def runtime_profile(spec):
    if spec.get('platform_version') != '8.3.27.1989' or spec.get('role') not in ('controller','worker_enter','worker_exit'):
        raise InputError('runtime source requires platform 8.3.27.1989 and controller/worker_enter/worker_exit role')
    offset=spec.get('platform_utc_offset')
    if (not isinstance(offset,str) or not re.fullmatch(r'[+-](?:[01][0-9]|2[0-3]):[0-5][0-9]',offset)
            or offset=='-00:00'):
        raise InputError('runtime source requires an explicit valid platform_utc_offset')
    return {k:spec[k] for k in ('platform_version','role','platform_utc_offset')}


def load_manifest(path,*,tolerant_sources=False):
    path = Path(path).resolve()
    try:
        raw = read_snapshot(path, 1024 * 1024)
        manifest = json_value(raw.decode('utf-8-sig'),reject_duplicates=True)
    except (OSError, UnicodeError, ValueError) as exc:
        raise InputError(f'Cannot read case manifest: {exc}') from exc
    if not isinstance(manifest, dict) or manifest.get('schema') != 1 or manifest.get('scenario') != 'SC-01':
        raise InputError('expected schema=1 and scenario=SC-01')
    if manifest.get('origin') not in ('synthetic', 'provided'):
        raise InputError('origin must explicitly be synthetic or provided')
    from .source_coverage import validate_request,validate_collection
    validate_request(window=manifest.get('incident_window'))
    selection = manifest.get('selection')
    correlation=manifest.get('correlation_profile')
    workload=manifest.get('workload_profile')
    if workload is not None and (workload!='sc01-order-load-v1' or correlation!='1c-file-job-markers-v1'):
        raise InputError('order-load workload requires the explicit controlled job correlation profile')
    if correlation is not None:
        if correlation!='1c-file-job-markers-v1':
            raise InputError('unsupported correlation_profile')
        if (not isinstance(selection,dict) or set(selection)!={'run'} or not isinstance(selection.get('run'),str)
                or not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',selection['run'])):
            raise InputError('job correlation selection requires only the actual job UUID in run')
    elif not isinstance(selection, dict) or any(not isinstance(selection.get(k), str) or not selection[k] for k in SCOPE_KEYS):
        raise InputError('selection requires database, node, process, epoch and run')
    specs = manifest.get('sources')
    if not isinstance(specs, list) or not 1 <= len(specs) <= 32:
        raise InputError('sources must contain 1..32 explicit files')
    events, native_events, sources, limits, seen, total = [], [], [], [], {}, 0
    lifecycle_documents=[]
    attempts=[];seen_ids={}
    records_seen, omitted_details = 0, 0
    for source_number, spec in enumerate(specs, 1):
        source_id=f's{source_number}'
        attempt=dict(id=source_id,format=spec.get('format') if isinstance(spec,dict) and isinstance(spec.get('format'),str) else None,
            path=spec.get('path') if isinstance(spec,dict) and isinstance(spec.get('path'),str) else None,availability='not_attempted')
        attempts.append(attempt)
        if (not isinstance(spec,dict) or not isinstance(spec.get('format'),str)
            or spec['format'] not in (set(AUXILIARY_FORMATS)|{'normalized-events-v1','1c-tj-text-v1','1c-job-runtime-v1'})):
            if tolerant_sources:
                attempt['availability']='unsupported_format'
                continue
            raise InputError('unsupported source format; native JR is not supported')
        is_runtime=spec['format']=='1c-job-runtime-v1'
        is_auxiliary=spec['format'] in AUXILIARY_FORMATS
        if is_auxiliary and workload is None:
            if tolerant_sources:
                attempt['availability']='unsupported_profile'
                continue
            raise InputError('auxiliary source requires workload_profile=sc01-order-load-v1')
        if (is_runtime and correlation is None) or (correlation is not None and spec['format']=='normalized-events-v1'):
            if tolerant_sources:
                attempt['availability']='unsupported_profile'
                continue
            raise InputError('job correlation requires native TJ/runtime sources and explicit correlation_profile')
        if not isinstance(spec.get('path'), str) or not spec['path'] or '\x00' in spec['path']:
            if tolerant_sources:
                attempt['availability']='invalid_source'
                continue
            raise InputError('source path required')
        source_path = Path(spec['path'])
        if not source_path.is_absolute():
            source_path = path.parent / source_path
        # Profile validation does not touch the path; inspection must not open an unsupported declaration.
        try:
            profile = validate_profile(spec, source_path) if spec['format'] == '1c-tj-text-v1' else None
            job_profile=runtime_profile(spec) if is_runtime else None
            collection=validate_collection(spec.get('collection'))
        except ValueError:
            if not tolerant_sources:raise
            attempt['availability']='unsupported_profile'
            continue
        context = spec.get('context', {})
        if (not isinstance(context, dict) or set(context) - {'node', 'process', 'epoch'} or
                any(not isinstance(v, str) or not 1 <= len(v) <= 256 for v in context.values())):
            if tolerant_sources:
                attempt['availability']='unsupported_profile'
                continue
            raise InputError('source context supports bounded node, process and epoch labels')
        try:source_path=source_path.resolve()
        except (OSError,ValueError) as exc:
            attempt['availability']='access_denied' if isinstance(exc,PermissionError) else 'read_error'
            limits.append(dict(code='source_unavailable',source=source_id,detail=str(exc)))
            continue
        identity = os.path.normcase(str(source_path))
        interpretation = (spec['format'], profile, job_profile, context,collection)
        if identity in seen:
            if seen[identity] != interpretation:
                if tolerant_sources:
                    attempt['availability']='conflicting_profile'
                    continue
                raise InputError('conflicting profiles for the same source file')
            attempt.update(availability='duplicate_source',duplicate_of=seen_ids[identity])
            continue
        seen[identity] = interpretation
        seen_ids[identity]=source_id
        try:
            data = read_snapshot(source_path, min(1024*1024 if is_runtime or is_auxiliary else MAX_FILE_BYTES, MAX_TOTAL_BYTES-total))
            total += len(data)
        except (OSError, InputError) as exc:
            attempt['availability']=('not_found' if isinstance(exc,FileNotFoundError) else 'access_denied' if isinstance(exc,PermissionError)
                else exc.code if isinstance(exc,SnapshotReadError) else 'read_error')
            limits.append(dict(code='source_unavailable', source=source_id, detail=str(exc)))
            continue
        attempt.update(availability='captured',path=str(source_path))
        digest = hashlib.sha256(data).hexdigest()
        source = dict(id=source_id, path=str(source_path), sha256=digest, size=len(data),
                      format=spec['format'], data=data,collection=collection)
        sources.append(source)
        if is_runtime or is_auxiliary:
            source['evidence']=dict(id=f'{source_id}:1',source=source_id,sha256=digest,line=1,
                end_line=max(1,len(data.splitlines())),byte_start=0,byte_end=len(data))
        if is_auxiliary:
            source['parse_status']='captured'
            try:
                text=data.decode('utf-8-sig')
                if spec['format'] in WHOLE_JSON_FORMATS:
                    document=json_value(text,reject_duplicates=True)
                    if not isinstance(document,dict) or type(document.get('schema')) is not int or document['schema']!=1:
                        raise InputError('auxiliary JSON requires schema=1 object')
                    source['parse_status']='parsed'
            except (UnicodeError,ValueError,RecursionError):
                source['parse_status']='invalid'
                limits.append(dict(code='invalid_auxiliary_source',source=source_id))
            continue
        if is_runtime:
            source.update(profile=job_profile,parse_status='not_parsed')
            if records_seen>=MAX_EVENTS:
                limits.append(dict(code='record_limit',source=source_id))
                continue
            records_seen+=1
            try:
                document=json_value(data.decode('utf-8-sig'),reject_duplicates=True)
                if not isinstance(document,dict) or document.get('schema')!=1:
                    raise InputError('runtime document requires schema=1 object')
            except (UnicodeError, ValueError, RecursionError):
                source['parse_status']='invalid'
                limits.append(dict(code='invalid_runtime_document',source=source_id))
                continue
            source['parse_status']='parsed'
            evidence=source['evidence']
            lifecycle_documents.append(dict(role=job_profile['role'],data=document,evidence=evidence,
                                            platform_utc_offset=job_profile['platform_utc_offset']))
            continue
        if profile is not None:
            parsed = parse_tj(data, profile, max_records=max(0, MAX_EVENTS-records_seen),
                              max_record_bytes=MAX_RECORD_BYTES)
            records_seen += parsed['records_seen']
            source.update(profile=profile, declared_context=context, context_status='user_declared_not_verified',
                          parse_status=parsed['status'], parsed_event_count=len(parsed['records']),
                          record_budget=max(0, MAX_EVENTS-(records_seen-parsed['records_seen'])))
            for record in parsed['records']:
                record['evidence'] = dict(id=f"{source_id}:{record['line']}", source=source_id,
                    sha256=digest, **{k: record[k] for k in ('line','end_line','byte_start','byte_end')})
                native_events.append(record)
            limits.extend(dict(issue, source=source_id) for issue in parsed['limitations'])
            continue
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
                manifest_data=raw, events=events, native_events=native_events, lifecycle_documents=lifecycle_documents,
                sources=sources, source_attempts=attempts, limitations=limits)
