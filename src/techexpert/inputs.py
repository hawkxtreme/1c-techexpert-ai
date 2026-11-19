"""Bounded immutable input capture with explicit format and provenance."""
import hashlib
import io
import json
import math
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path

from .analysis import SCOPE_KEYS
from .native_tj import FORMATS as TJ_FORMATS, JSON_FORMAT as TJ_JSON, validate_profile, parse_tj

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


def _schema2_source(spec):
    allowed={'path','format','platform_version','encoding','placement','timestamp_format','read_mode','context','collection',
             'utc_offset','file_hour','rotation_hours','external_window'}
    if set(spec)-allowed:raise InputError('unsupported schema=2 native TJ source fields')
    path=spec.get('path')
    if not isinstance(path,str) or not path or '\x00' in path:raise InputError('source path required')
    mode=spec.get('timestamp_format')
    if (mode=='iso' and any(key in spec for key in ('file_hour','rotation_hours'))
        or mode=='minute' and 'utc_offset' in spec):raise InputError('native TJ time fields conflict with timestamp_format')
    validate_profile(spec,path)
    if spec.get('read_mode','stable') not in ('stable','tj-prefix-v1'):raise InputError('unsupported source read mode')
    if 'external_window' in spec:
        if spec.get('read_mode','stable') != 'stable':
            raise InputError('external_window requires a stable file, without live prefix mode')
        from .tj_reference import window_spec
        window_spec(spec['external_window'])
    context=spec.get('context',{})
    if (not isinstance(context,dict) or set(context)-{'node','process','epoch'}
        or any(not isinstance(v,str) or not 1<=len(v)<=256 for v in context.values())):
        raise InputError('source context supports bounded node, process and epoch labels')
    from .source_coverage import validate_collection
    validate_collection(spec.get('collection'))


def _manifest_profile(manifest,*,tolerant_sources=False):
    if not isinstance(manifest,dict) or type(manifest.get('schema')) is not int or manifest['schema'] not in (1,2):
        raise InputError('expected manifest schema=1 (SC-01) or schema=2 (native TJ observations)')
    if manifest['schema']==1 and manifest.get('scenario')!='SC-01':raise InputError('schema=1 requires scenario=SC-01')
    if manifest.get('origin') not in ('synthetic','provided'):raise InputError('origin must explicitly be synthetic or provided')
    from .source_coverage import validate_request
    validate_request(window=manifest.get('incident_window'))
    if manifest['schema']==1:return
    if set(manifest)-{'schema','origin','sources','symptom','reported_normal_seconds','incident_window'}:
        raise InputError('schema=2 native TJ does not accept scenario, selection, correlation/workload or unknown fields')
    if 'symptom' in manifest:
        text=manifest['symptom']
        if (not isinstance(text,str) or not text.strip() or len(text)>8192
            or any(ord(c)<32 and c not in '\r\n\t' for c in text)):raise InputError('schema=2 symptom must be bounded nonblank text')
    normal=manifest.get('reported_normal_seconds')
    if normal is not None:
        try:valid=type(normal) in (int,float) and normal>0 and math.isfinite(normal)
        except OverflowError:valid=False
        if not valid:raise InputError('reported normal must be finite positive seconds or unknown')
    sources=manifest.get('sources')
    if (not isinstance(sources,list) or not 1<=len(sources)<=32
        or any(not isinstance(s,dict) or s.get('format') not in TJ_FORMATS for s in sources)):
        raise InputError('schema=2 requires1..32 native TJ sources; other adapters use their own explicit contracts')
    if not tolerant_sources:
        for source in sources:_schema2_source(source)


def read_manifest(path, *, tolerant_sources=False):
    path = Path(path).resolve()
    try:
        raw = read_snapshot(path, 1024 * 1024)
        manifest = json_value(raw.decode('utf-8-sig'),reject_duplicates=True)
    except (OSError, UnicodeError, ValueError) as exc:
        raise InputError(f'Cannot read case manifest: {exc}') from exc
    _manifest_profile(manifest,tolerant_sources=tolerant_sources)
    return path, raw, manifest


def load_manifest(path, *, tolerant_sources=False, reference_sha256=None, reference_state=None,
                  prefix_review=None, should_stop=None, retained=None):
    path, raw, manifest = read_manifest(path, tolerant_sources=tolerant_sources)
    from .source_coverage import validate_collection
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
    elif manifest['schema']==1 and (not isinstance(selection, dict) or any(not isinstance(selection.get(k), str) or not selection[k] for k in SCOPE_KEYS)):
        raise InputError('selection requires database, node, process, epoch and run')
    specs = manifest.get('sources')
    if not isinstance(specs, list) or not 1 <= len(specs) <= 32:
        raise InputError('sources must contain 1..32 explicit files')
    references = {}
    has_reference = any(type(spec) is dict and 'external_window' in spec for spec in specs)
    if has_reference and manifest['schema'] != 2:
        raise InputError('external_window requires the native TJ schema=2 manifest')
    if has_reference and not tolerant_sources:
        from . import tj_reference
        from .operation_state import digest as plan_digest
        if not isinstance(reference_sha256, str) or not re.fullmatch('[a-f0-9]{64}', reference_sha256) or reference_state is None:
            raise InputError('external TJ requires an approved reference preview before capture')
        if prefix_review is None:
            reference_review = tj_reference.build_review(path, raw, manifest, reference_state)
        else:
            tj_reference.validate_prefix_review(prefix_review, raw, manifest, reference_state)
            reference_review = prefix_review
        if plan_digest(reference_review) != reference_sha256:
            raise InputError('reference preview changed; inspect the current file and storage plan')
        references = {item['id']: item for item in reference_review['sources']}
    elif reference_sha256 is not None or prefix_review is not None:
        raise InputError('reference preview can only be used with an external TJ capture')
    supported_formats = {*AUXILIARY_FORMATS, *TJ_FORMATS, 'normalized-events-v1', '1c-job-runtime-v1'}
    events, native_events, sources, limits, seen, total = [], [], [], [], {}, 0
    lifecycle_documents=[]
    attempts=[];seen_ids={}
    records_seen, omitted_details = 0, 0
    for source_number, spec in enumerate(specs, 1):
        source_id=f's{source_number}'
        saved = None
        if retained is not None:
            if should_stop and should_stop():
                raise InputError('retained TJ correction stopped')
            saved = retained['sources'].get(source_id)
            if saved is None:
                attempts.append(dict(retained['attempts'][source_id]))
                continue
        attempt=dict(id=source_id,format=spec.get('format') if isinstance(spec,dict) and isinstance(spec.get('format'),str) else None,
            path=spec.get('path') if isinstance(spec,dict) and isinstance(spec.get('path'),str) else None,availability='not_attempted')
        attempts.append(attempt)
        if (not isinstance(spec,dict) or not isinstance(spec.get('format'),str)
            or spec['format'] not in supported_formats):
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
            if manifest['schema']==2:_schema2_source(spec)
            profile = validate_profile(spec, source_path) if spec['format'] in TJ_FORMATS else None
            job_profile=runtime_profile(spec) if is_runtime else None
            collection=validate_collection(spec.get('collection'))
            read_mode=spec.get('read_mode','stable')
            if (not isinstance(read_mode,str) or read_mode not in ('stable','tj-prefix-v1')
                or read_mode=='tj-prefix-v1' and profile is None):raise InputError('unsupported source read mode')
        except ValueError:
            if not tolerant_sources:raise
            attempt['availability']='unsupported_profile'
            continue
        if 'external_window' in spec and tolerant_sources:
            attempt.update(availability='reference_review_required', next_action='tj-reference-plan')
            continue
        context = spec.get('context', {})
        if (not isinstance(context, dict) or set(context) - {'node', 'process', 'epoch'} or
                any(not isinstance(v, str) or not 1 <= len(v) <= 256 for v in context.values())):
            if tolerant_sources:
                attempt['availability']='unsupported_profile'
                continue
            raise InputError('source context supports bounded node, process and epoch labels')
        reference = references.get(source_id)
        try:
            if saved is not None:
                from .operation_state import safe
                source_path = safe(source_path)
                if not stat.S_ISREG(source_path.lstat().st_mode):
                    raise InputError('retained input is not an ordinary snapshot')
            else:
                source_path=Path(reference['path']) if reference else source_path.absolute() if read_mode=='tj-prefix-v1' else source_path.resolve()
        except (OSError,ValueError) as exc:
            if saved is not None:
                raise
            attempt['availability']='access_denied' if isinstance(exc,PermissionError) else 'read_error'
            limits.append(dict(code='source_unavailable',source=source_id,detail=str(exc)))
            continue
        identity = os.path.normcase(str(source_path))
        interpretation = (spec['format'], profile, job_profile, context,collection,read_mode,spec.get('external_window'))
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
        acquisition = reference_capture = None
        try:
            maximum=min(1024*1024 if is_runtime or is_auxiliary else MAX_FILE_BYTES, MAX_TOTAL_BYTES-total)
            if reference:
                data, reference_capture = tj_reference.capture(source_path, reference, profile, max_retained=maximum,
                    max_records=MAX_EVENTS - records_seen, should_stop=should_stop, fixed_prefix=prefix_review is not None)
            elif read_mode=='tj-prefix-v1':
                from .tj_capture import read_prefix
                data,acquisition=read_prefix(source_path,maximum,max_records=max(0,MAX_EVENTS-records_seen),
                                             json_lines=spec['format']==TJ_JSON)
            else:data = read_snapshot(source_path,maximum)
            total += len(data)
        except (OSError, InputError) as exc:
            if reference or saved is not None:
                raise
            attempt['availability']=('not_found' if isinstance(exc,FileNotFoundError) else 'access_denied' if isinstance(exc,PermissionError)
                else exc.code if isinstance(exc,SnapshotReadError) else 'read_error')
            limits.append(dict(code='source_unavailable', source=source_id, detail=str(exc)))
            continue
        attempt.update(availability='captured',path=str(source_path))
        digest = hashlib.sha256(data).hexdigest()
        if saved is not None:
            if (saved['format'], saved['size'], saved['sha256']) != (spec['format'], len(data), digest):
                raise InputError('retained input does not match its saved snapshot')
            attempt['path'] = saved['path']
            acquisition = saved.get('acquisition')
            reference_capture = saved.get('reference_capture')
        source = dict(id=source_id, path=str(source_path), sha256=digest, size=len(data),
                      format=spec['format'], data=data,collection=collection)
        if saved is not None:
            source['path'] = saved['path']
            if 'input_origin' in saved:
                source['input_origin'] = saved['input_origin']
            source['retained_interpretation'] = True
        if acquisition is not None:source['acquisition']=acquisition
        if reference_capture is not None:
            source['reference_capture'] = reference_capture
            limits.append(dict(code='external_tj_window_only', source=source_id,
                detail='Retained records are from the selected recorded-time window of one observed external file. Collection coverage is unknown.'))
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
            from .observations import with_evidence
            budget = reference_capture['selected_records'] if reference_capture is not None else max(0, MAX_EVENTS - records_seen)
            if saved is not None:
                budget = min(budget, saved.get('record_budget', budget))
            parsed = parse_tj(data, profile, max_records=budget, max_record_bytes=MAX_RECORD_BYTES)
            if reference_capture is not None and len(parsed['records']) != budget:
                raise InputError('retained external TJ window does not match its capture')
            records_seen += reference_capture['records_scanned'] if reference_capture is not None else parsed['records_seen']
            source.update(profile=profile, declared_context=context, context_status='user_declared_not_verified',
                          parse_status=parsed['status'], parsed_event_count=len(parsed['records']),
                          record_budget=budget)
            for record in parsed['records']:
                native_events.append(with_evidence(record, source))
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
