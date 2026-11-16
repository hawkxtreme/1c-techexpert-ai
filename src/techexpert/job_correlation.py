"""Narrow correlation of controlled 8.3.27.1989 file-mode observations.

The loader owns immutable snapshots and evidence hashes. This module validates
their observed relationships, not their authenticity. A link covers only the
recorded subset between exact markers in one snapshot/thread, never a whole
file, OS process lifetime, job duration or arbitrary production capture.
Identity and cross-clock ordering are separate observations: even nested
runtime/TJ timestamps do not demonstrate that their clocks are synchronized.
"""
import ntpath
import re
import uuid
from datetime import datetime, timedelta, timezone


MAX_DOCUMENTS = 32
MAX_EVENTS = 100_000
MAX_LINK_REFS = 200
EPOCH = datetime(1, 1, 1, tzinfo=timezone.utc)
UUID_TEXT = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
MARKER = re.compile(r'SELECT(?P<eol>\r?\n)"SC01LIFECYCLE:(?P<stage>body_enter|body_exit):(?P<nonce>' +
                    UUID_TEXT + r'):(?P<job>' + UUID_TEXT + r')"(?P=eol)\Z')
ROLES = ('controller', 'worker_enter', 'worker_exit')
OWNERSHIP_KEYS = frozenset(('process', 'OSThread', 'SessionID', 'IB', 'Nmb', 'ID', 'Appl'))


class _Problem(ValueError):
    def __init__(self, code, conflict=False):
        self.code = code
        self.status = 'conflicting' if conflict else 'not_established'
        super().__init__(code)


def _text(value, maximum=256):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise _Problem('missing_or_invalid_text')
    return value


def _uuid(value):
    if not isinstance(value, str) or not re.fullmatch(UUID_TEXT, value):
        raise _Problem('missing_or_invalid_uuid')
    parsed = uuid.UUID(value)
    if not parsed.int:
        raise _Problem('zero_uuid')
    return str(parsed)


def _positive(value):
    if type(value) is not int or not 0 < value < 2 ** 63:
        raise _Problem('invalid_session_number')
    return value


def _numeric_text(value):
    if not isinstance(value, str) or not re.fullmatch(r'[1-9][0-9]{0,18}', value):
        raise _Problem('ambiguous_or_invalid_numeric_property')
    return str(_positive(int(value)))


def _reference(value):
    if not isinstance(value, dict):
        raise _Problem('missing_evidence')
    ref = {key: _text(value.get(key), 512 if key == 'id' else 256) for key in ('id', 'source')}
    digest = value.get('sha256')
    if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise _Problem('invalid_evidence_hash')
    ref['sha256'] = digest
    for key in ('line', 'end_line', 'byte_start', 'byte_end'):
        if key in value:
            if type(value[key]) is not int or value[key] < (0 if key.startswith('byte_') else 1):
                raise _Problem('invalid_evidence_position')
            ref[key] = value[key]
    return ref


def _event_ref(record):
    if not isinstance(record, dict):
        raise _Problem('invalid_native_record')
    ref = _reference(record.get('evidence'))
    for key in ('byte_start', 'byte_end'):
        value = record.get(key)
        if type(value) is not int or value < 0 or (key in ref and ref[key] != value):
            raise _Problem('invalid_evidence_position', True)
        ref[key] = value
    if ref['byte_end'] <= ref['byte_start']:
        raise _Problem('invalid_evidence_position', True)
    return ref


def _file_path(value):
    value = _text(value, 4096)
    drive, tail = ntpath.splitdrive(value)
    if not drive or not ntpath.isabs(value) or not tail or any(c in value for c in '\r\n\x00'):
        raise _Problem('unsupported_file_database_path')
    return ntpath.normcase(ntpath.normpath(value))


def _connection(value):
    value = _text(value, 8192)
    match = re.fullmatch(r'File="((?:[^"]|"")+)";', value)
    if not match:
        raise _Problem('only_observed_file_connection_supported')
    return _file_path(match[1].replace('""', '"'))


def _clock(data):
    if data.get('clock_epoch') != '0001-01-01T00:00:00Z' or data.get('clock_precision') != 'milliseconds':
        raise _Problem('unknown_runtime_clock')
    value = data.get('observed_utc_ms')
    if type(value) is not int or not 0 <= value <= 315537897599999:
        raise _Problem('invalid_runtime_clock')
    stamp = EPOCH + timedelta(milliseconds=value)
    seconds = stamp.isoformat(timespec='seconds').replace('+00:00', 'Z')
    if data.get('observed_utc_seconds') != seconds:
        raise _Problem('conflicting_runtime_clock', True)
    return stamp


def _utc(value):
    try:
        stamp = datetime.fromisoformat(_text(value, 64))
    except ValueError as error:
        raise _Problem('invalid_native_timestamp') from error
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise _Problem('missing_timestamp_offset')
    try:
        return stamp.astimezone(timezone.utc)
    except (ValueError, OverflowError) as error:
        raise _Problem('invalid_native_timestamp') from error


def _iso(stamp):
    return stamp.isoformat(timespec='microseconds')


def _offset(value):
    if not isinstance(value, str) or not re.fullmatch(r'[+-][0-9]{2}:[0-9]{2}', value):
        raise _Problem('missing_platform_utc_offset')
    hours, minutes = int(value[1:3]), int(value[4:])
    if hours > 23 or minutes > 59 or value == '-00:00':
        raise _Problem('invalid_platform_utc_offset')
    return timezone(timedelta(minutes=(hours * 60 + minutes) * (1 if value[0] == '+' else -1)))


def _platform_time(value, offset):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}', value):
        raise _Problem('missing_or_invalid_platform_date')
    try:
        return datetime.fromisoformat(value).replace(tzinfo=offset).astimezone(timezone.utc)
    except (ValueError, OverflowError) as error:
        raise _Problem('invalid_platform_date') from error


def _empty_lifecycle():
    return dict(status='not_established', job_uuid=None, state=None, begin_utc=None, end_utc=None,
                execution_seconds=None, precision_seconds=1, execution_bounds_seconds=None,
                queue_seconds=None, total_seconds=None, evidence=[], limitations=[],
                time_basis='explicit_offset_and_same_host_UTC_checks; second_resolution_not_exact')


def _empty_link():
    return dict(status='not_established', identity={}, body={}, session={}, linked_evidence=[],
                linked_count=0, linked_evidence_truncated=False, limitations=[],
                clock_alignment=dict(status='not_verified', containment_at_1ms_resolution=None,
                    marker_enter_minus_runtime_enter_ms=None, marker_exit_minus_runtime_exit_ms=None),
                coverage='recorded_subset_between_markers_only; not_whole_job_or_file')


def _documents(documents, selected):
    roles, refs, used_sources = {}, {}, set()
    for document in documents:
        if not isinstance(document, dict) or document.get('role') not in ROLES:
            raise _Problem('invalid_document_role')
        role, data = document['role'], document.get('data')
        if role in roles:
            raise _Problem('duplicate_document_role', True)
        if (not isinstance(data, dict) or type(data.get('schema')) is not int or data['schema'] != 1 or
                data.get('origin') != 'controlled_real_background_job'):
            raise _Problem('unsupported_runtime_document')
        if _uuid(data.get('job_uuid')) != selected:
            raise _Problem('runtime_job_identity_conflict', True)
        _uuid(data.get('nonce'))
        ref = _reference(document.get('evidence'))
        if ref['source'] in used_sources:
            raise _Problem('duplicate_runtime_snapshot_source', True)
        used_sources.add(ref['source'])
        roles[role], refs[role] = document, ref
    if 'controller' not in roles:
        raise _Problem('missing_controller')
    controller = roles['controller']['data']
    nonce = _uuid(controller.get('nonce'))
    database = _connection(controller.get('connection_string'))
    for document in roles.values():
        data = document['data']
        if _uuid(data['nonce']) != nonce:
            raise _Problem('runtime_nonce_conflict', True)
        if 'connection_string' in data and _connection(data['connection_string']) != database:
            raise _Problem('runtime_database_conflict', True)
    final = controller.get('final_job_snapshot')
    if isinstance(final, dict) and _uuid(final.get('job_uuid')) != selected:
        raise _Problem('final_snapshot_job_conflict', True)
    observed = [document['data'] for document in roles.values()]
    if isinstance(final, dict):
        observed.append(final)
    hosts = {_text(data['computer_name']).casefold() for data in observed if 'computer_name' in data}
    if len(hosts) > 1:
        raise _Problem('runtime_hostname_conflict', True)
    return roles, refs, nonce, database


def _lifecycle(roles, refs, selected):
    result = _empty_lifecycle()
    result.update(job_uuid=selected, evidence=list(refs.values()))
    try:
        final = roles['controller']['data'].get('final_job_snapshot')
        if not isinstance(final, dict):
            raise _Problem('missing_final_job_snapshot')
        state = final.get('job_state_code')
        if state not in ('completed', 'failed', 'canceled', 'active'):
            raise _Problem('canonical_job_state_missing')
        result['state'] = state
        if final.get('platform_date_precision') != 'seconds':
            raise _Problem('unsupported_platform_date_precision')
        offset_text = roles['controller'].get('platform_utc_offset')
        offset = _offset(offset_text)
        for document in roles.values():
            if document.get('platform_utc_offset') != offset_text:
                raise _Problem('conflicting_platform_utc_offsets', True)
        begin = _platform_time(final.get('job_begin_platform_date'), offset)
        observed = _clock(final)
        result['begin_utc'] = _iso(begin)
        end_value = final.get('job_end_platform_date')
        if state == 'active':
            if end_value is not None:
                raise _Problem('active_job_has_end', True)
            end = None
        else:
            end = _platform_time(end_value, offset)
            if end < begin:
                raise _Problem('reversed_platform_dates', True)
        # These are containment checks on the declared same-host profile,
        # not a time-proximity join or proof that clocks on other hosts agree.
        rounding = timedelta(seconds=1)
        if begin >= observed + rounding or (end is not None and end >= observed + rounding):
            raise _Problem('platform_dates_conflict_with_UTC_observation', True)
        for role in ('worker_enter', 'worker_exit'):
            if role not in roles:
                continue
            worker = roles[role]['data']
            stamp = _clock(worker)
            if begin >= stamp + rounding or (end is not None and end <= stamp - rounding):
                raise _Problem('platform_dates_conflict_with_worker_UTC', True)
            if stamp > observed + timedelta(milliseconds=1):
                raise _Problem('controller_observed_before_worker', True)
            if ('job_begin_platform_date' in worker and
                    worker['job_begin_platform_date'] != final['job_begin_platform_date']):
                raise _Problem('worker_platform_begin_conflict', True)
        if end is not None:
            duration = int((end - begin).total_seconds())
            result.update(end_utc=_iso(end), execution_seconds=duration,
                          execution_bounds_seconds=[max(0, duration - 1), duration + 1])
        result['status'] = 'established'
    except _Problem as error:
        result['status'] = error.status
        result['limitations'].append(dict(code=error.code))
    return result


def _marker(record):
    if not isinstance(record, dict) or record.get('event') != 'SDBL':
        return None
    properties = record.get('properties')
    value = properties.get('Sdbl') if isinstance(properties, dict) else None
    if not isinstance(value, str) or len(value) > 256:
        return None
    match = MARKER.fullmatch(value)
    return (match['stage'], _uuid(match['nonce']), _uuid(match['job'])) if match else None


def _ambiguous_identity(record):
    ambiguous = record.get('ambiguous_properties', {})
    if not isinstance(ambiguous, dict):
        return True
    keys = OWNERSHIP_KEYS
    if record.get('event') == 'SESN':
        keys = keys | {'Func'}
    elif record.get('event') == 'SDBL':
        keys = keys | {'Sdbl'}
    return any(key in ambiguous for key in keys)


def _context(record):
    props = record.get('properties')
    if not isinstance(props, dict):
        raise _Problem('missing_native_properties')
    return (_text(props.get('process'), 128), _numeric_text(props.get('OSThread')))


def record_matches_link(record, native_link):
    """Match only an already verified immutable body window; safe for paging."""
    try:
        if native_link.get('status') != 'established':
            return False
        if _ambiguous_identity(record):
            return False
        identity, body = native_link['identity'], native_link['body']
        ref = _event_ref(record)
        if (ref['source'], ref['sha256']) != (identity['source'], identity['sha256']):
            return False
        if _context(record) != (identity['process_label'], identity['os_thread']):
            return False
        if not body['marker_byte_start'] <= ref['byte_start'] < ref['byte_end'] <= body['marker_byte_end']:
            return False
        stamp = _utc(record.get('timestamp_utc'))
        if not _utc(body['marker_enter_utc']) <= stamp <= _utc(body['marker_exit_utc']):
            return False
        props = record['properties']
        if 'SessionID' in props and _numeric_text(props['SessionID']) != str(identity['session_number']):
            return False
        if 'IB' in props and _file_path(props['IB']) != identity['database_file']:
            return False
        marker = _marker(record)
        if marker and marker[1:] != (identity['nonce'], identity['job_uuid']):
            return False
        return True
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return False


def _native_link(roles, refs, nonce, database, selected, records):
    result = _empty_link()
    try:
        if not all(role in roles for role in ('worker_enter', 'worker_exit')):
            raise _Problem('missing_worker_body_boundary')
        enter, leave = roles['worker_enter']['data'], roles['worker_exit']['data']
        if enter.get('stage') != 'body_enter' or leave.get('stage') != 'body_exit':
            raise _Problem('worker_stage_conflict', True)
        session_number = _positive(enter.get('session_id'))
        if (_positive(enter.get('session_info_number')) != session_number or
                _positive(leave.get('session_id')) != session_number):
            raise _Problem('runtime_session_conflict', True)
        if 'session_info_number' in leave and _positive(leave['session_info_number']) != session_number:
            raise _Problem('runtime_session_conflict', True)
        if ('connection_id' in enter and 'connection_id' in leave and
                enter['connection_id'] != leave['connection_id']):
            raise _Problem('runtime_connection_conflict', True)
        if _connection(enter.get('connection_string')) != database:
            raise _Problem('runtime_database_conflict', True)
        body_enter, body_exit = _clock(enter), _clock(leave)
        if body_exit < body_enter:
            raise _Problem('reversed_worker_body_clock', True)
        elapsed_ms = (body_exit - body_enter) // timedelta(milliseconds=1)
        if 'body_observed_elapsed_ms' in leave:
            if type(leave['body_observed_elapsed_ms']) is not int or leave['body_observed_elapsed_ms'] != elapsed_ms:
                raise _Problem('worker_elapsed_clock_conflict', True)
        markers = {'body_enter': [], 'body_exit': []}
        all_markers = []
        for record in records:
            marker = _marker(record)
            if marker:
                all_markers.append((record, marker))
                stage, found_nonce, found_job = marker
                if found_nonce == nonce or found_job == selected:
                    if (found_nonce, found_job) != (nonce, selected):
                        raise _Problem('marker_run_identity_conflict', True)
                    markers[stage].append(record)
        if any(len(found) > 1 for found in markers.values()):
            raise _Problem('duplicate_job_marker', True)
        if any(not found for found in markers.values()):
            raise _Problem('missing_exact_job_marker')
        first, last = markers['body_enter'][0], markers['body_exit'][0]
        first_ref, last_ref = _event_ref(first), _event_ref(last)
        source, digest = first_ref['source'], first_ref['sha256']
        context = _context(first)
        if context[0] != '1cv8':
            raise _Problem('native_process_outside_tested_file_profile')
        if ((last_ref['source'], last_ref['sha256']) != (source, digest) or _context(last) != context):
            raise _Problem('marker_source_or_thread_conflict', True)
        if first_ref['byte_end'] > last_ref['byte_start']:
            raise _Problem('marker_byte_order_conflict', True)
        first_time, last_time = _utc(first.get('timestamp_utc')), _utc(last.get('timestamp_utc'))
        if last_time < first_time:
            raise _Problem('native_marker_time_order_conflict', True)
        # Do not use cross-clock containment as identity proof. Actual captures
        # show a later TJ timestamp for a query executed before runtime exit.
        # Retain the former 1 ms comparison as an explicit diagnostic, without
        # claiming synchronization or inventing a larger acceptable tolerance.
        resolution = timedelta(milliseconds=1)
        nested = body_enter - resolution <= first_time <= last_time <= body_exit + resolution
        clock_alignment = dict(status='not_verified', containment_at_1ms_resolution=nested,
            marker_enter_minus_runtime_enter_ms=(first_time - body_enter) // timedelta(microseconds=1) / 1000,
            marker_exit_minus_runtime_exit_ms=(last_time - body_exit) // timedelta(microseconds=1) / 1000)
        same_context, same_source = [], []
        for record in records:
            evidence = record.get('evidence', {}) if isinstance(record, dict) else {}
            if not isinstance(evidence, dict) or evidence.get('source') != source:
                continue
            if evidence.get('sha256') != digest:
                raise _Problem('source_snapshot_hash_conflict', True)
            ref = _event_ref(record)
            same_source.append(record)
            if first_ref['byte_start'] <= ref['byte_start'] < last_ref['byte_end'] and _ambiguous_identity(record):
                raise _Problem('ambiguous_body_ownership', True)
            try:
                if _context(record) == context:
                    same_context.append(record)
            except _Problem:
                continue
        starts, finishes = [], []
        for record in same_context:
            props = record['properties']
            if record.get('event') == 'SESN' and props.get('Nmb') == str(session_number):
                if props.get('Func') == 'Start':
                    starts.append(record)
                elif props.get('Func') == 'Finish':
                    finishes.append(record)
        if len(starts) > 1 or len(finishes) > 1:
            raise _Problem('session_number_reused_or_duplicated', True)
        if len(starts) != 1 or len(finishes) != 1:
            raise _Problem('missing_unique_session_boundaries')
        start, finish = starts[0], finishes[0]
        start_ref, finish_ref = _event_ref(start), _event_ref(finish)
        session_uuid = _uuid(start['properties'].get('ID'))
        for record in (start, finish):
            props = record['properties']
            if (props.get('Appl') != 'BackgroundJob' or _file_path(props.get('IB')) != database or
                    _uuid(props.get('ID')) != session_uuid):
                raise _Problem('session_identity_conflict', True)
        start_time, finish_time = _utc(start.get('timestamp_utc')), _utc(finish.get('timestamp_utc'))
        if (not start_ref['byte_end'] <= first_ref['byte_start'] < last_ref['byte_end'] <= finish_ref['byte_start'] or
                not start_time <= first_time <= last_time <= finish_time):
            raise _Problem('markers_outside_session_bounds', True)
        for record in same_source:
            if start_ref['byte_start'] <= record['byte_start'] < finish_ref['byte_end']:
                if _ambiguous_identity(record):
                    raise _Problem('ambiguous_session_ownership', True)
                if record.get('event') == 'SESN':
                    try:
                        _context(record)
                    except _Problem as error:
                        raise _Problem('session_context_missing_in_verified_window') from error
        # Any competing session or run inside these exact native boundaries
        # invalidates the narrow single-thread ownership claim.
        for record in same_context:
            ref = _event_ref(record)
            if not start_ref['byte_start'] <= ref['byte_start'] <= finish_ref['byte_start']:
                continue
            props = record['properties']
            if record.get('event') == 'SESN' and (
                    props.get('Nmb') != str(session_number) or _uuid(props.get('ID')) != session_uuid):
                raise _Problem('overlapping_session_on_worker_thread', True)
            if first_ref['byte_start'] <= ref['byte_start'] < last_ref['byte_end']:
                if 'SessionID' in props and _numeric_text(props['SessionID']) != str(session_number):
                    raise _Problem('body_record_session_conflict', True)
                if 'IB' in props and _file_path(props['IB']) != database:
                    raise _Problem('body_record_database_conflict', True)
        for record, marker in all_markers:
            ref = _event_ref(record)
            if ((ref['source'], ref['sha256']) == (source, digest) and _context(record) == context and
                    first_ref['byte_start'] <= ref['byte_start'] < last_ref['byte_end'] and
                    marker[1:] != (nonce, selected)):
                raise _Problem('overlapping_job_marker', True)
        result.update(status='established', identity=dict(job_uuid=selected, nonce=nonce, database_file=database,
            session_number=session_number, session_uuid=session_uuid, source=source, sha256=digest,
            process_label=context[0], os_thread=context[1], node=None, process_id=None, epoch=None))
        result['clock_alignment'] = clock_alignment
        if not nested:
            result['limitations'].append(dict(code='cross_clock_order_disagreement'))
        result['body'] = dict(enter_utc=_iso(body_enter), exit_utc=_iso(body_exit), observed_elapsed_ms=elapsed_ms,
            marker_enter_utc=_iso(first_time), marker_exit_utc=_iso(last_time),
            marker_byte_start=first_ref['byte_start'], marker_byte_end=last_ref['byte_end'],
            marker_evidence=[first_ref, last_ref], runtime_evidence=[refs['worker_enter'], refs['worker_exit']],
            clock_basis='controlled_same_host_only; runtime_resolution_1ms; synchronization_not_verified')
        result['session'] = dict(start_utc=_iso(start_time), end_utc=_iso(finish_time),
            recorded_seconds=(finish_time - start_time).total_seconds(), evidence=[start_ref, finish_ref],
            interpretation='recorded_SESN_interval_not_whole_job_execution')
        matching = sorted((record for record in same_context if record_matches_link(record, result)),
                          key=lambda record: record['byte_start'])
        previous_end = -1
        for record in matching:
            ref = _event_ref(record)
            if ref['byte_start'] < previous_end:
                raise _Problem('duplicate_or_overlapping_native_evidence', True)
            previous_end = ref['byte_end']
            result['linked_count'] += 1
            if len(result['linked_evidence']) < MAX_LINK_REFS:
                result['linked_evidence'].append(ref)
        result['linked_evidence_truncated'] = result['linked_count'] > MAX_LINK_REFS
    except _Problem as error:
        result = _empty_link()
        result['status'] = error.status
        result['limitations'].append(dict(code=error.code))
    return result


def correlate_job(lifecycle_documents, native_events, selection):
    """Correlate one explicitly selected real Job UUID, with independent results.

    Callers must enforce the versioned source profile and snapshot integrity.
    Selection labels other than run are deliberately not used as identity proof.
    """
    if not isinstance(lifecycle_documents, list) or len(lifecycle_documents) > MAX_DOCUMENTS:
        raise ValueError('lifecycle_documents must be a list of at most 32 snapshots')
    if not isinstance(native_events, list) or len(native_events) > MAX_EVENTS:
        raise ValueError('native_events must be a list of at most 100000 parsed observations')
    if not isinstance(selection, dict):
        raise ValueError('selection must identify a Job UUID')
    lifecycle, link = _empty_lifecycle(), _empty_link()
    try:
        selected = _uuid(selection.get('run'))
        roles, refs, nonce, database = _documents(lifecycle_documents, selected)
        lifecycle = _lifecycle(roles, refs, selected)
        link = _native_link(roles, refs, nonce, database, selected, native_events)
    except _Problem as error:
        for result in (lifecycle, link):
            result['status'] = error.status
            result['limitations'].append(dict(code=error.code))
    return dict(status=link['status'], job_lifecycle=lifecycle, native_link=link)
