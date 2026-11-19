"""Reparse the retained bytes of an attached case with corrected TJ offsets."""
from datetime import datetime
from hashlib import sha256
import re

from . import context_fields, context_policy, investigations, native_tj
from . import operation_state as fs, source_coverage, storage
from .case_retention import case_writers
from .inputs import InputError, MAX_EVENTS, json_value, read_snapshot


SOURCE_ID = re.compile(r's(?:[1-9]|[12][0-9]|3[0-2])')


def schema(cap):
    offset = cap.obj(dict(source_id=cap.string(3, pattern=SOURCE_ID.pattern),
                          utc_offset=cap.string(6, pattern=r'[+-][0-9]{2}:[0-9]{2}')),
                     ('source_id', 'utc_offset'))
    choice = cap.obj(dict(attachment=cap.string(62, pattern=r'A-[a-zA-Z0-9-]{1,60}'),
                          offsets=dict(type='array', items=offset, minItems=1, maxItems=32),
                          window=cap.WINDOW), ('attachment', 'offsets'))
    return cap.obj(dict(retained_tj=choice), ('retained_tj',))


def normalize(cap, arguments):
    result = cap.validate(arguments, schema(cap))
    selected = result['retained_tj']
    identifiers = [item['source_id'] for item in selected['offsets']]
    if len(identifiers) != len(set(identifiers)):
        raise InputError('choose at most one correction per retained TJ source')
    for item in selected['offsets']:
        native_tj._offset(item['utc_offset'])
    selected['offsets'].sort(key=lambda item: int(item['source_id'][1:]))
    if 'window' in selected:
        selected['window'] = source_coverage.validate_request(window=selected['window'])['window']
    return result


def attachment(doc, name):
    return next((item for item in doc['attachments'] if item['id'] == name and item['kind'] == 'case'), None)


def _offset(profile):
    if profile['timestamp_format'] == 'minute':
        return profile['file_hour'][-6:]
    return profile['utc_offset']


def _edit_profile(spec, old, offset):
    declared = native_tj.validate_profile(spec, spec['path'])
    keys = ('format', 'platform_version', 'encoding', 'placement', 'timestamp_format',
            'file_hour', 'rotation_hours', 'utc_offset')
    if any(old['profile'].get(key) != declared.get(key) for key in keys):
        raise InputError('retained TJ profile differs from its saved manifest')
    if spec['timestamp_format'] == 'minute':
        hour = datetime.fromisoformat(spec['file_hour'])
        spec['file_hour'] = hour.replace(tzinfo=native_tj._offset(offset)).isoformat()
    else:
        spec['utc_offset'] = offset


def _manifest(state, original, selected, window):
    folder = storage.case_folder(state, original['case_id'])
    raw = read_snapshot(fs.safe(folder / 'manifest.json'), 1024 * 1024)
    receipt = fs.read(folder / 'receipt.json', 8192)
    if sha256(raw).hexdigest() != receipt['manifest_sha256']:
        raise InputError('saved manifest changed during retained TJ correction')
    manifest = json_value(raw.decode('utf-8-sig'), reject_duplicates=True)
    if window is not None:
        manifest['incident_window'] = window
    sources = {item['id']: item for item in original['sources']}
    attempts = {item['id']: item for item in original.get('source_acquisition', [])}
    if any(item['format'] in native_tj.FORMATS and
           (type(item.get('record_budget')) is not int or not 0 <= item['record_budget'] <= MAX_EVENTS)
           for item in sources.values()):
        raise InputError('retained TJ correction requires the saved record budgets')
    requested = {item['source_id']: item['utc_offset'] for item in selected}
    if any(identifier not in sources or sources[identifier]['format'] not in native_tj.FORMATS
           for identifier in requested):
        raise InputError('correct only available retained native TJ sources')
    changed = any(_offset(sources[identifier]['profile']) != offset for identifier, offset in requested.items())
    if not changed:
        raise InputError('the requested TJ offsets are already in the retained case')
    for number, spec in enumerate(manifest['sources'], 1):
        identifier = f's{number}'
        if identifier in requested:
            _edit_profile(spec, sources[identifier], requested[identifier])
        # The original path remains capture metadata. All file access is to the
        # saved case. Uncaptured slots keep their original availability and ID.
        spec['path'] = str(folder / 'sources' / (identifier + '.bin'))
        spec.pop('external_window', None)
        spec.pop('read_mode', None)
        attempts.setdefault(identifier, dict(id=identifier, format=spec['format'], availability='not_retained'))
    return manifest, dict(sources=sources, attempts=attempts)


def _period(coverage, source):
    saved = next(row for row in coverage['sources'] if row['id'] == source['id'])
    value = saved['period']
    return dict(utc_offset=_offset(source['profile']),
                first_utc=value['first_recorded_timestamp_utc'], last_utc=value['last_recorded_timestamp_utc'],
                record_count=saved['record_count'], records_in_window=value['records_in_window'])


def _job(report):
    correlation = report.get('job_correlation', {})
    link = correlation.get('native_link', {})
    clock = link.get('clock_alignment', {})
    return dict(link_status=context_fields.enum(correlation.get('status'),
                ('established', 'conflicting', 'not_established'), 'not_established'),
                linked_records=context_fields.number(link.get('linked_count')),
                execution_seconds=context_fields.number(report['durations_seconds'].get('execution')),
                marker_enter_delta_ms=context_fields.number(clock.get('marker_enter_minus_runtime_enter_ms')),
                marker_exit_delta_ms=context_fields.number(clock.get('marker_exit_minus_runtime_exit_ms')))


def summarize(correction, derived):
    original = correction['original']
    before = correction['before']
    after = derived['source_coverage']
    if before['request']['window'] != after['request']['window']:
        raise InputError('before and after must use the same incident window')
    sources = {row['id']: row for row in derived['sources']}
    changes = []
    for selected in correction['selected']:
        identifier = selected['source_id']
        old = correction['input']['sources'][identifier]
        new = sources[identifier]
        changes.append(dict(source_id=identifier, before=_period(before, old), after=_period(after, new),
                            retained_capture_window_only='reference_capture' in old))
    return dict(original_case_id=original['case_id'], original_attachment=correction['attachment'],
                original_report_sha256=investigations._digest(original), sources=changes,
                window=after['request']['window'], window_basis=correction['window_basis'],
                before_job=_job(original), after_job=_job(derived),
                scope='same_retained_bytes', clock_alignment='not_verified',
                source_coverage_complete=False, causes_reassessed_by_tool=False)


def execute(state, output, selection, binding, *, stop):
    from . import profile_journals
    from .operations import _guard_dependency_paths

    doc = context_policy.selected_investigation(state, binding['investigation_id'], binding['expected_revision'])
    if fs.digest(doc) != binding['report_sha256']:
        raise InputError('retained TJ investigation binding changed')
    pinned = attachment(doc, selection['attachment'])
    if pinned is None:
        raise InputError('select a retained case attached to this investigation revision')
    case_id = pinned['target_id']
    window, basis = profile_journals._window(doc, selection.get('window'))
    with case_writers(state, (case_id,)):
        _guard_dependency_paths(state, 'cases', case_id)
        original, raw_sha = storage.load_case(state, case_id, with_digest=True)
        if investigations._digest(original) != pinned['report_sha256']:
            raise InputError('retained source differs from the investigation attachment')
        manifest, retained = _manifest(state, original, selection['offsets'], window)
        before = source_coverage.inspect_case(state, case_id, window=window)
        if before['case_report_sha256'] != raw_sha:
            raise InputError('retained source changed before correction')
        if stop():
            raise InputError('retained TJ correction stopped')
        correction = dict(original=original, input=retained, before=before, attachment=pinned['id'],
                          selected=selection['offsets'], window_basis=basis or (
                              'saved_case_window' if before['request']['window'] is not None else 'not_selected'))
        stage = fs.safe(output / 'retained-tj-manifest.json')
        with stage.open('xb') as stream:
            stream.write(fs.encode(manifest))
        result = storage.investigate(stage, output, should_stop=stop, time_correction=correction)
    return result, [dict(kind='cases', id=result['case_id'])]


def pin(args, report, add):
    correction = report['time_correction']
    original = add('cases', correction['original_case_id'])
    verify_parent(report, original)
    if correction['original_attachment'] != args['retained_tj']['attachment']:
        raise InputError('saved TJ correction differs from its retained input')
    expected = {item['source_id']: item['utc_offset'] for item in args['retained_tj']['offsets']}
    if {row['source_id']: row['after']['utc_offset'] for row in correction['sources']} != expected:
        raise InputError('saved TJ correction differs from the requested offsets')


def verify_parent(report, original):
    correction = report['time_correction']
    if (correction['original_case_id'] != original['case_id']
            or correction['original_report_sha256'] != investigations._digest(original)):
        raise InputError('saved TJ correction differs from its retained input')

    def members(case):
        return [(item['id'], item['format'], item['sha256'], item['size']) for item in case['sources']]

    if members(original) != members(report):
        raise InputError('TJ correction changed retained evidence bytes or source order')
