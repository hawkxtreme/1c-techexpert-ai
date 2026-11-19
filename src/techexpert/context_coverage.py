"""Recorded-time coverage of retained journals for a selected investigation window."""
from collections import Counter
import stat

from . import artifacts, context_fields as fields, investigations, native_jr, native_tj
from . import operation_state as fs, storage
from .analysis import parse_time
from .case_retention import SnapshotRetirement
from .inputs import InputError, MAX_EVENTS, MAX_FILE_BYTES, MAX_RECORD_BYTES, MAX_TOTAL_BYTES, open_verified_snapshot
from .investigation_progress import _occurrence_window
from .source_coverage import validate_collection
from .tj_reference import prefix_summary


VIEWS = {'tj-coverage': ('tj', 'case'), 'jr-coverage': ('jr', 'artifact')}
READER_CAPABILITY = 3
TJ_FIELDS = frozenset(name for names in fields.TJ_ALIASES.values() for name in names)
JR_FIELDS = ('computer', 'session', 'application', 'connection', 'transaction_state', 'metadata')
ACQUISITION_STATES = ('access_denied', 'not_found', 'read_error', 'byte_limit', 'changed_during_read',
                      'unsupported_format', 'unsupported_profile', 'duplicate_source', 'conflicting_profile')
READ_ERRORS = (OSError, ValueError, KeyError, TypeError, RecursionError)


class WindowRequired(InputError):
    pass


def _checked_file(path):
    path = fs.safe(path)
    if not stat.S_ISREG(path.stat().st_mode):
        raise InputError('expected a regular retained file')
    return path


def _pinned_report(state, attachment):
    identifier = attachment['target_id']
    if attachment['kind'] == 'case':
        folder = storage.case_folder(state, identifier)
        for name in ('report.json', 'manifest.json', 'receipt.json'):
            _checked_file(folder / name)
        report = storage.load_case(state, identifier)
    else:
        folder = artifacts.artifact_folder(state, identifier)
        for name in ('report.json', 'request.json', 'receipt.json'):
            _checked_file(folder / name)
        report, _ = artifacts.read_artifact_record(state, identifier)
    if investigations._digest(report) != attachment['report_sha256']:
        raise InputError('coverage attachment differs from its saved report')
    return report


def _failure(exc):
    # load_case preserves OS errors as the cause of its bounded read error.
    error = exc.__cause__ if isinstance(exc.__cause__, OSError) else exc
    if isinstance(error, FileNotFoundError):
        return 'not_found'
    if isinstance(error, PermissionError):
        return 'access_denied'
    if isinstance(error, SnapshotRetirement):
        return 'retired'
    return 'read_error'


def _tj_file(state, case_id, source):
    path = _checked_file(storage.case_source_path(state, case_id, source['id']))
    return open_verified_snapshot(path, source['sha256'], expected_size=source['size'])


def _tj_source(state, case_id, source, bounds, wanted, remaining_records):
    try:
        profile = native_tj.validate_profile(source['profile'], '')
    except (KeyError, ValueError, OverflowError):
        return dict(availability='not_checked', assessment='unsupported_profile'), 0
    saved_budget = source.get('record_budget', 0)
    if type(saved_budget) is not int or not 0 <= saved_budget <= MAX_EVENTS:
        raise InputError('invalid saved TJ record budget')
    collection = source.get('collection') or {}
    if collection not in ({}, {'status': 'unknown'}):
        collection = validate_collection({key: value for key, value in collection.items() if key != 'status'})
    declared_start_end = collection.get('window')
    declared = tuple(parse_time(declared_start_end[key]) for key in ('start', 'end')) if declared_start_end else None
    declares_wanted = wanted in collection['events'] if 'events' in collection else None
    declaration_applies = declares_wanted is not None and (declared is None or declared[0] <= bounds[0] < bounds[1] <= declared[1])
    first = last = None
    selected_count = other_count = total = contradicting_declaration = 0
    events = Counter()
    present = Counter()
    usable = Counter()
    with _tj_file(state, case_id, source) as content:
        scan = native_tj.iter_tj(content, profile, max_records=min(saved_budget, remaining_records),
                                 max_record_bytes=MAX_RECORD_BYTES)
        for record in scan:
            stamp = parse_time(record['timestamp_utc'])
            first = stamp if first is None else min(first, stamp)
            last = stamp if last is None else max(last, stamp)
            total += 1
            event = record['event']
            if (event == wanted and declares_wanted is False
                    and (declared is None or declared[0] <= stamp < declared[1])):
                contradicting_declaration += 1
            if not bounds[0] <= stamp < bounds[1]:
                continue
            selected_count += 1
            if event in fields.TJ_NAMES:
                events[event] += 1
            else:
                other_count += 1
            if wanted is None or event == wanted:
                properties, ambiguous = record['properties'], record['ambiguous_properties']
                present.update(TJ_FIELDS & (properties.keys() | ambiguous.keys()))
                usable.update(name for name in TJ_FIELDS & properties.keys()
                              if name not in ambiguous and properties[name].strip())
    parse = scan.summary
    # Catch a retirement admitted after the file was opened.
    storage.case_source_path(state, case_id, source['id'])
    assessment = ('observations_available' if selected_count else
                  'no_recorded_timestamps_in_window' if first is not None else 'insufficient_data')
    reference = source.get('reference_capture', {})
    prefix = prefix_summary(source)
    incomplete = prefix and (prefix['unread_appended_bytes'] or prefix['incomplete_tail_bytes'])
    if selected_count and (parse['status'] != 'parsed' or reference.get('original_parse_status', 'parsed') != 'parsed' or incomplete):
        assessment = 'partial_observations'
    result = dict(availability='captured', assessment=assessment, snapshot_verified=True,
        profile={key: profile[key] for key in ('platform_version', 'encoding', 'placement', 'timestamp_format', 'time_basis')},
        observed_utc_range=[stamp.isoformat() if stamp is not None else None for stamp in (first, last)],
        span_intersects_window=None if first is None else last >= bounds[0] and first < bounds[1],
        records_in_window=selected_count, parsed_records=total, parse_status=parse['status'],
        issue_count=sum(issue.get('count', 1) for issue in parse['limitations']),
        snapshot_scope='saved_reference_window' if reference else 'retained_file_bytes',
        observed_event_counts=dict(events), other_event_records=other_count, observed_field_counts=dict(present),
        usable_field_counts=dict(usable), field_event_scope=wanted,
        collection_basis=collection.get('status', 'unknown'), collection_window=declared_start_end)
    if prefix is not None:
        result.update(snapshot_scope='saved_prefix_window', prefix_capture=prefix)
    if wanted:
        status = ('declaration_conflicts_with_observed' if contradicting_declaration else
                  'observed_in_requested_scope' if events[wanted] else
                  'not_collected_declared' if declaration_applies and not declares_wanted else 'not_observed_collection_unknown')
        result['requested_event'] = dict(name=wanted, status=status, records_in_window=events[wanted],
                                         collection_verified=False)
    return result, parse['records_seen']


def _tj_coverage(state, report, args, window):
    metadata = report['sources']
    attempts = report.get('source_acquisition', [])
    if (type(metadata) is not list or len(metadata) > 32 or type(attempts) is not list or len(attempts) > 32
            or any(type(row) is not dict or fields.identifier(row.get('id'), fields.SOURCE_ID) is None
                   for row in metadata + attempts)):
        raise InputError('invalid saved source catalogue')
    saved = {row['id']: row for row in metadata if row['format'] == native_tj.FORMAT}
    acquisition = {row['id']: row for row in attempts if row.get('format') == native_tj.FORMAT}
    if (any(type(row.get('size')) is not int or not 0 <= row['size'] <= MAX_FILE_BYTES for row in saved.values())
            or sum(row['size'] for row in saved.values()) > MAX_TOTAL_BYTES):
        raise InputError('invalid saved TJ byte budget')
    selected = sorted(saved.keys() | acquisition.keys(), key=lambda value: int(value[1:]))
    start = args.get('offset', 0)
    page = selected[start:start + args.get('limit', 8)]
    bounds = tuple(parse_time(window[key]) for key in ('start', 'end'))
    rows = []
    remaining = MAX_EVENTS
    for source_id in page:
        row = dict(source=source_id, format=native_tj.FORMAT, snapshot_verified=False, assessment='insufficient_data')
        if source_id not in saved:
            capture = acquisition[source_id]
            row.update(availability=fields.enum(capture['availability'], ACQUISITION_STATES),
                       availability_basis='capture_attempt')
            if row['availability'] == 'duplicate_source':
                row['duplicate_of'] = fields.identifier(capture.get('duplicate_of'), fields.SOURCE_ID)
        else:
            row['availability_basis'] = 'retained_snapshot'
            try:
                observed, checked = _tj_source(state, report['case_id'], saved[source_id], bounds,
                                               args.get('event'), remaining)
                row.update(observed)
                remaining -= checked
            except READ_ERRORS as exc:
                row['availability'] = _failure(exc)
        rows.append(row)
    return dict(status='checked' if selected else 'unsupported_format', sources=rows, offset=start,
                total_sources=len(selected), next_offset=start + len(rows) if start + len(rows) < len(selected) else None)


def _jr_file(state, report, source):
    return _checked_file(artifacts.source_path(artifacts.artifact_folder(state, report['artifact_id']),
                                              source, kind=report['kind']))


def _jr_coverage(state, report, window, aliases):
    if report['kind'] != 'native-jr':
        return dict(status='unsupported_format')
    profile = report['result'].get('profile')
    if profile not in (native_jr.PROFILE, native_jr.lgd.PROFILE):
        return dict(status='unsupported_profile')
    journal = dict(profile=profile, snapshot_verified=False, availability='captured')
    try:
        for source in report['sources']:
            _jr_file(state, report, source)
        _, parsed = native_jr._parse_saved(state, report)
        records, period = native_jr._window_rows(parsed, window)
    except READ_ERRORS as exc:
        journal.update(availability=_failure(exc), assessment='insufficient_data')
        return dict(status='checked', journal=journal)
    categories = Counter(row['event'] for row in records)
    top = {alias: count for name, count in categories.most_common(8) if (alias := aliases('jr_event', name))}
    journal.update(period, snapshot_verified=True, assessment=period['status'],
        observed_event_counts=top, other_event_records=len(records) - sum(top.values()),
        observed_field_counts={name: sum(row.get(name) not in (None, '') for row in records) for name in JR_FIELDS})
    return dict(status='checked', journal=journal)


def view(state, doc, attachment, args, aliases):
    occurrence = doc.get('occurrence') or {}
    window = args.get('window') or _occurrence_window(occurrence)
    if window is None:
        raise WindowRequired('coverage requires an explicit bounded episode window')
    common = dict(window=window, window_basis='explicit_window' if 'window' in args else 'saved_occurrence',
        occurrence_status=fields.enum(occurrence.get('status'), ('reported_not_verified', 'evidenced_by_harness'), None),
        time_selection='half_open_recorded_timestamps', continuity='unknown',
        clock_alignment='not_verified', source_identity='not_established', can_establish_absence=False)
    try:
        report = _pinned_report(state, attachment)
    except READ_ERRORS as exc:
        return dict(common, status=_failure(exc), report_verified=False)
    data = (_tj_coverage(state, report, args, window) if args['kind'] == 'tj-coverage'
            else _jr_coverage(state, report, window, aliases))
    if _pinned_report(state, attachment) != report:
        raise InputError('coverage metadata changed during inspection')
    return dict(common, **data, report_verified=True)


def verify_view(state, attachment, kind, data):
    """Recheck material behind a saved program view, without rescanning its records."""
    if not data['report_verified']:
        return  # An unavailable attachment was an observation, with no source proof.
    report = _pinned_report(state, attachment)
    if kind == 'tj-coverage':
        used = {row['source'] for row in data.get('sources', []) if row['snapshot_verified']}
        sources = {row['id']: row for row in report['sources'] if row['format'] == native_tj.FORMAT}
        for source_id in sorted(used):
            with _tj_file(state, report['case_id'], sources[source_id]):
                pass
            storage.case_source_path(state, report['case_id'], source_id)
    elif data.get('journal', {}).get('snapshot_verified'):
        for source in report['sources']:
            with open_verified_snapshot(_jr_file(state, report, source), source['sha256'], expected_size=source['bytes']):
                pass
