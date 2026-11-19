"""Find registration-journal candidates near a retained native TJ record."""
from datetime import datetime, timedelta

from . import artifacts, context_coverage, context_fields as fields, native_jr, source_passports, storage
from .analysis import parse_time
from .inputs import InputError


VIEW = 'jr-near-tj'
DEFAULT_RADIUS = 5
MAX_RADIUS = 300
READER_CAPABILITY = 6


def anchor_ref(doc, args):
    label = args['anchor_attachment']
    target = next((item for item in doc['attachments'] if item['id'] == label and item['kind'] == 'case'), None)
    if target is None:
        raise InputError('select a retained TJ anchor in the same investigation revision')
    return dict(attachment=label, source_id=target['target_id'], source_report_sha256=target['report_sha256'],
                record=args['record'])


def _bound_passports(doc, attachment, source):
    result = []
    for item in doc.get('source_bindings', []):
        passport = item['passport']
        if item['attachment'] != attachment or passport['type'] != ('tj' if source else 'jr'):
            continue
        if source and not any(member['id'] == source for member in passport['content']):
            continue
        if not source and passport['access_scope']['record_source'] is not None:
            continue
        result.append(item)
    return result


def _relation(doc, anchor, journal, stamp, bounds):
    tj = _bound_passports(doc, anchor['attachment'], anchor['record'].split(':')[0])
    jr = _bound_passports(doc, journal, None)
    common = dict(exact_correlation_allowed=False, status='unknown',
                  required_checks=['source_ownership_and_applicability', 'independent_clock_alignment',
                                   'session_or_run_identifier_with_lifetime'])
    if len(tj) != 1 or len(jr) != 1:
        return dict(common, reasons=['ambiguous_passports' if len(tj) > 1 or len(jr) > 1 else 'missing_passport'])

    left, right = tj[0], jr[0]
    saved = [dict(id=link['id'], claim=link['claim'], status=link['check']['status'])
             for link in doc.get('source_links', [])
             if {link['left'], link['right']} == {left['id'], right['id']}
             and link['claim'] in ('same_infobase', 'same_run')]
    one, two = left['passport'], right['passport']
    check = source_passports._check(one, two, 'same_infobase', False)
    reasons = check['reasons']
    conflict = check['status'] == 'conflict' or 'different_declared_bases' in reasons
    for field, reason in (('infobase_identity','different_infobase_claims'), ('database_mode','different_database_modes')):
        a, b = one['facts'][field], two['facts'][field]
        if a['value'] is not None and b['value'] is not None and a['value'] != b['value']:
            reasons.append(reason)
            conflict = True
    left_time, right_time = one['applicability'], two['applicability']
    outside = (left_time['start'] and stamp < datetime.fromisoformat(left_time['start'])
               or left_time['end'] and stamp >= datetime.fromisoformat(left_time['end'])
               or right_time['start'] and bounds[0] < datetime.fromisoformat(right_time['start'])
               or right_time['end'] and bounds[1] > datetime.fromisoformat(right_time['end']))
    if outside:
        reasons.append('outside_declared_applicability')
    status = 'conflict' if conflict else 'outside_applicability' if outside else 'unconfirmed'
    return dict(common, status=status, reasons=reasons, tj_passport=left['id'], jr_passport=right['id'],
                saved_links=saved[:4], saved_link_count=len(saved))


def view(state, doc, attachment, anchor, args, aliases):
    from .operations import _guard_dependency_paths

    case = anchor['source_id']
    journal = attachment['target_id']
    _guard_dependency_paths(state,'cases',case)
    _guard_dependency_paths(state,'artifacts',journal)
    a = dict(kind='case',target_id=case,report_sha256=anchor['source_report_sha256'])
    tj_report = context_coverage._pinned_report(state,a)
    jr_report = context_coverage._pinned_report(state,attachment)
    if jr_report.get('kind') != 'native-jr':
        raise InputError('select a retained native registration journal')
    retained = storage.read_evidence(state, case, anchor['record'], native_metadata=True)
    stamp = parse_time(retained['timestamp_utc'])
    radius = timedelta(seconds=args.get('within_seconds', DEFAULT_RADIUS))
    try:
        bounds = stamp - radius, stamp + radius
    except OverflowError as exc:
        raise InputError('the journal search window extends past the supported timestamp range') from exc
    window = dict(start=bounds[0].isoformat(),end=bounds[1].isoformat())
    page = native_jr.list_events(state,journal,window=window,nearest_to=stamp.isoformat(),
                                 offset=args.get('offset',0),limit=args.get('limit',20))
    if storage.load_case(state,case) != tj_report or artifacts.load_artifact(state,journal) != jr_report:
        raise InputError('a selected journal changed during verification')
    records = [dict(fields.jr_event(row,aliases),
                    recorded_delta_seconds=(parse_time(row['timestamp']) - stamp).total_seconds()) for row in page['records']]
    event = retained['event']
    anchor_view = dict(attachment=anchor['attachment'], event=fields.enum(event, fields.TJ_NAMES, None) or aliases('event',event),
                       timestamp_utc=stamp.isoformat(), time_basis=fields.enum(retained['time_basis'],
                           ('user_declared_hour_and_offset','recorded_date_and_user_declared_offset')),
                       evidence=fields.proof(retained))
    return dict(anchor=anchor_view, records=records, coverage=page['coverage'],window=window,offset=page['offset'],
                matched_count=page['total_matched'],next_offset=page['next_offset'],order='nearest_recorded_timestamp',
                time_selection='half_open_recorded_timestamps',clock_alignment='not_verified',can_establish_absence=False,
                source_relation=_relation(doc,anchor,attachment['id'],stamp,bounds))
