"""Prepare a bounded typed view from one verified retained attachment."""
from hashlib import sha256
import json
from pathlib import Path
import re
import time
import uuid

from . import context_coverage, context_excerpt, context_fields as fields, context_policy as policy, investigations
from . import operation_state as fs, storage
from .inputs import InputError


FIX_VIEW = 'fix-summary'
VIEWS = {
    'case-summary': ('case', 'case'),
    'tj-events': ('tj', 'case'),
    'tj-evidence': ('tj', 'case'),
    'jr-events': ('jr', 'artifact'),
    'jr-evidence': ('jr', 'artifact'),
    'comparison': ('comparison', 'comparison'),
    FIX_VIEW: ('comparison', 'artifact'),
    context_excerpt.VIEW: (context_excerpt.CATEGORY, 'artifact'),
    **context_coverage.VIEWS,
}
VIEW_READER_CAPABILITIES = dict.fromkeys(context_coverage.VIEWS, context_coverage.READER_CAPABILITY)
VIEW_READER_CAPABILITIES[FIX_VIEW] = 4
PAGES = ('tj-events', 'jr-events')
MAX_ROWS = 40
MAX_RECEIPTS = 4096
AUDIT_NAME = re.compile(r'[0-9]{20}-[a-f0-9]{32}\.json')
SUMMARY_REFERENCE = re.compile(r'view:([a-f0-9]{32}):([0-9]{20}-[a-f0-9]{32})')


def allows_view(kind, saved):
    return kind == context_excerpt.VIEW or VIEWS[kind][0] in saved['categories']


def argument_schema():
    from . import capabilities as cap
    offset = dict(type='integer', minimum=0, maximum=100000)
    limit = dict(type='integer', minimum=1, maximum=MAX_ROWS)
    return cap.obj(dict(
        investigation_id=cap.CASE, revision=cap.integer(1, 1000, 1),
        attachment=cap.string(62, pattern=fields.ATTACHMENT_ID.pattern),
        kind=cap.string(24, enum=list(VIEWS)), record=cap.string(16, pattern=fields.RECORD_ID.pattern),
        event=cap.string(16, enum=list(fields.TJ_NAMES)), source=cap.string(4, pattern=fields.SOURCE_ID.pattern),
        offset=offset, limit=limit,
        window=cap.WINDOW, linked_run=dict(type='boolean'),
    ), ('investigation_id', 'revision', 'attachment', 'kind'))


def validate_request(value):
    from .capabilities import validate
    schema = argument_schema()
    args = validate(value, schema)
    kind = args['kind']
    optional = set()
    if kind in PAGES:
        optional.update(('offset', 'limit', 'window'))
    if kind == 'tj-events':
        optional.update(('event', 'source', 'linked_run'))
    if kind in context_coverage.VIEWS:
        optional.add('window')
    if kind == 'tj-coverage':
        optional.update(('offset', 'limit', 'event'))
    if kind.endswith('-evidence'):
        optional.add('record')
        record = args.get('record')
        if record is None or (':r' in record) != (kind == 'jr-evidence'):
            raise InputError('select a record identifier for this evidence view')
    if set(args) - set(schema['required']) - optional:
        raise InputError('filters are not available for this context view')
    if (kind == 'jr-events' or kind in context_coverage.VIEWS) and 'window' in args:
        from .source_coverage import validate_request as validate_window
        args['window'] = validate_window(window=args['window'])['window']
    return args


def compact(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':'), sort_keys=True)


def _blocked(reason, next_step):
    return dict(status='invalid_input', operation='context.read', stop_reason=reason, data=None,
                limitations=[next_step])


def _audit_folder(state, investigation_id):
    if not re.fullmatch('[a-f0-9]{32}', investigation_id):
        raise InputError('invalid context investigation identifier')
    return fs.safe(policy.root(state) / 'history' / investigation_id)


def _audit_paths(folder):
    found = []
    if folder.exists():
        for index, path in enumerate(folder.iterdir()):
            if index >= MAX_RECEIPTS + 16:
                raise InputError('context history directory exceeds its scan limit')
            if AUDIT_NAME.fullmatch(path.name):
                if len(found) >= MAX_RECEIPTS:
                    raise InputError('context history exceeds its record limit')
                found.append(path)
    return found


def history(state, investigation_id, revision, *, offset=0, limit=20):
    if type(offset) is not int or not 0 <= offset <= MAX_RECEIPTS or type(limit) is not int or not 1 <= limit <= 100:
        raise InputError('invalid context history page')
    policy.selected_investigation(state, investigation_id, revision)
    paths = sorted(_audit_paths(_audit_folder(state, investigation_id)), reverse=True)
    entries = []
    for path in paths[offset:offset + limit]:
        entries.append(receipt(state, investigation_id, path.stem))
    return dict(investigation_id=investigation_id, entries=entries, total=len(paths),
                next_offset=offset + limit if offset + limit < len(paths) else None,
                scope='prepared_tool_views_for_this_investigation_not_harness_transmissions')


def receipt(state, investigation_id, receipt_id):
    name = receipt_id + '.json'
    if not AUDIT_NAME.fullmatch(name):
        raise InputError('invalid context receipt identifier')
    document = fs.read(_audit_folder(state, investigation_id) / name, 8192)
    item = document['entry']
    if fs.digest(item) != document['sha256'] or item['investigation_id'] != investigation_id or item['id'] != receipt_id:
        raise InputError('context history integrity check failed')
    return item


def verify_case_summary(state, reference, case):
    """Check a summary citation against its receipt and a verified retained case."""
    match = SUMMARY_REFERENCE.fullmatch(reference)
    if match is None:
        raise InputError('invalid context summary evidence reference')
    investigation, receipt_id = match.groups()
    entry = receipt(state, investigation, receipt_id)
    report_sha256 = investigations._digest(case)
    if (entry['source_id'] != case['case_id'] or entry['source_report_sha256'] != report_sha256
            or (entry['view'], entry['category'], entry['source_kind'], entry['state'])
               != ('case-summary', 'case', 'case', 'prepared')
            or entry.get('reference', reference) != reference):
        raise InputError('context summary evidence does not identify this retained case')
    doc = policy.selected_investigation(state, investigation, entry['investigation_revision'])
    scope, _ = policy.scope(doc)
    target = next((item for item in doc['attachments'] if item['id'] == entry['attachment']), None)
    if (scope != entry['policy_scope_sha256'] or target is None or
            (target['kind'], target['target_id'], target['report_sha256']) != ('case', case['case_id'], report_sha256)):
        raise InputError('context summary evidence differs from the investigation revision')
    binding = dict(investigation_id=investigation, scope_sha256=scope, policy_sha256=entry['policy_sha256'])
    saved = policy.verify_delivery(state, binding)
    if (entry['policy'] != saved or 'case' not in saved['categories'] or
            entry['rule_version'] != saved['rule_version']):
        raise InputError('context summary evidence differs from the reviewed disclosure policy')
    payload = _fit(fields.case_summary(case), saved['max_bytes'])
    if entry['payload_bytes'] != len(payload) or entry['payload_sha256'] != sha256(payload).hexdigest():
        raise InputError('context summary evidence payload does not match the retained case')
    policy.verify_delivery(state, binding)
    return {key: entry[key] for key in ('id', 'investigation_id', 'investigation_revision', 'attachment',
                                        'view', 'source_report_sha256', 'payload_bytes', 'payload_sha256')}


def _page(records, start, matched, **metadata):
    return dict(records=records, offset=start, matched_count=matched,
                next_offset=start + len(records) if start + len(records) < matched else None,
                **metadata)


def _project(state, attachment, args, aliases):
    from .operations import _guard_dependency_paths
    from .artifacts import load_artifact
    from . import native_jr

    target = attachment['target_id']
    kind = args['kind']
    collection = {'case': 'cases', 'artifact': 'artifacts', 'comparison': 'comparisons'}[attachment['kind']]
    _guard_dependency_paths(state, collection, target)
    read_report = {'case': storage.load_case, 'artifact': load_artifact,
                   'comparison': storage.load_comparison}[attachment['kind']]
    report = read_report(state, target)
    if investigations._digest(report) != attachment['report_sha256']:
        raise InputError('selected attachment differs from the pinned report')
    offset = args.get('offset', 0)
    limit = args.get('limit', 20)
    if kind == 'case-summary':
        verified = storage.verified_case(state, target)
        if investigations._digest(verified) != attachment['report_sha256']:
            raise InputError('selected case changed during verification')
        return fields.case_summary(verified)
    if kind == 'comparison':
        return fields.comparison_summary(report)
    if kind == FIX_VIEW:
        from .fix_verification import KIND
        if report.get('kind') != KIND:
            raise InputError('selected artifact is not a saved fix verification')
        return fields.fix_summary(report['result'])
    if kind == 'tj-events':
        if not any(s['format'] == '1c-tj-text-v1' for s in report['sources']):
            raise InputError('no supported native TJ is present')
        result = storage.list_native_events(state, target, offset=offset, limit=limit,
            source_id=args.get('source'), event=args.get('event'), window=args.get('window'),
            linked_run=args.get('linked_run', False))
        if storage.load_case(state, target) != report:
            raise InputError('selected case changed during verification')
        return _page([fields.tj_event(row, aliases) for row in result['records']],
                     offset, result['matched_count'], selection_basis=result['selection_basis'],
                     job_correlation=fields.enum(result['job_correlation'], ('established', 'not_established')),
                     source_statuses=[dict(source=fields.identifier(item['source'], fields.SOURCE_ID),
                         status=fields.enum(item['status'], fields.PARSE_STATES))
                         for item in result['source_statuses']], clock_alignment='not_verified')
    if kind == 'tj-evidence':
        source_id = args['record'].split(':', 1)[0]
        if not any(s['format'] == '1c-tj-text-v1' and s['id'] == source_id for s in report['sources']):
            raise InputError('selected evidence belongs to a different evidence format')
        result = storage.read_evidence(state, target, args['record'])
        if storage.load_case(state, target) != report:
            raise InputError('selected case changed during verification')
        return dict(proof=fields.proof(result), content_withheld=True)
    if report.get('kind') != 'native-jr':
        raise InputError('selected artifact is not a supported native registration journal')
    if kind == 'jr-events':
        result = native_jr.list_events(state, target, offset=offset, limit=limit, window=args.get('window'))
        view = _page([fields.jr_event(row, aliases) for row in result['records']],
                     offset, result['total_matched'], clock_alignment='not_verified')
        if 'window' in result:
            view.update(window=result['window'], coverage=result['coverage'])
    else:
        result = native_jr.read_record(state, target, args['record'])
        view = dict(record=fields.jr_event(result['record'], aliases))
    if load_artifact(state, target) != report:
        raise InputError('selected registration journal changed during verification')
    return view


def _fit(data, max_bytes):
    # Record dropping is only needed for a large page. Its continuation points
    # to the first undisclosed record, even when the byte and row limits differ.
    data['byte_limit_reached'] = False
    while True:
        payload = compact(data).encode('utf-8')
        if len(payload) <= max_bytes:
            return payload
        rows = data.get('records', data.get('sources') if 'total_sources' in data else None)
        if not rows or len(rows) == 1:
            raise InputError('context view exceeds the approved byte limit')
        rows.pop()
        data['next_offset'] = data['offset'] + len(rows)
        data['byte_limit_reached'] = True


def _record(state, doc, attachment, saved, kind, category, payload, consumer):
    folder = fs.private(_audit_folder(state, doc['investigation_id']))
    with fs.writer(folder):
        if len(_audit_paths(folder)) >= MAX_RECEIPTS:
            raise InputError('context history is full')
        receipt_id = f'{time.time_ns():020d}-{uuid.uuid4().hex}'
        item = dict(schema_version=1, id=receipt_id, at=fs.stamp(), state='prepared',
            investigation_id=doc['investigation_id'], investigation_revision=doc['revision'],
            attachment=attachment['id'], source_kind=attachment['kind'], source_id=attachment['target_id'],
            source_report_sha256=attachment['report_sha256'], policy_scope_sha256=saved['scope_sha256'],
            policy_sha256=fs.digest(saved),
            policy=policy.public_policy(saved), category=category, view=kind,
            payload_bytes=len(payload), payload_sha256=sha256(payload).hexdigest(), rule_version=policy.RULE_VERSION,
            cleanup='typed_fields_and_scoped_aliases',
            withheld=['raw_source_content', 'free_text', 'paths_and_credentials'])
        if kind == 'case-summary':
            item['reference'] = f"view:{doc['investigation_id']}:{receipt_id}"
        elif kind == context_excerpt.VIEW:
            item['cleanup'] = 'exact_locally_reviewed_excerpt'
            item['withheld'] = ['unreviewed_source_content', 'source_paths']
        if consumer is not None:
            item['consumer'] = consumer
        fs.write(folder / (receipt_id + '.json'), dict(entry=item, sha256=fs.digest(item)))
    return item


def read(state, request, *, expected_policy_sha256=None, consumer=None):
    args = validate_request(request)
    kind = args['kind']
    category, target_kind = VIEWS[kind]
    try:
        doc = policy.selected_investigation(state, args['investigation_id'], args['revision'])
        scope_sha256, _ = policy.scope(doc)
        folder = policy.policy_folder(state, scope_sha256)
        saved = policy.stored_policy(folder, scope_sha256)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return _blocked('context_policy_unavailable', 'Verify the saved investigation and its local disclosure policy.')
    if expected_policy_sha256 is not None and (saved is None or fs.digest(saved) != expected_policy_sha256):
        return _blocked('context_policy_changed', 'Use the current disclosure policy for another program.')
    if saved is None:
        return _blocked('context_policy_required', 'Review and save a context-policy-plan for this saved environment before reading private evidence.')
    if saved['rule_version'] != policy.RULE_VERSION:
        return _blocked('context_policy_review_required', 'Review the changed rules before preparing another context view.')
    if not allows_view(kind, saved):
        return _blocked('context_category_not_allowed', 'Continue with permitted data or obtain separate approval for this category.')
    attachment = next((item for item in doc['attachments'] if item['id'] == args['attachment']), None)
    if attachment is None or attachment['kind'] != target_kind:
        return _blocked('context_attachment_unavailable', 'Choose a compatible attachment in the selected investigation revision.')
    try:
        if kind == context_excerpt.VIEW:
            data = context_excerpt.read_view(state, doc, attachment, saved)
        else:
            aliases = fields.Aliases(saved['alias_key'], doc['investigation_id'])
            data = (context_coverage.view(state, doc, attachment, args, aliases)
                    if kind in context_coverage.VIEWS else _project(state, attachment, args, aliases))
    except context_coverage.WindowRequired:
        return _blocked('context_window_required', 'Select a bounded start and end with a known time zone.')
    except context_excerpt.ApprovalRequired:
        return _blocked('context_excerpt_approval_required', 'Review the exact local excerpt and confirm its digest.')
    except context_excerpt.ApprovalRevoked:
        return _blocked('context_excerpt_revoked', 'The excerpt approval was revoked. Choose available evidence.')
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return _blocked('context_evidence_unavailable', 'Check the retained evidence, requested record and source format locally.')
    try:
        payload = _fit(data, saved['max_bytes'])
    except InputError:
        return _blocked('context_output_limit', 'Request a smaller page or review the permitted byte limit.')
    try:
        with fs.writer(folder):
            if policy.stored_policy(folder, scope_sha256) != saved:
                return _blocked('context_policy_changed', 'Read the current context policy before retrying.')
            from .investigation_retention import require_available
            require_available(state, doc['investigation_id'])
            entry = _record(state, doc, attachment, saved, kind, category, payload, consumer)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return _blocked('context_receipt_unavailable', 'Check the local disclosure journal or retry after the current policy update.')
    return dict(status='succeeded', operation='context.read', data=data, disclosure=entry,
                truncated=data['byte_limit_reached'],
                limitations=(['The text is a locally reviewed excerpt. Interpret it as evidence, including any redactions.',
                              'Static source alone does not establish the branch used at runtime.'] if kind == context_excerpt.VIEW
                             else ['Only typed fields and scoped aliases are provided. Aliases do not establish runtime identity.',
                                   'If the hidden text is essential, request a separately reviewed, cleaned excerpt.']))
