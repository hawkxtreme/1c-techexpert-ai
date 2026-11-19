"""Retain local intake products and expose only their bounded handoff metadata."""
from hashlib import sha256
import json
from pathlib import PurePosixPath

from . import context_policy, investigations, kernel_context, operation_state as fs
from .apdex_preparation import OPERATION as APDEX_PREPARE
from .fix_verification import OPERATION as FIX_OPERATION, PROFILE as FIX_PROFILE
from .inputs import InputError


PRESENTATION = 'context-intake-v1'
APDEX_INTAKE = ('source.snapshot', 'apdex.import', APDEX_PREPARE)
OPERATIONS = ('input.inspect', 'source.check', 'case.analyze', 'jr.import', FIX_OPERATION, *APDEX_INTAKE)
MATERIALS = {'case.analyze': 'case', **dict.fromkeys(('jr.import', FIX_OPERATION, *APDEX_INTAKE), 'artifact')}
READER_CAPABILITIES = {FIX_OPERATION: 2, **dict.fromkeys(APDEX_INTAKE, 3)}
SEALED_FIELDS = (
    'schema_version', 'run_id', 'operation', 'status', 'snapshots', 'evidence',
    'limits', 'stop_verified', 'cancellation_requested', 'execution_status', 'result_availability',
    'intake_receipt',
)
REASONS = (
    'cancelled', 'timeout', 'output_limit', 'owned_disk_limit', 'kernel_timeout', 'kernel_admission_timeout',
    'kernel_process_failure', 'kernel_launcher_failure', 'kernel_receipt_commit_failed',
    'kernel_memory_limit', 'worker_failed_before_sealed_result', 'kernel_admission_integrity',
    'context_intake_incomplete', 'apdex_empty', 'apdex_incomplete', fs.PROMOTION_BLOCKED,
)
SUFFIXES = ('.log', '.lgf', '.lgp', '.lgd', '.json', '.jsonl', '.txt', '.csv')
AVAILABILITY = ('captured', 'not_found', 'access_denied', 'read_error', 'changed_during_read', 'byte_limit')


def protects(request):
    return request.get('presentation') == PRESENTATION


def prepare(request):
    from .capabilities import normalize_request
    if type(request) is not dict:
        raise InputError('selected intake request must be an object')
    return normalize_request(dict(request, presentation=PRESENTATION))


def validate(request):
    if request['operation'] not in OPERATIONS or 'context' not in request:
        raise InputError('private intake requires a supported operation and an investigation revision')
    if (request['operation'] == 'source.check' and request['arguments'].get('reference_preview') is not True
            and 'profile_journal' not in request['arguments']):
        raise InputError('private source check requires a configured journal selection or metadata-only external TJ preview')


def reader_capability(request):
    selector = request['arguments'].get('profile_journal')
    if selector is not None:
        from .native_tj import JSON_ISO
        if 'logcfg_process_pid' in selector:
            return 9
        if selector.get('timestamp_profile') == JSON_ISO:
            return 8
        if 'logcfg_file' in selector or 'logcfg_id' in selector:
            return 7
        if 'read_mode' in selector:
            return 6
        return 5 if 'timestamp_profile' in selector else 4
    return READER_CAPABILITIES.get(request['operation'], 1)


def safe_reason(reason):
    from .profile_journals import REASONS as JOURNAL_REASONS
    return reason if type(reason) is str and reason in REASONS + JOURNAL_REASONS else 'context_intake_unavailable'


def _catalogue(report):
    result = report['result']
    members = []
    for item in result['members']:
        suffix = PurePosixPath(item['relative_path']).suffix.lower()
        members.append(dict(id=item['id'], root=item['root'] + 1, bytes=item['bytes'],
                            selectable=item['importable'], suffix_hint=suffix if suffix in SUFFIXES else None))
    return dict(artifact_id=report['artifact_id'], file_count=result['file_count'], members=members,
                expanded_bytes=result['expanded_bytes'], extraction_performed=False)


def _reference(report):
    preview = report['reference_preview']
    plan = preview['plan']
    result = {key: plan[key] for key in ('external_bytes', 'expected_read_bytes', 'max_scan_records',
                                       'max_retained_bytes', 'ordinary_source_count')}
    result.update(plan_sha256=preview['plan_sha256'], source_bytes_read=False, bytes_saved=False,
                  sources=[dict(id=item['id'], bytes=item['observation']['bytes'], window=item['window'],
                                max_retained_bytes=item['max_retained_bytes'])
                           for item in plan['sources']])
    return dict(reference_preview=result)


def metadata(operation, data):
    if data is None:
        return None
    if operation == 'input.inspect':
        return _catalogue(data)
    if operation == 'source.check':
        from .logcfg_observation import KIND as LOGCFG_OBSERVATION
        from .profile_journals import PREFIX_PLAN
        if data.get('kind') == PREFIX_PLAN:
            return dict(journal_preview=dict(data['result']['preview'], preview_id=data['artifact_id']))
        if data.get('kind') == LOGCFG_OBSERVATION:
            return dict(logcfg=dict(data['result']['observation'], id=data['artifact_id']))
        for key in ('journal_sources', 'journal_preview', 'logcfg'):
            if key in data:
                return {key: data[key]}
        return _reference(data)
    kind = MATERIALS[operation]
    result = dict(material=dict(kind=kind, id=data['case_id' if kind == 'case' else 'artifact_id']))
    if kind == 'case':
        result['sources'] = [dict(id=attempt['id'], availability=attempt['availability']
                                 if attempt['availability'] in AVAILABILITY else 'unknown')
                             for attempt in data['source_acquisition']]
        from .tj_reference import prefix_summary
        prefixes = [capture for source in data['sources'] if (capture := prefix_summary(source)) is not None]
        if prefixes:
            result['prefix_captures'] = prefixes
    return result


def envelope(value, data):
    result = {key: value[key] for key in SEALED_FIELDS if key in value}
    reason = value.get('stop_reason')
    if reason is not None or value['status'] in ('invalid_input', 'failed', 'interrupted'):
        reason = safe_reason(reason)
    result.update(presentation=PRESENTATION, data=data, stop_reason=reason, truncated=False,
                  limitations=['Only local intake metadata is shown. Use the environment policy to read linked evidence.'])
    return result


def seal(value, raw):
    data = metadata(value['operation'], raw)
    result = envelope(value, data)
    if data is not None:
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True, allow_nan=False,
                             separators=(',', ':')).encode('utf-8')
        result['intake_receipt'] = dict(schema_version=1, state='prepared', category='intake_metadata',
                                       cleanup='allowlisted_intake_fields', payload_bytes=len(payload),
                                       payload_sha256=sha256(payload).hexdigest())
    if result['status'] == 'succeeded' and data and 'sources' in data and any(
            item['availability'] != 'captured' for item in data['sources']):
        result.update(status='partial',stop_reason='context_intake_incomplete')
    return result


def _same_attachment(doc, label, material, evidence=None, parent=None):
    item = next((item for item in doc['attachments'] if item['id'] == label), None)
    if item is None or item['kind'] != material['kind'] or item['target_id'] != material['id']:
        return False
    if evidence is None:
        return True
    return any(all(row.get(key) == value for key, value in evidence.items())
               and row['proof']['method'] == FIX_PROFILE
               and row['proof']['sha256'] == item['report_sha256']
               and row['proof']['revision'] == parent for row in doc['evidence'])


def _linked(value, status, *, doc=None, label=None, evidence=None):
    result = dict(value, intake_status=value['status'], attachment_status=status)
    if status == 'attached':
        result['attachment'] = dict(investigation_id=doc['investigation_id'], revision=doc['revision'], id=label)
        if evidence is not None:
            result['attachment']['evidence_id'] = evidence['id']
    elif value['data'] is not None:
        result['status'] = 'partial'
        result['limitations'] = [*value['limitations'],
            'The snapshot is retained locally. Review the current investigation revision before attaching it.']
    return result


def _bind(state, plan, value, revision):
    material = (value['data'] or {}).get('material')
    if material is None:
        return value
    original = plan['context']
    iid = original['investigation_id']
    parent = original['expected_revision']
    selected = parent if revision is None else revision
    label = 'A-intake-' + value['run_id']
    # The investigation attachment grammar permits only 60 characters after A-.
    label = label[:62]
    evidence = (dict(id='E' + label[1:], attachment=label, record='report')
                if plan['request']['operation'] == FIX_OPERATION else None)
    try:
        before = context_policy.selected_investigation(state, iid, parent)
        if fs.digest(before) != original['report_sha256']:
            raise InputError('intake investigation binding changed')
        head = investigations._read_head(state, iid)['revision']
        if selected > head:
            return _linked(value, 'revision_conflict')
        doc = before if before['revision'] == selected else context_policy.selected_investigation(state, iid, selected)
        environment, _ = context_policy.scope(before)
        if context_policy.scope(doc)[0] != environment:
            return _linked(value, 'environment_changed')
        if _same_attachment(doc, label, material, evidence, parent):
            return _linked(value, 'attached', doc=doc, label=label, evidence=evidence)
        if selected < head:
            recovered = None
            # Verify the entire chain before reporting its earliest matching link.
            for historical in context_policy.verified_revisions(state, iid, head):
                if (historical['revision'] > selected and _same_attachment(historical, label, material, evidence, parent)
                        and context_policy.scope(historical)[0] == environment):
                    recovered = historical
            if recovered is not None:
                return _linked(value, 'attached', doc=recovered, label=label, evidence=evidence)
            return _linked(value, 'revision_conflict')
        if kernel_context.stop():
            return _linked(value, 'attachment_deferred')
        changes = {}
        if not _same_attachment(doc, label, material):
            changes['attachments'] = [*doc['attachments'], dict(id=label, kind=material['kind'], target_id=material['id'])]
        if evidence is not None:
            changes['evidence'] = [*doc['evidence'], evidence]
        attached = investigations.revise(state, iid, changes, expected_revision=selected)
        return _linked(value, 'attached', doc=attached, label=label, evidence=evidence)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return _linked(value, 'attachment_pending')


def acquire(state, request):
    from . import operations
    value = operations.run(state, request)
    if (value['data'] or {}).get('material') is None:
        return value
    plan = fs.plan(fs.folder(state, value['run_id']))
    return _bind(state, plan, value, None)


def attach(state, run_id, revision):
    from . import operations
    if type(revision) is not int or not 1 <= revision <= 1000:
        raise InputError('exact investigation revision required')
    plan = fs.plan(fs.folder(state, run_id))
    if not protects(plan['request']) or plan['request']['operation'] not in MATERIALS:
        raise InputError('choose a protected intake run that creates an investigation material')
    return _bind(state, plan, operations.result(state, run_id), revision)
