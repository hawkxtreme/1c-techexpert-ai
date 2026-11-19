"""CodeMode access to explicitly selected, policy-filtered document views."""
from copy import deepcopy
from hashlib import sha256

from . import context_coverage, context_disclosure as disclosure, context_excerpt, context_journal_match
from . import context_policy as policy, operation_state as fs
from .code_values import CodeError
from .context_fields import ATTACHMENT_ID
from .inputs import InputError


OPERATION = 'code.context'
API = 'context.read'
KINDS = {'case': 'cases', 'artifact': 'artifacts', 'comparison': 'comparisons'}
READ_ERRORS = (OSError, ValueError, KeyError, TypeError, RecursionError)


def formal_arguments(cap, regular):
    values = deepcopy(regular)
    label = cap.string(62, pattern=ATTACHMENT_ID.pattern)
    view = cap.obj(dict(attachment=label, kind=cap.string(24, enum=list(disclosure.VIEWS)),
                        anchor_attachment=label), ('attachment', 'kind'))
    values['scope'] = cap.obj(dict(views=dict(type='array', minItems=1, maxItems=32, items=view)), ('views',))
    return values


def selections(args):
    return {_selection(entry) for entry in args['scope']['views']}


def _selection(entry):
    return entry['attachment'], entry['kind'], entry.get('anchor_attachment')


def normalize(args):
    views = args['scope']['views']
    if len(selections(args)) != len(views):
        raise CodeError('scope_denied', 'Select each attachment and view only once.')
    for row in views:
        label, kind, anchor = _selection(row)
        if (anchor is not None) != (kind in disclosure.ANCHORED_VIEWS) or anchor == label:
            raise CodeError('scope_denied', 'Select the distinct TJ anchor attachment in the journal view scope.')
    args['scope']['views'] = sorted(views, key=lambda row: (row['attachment'], row['kind'], row.get('anchor_attachment','')))
    return args


def _document(state, plan):
    context = plan['context']
    doc = policy.selected_investigation(state, context['investigation_id'], context['expected_revision'])
    if fs.digest(doc) != context['report_sha256']:
        raise InputError('saved program investigation revision changed')
    return doc


def authorize(state, plan):
    try:
        doc = _document(state, plan)
        scope, _ = policy.scope(doc)
        saved = policy.stored_policy(policy.policy_folder(state, scope), scope)
    except READ_ERRORS as exc:
        raise CodeError('context_policy_unavailable', 'Verify the saved investigation and its disclosure policy.') from exc
    if saved is None:
        raise CodeError('context_policy_required', 'Review and save the environment disclosure policy.')
    if saved['rule_version'] != policy.RULE_VERSION:
        raise CodeError('context_policy_review_required', 'Review the current disclosure rules before running the program.')
    attachments = {item['id']: item['kind'] for item in doc['attachments']}
    for label, view, anchor in selections(plan['request']['arguments']):
        _, kind = disclosure.VIEWS[view]
        if not disclosure.allows_view(view, saved):
            raise CodeError('context_category_not_allowed', 'Continue with views covered by the saved policy.')
        if attachments.get(label) != kind or (anchor is not None and attachments.get(anchor) != 'case'):
            raise CodeError('scope_denied', 'Use an approved view of an attachment in the selected revision.')
    binding = dict(investigation_id=doc['investigation_id'], scope_sha256=scope, policy_sha256=fs.digest(saved))
    if 'check_binding' in plan and (plan['check_binding'] or {}).get('policy') != binding:
        raise CodeError('context_policy_changed', 'The disclosure policy changed after admission. Review it before a new run.')
    return binding, saved['max_bytes']


def call_request(plan, operation, args):
    context = plan['context']
    if operation != API or set(args) & {'investigation_id', 'revision'}:
        raise CodeError('scope_denied', 'Only the selected context.read views of this investigation revision are available.')
    request = disclosure.validate_request(dict(args, investigation_id=context['investigation_id'],
                                                revision=context['expected_revision']))
    if _selection(request) not in selections(plan['request']['arguments']):
        raise CodeError('scope_denied', 'This attachment and view are outside the selected scope.')
    return request


def bytes_of(data):
    return disclosure.compact(data).encode('utf-8')


def body_receipt(value, limit):
    payload = bytes_of(value)
    if len(payload) > limit:
        raise CodeError('context_output_limit', 'Return a smaller projection within the saved disclosure byte limit.')
    return dict(category='program_projection', state='prepared',
                payload_bytes=len(payload), payload_sha256=sha256(payload).hexdigest())


def proof_for_call(entry):
    keys = ('id', 'attachment', 'view', 'source_kind', 'source_id', 'source_report_sha256',
            'payload_sha256', 'payload_bytes')
    proof = {key: entry[key] for key in keys}
    if 'anchor' in entry:
        proof['anchor'] = entry['anchor']
    return proof


def verify_view(state, plan, run_id, doc, binding, record, saved):
    request = saved['selection']
    args = {key: value for key, value in request.items() if key not in ('investigation_id', 'revision')}
    if request != call_request(plan, API, args) or fs.digest(request) != record['request_sha256']:
        raise InputError('saved program view request changed')
    if fs.digest(saved) != record['output_sha256']:
        raise InputError('saved program view integrity mismatch')
    entry = saved['disclosure']
    if entry != disclosure.receipt(state, doc['investigation_id'], entry['id']) or proof_for_call(entry) != record['view']:
        raise InputError('program view differs from the disclosure journal')
    target = next((item for item in doc['attachments'] if item['id'] == request['attachment']), None)
    category, kind = disclosure.VIEWS[request['kind']]
    if (target is None or entry['source_kind'] != kind or target['kind'] != kind or
            target['target_id'] != entry['source_id'] or target['report_sha256'] != entry['source_report_sha256'] or
            entry['investigation_revision'] != doc['revision'] or entry['attachment'] != request['attachment'] or
            entry['view'] != request['kind'] or entry['category'] != category or
            entry['policy_sha256'] != binding['policy_sha256'] or entry['policy_scope_sha256'] != binding['scope_sha256'] or
            entry.get('consumer') != dict(kind=OPERATION, run_id=run_id, index=record['index'])):
        raise InputError('program view source or policy identity mismatch')
    if request['kind'] == context_excerpt.VIEW:
        context_excerpt.require_approval(state, target['target_id'], target['report_sha256'])
    if request['kind'] in disclosure.ANCHORED_VIEWS and entry.get('anchor') != context_journal_match.anchor_ref(doc,request):
        raise InputError('saved journal view anchor differs from its selected investigation evidence')
    reply = saved['reply']
    if (set(reply) != {'status', 'data', 'truncated'} or reply['status'] != 'succeeded' or
            type(reply['truncated']) is not bool or reply['truncated'] != record['truncated'] or
            len(bytes_of(reply)) != record['response_bytes']):
        raise InputError('saved program view response changed')
    payload = bytes_of(reply['data'])
    if len(payload) != entry['payload_bytes'] or sha256(payload).hexdigest() != entry['payload_sha256']:
        raise InputError('program view payload differs from its disclosure receipt')
    if request['kind'] in context_coverage.VIEWS:
        context_coverage.verify_view(state, target, request['kind'], reply['data'])


def pins(data):
    # Coverage views verify the specific observed files in verify_view.
    views = [item for call in data['calls'] if (item := call.get('view')) is not None and item['view'] not in context_coverage.VIEWS]
    pinned = {(KINDS[item['source_kind']], item['source_id'], item['source_report_sha256']) for item in views}
    pinned.update(('cases',anchor['source_id'],anchor['source_report_sha256'])
                  for item in views if (anchor := item.get('anchor')) is not None)
    return pinned


def withhold(state, value):
    data = value.get('data')
    binding = data.get('policy_binding') if data else None
    if binding is not None:
        try:
            policy.verify_delivery(state, binding)
        except READ_ERRORS:
            return dict(status='invalid_input', operation=OPERATION, run_id=value['run_id'], data=None,
                        stop_reason='context_policy_changed', stop_verified=True, limits=value['limits'],
                        limitations=['Check the current policy before starting a separately reviewed run.'])
    return None


def public_state(value):
    keys = ('schema_version', 'run_id', 'operation', 'status', 'data', 'snapshots', 'evidence',
            'limits', 'stop_verified', 'cancellation_requested', 'execution_status', 'result_availability',
            'truncated')
    result = {key: value[key] for key in keys if key in value}
    reason = value.get('stop_reason')
    if reason is not None:
        result['stop_reason'] = reason if reason in ('cancelled', 'timeout', 'output_limit', 'owned_disk_limit') else 'context_program_unavailable'
    result['limitations'] = ['The program uses selected, policy-filtered views of retained evidence.']
    return result


def present(value):
    result = public_state(value)
    calls = (value.get('data') or {}).get('calls', ())
    # Use the checked call journal so the note survives a filtered return value.
    # Keep it out of the sealed program output for interrupted commit recovery.
    if any(call['status'] == 'succeeded' and (call.get('view') or {}).get('view') == 'comparison' for call in calls):
        result['limitations'].append(disclosure.COMPARISON_LIMITATION)
    return result
