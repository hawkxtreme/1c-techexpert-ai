"""Find an equivalent managed read using only sealed plans and status metadata."""
import re
import stat

from . import context_program, operation_state as fs
from .diagnostic_adapters import ARTIFACT_READS
from .inputs import InputError


FORMAT = 1
READS = frozenset({'case.show', 'case.coverage', 'case.events', 'case.evidence',
                   'comparison.show', 'artifact.show', context_program.OPERATION} | ARTIFACT_READS)
ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError)
SHA256 = re.compile('[a-f0-9]{64}')


def _fingerprint(request, context, versions, policy):
    basis = dict(operation=request['operation'], arguments=request['arguments'], versions=versions,
                 investigation_id=context['investigation_id'], profile_sha256=context['profile_sha256'])
    if policy is not None:
        basis.update(context=context, policy=policy)
    return fs.digest(basis)


def binding(state, request, context, versions):
    if request['operation'] not in READS or context is None:
        return None
    policy = None
    if request['operation'] == context_program.OPERATION:
        try:
            policy, _ = context_program.authorize(state, dict(request=request, context=context))
        except context_program.CodeError:
            # Leave policy denial to the normal protected operation's own receipt.
            return None
    return dict(schema_version=FORMAT, sha256=_fingerprint(request, context, versions, policy), policy=policy)


def saved_binding(plan):
    request, context = plan['request'], plan['context']
    value = plan['check_binding']
    if value is None and request['operation'] == context_program.OPERATION:
        return None  # admission observed no policy authorizing a read
    policy = value['policy']
    if (set(value) != {'schema_version', 'sha256', 'policy'} or type(value['schema_version']) is not int
        or value['schema_version'] != FORMAT or request['operation'] not in READS
        or type(context['expected_revision']) is not int or not 1 <= context['expected_revision'] <= 1000
        or request['context'] != dict(investigation_id=context['investigation_id'],
                                     expected_revision=context['expected_revision'])
        or value['sha256'] != _fingerprint(request, context, plan['versions'], policy)):
        raise InputError('saved check history binding is invalid')
    if request['operation'] == context_program.OPERATION:
        if (type(policy) is not dict or set(policy) != {'investigation_id', 'scope_sha256', 'policy_sha256'}
            or policy['investigation_id'] != context['investigation_id']
            or not all(type(policy[key]) is str and SHA256.fullmatch(policy[key]) for key in ('scope_sha256', 'policy_sha256'))):
            raise InputError('saved check disclosure binding is invalid')
    elif policy is not None:
        raise InputError('unexpected disclosure binding for saved read')
    return value


def _receipt_observed(folder):
    try:
        info = fs.safe(folder / 'output.json').lstat()
        digest = fs.read(folder / 'output-receipt.json', 8192)['sha256']
        return (stat.S_ISREG(info.st_mode) and 0 < info.st_size <= fs.MAX_DOCUMENT
                and type(digest) is str and SHA256.fullmatch(digest) is not None)
    except ERRORS:
        return False


def _observation(folder, plan):
    from .operations import TERMINAL

    stopped = False
    try:
        status = fs.read(folder / 'status.json', 64 * 1024)
        stopped = (type(status['schema_version']) is int and status['schema_version'] == 1
                   and status['run_id'] == folder.name and status['status'] in TERMINAL
                   and status.get('stop_verified') is True)
    except ERRORS:
        pass
    return dict(run_id=folder.name, revision=plan['context']['expected_revision'],
                local_stop_verified=stopped, result_receipt_observed=stopped and _receipt_observed(folder))


def previous(state, request, context, current_binding):
    from .investigation_retention import iter_saved_plans

    selected = None
    latest = None
    try:
        for folder, plan in iter_saved_plans(state):
            if ('check_binding' not in plan or plan['request']['operation'] != request['operation']
                or (plan.get('context') or {}).get('investigation_id') != context['investigation_id']
                or saved_binding(plan) != current_binding):
                continue
            observation = _observation(folder, plan)
            if not observation['local_stop_verified']:
                return 'equivalent_check_unresolved', observation
            order = plan['created_at'], folder.name
            if latest is None or order > latest:
                selected, latest = observation, order
    except ERRORS:
        return 'check_history_unavailable', selected
    if selected is not None and 'repeat_reason' not in request:
        return 'equivalent_check_recorded', selected
    return None, None


def declined(request, run_id, reason, last):
    messages = {
        'equivalent_check_recorded': 'Verify the previous RUN_ID with operation-result, or state why a fresh read is needed.',
        'equivalent_check_unresolved': 'Inspect the previous RUN_ID. Verify its stop before starting an equivalent check.',
        'check_history_unavailable': 'The saved check inventory could not be verified for a new equivalent read.',
    }
    reply = dict(schema_version=1, run_id=run_id, operation=request['operation'], status='partial',
                 execution_status='not_started', data=None, stop_verified=True, stop_reason=reason,
                 limits=request['budget'], snapshots=[], evidence=[], truncated=False, limitations=[messages[reason]])
    if last is not None:
        reply['previous_check'] = last
    return reply
