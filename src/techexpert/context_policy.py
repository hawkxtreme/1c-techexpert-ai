"""Reviewed local policy for preparing selected investigation data for a model."""
from pathlib import Path
import re
import secrets

from . import investigations, operation_state as fs
from .inputs import InputError
from .profiles import validate_profile


CATEGORIES = {
    'case': 'Typed case measurements, source coverage metadata and evidence coordinates.',
    'tj': 'Technological journal timestamps, durations, event types, evidence coordinates and scoped aliases.',
    'jr': 'Registration journal timestamps, severity, evidence coordinates and scoped aliases.',
    'comparison': 'Measured comparison statistics, pairing and outcome states.',
}
DEFAULT_BYTES = 16384
MIN_BYTES = 4096
MAX_BYTES = 32768
RULE_VERSION = 1
SHA = re.compile(r'[a-f0-9]{64}')


def selected_investigation(state, investigation_id, revision):
    folder = investigations.revision_folder(state, investigation_id, revision)
    for number in range(1, revision + 1):
        candidate = folder.parent / f'{number:06d}'
        for name in ('report.json', 'report.md', 'receipt.json'):
            fs.safe(candidate / name)
    return investigations._committed_revision(state, investigation_id, revision)


def scope(doc):
    profile = doc.get('profile_snapshot')
    if profile is None:
        return fs.digest({'investigation_id': doc['investigation_id']}), 'investigation_without_profile'
    if doc.get('profile_sha256') != investigations._digest(profile):
        raise InputError('saved environment binding is invalid')
    return fs.digest(validate_profile(profile)), 'saved_environment'


def root(state):
    return fs.safe(Path(state) / 'context-disclosure')


def policy_folder(state, scope_sha256):
    if not isinstance(scope_sha256, str) or not SHA.fullmatch(scope_sha256):
        raise InputError('invalid environment disclosure scope')
    return fs.safe(root(state) / 'policies' / scope_sha256)


def _choices(categories, max_bytes):
    if (not isinstance(categories, (list, tuple)) or
            any(type(name) is not str or name not in CATEGORIES for name in categories) or
            len(categories) != len(set(categories))):
        raise InputError('select distinct supported context categories')
    if type(max_bytes) is not int or not MIN_BYTES <= max_bytes <= MAX_BYTES:
        raise InputError('context byte limit must be 4096..32768')
    return {'categories': sorted(categories), 'max_bytes': max_bytes}


def stored_policy(folder, scope_sha256, *, read=fs.read):
    try:
        sealed = read(folder / 'policy.json', 8192)
    except FileNotFoundError:
        return None
    if type(sealed) is not dict or set(sealed) != {'policy', 'sha256'}:
        raise InputError('invalid saved disclosure policy')
    policy = sealed['policy']
    if (type(policy) is not dict or set(policy) != {
            'schema_version', 'scope_sha256', 'revision', 'categories', 'max_bytes', 'alias_key', 'rule_version'
            } or type(policy['schema_version']) is not int or policy['schema_version'] != 1 or
            policy['scope_sha256'] != scope_sha256 or fs.digest(policy) != sealed['sha256'] or
            type(policy['revision']) is not int or policy['revision'] < 1 or
            type(policy['rule_version']) is not int or not 1 <= policy['rule_version'] <= RULE_VERSION or
            not isinstance(policy['alias_key'], str) or not SHA.fullmatch(policy['alias_key'])):
        raise InputError('invalid saved disclosure policy')
    choices = _choices(policy['categories'], policy['max_bytes'])
    if choices['categories'] != policy['categories']:
        raise InputError('invalid saved disclosure category order')
    return policy


def public_policy(policy):
    if policy is None:
        return dict(revision=0, categories=[], max_bytes=DEFAULT_BYTES, rule_version=None)
    return {key: policy[key] for key in ('revision', 'categories', 'max_bytes', 'rule_version')}


def _plan(doc, current, selected):
    scope_sha256, scope_kind = scope(doc)
    previous = public_policy(current)
    old = set(previous['categories'])
    new = set(selected['categories'])
    value = dict(
        schema_version=1, rule_version=RULE_VERSION, scope=scope_kind, scope_sha256=scope_sha256,
        investigation_id=doc['investigation_id'], investigation_revision=doc['revision'],
        investigation_sha256=investigations._digest(doc), previous=previous, selected=selected,
        categories_added=sorted(new - old), categories_removed=sorted(old - new),
        byte_limit_increased=bool(old and new and selected['max_bytes'] > previous['max_bytes']),
        rule_review_required=current is not None and current['rule_version'] != RULE_VERSION,
        category_descriptions={name: CATEGORIES[name] for name in selected['categories']},
        output_scope='selected_retained_investigation_material', byte_limit_scope='compact_typed_payload',
    )
    return dict(plan=value, plan_sha256=fs.digest(value))


def show(state, investigation_id, revision):
    doc = selected_investigation(state, investigation_id, revision)
    scope_sha256, scope_kind = scope(doc)
    current = stored_policy(policy_folder(state, scope_sha256), scope_sha256)
    status = 'approval_required' if current is None else (
        'configured' if current['rule_version'] == RULE_VERSION else 'review_required')
    return dict(status=status,
                scope=scope_kind, scope_sha256=scope_sha256, policy=public_policy(current),
                categories=dict(CATEGORIES), rule_version=RULE_VERSION,
                attachments=[dict(id=item['id'], kind=item['kind']) for item in doc['attachments']])


def plan(state, investigation_id, revision, categories, max_bytes):
    selected = _choices(categories, max_bytes)
    doc = selected_investigation(state, investigation_id, revision)
    scope_sha256, _ = scope(doc)
    current = stored_policy(policy_folder(state, scope_sha256), scope_sha256)
    return _plan(doc, current, selected)


def save(state, investigation_id, revision, categories, max_bytes, expected_sha256):
    if not isinstance(expected_sha256, str) or not SHA.fullmatch(expected_sha256):
        raise InputError('exact reviewed context-policy-plan digest required')
    selected = _choices(categories, max_bytes)
    doc = selected_investigation(state, investigation_id, revision)
    scope_sha256, _ = scope(doc)
    folder = policy_folder(state, scope_sha256)
    current = stored_policy(folder, scope_sha256)
    if _plan(doc, current, selected)['plan_sha256'] != expected_sha256:
        raise InputError('context policy changed; review a fresh plan')
    fs.private(root(state))
    fs.private(folder)
    with fs.writer(folder):
        current = stored_policy(folder, scope_sha256)
        if _plan(doc, current, selected)['plan_sha256'] != expected_sha256:
            raise InputError('context policy changed; review a fresh plan')
        if (current is None or current['rule_version'] != RULE_VERSION or
                any(current[key] != selected[key] for key in selected)):
            policy = dict(schema_version=1, scope_sha256=scope_sha256, rule_version=RULE_VERSION,
                          revision=current['revision'] + 1 if current else 1,
                          alias_key=current['alias_key'] if current else secrets.token_hex(32),
                          **selected)
            fs.write(folder / 'policy.json', dict(policy=policy, sha256=fs.digest(policy)))
        else:
            policy = current
    return dict(status='configured', scope_sha256=scope_sha256, policy=public_policy(policy),
                reviewed_plan_sha256=expected_sha256)


def verify_delivery(state, binding):
    from .investigation_retention import require_available

    scope_sha256 = binding['scope_sha256']
    folder = policy_folder(state, scope_sha256)
    saved = stored_policy(folder, scope_sha256)
    if saved is None or saved['rule_version'] != RULE_VERSION or fs.digest(saved) != binding['policy_sha256']:
        raise InputError('context policy changed before delivery')
    require_available(state, binding['investigation_id'])
