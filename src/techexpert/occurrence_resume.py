"""Keep verifiable material in a new episode while preserving earlier revisions."""
import re

from .inputs import InputError


READER_CAPABILITY = 2
MAX_GAPS = 32
GAP_STATES = ('not_found', 'access_denied', 'read_error', 'retired_or_unverified')
KINDS = ('case', 'artifact', 'comparison')


def is_notice(patch):
    occurrence = patch.get('occurrence')
    return (type(occurrence) is dict and occurrence.get('evidence') == []
            and patch.get('workflow_stage', 'analyze_episode') == 'analyze_episode'
            and patch.keys() <= {'occurrence', 'workflow_stage'})


def gaps(doc):
    rows = doc.get('source_gaps', [])
    if type(rows) is not list or len(rows) > MAX_GAPS:
        raise InputError('invalid retained source gaps')
    for row in rows:
        if (type(row) is not dict or set(row) != {'attachment', 'revision', 'status'}
                or row['status'] not in GAP_STATES or type(row['revision']) is not int
                or not 1 <= row['revision'] < doc['revision']):
            raise InputError('invalid retained source gap')
        item = row['attachment']
        if (type(item) is not dict or set(item) - {'id', 'kind', 'target_id', 'report_sha256', 'source_origin', 'scope'}
                or item.get('kind') not in KINDS or type(item.get('id')) is not str
                or not re.fullmatch(r'A-[A-Za-z0-9-]{1,60}', item['id'])
                or not _hex(item.get('target_id'), 32) or not _hex(item.get('report_sha256'), 64)):
            raise InputError('invalid historical attachment identity')
    return rows


def _hex(value, length):
    return type(value) is str and len(value) == length and re.fullmatch('[a-f0-9]+', value) is not None


def public_gaps(doc):
    return [dict(attachment=row['attachment']['id'], revision=row['revision'], status=row['status'])
            for row in gaps(doc)]


def _state(exc):
    from .case_retention import SnapshotRetirement

    error = exc.__cause__ if isinstance(exc.__cause__, OSError) else exc
    if isinstance(error, FileNotFoundError):
        return 'not_found'
    if isinstance(error, PermissionError):
        return 'access_denied'
    if isinstance(error, SnapshotRetirement):
        return 'retired_or_unverified'
    return 'read_error'


def retain_available(state, doc, previous):
    from .investigations import _verify_attachment

    unavailable = []
    for item in previous['attachments']:
        try:
            _verify_attachment(state, doc, dict(item))
        except (OSError, InputError) as exc:
            unavailable.append(dict(attachment=item, revision=previous['revision'], status=_state(exc)))
    if not unavailable:
        return
    doc['source_gaps'] = (unavailable + gaps(previous))[:MAX_GAPS]
    lost = {row['attachment']['id'] for row in unavailable}

    doc['attachments'] = [item for item in doc['attachments'] if item['id'] not in lost]
    doc['evidence'] = [item for item in doc['evidence'] if item['attachment'] not in lost]
    evidence = {item['id'] for item in doc['evidence']}
    doc['source_bindings'] = [item for item in doc['source_bindings'] if item['attachment'] not in lost]
    bindings = {item['id'] for item in doc['source_bindings']}
    doc['source_links'] = [item for item in doc['source_links'] if {item['left'], item['right']} <= bindings]
    links = {item['id'] for item in doc['source_links']}
    for name in ('facts', 'hypotheses'):
        doc[name] = [item for item in doc[name]
                     if evidence.issuperset(item['evidence']) and links.issuperset(item.get('source_links', []))]
    hypotheses = {item['id'] for item in doc['hypotheses']}
    doc['contradictions'] = [item for item in doc['contradictions']
                             if evidence.issuperset(item['evidence']) and hypotheses.issuperset(item['hypotheses'])]
    for item in doc['tool_runs']:
        if item.get('attachment') in lost:
            item.pop('attachment')
    plan = doc['observation_plan']
    if plan is not None and not evidence.issuperset(plan.get('evidence', [])):
        plan['evidence'] = [identifier for identifier in plan['evidence'] if identifier in evidence]
        if plan['status'] == 'data_verified':
            plan['status'] = 'evidence_unavailable'
        if plan.get('collection_state') == 'receiving_data':
            plan['collection_state'] = 'unknown'
    doc['improvement'] = None


def check_restored(doc):
    """Close a gap only when the same sealed product is again a verified input."""
    previous = gaps(doc)
    if not previous:
        return
    selected = {(item['kind'], item['target_id']): item['report_sha256'] for item in doc['attachments']}
    remaining = []
    for gap in previous:
        item = gap['attachment']
        digest = selected.get((item['kind'], item['target_id']))
        if digest is None:
            remaining.append(gap)
        elif digest != item['report_sha256']:
            raise InputError('restored attachment differs from the retained identity')
    if remaining:
        doc['source_gaps'] = remaining
    else:
        doc.pop('source_gaps')
