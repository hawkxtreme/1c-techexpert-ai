"""Compare committed investigation revisions without opening original sources."""
import re

from . import context_fields
from .inputs import InputError


ATTACHMENT = context_fields.ATTACHMENT_ID
PRODUCT_ID = re.compile('[a-f0-9]{32}')
EVIDENCE = re.compile(r'E-[A-Za-z0-9-]{1,60}')
HYPOTHESIS = re.compile(r'H-[A-Za-z0-9-]{1,60}')
SOURCE_BINDING = re.compile(r'S-[A-Za-z0-9-]{1,60}')
RECOMMENDATION_BASIS = re.compile(r'[EH]-[A-Za-z0-9-]{1,60}')
RECORD = re.compile(r'(?:report|s[1-9][0-9]{0,2}(?::r?[1-9][0-9]{0,8})?)')
HYPOTHESIS_STATUSES = ('proposed', 'testing', 'supported', 'refuted', 'insufficient_data')
ASSESSMENT_STATUSES = ('not_provided', 'provided_by_harness', 'stale_due_to_revision')
GROUPS = (('attachments', 'attachment', 'A'), ('evidence', 'evidence', 'E'),
          ('source_bindings', 'source_binding', 'S'), ('source_links', 'source_link', 'L'), ('facts', 'fact', 'F'),
          ('hypotheses', 'hypothesis', 'H'), ('contradictions', 'contradiction', 'C'),
          ('recommendations', 'recommendation', 'R'))
SECTIONS = ('episode', 'time_mode', 'scale', 'template', 'variant', 'profile_sha256', 'occurrence',
            'open_questions', 'observation_plan', 'workflow_stage', 'execution_status',
            'stage_decision', 'improvement', 'task_notes')
REFERENCE_LIMIT = 8


def schema(cap):
    revision = dict(type='integer', minimum=1, maximum=1000)
    return cap.obj(dict(before_revision=revision, after_revision=revision,
                        offset=cap.integer(0, 100_000, 0), limit=cap.integer(1, 40, 20)), ('before_revision',))


def normalize(value):
    from . import capabilities as cap

    result = cap.validate(value, schema(cap))
    if result['offset'] and 'after_revision' not in result:
        raise InputError('a subsequent comparison page requires the exact after revision')
    if result['before_revision'] > result.get('after_revision', 1000):
        raise InputError('the before revision must not follow the after revision')
    return result


def _references(values, pattern):
    checked = [value for value in values if context_fields.identifier(value, pattern)]
    return dict(ids=checked[:REFERENCE_LIMIT], count=len(checked))


def _attachment(item):
    return dict(id=context_fields.identifier(item['id'], ATTACHMENT),
                kind=context_fields.enum(item['kind'], ('case', 'artifact', 'comparison')),
                target_id=context_fields.identifier(item['target_id'], PRODUCT_ID),
                origin=context_fields.enum(item.get('source_origin'), ('provided', 'synthetic', 'not_established')))


def _assessment(doc):
    item = doc['assessment'] or {}
    return dict(status=context_fields.enum(doc['assessment_status'], ASSESSMENT_STATUSES),
                cause_state=context_fields.enum(doc['cause_state'], ('confirmed', 'hypothesis', 'insufficient_data')),
                hypothesis_id=context_fields.identifier(item.get('hypothesis_id'), HYPOTHESIS),
                evidence=_references(item.get('evidence', []), EVIDENCE))


def _improvement(doc):
    from .investigations import IMPROVEMENT_STATES

    item = doc.get('improvement')
    if item is None:
        return None
    states = {key: context_fields.enum(item.get(key), values) for key, values in IMPROVEMENT_STATES.items()}
    states['evidence'] = _references(item['evidence'], EVIDENCE)
    return states


def resume(doc, last_assessment_revision):
    result = dict(assessment_status=_assessment(doc)['status'], last_saved_assessment_revision=last_assessment_revision,
                  attachments=[_attachment(item) for item in doc['attachments']],
                  hypothesis_counts={status:sum(item['status'] == status for item in doc['hypotheses'])
                                     for status in HYPOTHESIS_STATUSES},
                  open_questions=len(doc['open_questions']))
    if doc.get('improvement') is not None:
        result['improvement'] = _improvement(doc)
    return result


def _project(kind, row):
    if row is None:
        return None
    if kind == 'attachment':
        return _attachment(row)
    if kind == 'evidence':
        return dict(attachment=context_fields.identifier(row['attachment'], ATTACHMENT),
                    record=context_fields.identifier(row['record'], RECORD))
    if kind == 'source_binding':
        return dict(attachment=context_fields.identifier(row['attachment'], ATTACHMENT),
                    record_source=context_fields.identifier(row.get('record_source'), context_fields.SOURCE_ID))
    if kind == 'source_link':
        check = row['check']
        return dict(status=context_fields.enum(check['status'], ('unknown', 'reported', 'candidate', 'confirmed', 'conflict')),
                    left=context_fields.identifier(row['left'], SOURCE_BINDING),
                    right=context_fields.identifier(row['right'], SOURCE_BINDING),
                    exact_correlation_allowed=check.get('exact_correlation_allowed') is True)
    if kind == 'recommendation':
        return dict(kind=context_fields.enum(row['kind'], ('diagnostic', 'lab_change', 'production_change')),
                    basis=_references(row['basis'], RECOMMENDATION_BASIS))
    result = dict(evidence=_references(row.get('evidence', []), EVIDENCE))
    if kind == 'hypothesis':
        result['status'] = context_fields.enum(row['status'], HYPOTHESIS_STATUSES)
    elif kind == 'contradiction':
        result['status'] = context_fields.enum(row['status'], ('resolved', 'unresolved'))
        result['hypotheses'] = _references(row['hypotheses'], HYPOTHESIS)
    elif 'measurement' in row:
        result['measurement'] = dict(attachment=context_fields.identifier(row['measurement']['attachment'], ATTACHMENT),
                                     basis='saved_tool_report')
    return result


def _records(doc, section, prefix):
    from .investigations import _ids

    owner = (doc['assessment'] or {}) if section == 'recommendations' else doc
    values = owner.get(section, [])
    _ids(values, prefix)
    return {item['id']: item for item in values}


def _dependencies(item):
    item = item or {}
    direct = {item[key] for key in ('attachment', 'left', 'right', 'hypothesis_id') if item.get(key) is not None}
    return direct.union(*(item.get(key, []) for key in ('evidence', 'basis', 'hypotheses', 'source_links')))


def compare(before, after, *, offset, limit):
    from .investigations import _digest

    items = []
    total = 0
    changed = set()
    for section, kind, prefix in GROUPS:
        old, new = _records(before, section, prefix), _records(after, section, prefix)
        for identifier in sorted(old.keys() | new.keys()):
            left, right = old.get(identifier), new.get(identifier)
            basis_changed = (left is not None and right is not None
                             and bool((_dependencies(left) | _dependencies(right)) & changed))
            if not basis_changed and _digest(left) == _digest(right):
                continue
            changed.add(identifier)
            total += 1
            if total <= offset or len(items) == limit:
                continue
            item = dict(kind=kind, id=identifier, change='added' if left is None else 'removed' if right is None else 'updated',
                        before=_project(kind, left), after=_project(kind, right))
            if basis_changed:
                item['linked_basis_changed'] = True
            if kind == 'fact' and left and right and 'measurement' in left and 'measurement' in right:
                a, b = left['measurement'], right['measurement']
                item['measurement_value_changed'] = _digest(a['value']) != _digest(b['value'])
                item['measurement_basis_changed'] = ((a['attachment'], a['pointer']) != (b['attachment'], b['pointer'])
                                                     or a['attachment'] in changed)
            items.append(item)
    old_assessment, new_assessment = _assessment(before), _assessment(after)
    assessment_basis_changed = bool((_dependencies(before['assessment']) | _dependencies(after['assessment'])) & changed)
    result = dict(before_revision=before['revision'], after_revision=after['revision'],
                analysis_basis_changed=before['analysis_basis_sha256'] != after['analysis_basis_sha256'],
                assessment=dict(before=old_assessment, after=new_assessment, linked_basis_changed=assessment_basis_changed,
                                changed=old_assessment != new_assessment or _digest(before['assessment']) != _digest(after['assessment'])
                                or assessment_basis_changed),
                changed_sections=[key for key in SECTIONS if _digest(before.get(key)) != _digest(after.get(key))],
                total=total, offset=offset, items=items,
                next_offset=offset+len(items) if offset+len(items)<total else None,
                scope='committed_revision_metadata', evidence_content_revalidated=False)
    if before.get('improvement') is not None or after.get('improvement') is not None:
        result['improvement'] = dict(before=_improvement(before), after=_improvement(after))
    return result
