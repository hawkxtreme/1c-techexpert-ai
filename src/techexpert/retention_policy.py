"""Revisioned local retention choices. Saving a choice does not run cleanup."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import operation_state as fs
from .inputs import InputError

CATEGORIES = {
    'export-work-copies': ('policy.json', 'source_export_work_copy_days'),
    'case-inputs': ('case-input-policy.json', 'case_input_days'),
    'case-indexes': ('case-index-policy.json', 'case_index_days'),
    'reports': ('report-policy.json', 'investigation_report_days'),
}
DEFAULT_CATEGORY = 'export-work-copies'


class PolicyRevisionConflict(InputError):
    """The requested policy revision no longer matches the saved choice."""


def _policy_fields(category):
    if category not in CATEGORIES:
        raise InputError('unknown retention category')
    return CATEGORIES[category]


def _validate(value, field):
    if (type(value) is not dict or set(value) != {'schema_version', field}
            or type(value['schema_version']) is not int or value['schema_version'] != 1):
        raise InputError('invalid retention policy properties')
    days = value[field]
    if days is not None and (type(days) is not int or not 0 <= days <= 36500):
        raise InputError(field + ' must be null or an integer 0..36500')


def load(state, *, category=DEFAULT_CATEGORY):
    filename, field = _policy_fields(category)
    path = fs.safe(Path(state) / 'retention' / filename)
    try:
        value = fs.read(path, 8192)
    except FileNotFoundError:
        return dict(schema_version=1, revision=0, **{field: None})
    if type(value) is not dict or type(value.get('revision')) is not int or value['revision'] < 1:
        raise InputError('invalid saved retention policy revision')
    _validate({key: item for key, item in value.items() if key != 'revision'}, field)
    return value


def save(state, request, *, expected_revision, category=DEFAULT_CATEGORY):
    filename, field = _policy_fields(category)
    _validate(request, field)
    if type(expected_revision) is not int or expected_revision < 0:
        raise InputError('expected retention policy revision required')
    folder = fs.private(Path(state) / 'retention')
    with fs.writer(folder):
        previous = load(state, category=category)
        if previous['revision'] != expected_revision:
            raise PolicyRevisionConflict('retention policy revision changed; reload before saving')
        value = dict(request, revision=expected_revision + 1)
        fs.write(folder / filename, value)
        return value


def eligibility(state, recorded_at, *, category=DEFAULT_CATEGORY):
    _, field = _policy_fields(category)
    policy = load(state, category=category)
    timestamp = datetime.fromisoformat(recorded_at)
    if timestamp.utcoffset() is None:
        raise InputError('retention age requires a recorded time zone')
    days = policy[field]
    return policy, days is not None and datetime.now(timezone.utc) - timestamp >= timedelta(days=days)
