"""Revisioned local retention choices. Saving a choice does not run cleanup."""
from pathlib import Path

from . import operation_state as fs
from .inputs import InputError

FIELDS = {'schema_version', 'source_export_work_copy_days'}


def _validate(value):
    if (type(value) is not dict or set(value) != FIELDS
            or type(value['schema_version']) is not int or value['schema_version'] != 1):
        raise InputError('invalid retention policy properties')
    days = value['source_export_work_copy_days']
    if days is not None and (type(days) is not int or not 0 <= days <= 36500):
        raise InputError('source_export_work_copy_days must be null or an integer 0..36500')


def load(state):
    path = fs.safe(Path(state) / 'retention' / 'policy.json')
    try:
        value = fs.read(path, 8192)
    except FileNotFoundError:
        return dict(schema_version=1, revision=0, source_export_work_copy_days=None)
    if type(value) is not dict or type(value.get('revision')) is not int or value['revision'] < 1:
        raise InputError('invalid saved retention policy revision')
    _validate({key: item for key, item in value.items() if key != 'revision'})
    return value


def save(state, request, *, expected_revision):
    _validate(request)
    if type(expected_revision) is not int or expected_revision < 0:
        raise InputError('expected retention policy revision required')
    folder = fs.private(Path(state) / 'retention')
    with fs.writer(folder):
        previous = load(state)
        if previous['revision'] != expected_revision:
            raise InputError('retention policy revision changed; reload before saving')
        value = dict(request, revision=expected_revision + 1)
        fs.write(folder / 'policy.json', value)
        return value
