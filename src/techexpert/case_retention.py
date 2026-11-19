"""Reviewed disposition of a case's exact retained source and its impact receipt."""
from contextlib import ExitStack, contextmanager
from itertools import islice
import os
from pathlib import Path
import re

from . import operation_state as fs, retained_resources, retention_policy, storage, windows_native
from .inputs import InputError

_SOURCE = re.compile(r's(?:[1-9]|[12][0-9]|3[0-2])')
_KIND = 'case_source_snapshot_v1'
_PLAN = {'schema_version', 'kind', 'case_id', 'source_id', 'report_sha256', 'file', 'impact', 'policy'}
MAX_PLAN_BYTES = 512 * 1024


class SnapshotRetirement(InputError):
    """A retained case cannot be reverified after an admitted disposition."""


def registry(state, case_id):
    storage.case_folder(state, case_id)  # validates the identifier
    return fs.safe(Path(state) / 'retention' / 'case-sources' / case_id)


def _paths(state, case_id, source_id):
    case = storage.case_folder(state, case_id)
    if not isinstance(source_id, str) or not _SOURCE.fullmatch(source_id):
        raise InputError('invalid retained case source identifier')
    return registry(state, case_id) / source_id, fs.safe(case / 'sources') / (source_id + '.bin')


def _validate(plan):
    if (type(plan) is not dict or set(plan) != _PLAN or plan['kind'] != _KIND
            or type(plan['schema_version']) is not int or plan['schema_version'] != 1
            or type(plan['file']) is not dict or type(plan['impact']) is not dict):
        raise InputError('invalid case snapshot retirement plan')
    if len(fs.encode(plan)) > MAX_PLAN_BYTES:
        raise InputError('case snapshot retirement plan exceeds its review limit')


def _file_status(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return 'absent'
    except OSError:
        return 'unavailable'
    return 'path_reoccupied'


def status(state, case_id, source_id, *, read=fs.read):
    folder, target = _paths(state, case_id, source_id)
    try:
        intent = read(folder / 'intent.json', MAX_PLAN_BYTES + 8192)
    except FileNotFoundError:
        if fs.safe(folder / 'receipt.json').exists():
            raise InputError('case snapshot retirement receipt has no intent')
        return None
    if (type(intent) is not dict or intent.get('schema_version') != 1
            or intent.get('plan_sha256') != fs.digest(intent.get('plan'))):
        raise InputError('case snapshot retirement intent integrity mismatch')
    plan = intent['plan']
    _validate(plan)
    if (plan['case_id'], plan['source_id'], plan['file']['path']) != (case_id, source_id, str(target)):
        raise InputError('case snapshot retirement identity mismatch')
    result = dict(schema_version=plan['schema_version'], status='outcome_unverified', case_id=case_id, source_id=source_id,
                  report_sha256=plan['report_sha256'], plan_sha256=intent['plan_sha256'],
                  impact=plan['impact'], current_file_status=_file_status(target), logical_bytes_removed=None,
                  policy=plan['policy'])
    try:
        sealed = read(folder / 'receipt.json', 8192)
    except FileNotFoundError:
        return result
    record = sealed.get('record') if type(sealed) is dict else None
    if (type(record) is not dict or record.get('schema_version') != 1 or sealed.get('sha256') != fs.digest(record)
            or record.get('intent_sha256') != fs.digest(intent) or record.get('status') != 'removed'
            or record.get('logical_bytes_removed') != plan['file']['identity']['bytes']):
        raise InputError('case snapshot retirement receipt integrity mismatch')
    return dict(result, status='removed', logical_bytes_removed=record['logical_bytes_removed'],
                removed_at=record['removed_at'])


def require_available(state, case_id, source_id):
    retirement = status(state, case_id, source_id)
    if retirement is not None:
        if retirement['status'] == 'removed':
            raise SnapshotRetirement('retired case snapshot; see the retained report and retirement receipt')
        raise SnapshotRetirement('case snapshot retirement outcome is unverified; inspect its receipt')


def _case_retirements(state, case_id):
    folder = registry(state, case_id)
    try:
        items = sorted(islice(folder.iterdir(), 34))
    except FileNotFoundError:
        return
    if len(items) > 33:
        raise InputError('too many case snapshot retirement entries')
    for path in items:
        if path.name == 'writer.lock':
            continue
        item = status(state, case_id, path.name)
        if item is not None:
            yield item


@contextmanager
def case_writers(state, case_ids, *, require_sources=True):
    """Serialize reference publication with retirement for the cases involved."""
    with ExitStack() as stack:
        for case_id in sorted(set(case_ids)):
            stack.enter_context(fs.writer(fs.private(registry(state, case_id))))
            if require_sources and any(_case_retirements(state, case_id)):
                raise SnapshotRetirement('retired case snapshot or unverified retirement; reference publication refused')
        yield


def derived_case_dependencies(state, attachment):
    if attachment.get('scope') == 'fix_verification':
        from .fix_verification import case_dependencies
    elif attachment.get('scope') == 'apdex_preparation':
        from .apdex_preparation import case_dependencies
    else:
        return {}
    return case_dependencies(state, attachment)


def attachment_case_ids(state, attachments):
    cases = {item['target_id'] for item in attachments if item['kind'] == 'case'}
    for item in attachments:
        if item['kind'] == 'comparison':
            folder = fs.safe(storage.comparison_folder(state, item['target_id']))
            for name in ('report.json', 'report.md', 'receipt.json'):
                fs.safe(folder / name)
            report, _ = storage.read_comparison_record(state, item['target_id'])
            cases.update(input_['case_id'] for input_ in report['input_reports'])
        cases.update(derived_case_dependencies(state, item))
    return cases


def affected_revision(retirements, doc):
    from .investigations import _digest
    key = (doc['investigation_id'], doc['revision'], _digest(doc))
    for item in retirements:
        for affected in item['impact']['investigations']:
            if (affected['investigation_id'], affected['revision'], affected['report_sha256']) == key:
                yield dict(case_id=item['case_id'], source_id=item['source_id'], status=item['status'],
                           plan_sha256=item['plan_sha256'], attachments=affected['attachments'],
                           evidence=affected['evidence'])


def for_report(state, doc):
    case_ids = attachment_case_ids(state, doc['attachments'])
    retirements = (item for identifier in sorted(case_ids) for item in _case_retirements(state, identifier))
    return list(affected_revision(retirements, doc))


def _bound_case(state, case_id, source_id):
    folder = fs.safe(storage.case_folder(state, case_id))
    for name in ('report.json', 'receipt.json', 'manifest.json'):
        fs.safe(folder / name)
    report, digest = storage.load_case(state, case_id, with_digest=True)
    source = retained_resources.selected(report, dict(kind='case', source_id=source_id))
    return report, digest, source


def _check_snapshot(snapshot, source):
    if snapshot['sha256'] != source['sha256'] or snapshot['identity']['bytes'] != source['size']:
        raise InputError('case snapshot integrity mismatch; cannot retire under this receipt')


def preview(state, case_id, source_id, *, use_policy=False):
    from .case_impact import observed
    from .profiles import require_unconfigured_path
    state = fs.safe(state)
    old = status(state, case_id, source_id)
    if old is not None:
        return old
    if os.name != 'nt':
        raise InputError('case snapshot retirement currently requires the Windows file profile')
    _, target = _paths(state, case_id, source_id)
    require_unconfigured_path(state, target)
    report, digest, source = _bound_case(state, case_id, source_id)
    policy = None
    if use_policy:
        policy, eligible = retention_policy.eligibility(state, report['created_at'], category='case-inputs')
        if not eligible:
            return dict(status='retained_by_policy', case_id=case_id, source_id=source_id, policy=policy)
    impact = observed(state, report, digest, source_id)
    snapshot = windows_native.snapshot_cleanup_file(fs.safe(target), max_bytes=source['size'], timeout_seconds=30)
    _check_snapshot(snapshot, source)
    plan = dict(schema_version=1, kind=_KIND, case_id=case_id, source_id=source_id, report_sha256=digest,
                file=dict(snapshot, path=str(target)), impact=impact, policy=policy)
    _validate(plan)
    return dict(status='ready', plan=plan, plan_sha256=fs.digest(plan), logical_bytes=source['size'])


def apply(state, plan, *, expected_sha256):
    from .case_impact import observed
    from .profiles import profile_writer, require_unconfigured_path
    _validate(plan)
    if fs.digest(plan) != expected_sha256:
        raise InputError('case snapshot retirement plan digest changed; review the current plan')
    if os.name != 'nt':
        raise InputError('case snapshot retirement currently requires the Windows file profile')
    state = fs.safe(state)
    case_id, source_id = plan['case_id'], plan['source_id']
    folder, target = _paths(state, case_id, source_id)
    if plan['file'].get('path') != str(target):
        raise InputError('retirement path is not the selected case snapshot')
    with case_writers(state, [case_id], require_sources=False), ExitStack() as locks:
        old = status(state, case_id, source_id)
        if old is not None:
            if old['plan_sha256'] != expected_sha256:
                raise InputError('another retirement is already recorded for this snapshot')
            return dict(old, replayed=True)
        locks.enter_context(profile_writer(fs.safe(state / 'profiles')))
        require_unconfigured_path(state, target)
        report, report_digest, source = _bound_case(state, case_id, source_id)
        if plan['policy'] is not None:
            locks.enter_context(fs.writer(fs.safe(state / 'retention')))
            current, eligible = retention_policy.eligibility(state, report['created_at'], category='case-inputs')
            if current != plan['policy'] or not eligible:
                raise InputError('retention policy changed or no longer selects the case snapshot')
        impact = observed(state, report, report_digest, source_id)
        if report_digest != plan['report_sha256'] or impact != plan['impact']:
            raise InputError('case snapshot dependencies changed; review the current plan')
        intent = dict(schema_version=1, plan=plan, plan_sha256=expected_sha256, admitted_at=fs.stamp())

        def admit(snapshot):
            _check_snapshot(snapshot, source)
            if dict(snapshot, path=str(target)) != plan['file']:
                raise InputError('case snapshot changed since review')
            fs.private(folder)
            fs.write(folder / 'intent.json', intent)

        windows_native.snapshot_cleanup_file(fs.safe(target), max_bytes=source['size'], timeout_seconds=30,
                                             before_remove=admit)
        if _file_status(target) != 'absent':
            raise InputError('case snapshot retirement outcome is unverified; inspect its receipt')
        record = dict(schema_version=1, status='removed', intent_sha256=fs.digest(intent),
                      removed_at=fs.stamp(), logical_bytes_removed=source['size'])
        fs.write(folder / 'receipt.json', dict(record=record, sha256=fs.digest(record)))
        return dict(status(state, case_id, source_id), replayed=False)
