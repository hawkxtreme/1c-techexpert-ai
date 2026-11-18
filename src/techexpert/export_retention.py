"""Reviewed removal of the owned database copy of a completed Windows export."""
from contextlib import ExitStack
import os
from pathlib import Path
import re

from . import artifacts, operation_state as fs, retention_policy, source_export, windows_native as native
from .inputs import InputError

KIND = 'source_export_work_copy_v1'
FILE = '1Cv8.1CD'
INTENT = 'work-copy-removal.json'
RECEIPT = 'work-copy-removal-receipt.json'
PLAN_FIELDS = {'schema_version', 'kind', 'export_plan_id', 'export_binding', 'file', 'policy'}
RECEIPT_FIELDS = {'schema_version', 'status', 'intent_sha256', 'removed_at', 'logical_bytes_removed',
                  'export_plan_id', 'retained_source_artifact_id', 'retained_execution_artifact_id'}


def _paths(state, export_id):
    folder = fs.safe(source_export._folder(fs.safe(state), export_id))
    return folder, folder / 'work-ib' / FILE


def _artifact_record(state, artifact_id):
    folder = fs.safe(artifacts.artifact_folder(state, artifact_id))
    for member in ('report.json', 'request.json', 'receipt.json'):
        fs.safe(folder / member)
    return artifacts.read_artifact_record(state, artifact_id)


def _bound_export(state, export_id, *, verify_outputs=False):
    folder, target = _paths(state, export_id)
    for name in ('plan.json', 'plan-receipt.json', 'execution.json', 'run.lock'):
        fs.safe(folder / name)
    _, plan, plan_sha = source_export._load(state, export_id)
    if fs.safe(folder / 'run.lock').exists():
        raise InputError('source export is active or interrupted; inspect its status')
    try:
        execution = fs.read(folder / 'execution.json', 8192)
    except FileNotFoundError as exc:
        raise InputError('cleanup requires a completed source export') from exc
    if type(execution) is not dict or execution.get('schema_version') != 1 or execution.get('plan_sha256') != plan_sha:
        raise InputError('source export execution receipt is incomplete or changed')
    record, report_sha = _artifact_record(state, execution['artifact_id'])
    request = fs.read(artifacts.artifact_folder(state, record['artifact_id']) / 'request.json', 1024**2)
    if (record['kind'] != 'source_export' or execution.get('artifact_report_sha256') != report_sha
            or request != dict(plan_id=export_id, plan_sha256=plan_sha)):
        raise InputError('source export artifact does not match this plan')
    result = record['result']
    run = result.get('native') if type(result) is dict else None
    if (type(result) is not dict or result.get('status') != 'completed'
            or type(result.get('platform_result')) is not int or result['platform_result'] != 0
            or type(run) is not dict or run.get('tree_finished') is not True
            or not result.get('source_artifact_id')):
        raise InputError('cleanup requires a completed export with verified stop and a saved source snapshot')
    original = Path(plan['source_file'])
    if (plan.get('profile') != 'windows-file-designer-8.3.27.1989-v1'
            or Path(plan['working_directory']) != target.parent or Path(result['private_working_copy']) != target.parent
            or not original.is_absolute() or '..' in original.parts or original.is_relative_to(folder)
            or result['copy']['source_identity'] != plan['source_identity']):
        raise InputError('unverified export working copy origin')
    source, source_sha = _artifact_record(state, result['source_artifact_id'])
    if source['kind'] != 'onec_source' or source_sha != result.get('source_artifact_report_sha256'):
        raise InputError('saved source snapshot changed')
    if verify_outputs:
        artifacts.load_artifact(state, record['artifact_id'])
        artifacts.load_artifact(state, source['artifact_id'])
    binding = dict(plan_sha256=plan_sha, execution_sha256=fs.digest(execution),
                   execution_artifact_id=record['artifact_id'], execution_report_sha256=report_sha,
                   source_artifact_id=source['artifact_id'], source_report_sha256=source_sha)
    return folder, target, plan, result, binding


def _file_status(target):
    try:
        fs.safe(target.parent)
        target.lstat()
    except FileNotFoundError:
        return 'absent'
    except (OSError, InputError):
        return 'unavailable'
    return 'present'


def _validate_review(plan):
    if type(plan) is not dict or set(plan) != PLAN_FIELDS or plan.get('kind') != KIND:
        raise InputError('invalid work copy cleanup plan')
    if type(plan['schema_version']) is not int or plan['schema_version'] != 1:
        raise InputError('invalid work copy cleanup schema')
    file = plan['file']
    if (type(file) is not dict or set(file) != {'path', 'identity', 'sha256'}
            or type(file['identity']) is not dict or type(file['identity'].get('bytes')) is not int
            or not isinstance(file['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', file['sha256'])):
        raise InputError('invalid reviewed work copy identity')


def _history(folder, target, *, expected_sha256=None, read=fs.read):
    intent_path = fs.safe(folder / INTENT)
    receipt_path = fs.safe(folder / RECEIPT)
    try:
        intent = read(intent_path, 32 * 1024)
    except FileNotFoundError:
        if receipt_path.exists():
            raise InputError('cleanup receipt has no recorded intent')
        return None
    if (type(intent) is not dict or intent.get('schema_version') != 1 or type(intent.get('plan')) is not dict
            or fs.digest(intent['plan']) != intent.get('plan_sha256')):
        raise InputError('cleanup intent integrity mismatch')
    plan = intent['plan']
    _validate_review(plan)
    if plan['export_plan_id'] != folder.name or plan['file']['path'] != str(target):
        raise InputError('cleanup intent does not match this export location')
    if expected_sha256 is not None and expected_sha256 != intent['plan_sha256']:
        raise InputError('another cleanup plan is already recorded for this copy')
    observed = _file_status(target)
    try:
        sealed = read(receipt_path, 32 * 1024)
    except FileNotFoundError:
        return dict(status='outcome_unverified', plan_sha256=intent['plan_sha256'],
                    current_file_status=observed, logical_bytes_removed=None)
    if (type(sealed) is not dict or type(sealed.get('receipt')) is not dict
            or fs.digest(sealed['receipt']) != sealed.get('sha256')):
        raise InputError('cleanup receipt integrity mismatch')
    record = sealed['receipt']
    if (set(record) != RECEIPT_FIELDS or record['schema_version'] != 1
            or record['intent_sha256'] != fs.digest(intent) or record['status'] != 'removed'
            or record['export_plan_id'] != folder.name or record['logical_bytes_removed'] != plan['file']['identity']['bytes']
            or record['retained_source_artifact_id'] != plan['export_binding']['source_artifact_id']
            or record['retained_execution_artifact_id'] != plan['export_binding']['execution_artifact_id']):
        raise InputError('cleanup receipt does not match the recorded intent')
    return dict(record, plan_sha256=intent['plan_sha256'],
                current_file_status='path_reoccupied' if observed == 'present' else observed)


def status(state, export_id):
    folder, target = _paths(state, export_id)
    return _history(folder, target)


def locate_working_copy(state, artifact_id, report_sha, working_directory, *, read):
    """Resolve a bound workspace for inventory without opening the database."""
    request = read(artifacts.artifact_folder(state, artifact_id) / 'request.json', 8192)
    export_id = request['plan_id']
    folder, target = _paths(state, export_id)
    receipt = read(folder / 'execution.json', 8192)
    if (type(receipt) is not dict or receipt.get('schema_version') != 1
            or receipt.get('artifact_id') != artifact_id or receipt.get('artifact_report_sha256') != report_sha
            or receipt.get('plan_sha256') != request.get('plan_sha256')
            or Path(working_directory) != target.parent):
        raise InputError('workspace does not match the saved source export')
    return export_id, target, _history(folder, target, read=read)


def _policy(state, result):
    return retention_policy.eligibility(state, result['finished_at'])


def _file_key(identity):
    if type(identity) is not dict:
        raise InputError('saved export file identity unavailable')
    if 'file_id' in identity:
        file_id = identity['file_id']
        if not isinstance(file_id, str) or not re.fullmatch('[a-f0-9]{32}', file_id):
            raise InputError('invalid saved Windows file ID')
        volume, index = identity.get('volume_serial'), int.from_bytes(bytes.fromhex(file_id), 'little')
    else:
        # Older Windows export plans retained the equivalent OS stat identity.
        volume, index = identity.get('device'), identity.get('inode')
    if type(volume) is not int or volume < 0 or type(index) is not int or index <= 0:
        raise InputError('saved export file identity unavailable')
    return volume, index


def _same_file(left, right):
    return _file_key(left) == _file_key(right)


def _check_references(state, folder, target, identity):
    from .profiles import require_unconfigured_path
    require_unconfigured_path(state, target)
    for count, candidate in enumerate(fs.safe(folder.parent).iterdir(), 1):
        if count > 1024:
            raise InputError('source export reference scan exceeds its bound')
        if candidate == folder or not re.fullmatch('[a-f0-9]{32}', candidate.name):
            continue
        for name in ('plan.json', 'plan-receipt.json'):
            fs.safe(candidate / name)
        _, plan, _ = source_export._load(state, candidate.name)
        if Path(plan['source_file']) == target or _same_file(plan['source_identity'], identity):
            raise InputError('working copy is the selected original of another source export')


def _inspect(state, folder, target, plan, *, before_remove=None):
    if os.name != 'nt':
        raise InputError('working copy cleanup requires the Windows file export profile')
    if not native.directory_policy(folder)['protected']:
        raise InputError('working copy cleanup requires the private export directory ACL')
    limits = plan['request']
    max_bytes = limits['max_copy_bytes']
    timeout = limits['timeout_seconds']
    if type(max_bytes) is not int or not 1 <= max_bytes <= 8 * source_export.GIB:
        raise InputError('invalid saved export copy size limit')
    if type(timeout) is not int or not 1 <= timeout <= 600:
        raise InputError('invalid saved export copy time limit')

    def validate(snapshot):
        identity = snapshot['identity']
        if _same_file(plan['source_identity'], identity):
            raise InputError('working copy aliases the recorded original file')
        if before_remove is None:
            _check_references(state, folder, target, identity)
        else:
            before_remove(snapshot)

    if before_remove is None:
        snapshot = native.snapshot_cleanup_file(fs.safe(target), max_bytes=max_bytes, timeout_seconds=timeout)
        validate(snapshot)
        return snapshot
    return native.snapshot_cleanup_file(fs.safe(target), max_bytes=max_bytes, timeout_seconds=timeout,
                                        before_remove=validate)


def preview(state, export_id, *, use_policy=False):
    old = status(state, export_id)
    if old is not None:
        return old
    folder, target, plan, result, binding = _bound_export(state, export_id, verify_outputs=True)
    selected = None
    if use_policy:
        selected, ready = _policy(state, result)
        if not ready:
            return dict(status='retained_by_policy', export_plan_id=export_id, policy=selected)
    snapshot = _inspect(state, folder, target, plan)
    review = dict(schema_version=1, kind=KIND, export_plan_id=export_id, export_binding=binding,
                  file=dict(snapshot, path=str(target)), policy=selected)
    return dict(status='ready', plan=review, plan_sha256=fs.digest(review),
                logical_bytes=snapshot['identity']['bytes'],
                effects=dict(retained_source_artifact_id=binding['source_artifact_id'],
                             retained_execution_artifact_id=binding['execution_artifact_id'],
                             work_copy_available_after=False))


def apply(state, approved, *, expected_sha256):
    _validate_review(approved)
    if fs.digest(approved) != expected_sha256:
        raise InputError('work copy cleanup plan digest changed; review the current plan')
    folder, target = _paths(state, approved['export_plan_id'])
    if approved['file']['path'] != str(target):
        raise InputError('cleanup path is not the selected export work copy')
    if os.name != 'nt':
        raise InputError('working copy cleanup requires the Windows file export profile')
    with fs.writer(folder.parent), ExitStack() as admitted_locks:
        old = _history(folder, target, expected_sha256=expected_sha256)
        if old is not None:
            return dict(old, replayed=True)
        _, _, plan, result, binding = _bound_export(state, approved['export_plan_id'], verify_outputs=True)
        if binding != approved['export_binding']:
            raise InputError('source export evidence changed after cleanup review')
        intent = dict(schema_version=1, plan=approved, plan_sha256=expected_sha256, admitted_at=fs.stamp())

        def admit(snapshot):
            if dict(snapshot, path=str(target)) != approved['file']:
                raise InputError('working copy changed after cleanup review')
            from .profiles import profile_writer
            admitted_locks.enter_context(profile_writer(fs.safe(Path(state) / 'profiles')))
            _check_references(state, folder, target, snapshot['identity'])
            if approved['policy'] is not None:
                admitted_locks.enter_context(fs.writer(fs.safe(Path(state) / 'retention')))
                choice, ready = _policy(state, result)
                if approved['policy'] != choice or not ready:
                    raise InputError('retention policy changed or no longer selects this copy')
            fs.write(folder / INTENT, intent)

        snapshot = _inspect(state, folder, target, plan, before_remove=admit)
        if _file_status(target) != 'absent':
            raise InputError('work copy removal outcome is unverified; inspect cleanup status')
        receipt = dict(schema_version=1,status='removed', intent_sha256=fs.digest(intent), removed_at=fs.stamp(),
                       logical_bytes_removed=snapshot['identity']['bytes'], export_plan_id=approved['export_plan_id'],
                       retained_source_artifact_id=binding['source_artifact_id'],
                       retained_execution_artifact_id=binding['execution_artifact_id'])
        fs.write(folder / RECEIPT, dict(receipt=receipt, sha256=fs.digest(receipt)))
        return dict(receipt, plan_sha256=expected_sha256, current_file_status='absent', replayed=False)
