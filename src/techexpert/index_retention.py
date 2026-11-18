"""Review and discard one owned, rebuildable case event index."""
from contextlib import ExitStack
import os
from pathlib import Path
import stat

from . import case_event_index as index, input_files, operation_state as fs, retention_policy, windows_native
from .case_retention import case_writers
from .inputs import InputError
from .profiles import profile_writer, require_unconfigured_path

_CATEGORY = 'case-indexes'
_PLAN = {'schema_version', 'kind', 'case_id', 'source_id', 'file', 'policy'}


def _identity(info):
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise InputError('index cleanup requires a regular single-link file')
    return dict(device=info.st_dev, inode=info.st_ino, bytes=info.st_size, mtime_ns=info.st_mtime_ns)


def _snapshot(path):
    path = fs.safe(path)
    if os.name == 'nt':
        return windows_native.snapshot_cleanup_file(path, max_bytes=index.MAX_BYTES, timeout_seconds=30)
    before = _identity(path.lstat())
    _, observed = input_files.read(path, index.MAX_BYTES)
    if before != _identity(path.lstat()) or observed['bytes'] != before['bytes']:
        raise InputError('index changed during inspection')
    return dict(identity=before, sha256=observed['sha256'])


def _selected_policy(state, path, snapshot):
    rules = retention_policy.load(state, category=_CATEGORY)
    if rules['case_index_days'] is None:
        return rules, False
    expected = dict(bytes=snapshot['identity']['bytes'], sha256=snapshot['sha256'])
    raw, _ = input_files.read(path, index.MAX_BYTES, keep=True, expected=expected)
    record, _ = index._decode(raw)
    return retention_policy.eligibility(state, record['created_at'], category=_CATEGORY)


def preview(state, case_id, source_id, *, use_policy=False):
    path = index.path_for(state, case_id, source_id)
    try:
        snapshot = _snapshot(path)
    except FileNotFoundError:
        return dict(status='absent', case_id=case_id, source_id=source_id)
    require_unconfigured_path(state, path)
    policy = None
    if use_policy:
        policy, eligible = _selected_policy(state, path, snapshot)
        if not eligible:
            return dict(status='retained_by_policy', case_id=case_id, source_id=source_id, policy=policy)
    plan = dict(schema_version=1, kind='case_event_index_v1', case_id=case_id, source_id=source_id,
                file=dict(snapshot, path=str(path)), policy=policy)
    return dict(status='ready', plan=plan, plan_sha256=fs.digest(plan), logical_bytes=snapshot['identity']['bytes'],
                effects=dict(evidence_loss=False, next_query='verified_source_scan_if_available'))


def _discard_posix(path, expected, claim):
    if _snapshot(path) != expected:
        raise InputError('index changed since cleanup review')
    claim.mkdir(mode=0o700)
    pending = claim / 'claimed.index'
    try:
        path.rename(pending)
    except OSError:
        claim.rmdir()
        raise
    if _snapshot(pending) != expected:
        # Keep or restore an unexpected member. Creating the original name must
        # fail if a writer has already placed another generation there.
        os.link(pending, path, follow_symlinks=False)
        pending.unlink()
        claim.rmdir()
        raise InputError('index changed during cleanup')
    pending.unlink()
    claim.rmdir()


def apply(state, plan, *, expected_sha256):
    if (type(plan) is not dict or set(plan) != _PLAN or type(plan['schema_version']) is not int
            or plan['schema_version'] != 1 or plan['kind'] != 'case_event_index_v1'
            or type(plan['file']) is not dict or set(plan['file']) != {'identity', 'sha256', 'path'}):
        raise InputError('invalid event index cleanup plan')
    if fs.digest(plan) != expected_sha256:
        raise InputError('event index cleanup plan digest changed')
    case_id, source_id = plan['case_id'], plan['source_id']
    path = index.path_for(state, case_id, source_id)
    if plan['file']['path'] != str(path):
        raise InputError('cleanup path is not the selected case index')
    reviewed = dict(identity=plan['file']['identity'], sha256=plan['file']['sha256'])
    claim = fs.safe(path.parent / ('discard-' + expected_sha256))
    with case_writers(state, [case_id], require_sources=False), ExitStack() as locks:
        if claim.exists():
            return dict(status='outcome_unverified', path=str(path), retained_claim=str(claim))
        if not path.exists():
            return dict(status='already_absent', path=str(path), logical_bytes_removed=0)
        locks.enter_context(profile_writer(fs.safe(Path(state) / 'profiles')))
        require_unconfigured_path(state, path)
        if plan['policy'] is not None:
            locks.enter_context(fs.writer(fs.safe(Path(state) / 'retention')))
            snapshot = _snapshot(path)
            if snapshot != reviewed:
                raise InputError('index changed since cleanup review')
            policy, eligible = _selected_policy(state, path, snapshot)
            if policy != plan['policy'] or not eligible:
                raise InputError('retention policy changed or no longer selects the event index')
        if os.name == 'nt':
            def confirm(snapshot):
                if snapshot != reviewed:
                    raise InputError('index changed since cleanup review')

            windows_native.snapshot_cleanup_file(path, max_bytes=index.MAX_BYTES, timeout_seconds=30,
                                                before_remove=confirm)
        else:
            _discard_posix(path, reviewed, claim)
        if path.exists():
            return dict(status='outcome_unverified', path=str(path))
        return dict(status='removed', path=str(path), logical_bytes_removed=reviewed['identity']['bytes'])
