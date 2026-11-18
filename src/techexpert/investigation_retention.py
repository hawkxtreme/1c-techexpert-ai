"""Reviewed disposal of an investigation's sealed report history."""
from collections import defaultdict
from contextlib import ExitStack, contextmanager
from itertools import chain
import os
from pathlib import Path
import re
import stat

from . import input_files, investigations, operation_state as fs, retention_policy, windows_native
from .inputs import InputError

_CATEGORY = 'reports'
_KIND = 'investigation_report_history_v1'
_FIELDS = {'schema_version', 'kind', 'investigation_id', 'path', 'head', 'directories', 'files',
           'attached_products', 'operation_references', 'policy'}
_MAX_HISTORY_BYTES = 256 * 1024**2
MAX_PLAN_BYTES = 4 * 1024**2


def _location(state, identifier):
    return fs.safe(investigations.revision_folder(state, identifier, 1).parent.parent)


def registry(state, identifier):
    investigations.revision_folder(state, identifier, 1)
    return fs.safe(Path(state) / 'retention' / 'reports' / identifier)


@contextmanager
def writer(state, identifier, *, require_report=True):
    folder = registry(state, identifier)
    with fs.writer(fs.private(folder)):
        if require_report:
            require_available(state, identifier)
        yield folder


def request_ids(state, request):
    """Investigation references declared at managed operation admission."""
    operation = request['operation']
    args = request.get('arguments', {})
    scope = args.get('scope', {}) if operation == 'code.execute' else {}
    ids = {item['id'] for item in scope.get('investigations', [])}
    for field in ('remote_plans', 'remote_profile_plans'):
        ids.update(item['settings']['investigation_id'] for item in scope.get(field, []))
    ids.update(item['investigation_id'] for item in (request.get('context') or {}, args) if 'investigation_id' in item)
    remote_plans = {item['plan_id'] for item in scope.get('remote_calls', [])}
    if operation in ('remote.inspect', 'remote.capture'):
        remote_plans.add(args['plan_id'])
    if remote_plans:
        from .remote_transfers import read_plan
        for plan_id in sorted(remote_plans):
            saved = read_plan(state, plan_id)['result']
            ids.add(saved['investigation']['id'])
    return sorted(ids)


def iter_saved_plans(state):
    """Read the finite saved-plan index without opening operation results or originals."""
    root = fs.safe(Path(state) / 'operations')
    try:
        entries = os.scandir(root)
    except FileNotFoundError:
        return
    remaining = 64 * 1024**2
    with entries:
        for count, entry in enumerate(entries, 1):
            if count > 8192 or not re.fullmatch('[a-f0-9]{64}', entry.name):
                raise InputError('saved operation inventory unavailable or above its bound')
            folder = fs.safe(entry.path)
            plan_path = fs.safe(folder / 'plan.json')
            try:
                remaining -= plan_path.lstat().st_size
            except FileNotFoundError as error:
                with os.scandir(folder) as members:
                    if any(member.name != 'writer.lock' for member in members):
                        raise InputError('saved operation relationship is unknown because its plan is missing') from error
                continue  # only the folder and writer may precede publication of the plan
            if remaining < 0:
                raise InputError('saved operation inventory exceeds its byte bound')
            try:
                plan = fs.plan(folder)
            except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
                raise InputError('saved operation relationship cannot be verified') from error
            yield folder, plan


def _related_operations(state, identifier):
    from .operations import TERMINAL
    found = []
    for folder, plan in iter_saved_plans(state):
        request = plan['request']
        try:
            if 'investigation_dependencies' in plan:
                related = plan['investigation_dependencies']
                if (type(related) is not list or any(type(item) is not str or not re.fullmatch('[a-f0-9]{32}', item)
                        for item in related) or related != sorted(set(related))):
                    raise InputError('invalid operation investigation dependencies')
            else:
                related = request_ids(state, request)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            raise InputError('saved operation relationship cannot be verified') from error
        if identifier not in related:
            continue
        try:
            current = fs.read(folder / 'status.json', 64 * 1024)
        except FileNotFoundError as error:
            raise InputError('related operation admission is incomplete') from error
        except (OSError, ValueError, TypeError) as error:
            raise InputError('related operation status cannot be verified') from error
        if type(current) is not dict or type(current.get('status')) is not str:
            raise InputError('related operation status cannot be verified')
        if (current.get('run_id') != folder.name
                or current.get('status') not in TERMINAL or current.get('stop_verified') is not True):
            raise InputError('related operation is active or its stop is unverified')
        found.append(dict(id=folder.name, operation=request['operation'], status=current['status']))
    return sorted(found, key=lambda item: item['id'])


def _identity(info, *, directory):
    if directory:
        if not stat.S_ISDIR(info.st_mode) or info.st_ino <= 0:
            raise InputError('report cleanup requires a stable directory identity')
        return dict(device=info.st_dev, inode=info.st_ino)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_ino <= 0:
        raise InputError('report cleanup requires regular, single-link files')
    return dict(device=info.st_dev, inode=info.st_ino, bytes=info.st_size, mtime_ns=info.st_mtime_ns,
                ctime_ns=info.st_ctime_ns)


def _snapshot(path):
    path = fs.safe(path)
    if os.name == 'nt':
        return windows_native.snapshot_cleanup_file(path, max_bytes=investigations.MAX_DOCUMENT, timeout_seconds=15)
    before = _identity(path.lstat(), directory=False)
    _, observed = input_files.read(path, investigations.MAX_DOCUMENT)
    if before != _identity(path.lstat(), directory=False) or observed['bytes'] != before['bytes']:
        raise InputError('report file changed during review')
    return dict(identity=before, sha256=observed['sha256'])


def _remove_file(path, expected, *, admit):
    if os.name == 'nt':
        def confirm(observed):
            if observed != expected:
                raise InputError('report file changed since approval')
            admit()

        windows_native.snapshot_cleanup_file(fs.safe(path), max_bytes=investigations.MAX_DOCUMENT,
                                            timeout_seconds=15, before_remove=confirm)
    else:
        if _snapshot(path) != expected:
            raise InputError('report file changed since approval')
        admit()
        path.unlink()


def _layout(latest):
    if type(latest) is not int or not 1 <= latest <= 1000:
        raise InputError('invalid retained report revision')
    revisions = [f'revisions/{revision:06}' for revision in range(1, latest+1)]
    directories = ['.', 'revisions', *revisions]
    files = ['head.json', *(f'{revision}/{name}' for revision in revisions
                           for name in ('receipt.json', 'report.json', 'report.md'))]
    return directories, files


def _members(root, latest, *, partial=False):
    """Observe the exact closed tree, or its remaining subset in custody."""
    dirs, files = _layout(latest)
    expected = defaultdict(set)
    for item in dirs[1:] + files:
        relative = Path(item)
        expected[relative.parent.as_posix()].add(relative.name)
    seen_dirs = {}
    seen_files = {}
    remaining = _MAX_HISTORY_BYTES
    for member in dirs:
        directory = fs.safe(root / member)
        try:
            seen_dirs[member] = _identity(directory.lstat(), directory=True)
        except FileNotFoundError:
            if partial:
                continue
            raise
        with os.scandir(directory) as rows:
            children = set()
            allowed = expected[member]
            for row in rows:
                if row.name not in allowed:
                    raise InputError('report directory contains unreviewed files or an active writer')
                children.add(row.name)
            if not partial and children != allowed:
                raise InputError('committed report history is incomplete')
    for member in files:
        try:
            sample = _snapshot(root / member)
        except FileNotFoundError:
            if partial:
                continue
            raise
        remaining -= sample['identity']['bytes']
        if remaining < 0:
            raise InputError('report history exceeds the cleanup verification byte bound')
        seen_files[member] = sample
    return seen_dirs, seen_files


def _selected(state, identifier, *, use_policy):
    root = _location(state, identifier)
    if fs.safe(root / 'write.lock').exists():
        raise InputError('investigation writer is active or interrupted')
    head = fs.read(root / 'head.json', 8192)
    directories, files = _members(root, head['revision'])
    references = set()
    revisions = investigations._revision_chain(state, identifier, head, None)
    current = next(revisions)
    for revision in chain((current,), revisions):
        references.update((item['kind'], item['target_id']) for item in revision['attachments'])
    if fs.read(root / 'head.json', 8192) != head:
        raise InputError('investigation revision changed during review')
    policy = None
    if use_policy:
        policy, eligible = retention_policy.eligibility(state, current['created_at'], category=_CATEGORY)
        if not eligible:
            return None, policy
    plan = dict(schema_version=1, kind=_KIND, investigation_id=identifier, path=str(root), head=head,
                directories=directories, files=files, attached_products=[dict(kind=kind, id=target)
                    for kind, target in sorted(references)], operation_references=_related_operations(state, identifier), policy=policy)
    _validate(plan)
    return plan, policy


def _validate(plan):
    if (type(plan) is not dict or set(plan) != _FIELDS or type(plan['schema_version']) is not int
            or plan['schema_version'] != 1 or plan['kind'] != _KIND or type(plan['head']) is not dict
            or type(plan['directories']) is not dict or type(plan['files']) is not dict):
        raise InputError('invalid investigation report cleanup plan')
    directories, files = _layout(plan['head']['revision'])
    if set(plan['directories']) != set(directories) or set(plan['files']) != set(files):
        raise InputError('cleanup plan does not identify the whole committed report history')
    if len(fs.encode(plan)) > MAX_PLAN_BYTES:
        raise InputError('report history cleanup plan exceeds its review limit')


def _bytes(plan):
    return sum(file['identity']['bytes'] for file in plan['files'].values())


def _sealed(path, limit, *, read=fs.read):
    value = read(path, limit)
    entry = value.get('record') if type(value) is dict else None
    if type(entry) is not dict or value.get('sha256') != fs.digest(entry) or entry.get('schema_version') != 1:
        raise InputError('report cleanup receipt integrity mismatch')
    return entry


def _seal(path, value):
    fs.write(path, dict(record=value, sha256=fs.digest(value)))


def _progress(folder, custody, plan, *, read):
    try:
        progress = _sealed(folder / 'progress.json', 8192, read=read)
    except FileNotFoundError:
        return None
    completed = progress.get('completed')
    in_flight = progress.get('in_flight')
    total = len(plan['files'])
    if (progress.get('custody_sha256') != fs.digest(custody) or type(completed) is not int
            or not 0 <= completed <= total or type(in_flight) is not bool or (in_flight and completed == total)):
        raise InputError('report cleanup progress receipt mismatch')
    return progress


def _history(state, identifier, *, read=fs.read):
    folder = registry(state, identifier)
    try:
        intent = _sealed(folder / 'intent.json', MAX_PLAN_BYTES + 8192, read=read)
    except FileNotFoundError:
        if any(fs.safe(folder / name).exists() for name in ('payload', 'custody.json', 'progress.json', 'empty.json', 'receipt.json')):
            raise InputError('report cleanup has saved effects without an intent')
        return None, None, None, None, None
    plan = intent['plan']
    _validate(plan)
    if (intent.get('plan_sha256') != fs.digest(plan) or plan['investigation_id'] != identifier
            or plan['path'] != str(_location(state, identifier))):
        raise InputError('report cleanup intent identity mismatch')
    try:
        custody = _sealed(folder / 'custody.json', 8192, read=read)
    except FileNotFoundError:
        if any(fs.safe(folder / name).exists() for name in ('progress.json', 'empty.json', 'receipt.json')):
            raise InputError('report cleanup has a completion receipt without custody')
        return intent, None, None, None, None
    if custody.get('intent_sha256') != fs.digest(intent) or custody.get('directory') != plan['directories']['.']:
        raise InputError('report cleanup custody receipt mismatch')
    try:
        emptied = _sealed(folder / 'empty.json', 8192, read=read)
    except FileNotFoundError:
        if fs.safe(folder / 'receipt.json').exists():
            raise InputError('report cleanup completion lacks a verified empty payload')
        return intent, custody, _progress(folder, custody, plan, read=read), None, None
    progress = _progress(folder, custody, plan, read=read)
    if (emptied.get('custody_sha256') != fs.digest(custody) or progress is None
            or progress['completed'] != len(plan['files']) or emptied.get('progress_sha256') != fs.digest(progress)):
        raise InputError('report cleanup empty payload receipt mismatch')
    try:
        done = _sealed(folder / 'receipt.json', 8192, read=read)
    except FileNotFoundError:
        return intent, custody, progress, emptied, None
    if (done.get('empty_sha256') != fs.digest(emptied) or done.get('logical_bytes_removed') != _bytes(plan)
            or fs.safe(folder / 'payload').exists()):
        raise InputError('report cleanup completion receipt mismatch')
    return intent, custody, progress, emptied, done


def status(state, identifier, *, read=fs.read):
    intent, custody, _, emptied, done = _history(state, identifier, read=read)
    if intent is None:
        return None
    plan = intent['plan']
    row = dict(schema_version=1, investigation_id=identifier, head_revision=plan['head']['revision'],
               plan_sha256=intent['plan_sha256'], status='removed' if done else 'cleanup_pending',
               phase='completed' if done else 'payload_verified_empty' if emptied else 'quarantined' if custody else 'admitted',
               path_reoccupied=bool(done and _location(state, identifier).exists()),
               logical_bytes_removed=done['logical_bytes_removed'] if done else None,
               affected_report_files=len(plan['files']), attached_products=plan['attached_products'],
               operation_references=plan['operation_references'])
    if done:
        row['removed_at'] = done['removed_at']
    return row


def require_available(state, identifier):
    row = status(state, identifier)
    if row is not None:
        raise InputError('investigation reports were removed' if row['status'] == 'removed'
                         else 'investigation report cleanup is pending; inspect its receipt')


def preview(state, identifier, *, use_policy=False):
    old = status(state, identifier)
    if old is not None:
        return old
    plan, policy = _selected(state, identifier, use_policy=use_policy)
    if plan is None:
        return dict(status='retained_by_policy', investigation_id=identifier, policy=policy)
    return _review(plan)


def pending_review(state, identifier):
    """Reopen only the exact approved plan once its intent has been saved."""
    intent, _, _, _, done = _history(state, identifier)
    if intent is None or done is not None:
        return None
    return dict(_review(intent['plan']), resuming=True)


def _review(plan):
    return dict(status='ready', plan=plan, plan_sha256=fs.digest(plan), logical_bytes=_bytes(plan),
                effects=dict(report_revisions=plan['head']['revision'], report_history_available_after=False,
                             attached_product_removal=False, harness_history_removal=False))


def _dispose_members(folder, payload, plan, custody, progress):
    revision = plan['head']['revision']
    remaining_dirs, remaining_files = _members(payload, revision, partial=True)
    if (remaining_dirs.get('.') != custody['directory']
            or any(plan['directories'][path] != value for path, value in remaining_dirs.items())
            or any(plan['files'][path] != value for path, value in remaining_files.items())):
        raise InputError('report cleanup payload contains a changed member')
    _, members = _layout(revision)
    completed = progress['completed'] if progress else 0
    in_flight = progress['in_flight'] if progress else False
    for position, member in enumerate(members):
        present = member in remaining_files
        if position < completed and present:
            raise InputError('previously removed report path is occupied')
        if position >= completed and not present and not (position == completed and in_flight):
            raise InputError('unattempted report file is missing; removal cannot be verified')

    custody_sha256 = fs.digest(custody)

    def record(count, active):
        value = dict(schema_version=1, custody_sha256=custody_sha256, completed=count, in_flight=active)
        _seal(folder / 'progress.json', value)
        return value

    for position in range(completed, len(members)):
        member = members[position]
        path = fs.safe(payload / member)
        if member in remaining_files:
            _remove_file(path, remaining_files[member], admit=lambda: record(position, True))
        try:
            path.lstat()
        except FileNotFoundError:
            progress = record(position + 1, False)
        else:
            raise InputError('report cleanup did not verify file removal')
    for member in reversed(remaining_dirs):
        if member != '.':
            path = fs.safe(payload / member)
            if _identity(path.lstat(), directory=True) != remaining_dirs[member]:
                raise InputError('report cleanup payload directory was replaced')
            path.rmdir()
    return progress


def apply(state, approved, *, expected_sha256):
    _validate(approved)
    if fs.digest(approved) != expected_sha256:
        raise InputError('report cleanup plan digest changed; review the current plan')
    identifier = approved['investigation_id']
    root = _location(state, identifier)
    if approved['path'] != str(root):
        raise InputError('cleanup path is not the selected investigation')
    with writer(state, identifier, require_report=False) as folder, ExitStack() as locks:
        payload = fs.safe(folder / 'payload')
        intent, custody, progress, emptied, done = _history(state, identifier)
        if intent is not None and intent['plan_sha256'] != expected_sha256:
            raise InputError('another report cleanup is already recorded for this investigation')
        if done is not None:
            return dict(status(state, identifier), replayed=True)
        if intent is None:
            if approved['policy'] is not None:
                locks.enter_context(fs.writer(fs.safe(Path(state) / 'retention')))
            current, policy = _selected(state, identifier, use_policy=approved['policy'] is not None)
            if policy != approved['policy'] or current is None:
                raise InputError('retention policy changed or no longer selects these reports')
            if current != approved:
                raise InputError('report history or its references changed since review')
            intent = dict(schema_version=1, plan=approved, plan_sha256=expected_sha256, admitted_at=fs.stamp())
            _seal(folder / 'intent.json', intent)
        if custody is None:
            if not payload.exists():
                if _members(root, approved['head']['revision']) != (approved['directories'], approved['files']):
                    raise InputError('report history changed before quarantine')
                root.rename(payload)
            if root.exists() or _members(payload, approved['head']['revision']) != (approved['directories'], approved['files']):
                raise InputError('report cleanup custody could not be verified')
            custody = dict(schema_version=1, intent_sha256=fs.digest(intent), directory=approved['directories']['.'],
                           adopted_at=fs.stamp())
            _seal(folder / 'custody.json', custody)
        if root.exists():
            raise InputError('investigation report path is occupied during cleanup')
        if emptied is None:
            if not payload.exists():
                raise InputError('report cleanup custody payload is missing; removal cannot be verified')
            progress = _dispose_members(folder, payload, approved, custody, progress)
            if (_identity(fs.safe(payload).lstat(), directory=True) != custody['directory']
                    or next(payload.iterdir(), None) is not None):
                raise InputError('report cleanup payload is not verified empty')
            emptied = dict(schema_version=1, custody_sha256=fs.digest(custody), progress_sha256=fs.digest(progress),
                           verified_at=fs.stamp())
            _seal(folder / 'empty.json', emptied)
        if payload.exists():
            if _identity(fs.safe(payload).lstat(), directory=True) != custody['directory']:
                raise InputError('report cleanup empty payload directory was replaced')
            payload.rmdir()
        if root.exists() or payload.exists():
            raise InputError('report cleanup outcome is unverified')
        _seal(folder / 'receipt.json', dict(schema_version=1, empty_sha256=fs.digest(emptied),
                                           logical_bytes_removed=_bytes(approved), removed_at=fs.stamp()))
        return dict(status(state, identifier), replayed=False)
