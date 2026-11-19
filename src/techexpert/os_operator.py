"""One reviewed local OS capture on an operator's node with offline return."""
from hashlib import sha256
import io
import math
import os
from pathlib import Path
import platform
import re
import socket
import tempfile

from . import __version__, artifacts, capabilities as cap, investigations, kernel
from . import operation_state as fs, os_observation, os_storage, profiles
from .inputs import InputError, json_value, read_snapshot
from .os_metrics import PROBE, validate_request
from .readiness import canonical


ROOT = os_observation.OPERATOR_ROOT
KIND = 'os-operator-v1'
SOURCE = 'operator'
BASE = 'selected-base'
TASK = 'One local collection of operating-system metrics'
METRICS = ('cpu', 'memory', 'disk', 'network')
LIMITS = ('duration_seconds', 'interval_seconds', 'max_bytes')
SHA256 = re.compile('[a-f0-9]{64}')


def _hostname(value, target_platform):
    return value.casefold() if target_platform == 'windows' else value


def _ticket(value):
    schema = cap.obj(dict(
        schema_version=dict(type='integer', minimum=1, maximum=1),
        target=cap.obj(dict(platform=cap.string(7, enum=['windows', 'linux']),
                            hostname=cap.string(253, pattern=r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}')),
                       ('platform', 'hostname')),
        window=cap.obj(dict(start=cap.string(64), end=cap.string(64)), ('start', 'end')),
        collection=cap.obj(dict(role=cap.string(16), duration_seconds=dict(type='number'),
                                interval_seconds=dict(type='number'),
                                max_bytes=dict(type='integer', minimum=16384, maximum=8*1024**2),
                                file_base=cap.string(2000)), ('role',))),
        ('schema_version', 'target', 'window', 'collection'))
    request = cap.validate(value, schema)
    target = request['target']
    target['hostname'] = _hostname(target['hostname'], target['platform'])
    start, end = (os_observation._date(request['window'][key]) for key in ('start', 'end'))
    window_seconds = (end-start).total_seconds()
    chosen = request['collection']
    file_base = chosen.pop('file_base', None)
    checked = validate_request(chosen)
    collection = {key: checked[key] for key in ('role', *LIMITS)}
    if not math.ceil(collection['duration_seconds']) <= window_seconds <= 7*86400:
        raise InputError('operator collection window must fit the sampling duration and be at most seven days')
    reader = dict(product_version=__version__, probe_sha256=sha256(canonical(PROBE.read_bytes())).hexdigest())
    if file_base is not None:
        if collection['role'] not in ('onec', 'storage'):
            raise InputError('file-base storage requires role onec or storage')
        collection['file_base'] = os_storage.local_path(file_base, platform=target['platform'])
        reader['storage_reader_sha256'] = sha256(canonical(Path(os_storage.__file__).read_bytes())).hexdigest()
    return dict(kind=KIND, schema_version=1, target=target, window=dict(start=start.isoformat(), end=end.isoformat()),
                collection=collection, reader=reader, metrics=list(METRICS), max_runs=1)


def _identity(digest):
    key = 'os-operator-' + digest
    return key, sha256(key.encode('ascii')).hexdigest()


def _check_digest(expected, actual):
    if not isinstance(expected, str) or not SHA256.fullmatch(expected) or expected != actual:
        raise InputError('operator plan does not match the reviewed plan digest')


def _write_ticket(path, document):
    path = fs.safe(path)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), 0o600)
    except FileExistsError:
        if fs.read(path, 8192) != document:
            raise InputError('operator plan output already exists with different content')
        return
    with os.fdopen(fd, 'wb') as stream:
        stream.write(fs.encode(document))
        stream.flush()
        os.fsync(stream.fileno())


def prepare(request, *, output=None, expected_sha256=None):
    ticket = _ticket(request)
    digest = fs.digest(ticket)
    document = dict(ticket=ticket, ticket_sha256=digest)
    if output is not None or expected_sha256 is not None:
        _check_digest(expected_sha256, digest)
    if output is not None:
        _write_ticket(output, document)
    return dict(document, status='plan_saved' if output is not None else 'planned_not_started',
                run_id=_identity(digest)[1], operator_state_suffix=f'{ROOT}/{digest}',
                plan_path=str(Path(output).absolute()) if output is not None else None)


def _read_ticket(path, expected):
    document = fs.read(path, 8192)
    ticket = document['ticket']
    digest = fs.digest(ticket)
    _check_digest(expected, digest)
    if document != dict(ticket=ticket, ticket_sha256=digest):
        raise InputError('invalid operator plan envelope')
    request = {key: ticket[key] for key in ('schema_version', 'target', 'window', 'collection')}
    if _ticket(request) != ticket:
        raise InputError('operator plan needs the reviewed plan format and collector build')
    target = ticket['target']
    actual_platform = platform.system().lower()
    if target != dict(platform=actual_platform, hostname=_hostname(socket.gethostname(), actual_platform)):
        raise InputError('operator plan does not match this target node and platform')
    return ticket


def _window(ticket):
    return tuple(os_observation._date(ticket['window'][key]) for key in ('start', 'end'))


def _require_window(ticket):
    start, end = _window(ticket)
    if not os_observation._fits(dict(ticket['collection'], transport='local'), start, end, os_observation.now()):
        raise InputError('requested run does not fit the approved operator collection window')


def _approved_request(state, ticket, digest):
    chosen = ticket['collection']
    settings = {key: value for key, value in chosen.items() if key != 'file_base'}
    connection = chosen.get('file_base', '')
    profile = profiles.validate_profile(dict(schema_version=1, name='Local operator collection',
        bases=[dict(id=BASE, name='Selected local scope', mode='file' if connection else 'unknown', connection=connection)],
        sources=[dict(id=SOURCE, type='os', host='', path='', base_ids=[BASE], settings=dict(settings, transport='local'))]))
    current = profiles.load_profile(state)
    if current is None:
        current = profiles.save_profile(state, profile, expected_revision=0)
    if current != dict(profile, revision=1):
        raise InputError('operator profile changed; original collection state retained')

    identifier = digest[:32]
    try:
        doc = investigations.read_for_display(state, identifier)
    except FileNotFoundError:
        # Create only in an unused slot. A damaged saved revision stays in place.
        if investigations.revision_folder(state, identifier, 1).parent.parent.exists():
            raise
        doc = investigations._create(state, dict(task=TASK), identifier=identifier)
    start, end = _window(ticket)
    plan = dict(ticket['window'], status='configured_reported', collection_state='not_started',
                operations=[TASK], sources=[SOURCE], metrics=list(METRICS), duration_seconds=(end-start).total_seconds(),
                max_bytes=chosen['max_bytes'], responsible='operator', rollback='cancel the owned operation',
                verification='return the retained measurements with their SHA-256')
    if doc['task'] != TASK or doc['profile_snapshot'] != current:
        raise InputError('operator investigation changed; original collection state retained')
    if doc['revision'] == 1:
        doc = investigations.revise(state, identifier, dict(observation_plan=plan), expected_revision=1)
    if doc['revision'] != 2 or doc['observation_plan'] != plan:
        raise InputError('operator observation changed; original collection state retained')

    context = dict(investigation_id=identifier, expected_revision=2)
    selection = dict(context=context, base_id=BASE, source_ids=[SOURCE], max_runs=1,
                     max_seconds=math.ceil(chosen['duration_seconds']), max_bytes=chosen['max_bytes'],
                     map_file_storage=bool(connection))
    preview = os_observation.control(state, dict(selection, mode='preview'))['data']
    if connection and preview['targets'][0].get('storage_selection') != 'profile_file_path':
        raise InputError('configured file-base storage could not be selected for the operator plan')
    return selection, preview['proposal_sha256']


def _request(digest, approval):
    chosen_key, _ = _identity(digest)
    return dict(schema_version=1, operation_key=chosen_key, executor_id=SOURCE, operation='os.collect',
                context=dict(investigation_id=digest[:32], expected_revision=2), arguments={},
                observation=dict(approval_sha256=approval, source_id=SOURCE))


def _run_request(state, ticket, digest, run_id):
    path = state / 'run-request.json'
    try:
        previous = fs.read(path, 8192)
    except FileNotFoundError:
        previous = None
    # Replay only the exact saved request, even after the approved window ends.
    if fs.folder(state, run_id).exists():
        if previous is None:
            raise InputError('original operator request is unavailable; saved run retained')
        approval = previous['observation']['approval_sha256']
        if not isinstance(approval, str) or not SHA256.fullmatch(approval) or previous != _request(digest, approval):
            raise InputError('saved operator request does not match the reviewed plan')
        return previous

    _require_window(ticket)
    selection, proposal = _approved_request(state, ticket, digest)
    request = _request(digest, proposal)
    if previous is not None and previous != request:
        raise InputError('saved operator request or execution domain changed')
    saved = os_observation.control(state, dict(selection, mode='approve', proposal_sha256=proposal))['data']
    if saved['stage'] != 'approved' or saved['approval_sha256'] != proposal:
        raise InputError('original operator approval is unavailable; saved state retained')
    if previous is None:
        fs.write(path, request)
    return request


def _verify_return_file(path, raw):
    try:
        retained = read_snapshot(fs.safe(path), len(raw), share_delete=True)
    except InputError as exc:
        raise InputError('saved measurement bytes do not match the sealed collection') from exc
    if retained != raw:
        raise InputError('saved measurement bytes do not match the sealed collection')


def _return_file(path, raw):
    try:
        _verify_return_file(path, raw)
        return
    except FileNotFoundError:
        pass

    fd, staging = tempfile.mkstemp(prefix='measurements-', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(staging, path, follow_symlinks=False)
        except FileExistsError:
            _verify_return_file(path, raw)
    finally:
        Path(staging).unlink(missing_ok=True)


def _measurements(state, ticket, response):
    artifact_id = response['data']['artifact_id']
    report = artifacts.load_artifact(state, artifact_id)
    if report['kind'] != 'os_metrics' or len(report['sources']) != 1:
        raise InputError('saved result is not the expected OS measurement artifact')
    source = report['sources'][0]
    observed = report['result']
    target = ticket['target']
    plan = {key: ticket['collection'][key] for key in LIMITS}
    start, end = _window(ticket)
    if (observed['role'] != ticket['collection']['role'] or observed['plan'] != plan
            or observed['scope'] != os_storage.PLATFORMS[target['platform']]
            or _hostname(observed['observed_hostname'], target['platform']) != target['hostname']
            or not start <= os_observation._date(observed['started_at']) <= os_observation._date(observed['finished_at']) <= end):
        raise InputError('saved OS measurements are outside the reviewed operator scope')
    artifact_file = artifacts.source_path(artifacts.artifact_folder(state, artifact_id), source, kind='os_metrics')
    raw = read_snapshot(fs.safe(artifact_file), plan['max_bytes'], share_delete=True)
    if len(raw) != source['bytes'] or sha256(raw).hexdigest() != source['sha256']:
        raise InputError('saved OS measurement source changed')
    destination = state / 'measurements.json'
    _return_file(destination, raw)
    return dict(path=str(destination), sha256=source['sha256'], bytes=source['bytes'], artifact_id=artifact_id,
                collection_status=observed['collection_status'], coverage_status=observed['coverage_status'],
                observed_samples=observed['observed_samples'], scope=observed['scope'],
                started_at=observed['started_at'], finished_at=observed['finished_at'])


def run(state, path, *, expected_sha256):
    ticket = _read_ticket(path, expected_sha256)
    _, run_id = _identity(expected_sha256)
    stage = fs.safe(Path(state) / ROOT / expected_sha256)
    if not fs.folder(stage, run_id).exists():
        _require_window(ticket)
    kernel._space(stage)
    fs.private(stage.parent)
    fs.private(stage)
    with fs.writer(stage):
        request = _run_request(stage, ticket, expected_sha256, run_id)
        call = kernel.invoke(stage, 'run', dict(request='run-request.json'), request_document=request)
        output = io.StringIO()
        kernel.emit(call, output)
        response = json_value(output.getvalue(), reject_duplicates=True)
        measurements = None
        if response.get('integrity_verified') and response.get('data') and response['status'] in ('succeeded','partial','cancelled'):
            reservation = response['observation_reservation']
            if (response['run_id'] != run_id or reservation['run_id'] != run_id
                    or any(reservation[key] != value for key, value in request['observation'].items())):
                raise InputError('saved operation does not match the operator reservation')
            measurements = _measurements(stage, ticket, response)
        return dict(status=response['status'], run_id=run_id, ticket_sha256=expected_sha256,
                    operator_state_dir=str(stage), kernel_call_id=call['call_id'],
                    replayed=response.get('replayed', False), stop_verified=response.get('stop_verified', False),
                    stop_reason=response.get('stop_reason'), message=response.get('message'), measurements=measurements,
                    exit_code=call['exit_code'])
