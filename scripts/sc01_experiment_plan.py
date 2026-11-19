"""Prepare and verify independent SC-01 workspaces from selected file captures."""

import argparse
import hashlib
from itertools import permutations
import json
from pathlib import Path
import random
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import sc01_trial
from scripts.sc01_experiment_report import METHODS, REPEATS, SERIES
from src.techexpert import operation_state as fs
from src.techexpert.inputs import InputError, read_snapshot


MIN_FREE_BYTES = 10 * 1024**3
REFERENCE = 'input-trial'
PREPARED_STATE = 'prepared-state'
TASK = 'Фоновая загрузка заказов выполняется дольше ожидаемого.'
METHOD_PROFILES = dict(cli=None, direct_mcp='direct', code_mode='program')


def _schedule(seed):
    if type(seed) is not int or not 0 <= seed < 2**64:
        raise InputError('seed must be an unsigned 64-bit integer')
    rng = random.Random(seed)
    rows = []
    for series in SERIES:
        orders = rng.sample(list(permutations(METHODS)), REPEATS)
        for repeat, order in enumerate(orders, 1):
            for position, method in enumerate(order, 1):
                leaf = f'{series}-{repeat:02d}-{method}'
                rows.append(dict(case='SC-01', series=series, repeat=repeat, position=position,
                                 method=method, trial='attempts/' + leaf))
    return rows


def _tool_commands():
    base = [sys.executable, '-E', '-s', '-B', '-X', 'utf8', 'techexpert.py', '--state-dir', 'state']
    return {method: base + (['mcp-stdio', '--profile', profile] if profile else [])
            for method, profile in METHOD_PROFILES.items()}


def _reserve(path, needed=0):
    existing = next(item for item in (path, *path.parents) if item.exists())
    if shutil.disk_usage(existing).free - needed < MIN_FREE_BYTES:
        raise InputError('insufficient space for the independent attempts and the 10 GiB free-space floor')


def _member_bytes(root, members):
    return sum(sc01_trial._relative(root, name).stat().st_size for name in members)


def _copy_members(root, destination, members):
    fs.private(destination)
    for name, expected in members.items():
        data = read_snapshot(sc01_trial._relative(root, name), sc01_trial.MAX_MEMBER_BYTES)
        if hashlib.sha256(data).hexdigest() != expected:
            raise InputError('experiment seed member changed during copy')
        target = sc01_trial._relative(destination, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)


def _prepare_state(workspace, state, request):
    """Build once through the trusted participant bundle and its knowledge projection."""
    fs.private(state)
    cli = [sys.executable, '-E', '-s', '-B', '-X', 'utf8', str(workspace / 'techexpert.py'),
           '--state-dir', str(state)]

    def run(name, *args):
        result = subprocess.run(cli + [name, *map(str, args)], cwd=workspace,
                                capture_output=True, timeout=45)
        if result.returncode:
            raise InputError('cannot prepare the starting state with ' + name)
        return json.loads(result.stdout)

    cases = fs.read(workspace / 'intake.json', 64 * 1024)['cases']
    attachments = []
    for number, name in enumerate(cases, 1):
        manifest = sc01_trial._relative(workspace, name)
        saved = run('analyze', manifest)
        if any(item['availability'] != 'captured' for item in saved['source_acquisition']):
            raise InputError('prepared source evidence is incomplete')
        attachments.append(dict(id=f'A-{number}', kind='case', target_id=saved['case_id']))
    fs.write(request, dict(task=TASK))
    context = run('investigation-create', request, '--handle')
    fs.write(request, dict(attachments=attachments))
    saved = run('investigation-update', context['investigation_id'], request,
                '--expected-revision', context['revision'])
    return dict(investigation_id=saved['investigation_id'], revision=saved['revision'])


def prepare(output, before, after, *, seed):
    output = fs.safe(output)
    if output == ROOT or output.is_relative_to(ROOT):
        raise InputError('keep the private experiment outside the source bundle')
    schedule = _schedule(seed)
    _reserve(output)
    output.mkdir(parents=True, exist_ok=False)
    fs.private(output)
    with fs.writer(output):
        reference = output / REFERENCE
        trial = sc01_trial.prepare(ROOT, reference, before, after)
        prepared = output / PREPARED_STATE
        context = _prepare_state(reference / 'diagnosis', prepared, output / 'bootstrap.json')
        snapshot = sc01_trial.inventory(prepared)
        cold_bytes = (_member_bytes(reference / 'diagnosis', trial['diagnosis_inventory'])
                      + _member_bytes(reference / 'private-inputs', trial['private_inventory'])
                      + len(fs.encode(trial)) + 1024)
        warm_bytes = _member_bytes(prepared, snapshot)
        _reserve(output, cold_bytes * len(schedule) + warm_bytes * (len(schedule) // len(SERIES)))
        trial_sha = fs.digest(trial)
        for slot in schedule:
            warm = slot['series'] == 'prepared_start'
            _reserve(output, cold_bytes + (warm_bytes if warm else 0))
            attempt = fs.private(sc01_trial._relative(output, slot['trial']))
            workspace = attempt / 'diagnosis'
            _copy_members(reference / 'diagnosis', workspace, trial['diagnosis_inventory'])
            _copy_members(reference / 'private-inputs', attempt / 'private-inputs', trial['private_inventory'])
            if warm:
                _copy_members(prepared, workspace / 'state', snapshot)
            fs.write(attempt / 'preparation.json', trial)
            fs.write(attempt / 'preparation-receipt.json', dict(sha256=trial_sha))
            fs.write(attempt / 'head.json', dict(stage='prepared'))

        plan = dict(schema_version=1, case='SC-01', seed=seed, status='prepared_unlaunched',
                    product_version=trial['product_version'], source_bundle_manifest_sha256=trial['source_bundle_manifest_sha256'],
                    trial_preparation_sha256=trial_sha, prepared_state=dict(context, inventory_sha256=fs.digest(snapshot)),
                    tool_argv=_tool_commands(), tool_workdir='diagnosis', schedule=schedule)
        fs.write(output / 'schedule.json', plan)
        fs.write(output / 'schedule-receipt.json', dict(sha256=fs.digest(plan)))
    return check(output)


def _verify_start(attempt, expected_trial, expected_state):
    workspace = attempt / 'diagnosis'
    if sc01_trial._head(attempt) != 'prepared' or any(
            (workspace / name).exists() for name in ('answer.json', 'transcript.jsonl', 'verification')):
        raise InputError('attempt has left its initial state')
    if fs.digest(sc01_trial.verify_prepared(attempt)) != expected_trial:
        raise InputError('attempt input snapshot disagrees with the schedule')
    state = workspace / 'state'
    if expected_state is None:
        if state.exists():
            raise InputError('first-start attempt must have an empty initial state')
    elif not state.is_dir() or fs.digest(sc01_trial.inventory(state)) != expected_state:
        raise InputError('prepared-start initial state disagrees with the schedule')


def check(output):
    output = fs.safe(output)
    plan = fs.read(output / 'schedule.json', 128 * 1024)
    sealed = fs.read(output / 'schedule-receipt.json', 8192)
    if (sealed != dict(sha256=fs.digest(plan)) or plan['schema_version'] != 1
            or plan['status'] != 'prepared_unlaunched' or plan['schedule'] != _schedule(plan['seed'])):
        raise InputError('experiment schedule integrity mismatch')
    reference = output / REFERENCE
    expected_trial = plan['trial_preparation_sha256']
    _verify_start(reference, expected_trial, None)
    expected_state = plan['prepared_state']['inventory_sha256']
    if fs.digest(sc01_trial.inventory(output / PREPARED_STATE)) != expected_state:
        raise InputError('prepared-state seed integrity mismatch')
    for slot in plan['schedule']:
        attempt = sc01_trial._relative(output, slot['trial'])
        _verify_start(attempt, expected_trial, expected_state if slot['series'] == 'prepared_start' else None)
    return dict(status=plan['status'], schedule=str(output / 'schedule.json'),
                verified_attempts=len(plan['schedule']), product_version=plan['product_version'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('prepare', help='create both sealed starting states and 30 independent attempts')
    build.add_argument('--before', nargs='+', type=Path, required=True)
    build.add_argument('--after', nargs='+', type=Path, required=True)
    build.add_argument('--seed', type=int, required=True)
    verify = commands.add_parser('check', help='verify all initial attempt workspaces before a series')
    for command in (build, verify):
        command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = (prepare(args.output, args.before, args.after, seed=args.seed) if args.command == 'prepare'
                  else check(args.output))
    except (OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.TimeoutExpired) as error:
        print(json.dumps(dict(status='error', error=str(error)[:512]), ensure_ascii=True))
        return 2
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
