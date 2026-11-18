"""Bounded observations of saved formats and local operation completion."""
import os
from pathlib import Path
import re
import stat

from . import operation_state as fs, operations
from .inputs import InputError, json_value, read_snapshot


FORMATS = dict(profiles=[1,2], cases=[1], artifacts=[1,2], comparisons=[1],
    investigations=[1,2], **{'custom-templates':[1], 'operations':[1], 'kernel-calls':[1]})
STATE_CONTRACT = dict(schema_version=1, family='techexpert-local-state', schemas=FORMATS)
_ID = re.compile(r'[a-f0-9]{32}')
_RUN = re.compile(r'[a-f0-9]{64}')
_REVISION = re.compile(r'[0-9]{6}')
_TEMPLATE = re.compile(r'USR-[a-z0-9][a-z0-9-]{0,47}')
_ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError)


def supports(metadata, observed):
    contract = metadata['state_contract']
    if contract is None and metadata['version'] in ('0.34.0','0.35.0'):
        contract = STATE_CONTRACT
    if (type(contract) is not dict or set(contract) != set(STATE_CONTRACT)
        or type(contract['schema_version']) is not int or contract['schema_version'] != 1
        or contract['family'] != STATE_CONTRACT['family'] or type(contract['schemas']) is not dict):
        return False
    declared = contract['schemas']
    if set(declared) != set(FORMATS) or type(metadata['knowledge_schema']) is not int or metadata['knowledge_schema'] not in (1,2):
        return False
    for name, versions in declared.items():
        if (type(versions) is not list or not versions or any(type(item) is not int or item not in FORMATS[name] for item in versions)
            or not set(observed[name]) <= set(versions)):
            return False
    return True


def _exists(path):
    try:
        fs.safe(path).lstat()
    except FileNotFoundError:
        return False
    return True


def inspect_state(state):
    """Inspect saved metadata and markers. Operation originals are never opened."""
    state = fs.safe(state)
    schemas = {name:set() for name in FORMATS}
    problems = []
    remaining_bytes = 64*1024**2
    remaining_entries = 8192

    def children(path, *, optional=True):
        nonlocal remaining_entries
        try:
            stream = os.scandir(fs.safe(path))
        except FileNotFoundError:
            if optional:
                return []
            raise
        with stream:
            found = []
            for item in stream:
                remaining_entries -= 1
                if remaining_entries < 0:
                    raise InputError('bounded state inventory exhausted')
                info = item.stat(follow_symlinks=False)
                if getattr(info,'st_file_attributes',0)&0x400 or not (
                        stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    raise InputError('linked or special saved resource')
                found.append(Path(item.path))
        return sorted(found)

    def document(path):
        nonlocal remaining_bytes
        data = read_snapshot(fs.safe(path),min(remaining_bytes,16*1024**2),share_delete=True)
        remaining_bytes -= len(data)
        value = json_value(data.decode('utf-8'),reject_duplicates=True)
        if type(value) is not dict:
            raise InputError('saved metadata must be an object')
        return value

    def schema(kind, value):
        version = value.get('schema_version')
        if type(version) is not int or not 1<=version<=2**31-1:
            raise InputError('missing saved state schema')
        schemas[kind].add(version)

    def pending(kind, folder, current):
        owners = (current.get('owner'), current.get('child'))
        live = any(fs.inspect_process(info)['state']=='running' for info in owners if type(info) is dict)
        problems.append(dict(kind=kind, id=folder.name, status='active' if live else 'stop_unverified'))

    def managed(root, kind, pattern):
        for folder in children(root):
            if not pattern.fullmatch(folder.name):
                raise InputError('unexpected managed operation entry')
            try:
                current = document(folder/'status.json')
                schema(kind,current)
                if kind=='operations':
                    if current.get('run_id')!=folder.name:
                        raise InputError('operation status identity mismatch')
                    plan = document(folder/'plan.json')
                    schema(kind,plan)
                    fs.checked_plan(folder,plan,document(folder/'plan-receipt.json'))
                    output = _exists(folder/'output.json')
                    receipt = _exists(folder/'output-receipt.json')
                    status = current.get('status')
                    if (status not in operations.TERMINAL or current.get('stop_verified') is not True or output!=receipt
                        or status in ('succeeded','partial') and not output):
                        pending(kind,folder,current)
                else:
                    if current.get('call_id')!=folder.name:
                        raise InputError('kernel status identity mismatch')
                    plan = document(folder/'plan.json')
                    schema(kind,plan)
                    if current.get('status')!='finished':
                        pending(kind,folder,current)
                        continue
                    claim = document(folder/'call-receipt.json')
                    value = claim.get('value')
                    digest = fs.digest(plan)
                    if (document(folder/'plan-receipt.json').get('sha256')!=digest
                        or type(claim.get('schema_version')) is not int or claim['schema_version']!=1
                        or type(value) is not dict or claim.get('sha256')!=fs.digest(value)
                        or value.get('call_id')!=folder.name or value.get('plan_sha256')!=digest
                        or value.get('controller',{}).get('tree_finished') is not True):
                        raise InputError('controller completion unverified')
            except _ERRORS:
                problems.append(dict(kind=kind,id=folder.name,status='state_unavailable_or_incomplete'))

    def marker(path, kind):
        if _exists(path):
            problems.append(dict(kind=kind,status='writer_or_interruption'))

    try:
        profiles = state/'profiles'
        marker(profiles/'write.lock','profiles')
        for path in children(profiles):
            if path.name=='current.json' or re.fullmatch(r'[0-9]+\.json',path.name):
                schema('profiles',document(path))

        for kind in ('cases','artifacts','comparisons','investigations','custom-templates'):
            for folder in children(state/kind):
                if kind=='custom-templates' and folder.name=='writer.lock':
                    continue
                pattern = _TEMPLATE if kind=='custom-templates' else _ID
                if not pattern.fullmatch(folder.name):
                    raise InputError('unexpected saved resource entry')
                if kind in ('investigations','custom-templates'):
                    marker(folder/'write.lock',kind)
                    revisions = children(folder/'revisions',optional=False)
                    if not revisions or any(not _REVISION.fullmatch(path.name) for path in revisions):
                        raise InputError('revision history is incomplete')
                    for path in revisions:
                        schema(kind,document(path/'report.json'))
                else:
                    schema(kind,document(folder/'report.json'))

        for folder in children(state/'source-exports'):
            marker(folder/'run.lock','source-exports')
            if _exists(folder/'started.json') and not _exists(folder/'execution.json'):
                problems.append(dict(kind='source-exports',id=folder.name,status='stop_unverified'))
        marker(state/'incident-drafts/write.lock','incident-drafts')
        for folder in children(state/'incident-drafts'):
            if _ID.fullmatch(folder.name):
                marker(folder/'write.lock','incident-drafts')
        for path in children(state/'incident-private'):
            if path.suffix=='.lock':
                marker(path,'incident-private')
        managed(state/'operations','operations',_RUN)
        managed(state/'kernel-calls','kernel-calls',_ID)
    except _ERRORS:
        problems.append(dict(kind='saved_state',status='state_unavailable_or_incomplete'))
    return dict(activity='active' if any(item['status']=='active' for item in problems)
        else 'unresolved' if problems else 'idle_observed', schemata={name:sorted(values) for name,values in schemas.items()},
        problem_count=len(problems), problems=problems[:32],
        metadata_complete=not any(item['status']=='state_unavailable_or_incomplete' for item in problems),
        managed_activity_only=True, admission_locked=False)
