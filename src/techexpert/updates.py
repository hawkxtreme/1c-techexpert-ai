"""Offline release assessment, retained staging and local marketplace selection."""
from importlib.util import MAGIC_NUMBER, source_hash
import marshal
import os
from pathlib import Path
import re
import shutil
import struct
import sys

from . import input_files, operation_state as fs
from .inputs import InputError
from .knowledge import load_library
from .release_packages import (PLUGIN, LIMITS, compare_packages, installed_inventory, read_package)
from .storage import ROOT
from .update_state import inspect_state, supports


MARKETPLACE = '1c-techexpert-managed'
SELECTOR = PLUGIN+'@'+MARKETPLACE
MANIFEST = '.agents/plugins/marketplace.json'
FLOOR = 10*1024**3
_HASH = re.compile(r'[a-f0-9]{64}')


def _hash(value):
    if type(value) is not str or not _HASH.fullmatch(value):
        raise InputError('exact release SHA256 required')
    return value


def _root(state):
    return fs.safe(Path(state)/'updates')


def _location(state, release_id):
    return fs.safe(_root(state)/'releases'/_hash(release_id))


def _plan(state, plan, expected_sha256, kind, fields):
    if (type(plan) is not dict or set(plan)!={'schema_version','kind','state',*fields}
        or type(plan.get('schema_version')) is not int or plan['schema_version']!=1 or plan.get('kind')!=kind):
        raise InputError('invalid update plan')
    if fs.digest(plan)!=_hash(expected_sha256):
        raise InputError('update plan digest changed')
    if plan['state']!=str(fs.safe(state)):
        raise InputError('update plan belongs to another state')


def _space(path, reserve=0):
    for current in (path,*path.parents):
        try:
            current.lstat()
        except FileNotFoundError:
            continue
        if shutil.disk_usage(current).free<FLOOR+reserve:
            raise InputError('update stage retains a 10 GiB free-space floor')
        return
    raise InputError('update destination volume unavailable')


def _selection_manifest(release_id):
    entry = dict(name=PLUGIN,source=dict(source='local',path='./releases/'+release_id+'/bundle'),
        policy=dict(installation='AVAILABLE',authentication='ON_INSTALL'),category='Productivity')
    return dict(name=MARKETPLACE,interface=dict(displayName='1C TechExpert AI'),plugins=[entry])


def _selection_id(state):
    try:
        value = fs.read(_root(state)/MANIFEST,64*1024)
    except FileNotFoundError:
        return None
    try:
        path = value['plugins'][0]['source']['path']
        release_id = _hash(path.split('/')[2])
    except (KeyError, TypeError, AttributeError, IndexError):
        raise InputError('local marketplace selection is malformed') from None
    if value!=_selection_manifest(release_id):
        raise InputError('local marketplace selection was modified')
    return release_id


def _verify_bytecode(root, path, expected):
    tag = sys.implementation.cache_tag
    match = re.fullmatch(r'(.+)\.'+re.escape(tag)+r'(?:\.opt-([12]))?\.pyc',path.name) if tag else None
    if not match:
        raise InputError('unrecognized installed Python bytecode')
    source = path.parent.parent/(match[1]+'.py')
    identity = expected.get(source.relative_to(root).as_posix())
    if identity is None:
        raise InputError('installed bytecode has no checked source')
    data,_ = input_files.read(source,LIMITS['max_file_bytes'],keep=True,expected=identity)
    projected,_ = input_files.read(path,LIMITS['max_file_bytes'],keep=True)
    if len(projected)<16 or projected[:4]!=MAGIC_NUMBER:
        raise InputError('installed bytecode interpreter is unverified')
    flags = struct.unpack_from('<I',projected,4)[0]
    if flags==0:
        marker = struct.pack('<II',int(source.stat().st_mtime)&0xffffffff,len(data))
    elif flags in (1,3):
        marker = source_hash(data)
    else:
        raise InputError('unsupported installed bytecode header')
    try:
        compiled = compile(data,str(source),'exec',dont_inherit=True,optimize=int(match[2] or 0))
    except SyntaxError as exc:
        raise InputError('installed bytecode source does not compile') from exc
    if projected[8:16]!=marker or projected[16:]!=marshal.dumps(compiled):
        raise InputError('installed bytecode differs from its checked source')


def _verify_tree(root, expected, *, installed=False):
    root = fs.safe(root)
    found = set()
    inspected = 0
    parents = {path.as_posix() for name in expected for path in Path(name).parents}
    for current, directories, files in os.walk(root,followlinks=False,onerror=_raise_scan):
        parent = fs.safe(current)
        for name in [*directories,*files]:
            inspected += 1
            output = fs.safe(parent/name)
            if inspected>2048 or len(output.relative_to(root).parts)>LIMITS['max_depth']+1:
                raise InputError('staged package inventory exceeds its bound')
        for name in directories:
            if (parent/name).relative_to(root).as_posix() not in parents and not (
                installed and name=='__pycache__' and parent.relative_to(root).as_posix() in parents):
                raise InputError('staged package has an unexpected directory')
        for name in files:
            path = parent/name
            relative = path.relative_to(root).as_posix()
            if installed and path.parent.name=='__pycache__':
                _verify_bytecode(root,path,expected)
                continue
            if relative not in expected:
                raise InputError('staged package has an unexpected file')
            input_files.read(path, LIMITS['max_file_bytes'],expected=expected[relative])
            found.add(relative)
    if found!=set(expected):
        raise InputError('staged package is missing expected files')


def _raise_scan(error):
    raise error


def _staged(state, release_id):
    folder = _location(state,release_id)
    try:
        sealed = fs.read(folder/'stage.json',1024*1024)
    except FileNotFoundError:
        raise InputError('missing or incomplete stage; keep retained files and select a new reviewed package') from None
    value = sealed.get('record') if type(sealed) is dict else None
    if (type(value) is not dict or sealed.get('sha256')!=fs.digest(value) or type(value.get('schema_version')) is not int
        or value['schema_version']!=1 or type(value.get('archive')) is not dict
        or value['archive'].get('sha256')!=release_id or type(value.get('metadata')) is not dict or type(value.get('files')) is not dict
        or not 1<=len(value['files'])<=LIMITS['max_files']):
        raise InputError('staged package receipt integrity mismatch')
    try:
        archive = read_package(folder/'bundle.zip')
        if (archive['identity']!=value['archive'] or archive['hashes']!=value['files']
            or archive['metadata']!=value['metadata']):
            raise InputError('stage receipt differs from its bound package')
        _verify_tree(folder/'bundle',value['files'])
    except (OSError,ValueError) as exc:
        raise InputError('staged package failed integrity verification') from exc
    return dict(value, case_retirement_schemas=archive['case_retirement_schemas'],
                report_retirement_schemas=archive['report_retirement_schemas'],
                report_reference_schemas=archive['report_reference_schemas'],
                tj_reference_schemas=archive['tj_reference_schemas'],
                context_disclosure_schemas=archive['context_disclosure_schemas'],
                context_intake_schemas=archive['context_intake_schemas'],
                context_program_schemas=archive['context_program_schemas'])


def _supports(package, observed):
    return supports(package['metadata'], observed['schemata'],
                    case_retirement_schemas=package['case_retirement_schemas'],
                    report_retirement_schemas=package['report_retirement_schemas'],
                    report_reference_schemas=package['report_reference_schemas'],
                    tj_reference_schemas=package['tj_reference_schemas'],
                    context_disclosure_schemas=package['context_disclosure_schemas'],
                    context_intake_schemas=package['context_intake_schemas'],
                    context_program_schemas=package['context_program_schemas'])


def _presentation(state, record):
    release_id = record['archive']['sha256']
    folder = _location(state,release_id)
    return dict(release_id=release_id,bundle_root=str(folder/'bundle'),version=record['metadata']['version'],
        knowledge_revision=record['metadata']['knowledge_revision'],archive=record['archive'])


def check(state, path, *, current_root=ROOT):
    state = fs.safe(state)
    current_root = fs.safe(current_root)
    if state.is_relative_to(current_root):
        raise InputError('select private state outside the current installed bundle')
    candidate = read_package(path)
    current = installed_inventory(current_root)
    change = compare_packages(current,candidate,compare_supplemental=False)
    changes = {path for item in change['components'].values() for path in item['changed']+item['added']+item['removed']}
    activity = inspect_state(state)
    compatible = _supports(candidate, activity) if activity['metadata_complete'] else None
    static = dict(root=str(current_root), inventory_sha256=current['inventory_sha256'],
        observed_sha256=fs.digest(current['observed']))
    plan = dict(schema_version=1,kind='stage',state=str(state),package=candidate['path'],archive=candidate['identity'],
        metadata=candidate['metadata'],current=static)
    return dict(status='checked',plan=plan,plan_sha256=fs.digest(plan),current_version=current['version'],
        current_knowledge_revision=current['knowledge_revision'],candidate=candidate['metadata'],changes=change,
        local_changes=current['local_changes'],overlap=sorted(changes&set(current['local_changes'])),
        local_change_scope='declared bundle members',activity=activity,state_schema_compatible=compatible,
        publisher_verified=False,automatic_network_checks=False,actions=['Обновить','Позже','Подробнее'])


def _unpack(package, folder):
    bundle = folder/'bundle'
    bundle.mkdir()
    for name, data in package['files'].items():
        path = fs.safe(bundle/name)
        path.parent.mkdir(parents=True,exist_ok=True)
        with fs.safe(path).open('xb') as stream:
            stream.write(data)
    with (folder/'bundle.zip').open('xb') as stream:
        stream.write(package['archive'])


def stage(state, plan, *, expected_sha256):
    _plan(state,plan,expected_sha256,'stage',{'package','archive','metadata','current'})
    release_id = _hash(plan['archive']['sha256'])
    folder = _location(state,release_id)
    if folder.exists():
        return dict(status='staged',replayed=True,**_presentation(state,_staged(state,release_id)))
    package = read_package(plan['package'])
    if package['identity']!=plan['archive'] or package['metadata']!=plan['metadata']:
        raise InputError('candidate changed since the reviewed update plan')
    current = installed_inventory(plan['current']['root'])
    if (current['inventory_sha256']!=plan['current']['inventory_sha256']
        or fs.digest(current['observed'])!=plan['current']['observed_sha256']):
        raise InputError('current bundle changed since the reviewed update plan')
    if not _supports(package, inspect_state(state)):
        raise InputError('candidate does not cover the observed saved state schema')
    reserve = package['identity']['bytes']+sum(row['bytes'] for row in package['hashes'].values())
    _space(folder,reserve)
    root = fs.private(_root(state))
    with fs.writer(root):
        if folder.exists():
            return dict(status='staged',replayed=True,**_presentation(state,_staged(state,release_id)))
        fs.private(folder.parent)
        folder.mkdir()
        fs.private(folder)
        _unpack(package,folder)
        _verify_tree(folder/'bundle',package['hashes'])
        library = load_library(folder/'bundle/knowledge')
        if library['revision']!=package['metadata']['knowledge_revision']:
            raise InputError('staged knowledge library revision mismatch')
        if {'knowledge/'+name for name in library['package_members']}!=set(package['inventory']['components']['knowledge']):
            raise InputError('staged knowledge inventory differs from its index')
        value = dict(schema_version=1,archive=package['identity'],metadata=package['metadata'],
            files=package['hashes'],staging_plan_sha256=expected_sha256)
        fs.write(folder/'stage.json',dict(record=value,sha256=fs.digest(value)))
        return dict(status='staged',replayed=False,**_presentation(state,_staged(state,release_id)))


def selected(state):
    release_id = _selection_id(state)
    if release_id is None:
        return dict(status='not_selected', release_id=None)
    return dict(status='selected_for_install',installation_verified=False,
        **_presentation(state,_staged(state,release_id)))


def _ensure_safe_point(state, record, *, require_idle):
    observed = inspect_state(state)
    if not _supports(record, observed):
        raise InputError('candidate does not cover the observed saved state schema')
    if require_idle and observed['activity']!='idle_observed':
        raise InputError('await a safe point: saved activity is active or unresolved')
    return observed


def select_plan(state, release_id, *, installed_root=None):
    state = fs.safe(state)
    record = _staged(state,release_id)
    previous = _selection_id(state)
    installed = str(fs.safe(installed_root)) if installed_root is not None else None
    if previous is not None and previous!=release_id and installed is None:
        raise InputError('select the observed installed cache before changing the marketplace version')
    plan = dict(schema_version=1,kind='select',state=str(state),release_id=release_id,
        expected_selection=previous,installed_root=installed)
    observed = _ensure_safe_point(state,record,require_idle=False)
    return dict(status='needs_safe_point' if observed['activity']!='idle_observed' else 'selection_plan',
        plan=plan,plan_sha256=fs.digest(plan),current=previous,activity=observed,**_presentation(state,record))


def _check_previous(state, current, target, installed_root):
    if installed_root is None:
        raise InputError('previous installed cache was not supplied')
    # A Codex install may have been interrupted after the selection changed.
    # Either exact generation is sufficient for safe local re-selection.
    for release in (current,target):
        record = _staged(state,release)
        try:
            _verify_tree(installed_root,record['files'],installed=True)
        except (OSError,ValueError):
            continue
        return
    raise InputError('previous installed cache has local changes or an unverified version')


def select(state, plan, *, expected_sha256):
    _plan(state,plan,expected_sha256,'select',{'release_id','expected_selection','installed_root'})
    release_id = _hash(plan['release_id'])
    record = _staged(state, release_id)
    root = _root(state)
    with fs.writer(root):
        current = _selection_id(state)
        replayed = current==release_id
        _ensure_safe_point(state,record,require_idle=True)
        if not replayed:
            if current!=plan['expected_selection']:
                raise InputError('local marketplace selection changed; use the displayed selection')
            if current is not None:
                _check_previous(state,current,release_id,plan['installed_root'])
            fs.private((root/MANIFEST).parent)
            fs.write(root/MANIFEST,_selection_manifest(release_id))
        return dict(status='selected_for_install',installation_verified=False,replayed=replayed,
            marketplace_root=str(root),**_presentation(state,record))
