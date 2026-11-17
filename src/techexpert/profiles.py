"""Local readiness and reusable source configuration; no connection side effects."""
import hashlib
import json
import os
import platform
import re
import shutil
import sys
import uuid
from pathlib import Path

from . import __version__
from .inputs import InputError, read_snapshot, json_value
from .storage import write_json, default_state_dir


class ProfileRevisionConflict(InputError):
    """The displayed profile no longer names the current environment revision."""


def doctor(state_dir=None):
    installations = []
    if os.name == 'nt':
        for root in (Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / '1cv8',
                     Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)')) / '1cv8'):
            if root.is_dir():
                for binary in root.glob('*/bin/1cv8.exe'):
                    installations.append(dict(path=str(binary), directory_version=binary.parent.parent.name,
                                              license='not_checked', compatibility='not_verified'))
    return dict(product_version=__version__, python=sys.version.split()[0], python_executable=sys.executable,
                os=platform.platform(), ai_harness_required=True,
                state_dir=str(default_state_dir() if state_dir is None else Path(state_dir).resolve()),
                onec_installations=installations,
                commands={x: shutil.which(x) for x in ('git', 'rac', 'ras', 'ssh', 'psql', 'sqlcmd')},
                capabilities=dict(sc01_normalized_evidence='ready', synthetic_demo='ready',
                                  source_profile='ready', native_tj='text_8.3.27.1989_only',
                                  job_correlation='controlled_file_job_markers_8.3.27.1989_only', native_jr='sequential_lgf_lgp_8.3.27.1989_only; lgd_not_supported',
                                  order_load='controlled_windows_file_8.3.27.1989_only',
                                  fix_comparison='sc01_order_load_five_pairs_only',
                                  sql='postgresql_fixed_read_only_catalogue; sql_server_not_implemented',
                                  local_os_collection='windows_pdh_linux_proc; counters_require_actual_check',
                                  remote_os_collection='ssh_winrm_launchers; existing_access_and_remote_python_required',
                                  apdex='normalized_measurements_only',source_snapshot='bounded_xml_bsl_catalog_or_local_git_commit',
                                  source_export='windows_file_8.3.27.1989_private_copy_editable_main_only',
                                  knowledge='bundled_offline_linked_cards',testpilot='not_implemented'))


def read_starter(path):
    from .discovery import inspect_starter
    return inspect_starter(path)['bases']


def validate_profile(value):
    if isinstance(value,dict) and type(value.get('schema_version')) is int and value['schema_version']==2:
        from .profile_resources import validate
        return validate(value)
    return _validate_legacy_profile(value)


def _validate_legacy_profile(value):
    if not isinstance(value, dict) or value.get('schema_version') != 1:
        raise InputError('profile schema_version=1 required')
    # Never accept arbitrary persisted properties from an HTTP client.
    if set(value) - {'schema_version', 'name', 'bases', 'sources', 'revision', 'capability_status'}:
        raise InputError('unknown profile property')
    def field(obj, key, limit=2048, empty=False):
        val = obj.get(key, '')
        if not isinstance(val, str) or len(val)>limit or (not empty and not val.strip()) or any(ord(c)<32 for c in val):
            raise InputError(f'invalid {key}')
        if re.search(r'(?i)(?:pwd|password|token|secret|authorization)\s*[=:]', val) or re.search(r'://[^/]*@', val):
            raise InputError('credentials must not be saved in profiles')
        return val.strip()
    name = field(value, 'name', 120)
    bases, sources = value.get('bases'), value.get('sources')
    if not isinstance(bases, list) or not 1 <= len(bases) <= 100 or not isinstance(sources, list) or len(sources)>100:
        raise InputError('profile requires 1..100 bases and at most 100 sources')
    clean_bases, clean_sources, ids = [], [], set()
    for base in bases:
        if not isinstance(base, dict) or set(base)-{'id','name','mode','connection'}:
            raise InputError('invalid base properties')
        bid, mode = field(base, 'id', 80), base.get('mode')
        if bid in ids or mode not in ('file','server','unknown'):
            raise InputError('duplicate base id or invalid mode')
        ids.add(bid)
        clean_bases.append(dict(id=bid,name=field(base,'name',120),mode=mode,connection=field(base,'connection',empty=True)))
    source_ids = set()
    for source in sources:
        if not isinstance(source, dict) or set(source)-{'id','type','path','host','base_ids','status','settings'}:
            raise InputError('invalid source properties')
        sid, kind = field(source,'id',80), source.get('type')
        path=field(source,'path',empty=kind in ('os','rac','sql'))
        linked = source.get('base_ids')
        if sid in source_ids or kind not in ('tj','jr','source','sql','os','rac'):
            raise InputError('duplicate source id or unknown type')
        if not isinstance(linked,list) or not linked or any(not isinstance(x,str) or x not in ids for x in linked) or len(set(linked))!=len(linked):
            raise InputError('source must link existing bases')
        if kind in ('sql','rac') and any(base['mode']!='server' for base in clean_bases if base['id'] in linked):
            raise InputError('SQL and RAC apply only to confirmed server databases')
        suffix = Path(path).suffix.lower()
        if kind=='jr' and suffix=='.xml':
            raise InputError('JR requires a native directory or consistent snapshot, not XML')
        if kind=='source' and suffix in ('.zip','.7z','.rar','.tar','.gz','.cf','.cfe'):
            raise InputError('1C sources require a directory or Git repository')
        settings=validate_source_settings(kind,source.get('settings',{}),linked)
        clean_sources.append(dict(id=sid,type=kind,path=path,host=field(source,'host',256,empty=True),base_ids=linked,
                                  status='not_checked',settings=settings))
        source_ids.add(sid)
    return dict(schema_version=1,name=name,bases=clean_bases,sources=clean_sources,capability_status='configured_not_connected')


def validate_source_settings(kind,value,base_ids):
    fields={
        'os':{'transport','duration_seconds','interval_seconds','max_bytes','role','port','python','use_ssl','identity_file','known_hosts_file'},
        'sql':{'engine','port','database','databases','user','credential_ref','executable','docker_container'},
        'rac':{'executable','docker_container','credential_ref'},
        'tj':{'platform_version','utc_offset','placement','timestamp_format'},
        'jr':{'platform_version','utc_offset'},
        'source':{'kind','ref','match_status'}}
    if not isinstance(value,dict) or set(value)-fields[kind]:raise InputError('unsupported '+kind+' settings')
    result={}
    for key,item in value.items():
        if key=='databases':
            if (not isinstance(item,dict) or set(item)-set(base_ids)
                or any(not isinstance(v,str) or not re.fullmatch(r'[\w][\w.-]{0,127}',v) for v in item.values())):
                raise InputError('SQL database map requires plain database names for linked bases')
            result[key]=dict(item)
        elif key in ('duration_seconds','interval_seconds','max_bytes','port','use_ssl'):
            result[key]=item
        else:
            if (not isinstance(item,str) or len(item)>2048 or any(ord(c)<32 for c in item)
                or re.search(r'(?i)(?:pwd|password|token|secret|authorization)\s*[=:]',item) or re.search(r'://[^/]*@',item)):
                raise InputError('invalid or secret-bearing source setting')
            result[key]=item
    if kind=='os':
        from .os_metrics import validate_request
        request=validate_request(dict(**result,host='configured-node' if result.get('transport','local')!='local' else ''))
        result={k:v for k,v in request.items() if k not in ('host','node')}
    if kind=='sql':
        result.setdefault('engine','postgresql');result.setdefault('port',5432 if result['engine']=='postgresql' else 1433)
        if result['engine'] not in ('postgresql','sqlserver') or type(result['port']) is not int or not 1<=result['port']<=65535:
            raise InputError('invalid SQL engine or port')
        if result.get('database') and not re.fullmatch(r'[\w][\w.-]{0,127}',result['database']):
            raise InputError('SQL database must be a plain name')
    if kind=='source' and (result.get('kind','catalog') not in ('catalog','git') or result.get('match_status','unknown') not in ('unknown','confirmed','mismatch','partial')):
        raise InputError('invalid source kind or match status')
    return result


def discover_ras(endpoint,*,executable='rac',docker_container=None,cluster=None,infobase=None):
    from .discovery import inspect_ras
    return inspect_ras(endpoint,executable=executable,docker_container=docker_container,cluster=cluster,infobase=infobase)


def check_profile(value):
    """Validate configuration only, without touching configured paths or endpoints.

    Even filesystem metadata checks can contact UNC shares, mapped drives or remote
    targets behind local links. Actual access belongs to an explicit adapter run.
    """
    from .profile_resources import effective_profile
    clean=effective_profile(validate_profile(value));checks=[]
    for source in clean['sources']:
        kind=source['type']
        if kind in ('tj','jr','source'):
            remote_git=kind=='source' and source['settings'].get('kind')=='git' and re.match(r'^(https://|git@|ssh://)',source['path'])
            if remote_git:status='requires_explicit_git_snapshot';detail='Git is configured; no clone/fetch was started.'
            else:status='requires_explicit_path_check';detail='Path configured; existence, access and contents require an explicit adapter run. No filesystem access attempted.'
        elif kind=='os':
            status='local_collector_available' if source['settings']['transport']=='local' and platform.system() in ('Windows','Linux') else 'remote_prerequisites_not_checked'
            detail='Plan only: no collection, service installation or permission change.'
        elif kind=='sql':
            status='client_configured_not_checked'
            detail='Client presence, credentials, permissions and database mapping require an explicit connection check. No executable path probed.'
        else:
            status='configured_not_connected';detail='Use explicit RAS discovery to test this endpoint.'
        checks.append(dict(source_id=source['id'],type=kind,status=status,detail=detail))
    return dict(status='local_preflight_only',sources=checks,connected=False,collection_started=False,logcfg_changed=False)


def save_profile(state_dir, profile, *, expected_revision=None):
    clean = validate_profile(profile)
    folder = Path(state_dir) / 'profiles'
    folder.mkdir(parents=True, exist_ok=True)
    lock = folder / 'write.lock'
    try:
        with lock.open('x', encoding='ascii') as stream:
            stream.write(str(os.getpid()))
    except FileExistsError as exc:
        raise InputError('profile is being saved; retry after the current writer completes') from exc
    try:
        current=load_profile(state_dir)
        if current is not None and current['schema_version']==2 and clean['schema_version']==1:
            raise ProfileRevisionConflict('profile schema downgrade is not allowed; preserve shared resources')
        if expected_revision is not None:
            if type(expected_revision) is not int or expected_revision<0:raise InputError('invalid expected profile revision')
            if (current['revision'] if current else 0)!=expected_revision:raise ProfileRevisionConflict('profile revision changed; inspect the current profile before saving')
        revisions = [int(p.stem) for p in folder.glob('*.json') if p.stem.isdecimal()]
        clean['revision'] = max(revisions, default=0) + 1
        if len((json.dumps(clean,ensure_ascii=False,indent=2)+'\n').encode('utf-8')) > 1024*1024:
            raise InputError('profile exceeds 1 MiB; reduce its size before saving')
        write_json(folder / f"{clean['revision']}.json", clean)
        write_json(folder / 'current.json', clean)
    finally:
        lock.unlink()
    return clean


def load_profile(state_dir):
    path = Path(state_dir) / 'profiles/current.json'
    if not path.exists():
        return None
    value = json_value(read_snapshot(path, 1024*1024).decode('utf-8'))
    validate_profile(value)
    return value
