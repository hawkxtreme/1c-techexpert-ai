"""Reuse sealed remote file bytes as selected inputs; never reconnect here."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import uuid

from . import artifacts,input_files,operation_state as fs
from .inputs import InputError,read_snapshot

PROFILE='sftp-v3-capture-v1'


def validate_capture(report):
    result=report.get('result')
    if (report.get('kind')!='remote_capture' or type(result) is not dict or result.get('profile')!=PROFILE
        or result.get('schema_version')!=1 or result.get('capture_complete') is not True
        or type(result.get('roots')) is not list or len(result['roots'])!=1
        or result['roots'][0].get('kind')!='sftp' or type(result['roots'][0].get('path')) is not str
        or not result['roots'][0]['path'].startswith('sftp://') or len(result['roots'][0]['path'])>4096
        or type(result.get('members')) is not list or not 1<=len(result['members'])<=32
        or len(result['members'])!=len(report.get('sources',[]))):raise InputError('complete verified remote capture required')
    ids=set();names=set();total=0
    for index,(member,source) in enumerate(zip(result['members'],report['sources']),1):
        if (type(member) is not dict or not re.fullmatch(r'm[1-9][0-9]{0,2}',str(member.get('id','')))
            or member['id'] in ids or member.get('root')!=0 or member.get('importable') is not True
            or member.get('source_id')!=source['id'] or source['id']!='s'+str(index)
            or type(member.get('bytes')) is not int or member['bytes']!=source['bytes'] or member.get('sha256')!=source['sha256']):raise InputError('remote catalogue binding disagrees with sealed source')
        input_files.name_parts(member.get('relative_path'))
        if member['relative_path'] in names or source['name']!=result['roots'][0]['path'].rstrip('/')+'/'+member['relative_path']:raise InputError('ambiguous remote source name binding')
        ids.add(member['id']);names.add(member['relative_path']);total+=member['bytes']
    if result.get('file_count')!=len(ids) or result.get('expanded_bytes')!=total:raise InputError('invalid remote capture totals')
    return report


def stage(state,output,plan,selection,*,flat=False):
    validate_capture(plan)
    base=artifacts.artifact_folder(state,plan['artifact_id']);directory=fs.private(Path(output)/'input-stage'/uuid.uuid4().hex)
    sources={s['id']:s for s in plan['sources']};captured={}
    for member in selection:
        source=sources[member['source_id']]
        raw=read_snapshot(artifacts.source_path(base,source))
        if len(raw)!=member['bytes'] or hashlib.sha256(raw).hexdigest()!=member['sha256']:raise InputError('remote retained bytes changed during staging')
        folder=directory if flat else fs.private(directory/member['id']);path=folder/member['relative_path'].rsplit('/',1)[-1]
        with path.open('xb') as stream:stream.write(raw)
        root=plan['result']['roots'][member['root']]
        captured[member['id']]=dict(path=str(path.resolve()),bytes=len(raw),sha256=member['sha256'],
            input_origin=dict(kind='sftp',path=root['path'],member=member['relative_path'],member_id=member['id']))
    intake=dict(schema_version=1,artifact_id=plan['artifact_id'],plan_report_digest=fs.digest(plan),selected=[dict(member_id=m['id'],**captured[m['id']]) for m in selection],
        layout='flat' if flat else 'members',collection_coverage='unknown',database_run_ownership='not_established')
    return directory,captured,intake


def settings_schema(cap,adapter):
    if adapter=='case':return cap.obj(dict(manifest=dict(type='object',additionalProperties=True,x_bounded_json=1024**2)),['manifest'])
    if adapter not in ('jr','os','apdex'):raise InputError('unsupported retained remote diagnostic adapter')
    properties={} if adapter=='os' else deepcopy(cap.ROUTES[adapter+'.import']['input_schema']['properties'])
    for key in ('path','measurements','input_plan','members'):properties.pop(key,None)
    properties['members']=dict(type='array',minItems=1,maxItems=32 if adapter=='jr' else 1,items=cap.string(4,pattern='m[1-9][0-9]{0,2}'))
    return cap.obj(properties,['members']+(['platform_version'] if adapter=='jr' else ['target_seconds'] if adapter=='apdex' else []))


def normalize(adapter,settings):
    from . import capabilities as cap,diagnostic_adapters as drivers
    value=cap.validate(settings,settings_schema(cap,adapter))
    if adapter in ('jr','apdex'):
        path='path' if adapter=='jr' else 'measurements'
        members=value['members']
        checked=drivers.normalize(adapter+'.import',dict({k:v for k,v in value.items() if k!='members'},**{path:'retained-input'}))
        checked.pop(path);value=dict(checked,members=members)
    return value


def parse(state,output,capture_id,adapter,settings):
    from .input_intake import read_plan,selected_members,capture_selected,analyze
    settings=normalize(adapter,settings);plan=read_plan(state,capture_id);validate_capture(plan)
    if adapter=='case':
        folder=fs.private(Path(output)/'remote-manifests'/uuid.uuid4().hex);path=folder/'case.json'
        path.write_text(json.dumps(settings['manifest'],ensure_ascii=False,allow_nan=False),encoding='utf-8')
        return analyze(state,output,path,capture_id)
    members=settings['members'];selection=selected_members(plan,members,flat=adapter=='jr')
    if adapter=='jr':
        names=[Path(m['relative_path']).name.lower() for m in selection]
        if len({str(Path(m['relative_path']).parent) for m in selection})!=1 or names.count('1cv8.lgf')!=1 or len(names)<2 or any(n!='1cv8.lgf' and not n.endswith('.lgp') for n in names):raise InputError('select one sequential JR dictionary and its LGP group')
    folder,captured,intake=capture_selected(state,output,capture_id,members,flat=adapter=='jr',expected_plan_digest=fs.digest(plan))
    if adapter=='jr':
        from .native_jr import read_journal
        return read_journal(output,folder,**{k:v for k,v in settings.items() if k!='members'},intake=intake)
    path=captured[members[0]]['path']
    if adapter=='os':
        from .os_metrics import import_os
        return import_os(output,path,intake=intake)
    return artifacts.import_apdex(output,path,**{k:v for k,v in settings.items() if k!='members'},intake=intake)
