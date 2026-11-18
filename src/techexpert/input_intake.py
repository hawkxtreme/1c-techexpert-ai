"""Saved metadata preview and explicit selected-member analysis for case adapters."""
from copy import deepcopy
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import uuid

from . import input_files as files,input_zip
from .artifacts import save_artifact,load_artifact
from .inputs import InputError,read_snapshot,json_value,AUXILIARY_FORMATS,runtime_profile
from .operation_state import private,digest


def catalogue(settings):
    roots=[];members=[];total=0;bound=settings['limits']
    for i,root in enumerate(settings['inputs']):
        if root['kind']=='zip':items,identity=input_zip.inspect(root['path'],bound)
        else:items=files.local(root,bound);identity=None
        roots.append(dict(root,identity=identity))
        for item in items:
            total+=item['bytes']
            if total>bound['max_total_bytes'] or len(members)>=bound['max_files']:raise InputError('combined input count or byte limit')
            members.append(dict(item,id='m'+str(len(members)+1),root=i))
    return dict(schema_version=1,roots=roots,members=members,file_count=len(members),expanded_bytes=total,limits=bound,
        extraction_performed=False,collection_coverage='unknown',identity_scope='selected paths and bounded bytes; not database or run ownership')


def inspect(state,inputs,*,limits=None):
    settings=files.normalize(inputs,limits);result=catalogue(settings)
    return save_artifact(state,'input_catalog',settings,[],result)


def read_plan(state,input_plan):
    plan=load_artifact(state,input_plan)
    if plan['kind']=='remote_capture':
        from .remote_intake import validate_capture
        return validate_capture(plan)
    if (plan['kind']!='input_catalog' or plan['sources'] or type(plan['result']) is not dict
        or plan['result'].get('schema_version')!=1):raise InputError('expected a saved diagnostic input catalogue')
    return plan


def path_key(path):return os.path.normcase(os.path.normpath(str(Path(path).absolute())))


def selected_members(plan,member_ids,*,expected_root=None,flat=False):
    if (type(member_ids) is not list or not 1<=len(member_ids)<=32
        or any(type(m) is not str or not re.fullmatch(r'm[1-9][0-9]{0,2}',m) for m in member_ids)
        or len(set(member_ids))!=len(member_ids)):raise InputError('select1..32 unique catalogue member IDs')
    saved=plan['result'];members={m['id']:m for m in saved['members']};selection=[];locations=set();names=set()
    for identifier in member_ids:
        member=members.get(identifier)
        if member is None or not member['importable']:raise InputError('select importable catalogue member IDs')
        parts=files.name_parts(member['relative_path'])
        root=saved['roots'][member['root']]
        if expected_root is not None and path_key(root['path'])!=path_key(expected_root):raise InputError('selected member is outside the approved original root')
        if root['kind']=='sftp':locator=('sftp',root['path'],member['relative_path'])
        elif root['kind']=='zip':locator=('zip',os.path.normcase(root['path']),member['relative_path'])
        else:
            original=Path(root['path']) if root['kind']=='file' else Path(root['path']).joinpath(*member['relative_path'].split('/'))
            locator=('file',path_key(original))
        if locator in locations:raise InputError('selected catalogue members refer to the same original input')
        locations.add(locator)
        if flat:
            key=files.name_key(parts[-1])
            if key in names:raise InputError('selected members collide in a flat diagnostic snapshot')
            names.add(key)
        selection.append(member)
    return selection


def capture_selected(state,output,input_plan,member_ids,*,expected_root=None,flat=False,expected_plan_digest=None):
    plan=read_plan(state,input_plan)
    if expected_plan_digest is not None and digest(plan)!=expected_plan_digest:raise InputError('saved input catalogue changed during preparation')
    selection=selected_members(plan,member_ids,expected_root=expected_root,flat=flat);saved=plan['result']
    needed=sum(m['bytes'] for m in selection)*2+2*1024**2
    ancestor=Path(output).absolute()
    while not ancestor.exists():ancestor=ancestor.parent
    if shutil.disk_usage(ancestor).free-needed<10*1024**3:raise InputError('insufficient private capture space above disk floor')
    if plan['kind']=='remote_capture':
        if expected_root is not None:raise InputError('use remote.parse for retained remote adapter imports')
        from .remote_intake import stage
        return stage(state,output,plan,selection,flat=flat)
    settings=files.normalize([{k:r[k] for k in ('path','kind')} for r in saved['roots']],saved['limits'])
    if catalogue(settings)!=saved:raise InputError('input catalogue changed since preview')
    stage=private(Path(output)/'input-stage'/uuid.uuid4().hex);captured={}
    for root_index,root in enumerate(saved['roots']):
        selected=[m for m in selection if m['root']==root_index]
        if root['kind']=='zip':
            contents=input_zip.selected(root['path'],saved['limits'],root['identity'],[(m['relative_path'],m['bytes']) for m in selected]) if selected else []
        else:
            contents=[]
            for member in selected:
                path=Path(root['path']) if root['kind']=='file' else Path(root['path']).joinpath(*member['relative_path'].split('/'))
                data,_=files.read(path,saved['limits']['max_file_bytes'],keep=True,expected={k:member[k] for k in ('bytes','sha256')});contents.append((member['relative_path'],data))
        by_name={m['relative_path']:m for m in selected}
        for name,data in contents:
            member=by_name[name];folder=stage if flat else private(stage/member['id']);path=folder/name.rsplit('/',1)[-1]
            with path.open('xb') as stream:stream.write(data)
            captured[member['id']]=dict(path=str(path.resolve()),sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),
                input_origin=dict(kind=root['kind'],path=root['path'],member=name if root['kind']!='file' else None,member_id=member['id']))
    intake=dict(schema_version=1,artifact_id=input_plan,plan_report_digest=digest(plan),
        selected=[dict(member_id=m['id'],**captured[m['id']]) for m in selection],layout='flat' if flat else 'members',collection_coverage='unknown',database_run_ownership='not_established')
    return stage,captured,intake


def bind_sources(intake,sources):
    """Pin actual parser bytes and artifact source order, without original reads."""
    if len(sources)!=len(intake['selected']):raise InputError('selected adapter capture is incomplete')
    expected={}
    for capture in intake['selected']:
        name=Path(capture['path']).name if intake['layout']=='flat' else capture['path']
        if name in expected:raise InputError('ambiguous selected adapter source name')
        expected[name]=capture
    selected=[]
    for number,(name,data) in enumerate(sources,1):
        capture=expected.pop(name,None)
        if capture is None or len(data)!=capture['bytes'] or hashlib.sha256(data).hexdigest()!=capture['sha256']:raise InputError('selected adapter snapshot integrity mismatch')
        selected.append(dict(capture,source_id=f's{number}'))
    if expected:raise InputError('selected adapter capture is incomplete')
    return dict(intake,selected=selected)


def analyze(state,output,manifest,input_plan):
    plan=read_plan(state,input_plan);raw=read_snapshot(manifest,1024**2);requested=json_value(raw.decode('utf-8-sig'),reject_duplicates=True)
    if type(requested) is not dict or type(requested.get('sources')) is not list or not 1<=len(requested['sources'])<=32:raise InputError('selected case requires1..32 explicit member sources')
    formats=set(AUXILIARY_FORMATS)|{'1c-tj-text-v1','1c-job-runtime-v1','normalized-events-v1'}
    if any(type(s) is not dict or type(s.get('format')) is not str or s['format'] not in formats or type(s.get('path')) is not str for s in requested['sources']):raise InputError('unsupported selected diagnostic format or member')
    ids=[s['path'] for s in requested['sources']];selection=selected_members(plan,ids)
    for source,member in zip(requested['sources'],selection):
        if source.get('read_mode','stable')!='stable':raise InputError('catalogue member analysis requires stable read mode; TJ prefix reads use explicit original paths')
        if plan['result']['roots'][member['root']]['kind']=='zip' and source['format']=='1c-source-text-v1':raise InputError('source-code archives are excluded')
        try:
            if source['format']=='1c-tj-text-v1':
                from .native_tj import validate_profile
                validate_profile(source,member['relative_path'])
            elif source['format']=='1c-job-runtime-v1':runtime_profile(source)
        except ValueError as exc:raise InputError('unsupported selected source profile') from exc
    stage,captured,intake=capture_selected(state,output,input_plan,ids,expected_plan_digest=digest(plan))
    prepared=deepcopy(requested)
    for source in prepared['sources']:source['path']=captured[source['path']]['path']
    private_manifest=stage/'case.json';private_manifest.write_text(json.dumps(prepared,ensure_ascii=False,allow_nan=False),encoding='utf-8')
    intake['requested_manifest_sha256']=hashlib.sha256(raw).hexdigest()
    from .storage import investigate
    return investigate(private_manifest,output,intake=intake)
