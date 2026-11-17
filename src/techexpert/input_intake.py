"""Saved metadata preview and explicit selected-member analysis for case adapters."""
from copy import deepcopy
import hashlib
import json
import os
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


def analyze(state,output,manifest,input_plan):
    plan=load_artifact(state,input_plan)
    if plan['kind']!='input_catalog' or plan['sources']:raise InputError('expected a saved diagnostic input catalogue')
    saved=plan['result'];settings=files.normalize([{k:r[k] for k in ('path','kind')} for r in saved['roots']],saved['limits'])
    raw=read_snapshot(manifest,1024**2);requested=json_value(raw.decode('utf-8-sig'),reject_duplicates=True)
    if type(requested) is not dict or type(requested.get('sources')) is not list or not 1<=len(requested['sources'])<=32:raise InputError('selected case requires1..32 explicit member sources')
    members={m['id']:m for m in saved['members']};selection=[];seen=set();locations=set()
    formats=set(AUXILIARY_FORMATS)|{'1c-tj-text-v1','1c-job-runtime-v1','normalized-events-v1'}
    for source in requested['sources']:
        if (type(source) is not dict or type(source.get('format')) is not str or source['format'] not in formats
            or type(source.get('path')) is not str):raise InputError('unsupported selected diagnostic format or member')
        member=members.get(source.get('path'))
        if member is None or member['id'] in seen or not member['importable']:raise InputError('select unique importable catalogue member IDs')
        root=saved['roots'][member['root']]
        if root['kind']=='zip':locator=('zip',os.path.normcase(root['path']),member['relative_path'])
        else:
            original=Path(root['path']) if root['kind']=='file' else Path(root['path']).joinpath(*member['relative_path'].split('/'))
            locator=('file',os.path.normcase(str(original)))
        if locator in locations:raise InputError('selected catalogue members refer to the same original input')
        locations.add(locator)
        if root['kind']=='zip' and source['format']=='1c-source-text-v1':raise InputError('source-code archives are excluded')
        try:
            if source['format']=='1c-tj-text-v1':
                from .native_tj import validate_profile
                validate_profile(source,member['relative_path'])
            elif source['format']=='1c-job-runtime-v1':runtime_profile(source)
        except ValueError as exc:raise InputError('unsupported selected source profile') from exc
        seen.add(member['id']);selection.append(member)
    if catalogue(settings)!=saved:raise InputError('input catalogue changed since preview')
    needed=sum(m['bytes'] for m in selection)*2+2*1024**2
    ancestor=Path(output).absolute()
    while not ancestor.exists():ancestor=ancestor.parent
    if shutil.disk_usage(ancestor).free-needed<10*1024**3:raise InputError('insufficient private capture space above disk floor')
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
            member=by_name[name];folder=private(stage/member['id']);path=folder/name.rsplit('/',1)[-1]
            with path.open('xb') as stream:stream.write(data)
            captured[member['id']]=dict(path=str(path),sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),
                input_origin=dict(kind=root['kind'],path=root['path'],member=name if root['kind']!='file' else None,member_id=member['id']))
    prepared=deepcopy(requested)
    for source in prepared['sources']:source['path']=captured[source['path']]['path']
    private_manifest=stage/'case.json';private_manifest.write_text(json.dumps(prepared,ensure_ascii=False,allow_nan=False),encoding='utf-8')
    intake=dict(schema_version=1,artifact_id=input_plan,plan_report_digest=digest(plan),requested_manifest_sha256=hashlib.sha256(raw).hexdigest(),
        selected=[dict(member_id=m['id'],**captured[m['id']]) for m in selection],collection_coverage='unknown',database_run_ownership='not_established')
    from .storage import investigate
    return investigate(private_manifest,output,intake=intake)
