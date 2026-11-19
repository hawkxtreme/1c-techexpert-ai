"""Immutable local observations with bounded evidence and integrity receipts."""
import hashlib
import json
from pathlib import Path
import re
import uuid
from datetime import datetime, timezone

from . import __version__
from .inputs import InputError, json_value, read_snapshot, MAX_TOTAL_BYTES, MAX_FILE_BYTES
from .storage import write_json, knowledge_revision, MAX_REPORT_BYTES


def encoded(value, limit):
    data=(json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode('utf-8')
    if len(data)>limit:raise InputError('artifact document exceeds byte limit')
    return data


def artifact_folder(state_dir, artifact_id):
    if not isinstance(artifact_id,str) or not re.fullmatch('[a-f0-9]{32}',artifact_id):
        raise InputError('invalid artifact identifier')
    return Path(state_dir)/'artifacts'/artifact_id


def _file_name(value, *, kind=None):
    if kind == 'context_excerpt' and value == 'review.txt':
        return value
    if (type(value) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}\.(?:xml|bin|diff)',value)
        or value.split('.')[0].upper() in {'CON','PRN','AUX','NUL',*[f'{p}{i}' for p in ('COM','LPT') for i in range(1,10)]}):
        raise InputError('invalid artifact source file name')
    return value


def source_name(source, *, kind=None):
    if type(source) is not dict or not re.fullmatch(r's(?:[1-9]|[12][0-9]|3[0-2])',str(source.get('id',''))):
        raise InputError('invalid artifact source identity')
    return _file_name(source.get('file_name',source['id']+'.bin'),kind=kind)


def source_path(folder, source, *, kind=None):
    """Resolve a sealed leaf, never an original input path or supplied directory."""
    from .operation_state import safe
    return safe(Path(folder)/'sources'/source_name(source,kind=kind))


def save_artifact(state_dir, kind, request, sources, result, *, input_intake=None, source_names=None):
    if not isinstance(kind,str) or not re.fullmatch('[a-z][a-z0-9_-]{0,63}',kind):
        raise InputError('invalid artifact kind')
    if not isinstance(sources,list) or len(sources)>32:raise InputError('at most 32 evidence files allowed')
    if source_names is not None:
        if type(source_names) is not list or len(source_names)!=len(sources):raise InputError('invalid artifact source names')
        names=[_file_name(name,kind=kind) for name in source_names]
        if len({name.casefold() for name in names})!=len(names):raise InputError('duplicate artifact source file name')
    request_data=encoded(request,1024*1024)
    evidence=[];total=0
    for i,source in enumerate(sources,1):
        name,data=source
        if not isinstance(name,str) or len(name)>4096 or not isinstance(data,bytes):
            raise InputError('evidence requires a bounded source name and bytes')
        total+=len(data)
        if len(data)>MAX_FILE_BYTES or total>MAX_TOTAL_BYTES:raise InputError('evidence exceeds byte limit')
        evidence.append(dict(id=f's{i}',name=name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
        if source_names is not None:evidence[-1]['file_name']=names[i-1]
    if input_intake is not None:
        from .input_intake import bind_sources
        bound=bind_sources(input_intake,sources)
        result=dict(result,input_intake=bound)
        for metadata,capture in zip(evidence,bound['selected']):metadata['input_origin']=dict(capture['input_origin'])
    report=dict(schema_version=2 if source_names is not None else 1,artifact_id=uuid.uuid4().hex,kind=kind,product_version=__version__,
                created_at=datetime.now(timezone.utc).isoformat(),knowledge_revision=knowledge_revision(),
                result=result,sources=evidence,requires_ai_interpretation=True)
    report_data=encoded(report,MAX_REPORT_BYTES)
    folder=artifact_folder(state_dir,report['artifact_id'])
    folder.mkdir(parents=True,exist_ok=False)
    from .windows_native import protect_directory
    protect_directory(folder)
    (folder/'sources').mkdir()
    (folder/'request.json').write_bytes(request_data)
    (folder/'report.json').write_bytes(report_data)
    for metadata,(_,data) in zip(evidence,sources):
        source_path(folder,metadata,kind=kind).write_bytes(data)
    write_json(folder/'receipt.json',dict(schema_version=1,
        report_sha256=hashlib.sha256(report_data).hexdigest(),request_sha256=hashlib.sha256(request_data).hexdigest()))
    return report


def read_artifact_record(state_dir,artifact_id):
    """Check the saved report and request receipts. Source bytes are separate."""
    folder=artifact_folder(state_dir,artifact_id)
    receipt=json_value(read_snapshot(folder/'receipt.json',8192).decode('utf-8'),reject_duplicates=True)
    if type(receipt) is not dict:raise InputError('invalid saved artifact receipt')
    report_data=read_snapshot(folder/'report.json',MAX_REPORT_BYTES)
    request_data=read_snapshot(folder/'request.json',1024*1024)
    for name,data in (('report',report_data),('request',request_data)):
        if hashlib.sha256(data).hexdigest()!=receipt.get(name+'_sha256'):
            raise InputError('saved artifact '+name+' integrity mismatch')
    report=json_value(report_data.decode('utf-8'),reject_duplicates=True)
    if type(report) is not dict or report.get('schema_version') not in (1,2) or report.get('artifact_id')!=artifact_id:
        raise InputError('unsupported artifact schema')
    evidence=report.get('sources')
    if not isinstance(evidence,list) or len(evidence)>32:raise InputError('invalid artifact evidence')
    total=0;names=set()
    for i,source in enumerate(evidence,1):
        if type(source) is not dict or source.get('id')!=f's{i}':raise InputError('invalid artifact evidence identity')
        if ('file_name' in source)!=(report['schema_version']==2):raise InputError('invalid artifact source schema')
        name=source_name(source,kind=report['kind']).casefold()
        if name in names:raise InputError('duplicate artifact source file name')
        names.add(name)
        size=source.get('bytes');sha256=source.get('sha256')
        if type(size) is not int or not 0<=size<=MAX_FILE_BYTES or not isinstance(sha256,str) or not re.fullmatch('[a-f0-9]{64}',sha256):
            raise InputError('invalid artifact source metadata')
        total+=size
        if total>MAX_TOTAL_BYTES:raise InputError('invalid artifact source byte total')
    return report,receipt['report_sha256']


def load_artifact(state_dir,artifact_id,*,input_state_dir=None):
    report,_=read_artifact_record(state_dir,artifact_id)
    folder=artifact_folder(state_dir,artifact_id)
    for source in report['sources']:
        data=read_snapshot(source_path(folder,source,kind=report['kind']))
        if len(data)!=source['bytes'] or hashlib.sha256(data).hexdigest()!=source['sha256']:
            raise InputError('saved artifact evidence integrity mismatch')
    if report['kind']=='fix_verification':
        from .fix_verification import verify_inputs
        verify_inputs(state_dir if input_state_dir is None else input_state_dir,report)
    elif report['kind'] == 'apdex_preparation':
        from .apdex_preparation import verify_inputs
        verify_inputs(state_dir if input_state_dir is None else input_state_dir, report)
    return report


def artifact_evidence(state_dir,artifact_id,source_id):
    report=load_artifact(state_dir,artifact_id)
    if report['kind']=='context_excerpt':raise InputError('use the reviewed excerpt context view')
    if report['kind']=='native-jr':
        from .native_jr_sqlite import PROFILE
        if report['result'].get('profile')==PROFILE:raise InputError('use jr.record for LGD row evidence')
    source=next((s for s in report['sources'] if s['id']==source_id),None)
    if source is None:raise InputError('unknown artifact evidence source')
    path=source_path(artifact_folder(state_dir,artifact_id),source)
    data=read_snapshot(path)
    if len(data)!=source['bytes'] or hashlib.sha256(data).hexdigest()!=source['sha256']:raise InputError('saved artifact evidence integrity mismatch')
    return dict(artifact_id=artifact_id,source_id=source_id,sha256=source['sha256'],
                file_path=str(path.absolute()),
                integrity_verified=True,untrusted_source_content=True,
                text=data[:8192].decode('utf-8-sig',errors='replace'),truncated=len(data)>8192)


def import_apdex(state_dir,path,target_seconds=None,*,intake=None,inventory_only=False,**selection):
    from .apdex import calculate, inventory, validate_target_selection
    validate_target_selection(target_seconds, inventory_only)
    data=read_snapshot(path)
    records=json_value(data.decode('utf-8-sig'),reject_duplicates=True)
    result = inventory(records, **selection) if inventory_only else calculate(records, target_seconds, **selection)
    request = dict(path=str(Path(path).resolve()), target_seconds=target_seconds, **selection)
    if inventory_only:
        request['inventory_only'] = True
    return save_artifact(state_dir,'apdex',request,
                         [(str(Path(path).resolve()),data)],result,input_intake=intake)
