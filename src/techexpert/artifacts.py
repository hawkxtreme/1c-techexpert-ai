"""Immutable local observations with bounded evidence and integrity receipts."""
import hashlib
import json
import os
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


def save_artifact(state_dir, kind, request, sources, result):
    if not isinstance(kind,str) or not re.fullmatch('[a-z][a-z0-9_-]{0,63}',kind):
        raise InputError('invalid artifact kind')
    if not isinstance(sources,list) or len(sources)>32:raise InputError('at most 32 evidence files allowed')
    request_data=encoded(request,1024*1024)
    evidence=[];total=0
    for i,source in enumerate(sources,1):
        name,data=source
        if not isinstance(name,str) or len(name)>4096 or not isinstance(data,bytes):
            raise InputError('evidence requires a bounded source name and bytes')
        total+=len(data)
        if len(data)>MAX_FILE_BYTES or total>MAX_TOTAL_BYTES:raise InputError('evidence exceeds byte limit')
        evidence.append(dict(id=f's{i}',name=name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
    report=dict(schema_version=1,artifact_id=uuid.uuid4().hex,kind=kind,product_version=__version__,
                created_at=datetime.now(timezone.utc).isoformat(),knowledge_revision=knowledge_revision(),
                result=result,sources=evidence,requires_ai_interpretation=True)
    report_data=encoded(report,MAX_REPORT_BYTES)
    folder=artifact_folder(state_dir,report['artifact_id'])
    (folder/'sources').mkdir(parents=True,exist_ok=False)
    if os.name!='nt':folder.chmod(0o700)
    (folder/'request.json').write_bytes(request_data)
    (folder/'report.json').write_bytes(report_data)
    for metadata,(_,data) in zip(evidence,sources):
        (folder/'sources'/(metadata['id']+'.bin')).write_bytes(data)
    write_json(folder/'receipt.json',dict(schema_version=1,
        report_sha256=hashlib.sha256(report_data).hexdigest(),request_sha256=hashlib.sha256(request_data).hexdigest()))
    return report


def load_artifact(state_dir,artifact_id):
    folder=artifact_folder(state_dir,artifact_id)
    receipt=json_value(read_snapshot(folder/'receipt.json',8192).decode('utf-8'),reject_duplicates=True)
    report_data=read_snapshot(folder/'report.json',MAX_REPORT_BYTES)
    request_data=read_snapshot(folder/'request.json',1024*1024)
    for name,data in (('report',report_data),('request',request_data)):
        if hashlib.sha256(data).hexdigest()!=receipt.get(name+'_sha256'):
            raise InputError('saved artifact '+name+' integrity mismatch')
    report=json_value(report_data.decode('utf-8'),reject_duplicates=True)
    if report.get('schema_version')!=1 or report.get('artifact_id')!=artifact_id:
        raise InputError('unsupported artifact schema')
    evidence=report.get('sources')
    if not isinstance(evidence,list) or len(evidence)>32:raise InputError('invalid artifact evidence')
    total=0
    for i,source in enumerate(evidence,1):
        if source.get('id')!=f's{i}':raise InputError('invalid artifact evidence identity')
        data=read_snapshot(folder/'sources'/(source['id']+'.bin'))
        total+=len(data)
        if total>MAX_TOTAL_BYTES or len(data)!=source.get('bytes') or hashlib.sha256(data).hexdigest()!=source.get('sha256'):
            raise InputError('saved artifact evidence integrity mismatch')
    return report


def artifact_evidence(state_dir,artifact_id,source_id):
    report=load_artifact(state_dir,artifact_id)
    source=next((s for s in report['sources'] if s['id']==source_id),None)
    if source is None:raise InputError('unknown artifact evidence source')
    data=read_snapshot(artifact_folder(state_dir,artifact_id)/'sources'/(source_id+'.bin'))
    return dict(artifact_id=artifact_id,source_id=source_id,sha256=source['sha256'],
                integrity_verified=True,untrusted_source_content=True,
                text=data[:8192].decode('utf-8-sig',errors='replace'),truncated=len(data)>8192)


def import_apdex(state_dir,path,target_seconds,**selection):
    from .apdex import calculate
    data=read_snapshot(path)
    records=json_value(data.decode('utf-8-sig'),reject_duplicates=True)
    result=calculate(records,target_seconds,**selection)
    return save_artifact(state_dir,'apdex',dict(path=str(Path(path).resolve()),target_seconds=target_seconds,**selection),
                         [(str(Path(path).resolve()),data)],result)
