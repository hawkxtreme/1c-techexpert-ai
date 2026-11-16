"""Thin bounded-file transport for the finite managed controller, not an AI provider."""
import codecs
import hashlib
import math
import os
from pathlib import Path
import re
import shutil
import time
import uuid

from . import operation_state as fs,kernel_process
from .inputs import InputError

CHUNK=65536
MAX_RESPONSE=16*1024**2
DEFAULT_LIMITS=dict(admission_seconds=10,query_seconds=30,memory_bytes=1024**3)
_ACTIONS={'run':{'request'},'status':{'run_id'},'result':{'run_id'},'reconcile':{'run_id'},
    'cancel':{'run_id','executor_id'},'inspect':{'call_id'}}


def _limits(value):
    result=dict(DEFAULT_LIMITS)
    if value is not None:
        if not isinstance(value,dict) or set(value)-result.keys():raise InputError('unsupported kernel limit')
        result.update(value)
    for key,high in [('admission_seconds',30),('query_seconds',60)]:
        v=result[key]
        if type(v) not in (int,float) or not math.isfinite(v) or not .25<=v<=high:raise InputError('invalid kernel deadline')
    if type(result['memory_bytes']) is not int or not 64*1024**2<=result['memory_bytes']<=1024**3:raise InputError('invalid kernel memory limit')
    return result


def _arguments(action,value):
    if action not in _ACTIONS or not isinstance(value,dict) or set(value)!=_ACTIONS[action]:raise InputError('unsupported kernel action or arguments')
    if any(not isinstance(v,str) or not 1<=len(v)<=2048 or any(ord(c)<32 for c in v) for v in value.values()):raise InputError('invalid kernel argument')
    if 'run_id' in value and not re.fullmatch('[a-f0-9]{64}',value['run_id']):raise InputError('invalid operation run ID')
    if 'call_id' in value and not re.fullmatch('[a-f0-9]{32}',value['call_id']):raise InputError('invalid kernel call ID')
    if 'executor_id' in value and not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',value['executor_id']):raise InputError('invalid executor ID')
    return dict(value,request=str(Path(value['request']).absolute())) if action=='run' else dict(value)


def _space(path):
    for parent in (path,*path.parents):
        if parent.exists():
            if shutil.disk_usage(parent).free<10*1024**3:raise InputError('kernel calls retain a 10 GiB free floor; select a local state volume with space')
            return
    raise InputError('kernel state volume unavailable')


def folder(state,call_id):
    if not isinstance(call_id,str) or not re.fullmatch('[a-f0-9]{32}',call_id):raise InputError('invalid kernel call ID')
    return fs.safe(Path(state)/'kernel-calls'/call_id)


def file_identity(path,limit):
    with fs.safe(path).open('rb') as stream:
        return _stream_identity(stream,limit)


def _stream_identity(stream,limit):
    digest=hashlib.sha256();size=0;before=os.fstat(stream.fileno())
    if before.st_size>limit:raise InputError('kernel response exceeds byte limit')
    while block:=stream.read(CHUNK):
        size+=len(block)
        if size>limit:raise InputError('kernel response exceeds byte limit')
        digest.update(block)
    after=os.fstat(stream.fileno())
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns) or size!=before.st_size:raise InputError('kernel response changed during verification')
    return dict(bytes=size,sha256=digest.hexdigest())


def _write_checked(path,value):fs.write(path,dict(schema_version=1,value=value,sha256=fs.digest(value)))


def _checked(path,limit):
    document=fs.read(path,limit)
    if (not isinstance(document,dict) or document.get('schema_version')!=1 or not isinstance(document.get('value'),dict)
        or document.get('sha256')!=fs.digest(document['value'])):raise InputError('kernel document integrity mismatch')
    return document['value']


def _write_response(path,value,code,plan):
    fs.write(path,value)
    identity=file_identity(path,MAX_RESPONSE)
    receipt=dict(**identity,name=path.name,exit_code=code,plan_sha256=fs.digest(plan))
    _write_checked(path.with_name(path.stem+'-receipt.json'),receipt)
    return receipt


def _response(folder,plan,name='response.json',*,verify=True):
    if name not in ('response.json','error-response.json'):raise InputError('invalid kernel response member')
    receipt=_checked(folder/(Path(name).stem+'-receipt.json'),16384)
    if (not isinstance(receipt,dict) or receipt.get('name')!=name or receipt.get('plan_sha256')!=fs.digest(plan)
        or receipt.get('exit_code') not in (0,1,2,3,130) or type(receipt.get('exit_code')) is not int):raise InputError('kernel response receipt integrity mismatch')
    if verify:
        actual=file_identity(folder/name,MAX_RESPONSE)
        if any(receipt.get(k)!=v for k,v in actual.items()):raise InputError('kernel response integrity mismatch')
    return receipt


def _worker_observation(state,run_id,controller):
    if not run_id:return dict(state='not_admitted')
    try:
        status=fs.read(fs.folder(state,run_id)/'status.json',64*1024)
        owner=status.get('owner',{})
        if any(owner.get(k)!=controller.get(k) for k in ('pid','lifetime','hostname','platform','pid_namespace')):return dict(state='not_owned_by_this_call')
        identity=status.get('child')
        if not identity:return dict(state='unknown',basis='worker_not_recorded')
        process=fs.inspect_process(identity)
        group=fs.inspect_group(identity) if os.name!='nt' else None
        stopped=process['state'] in ('not_running','different_lifetime') and (group is None or group['state']=='stopped')
        return dict(state='stopped' if stopped else 'unknown',process=process,group=group)
    except (OSError,ValueError,KeyError,TypeError):return dict(state='unknown',basis='operation_observation_unavailable')


def _admission(directory,plan):
    value=fs.read(directory/'admitted.json',16384)
    high=1830 if plan['action']=='run' else plan['limits']['query_seconds']
    if (not isinstance(value,dict) or set(value)!={'plan_sha256','run_id','timeout_seconds'}
        or value.get('plan_sha256')!=fs.digest(plan)
        or type(value.get('timeout_seconds')) not in (int,float)
        or not math.isfinite(value['timeout_seconds']) or not 0<value['timeout_seconds']<=high
        or value.get('run_id') is not None and (not isinstance(value['run_id'],str) or not re.fullmatch('[a-f0-9]{64}',value['run_id']))
        or plan['action']!='run' and value.get('run_id')!=plan['arguments'].get('run_id')):
        raise InputError('kernel_admission_integrity')
    return value


def invoke(state,action,arguments,*,limits=None):
    arguments=_arguments(action,arguments);limits=_limits(limits);state=fs.safe(state);_space(state)
    owner=fs.process_identity(os.getpid())
    if owner['state']!='running' or not owner['lifetime']:raise InputError('kernel owner process identity unknown')
    call_id=uuid.uuid4().hex;directory=folder(state,call_id);fs.private(directory)
    started=time.monotonic()
    plan=dict(schema_version=1,call_id=call_id,state_dir=str(state),action=action,arguments=arguments,
        limits=limits,started_monotonic=started,parent=owner,created_at=fs.stamp())
    fs.write(directory/'plan.json',plan);fs.write(directory/'plan-receipt.json',dict(sha256=fs.digest(plan)))
    current=dict(schema_version=1,call_id=call_id,status='starting',owner=owner,child=None)
    fs.write(directory/'status.json',current)
    admitted=None;last_scan=0
    def on_started(pid):
        identity=fs.process_identity(pid)
        if identity['state']!='running' or not identity['lifetime']:raise InputError('kernel child process identity unknown')
        current.update(child=identity);fs.write(directory/'status.json',current)
        fs.write(directory/'start-permit.json',dict(child=identity,plan_sha256=fs.digest(plan)))
    def guard():
        nonlocal admitted,last_scan
        if admitted is None and (directory/'admitted.json').exists():
            admitted=_admission(directory,plan);current['status']='running';fs.write(directory/'status.json',current)
        deadline=started+(admitted['timeout_seconds'] if admitted else limits['admission_seconds'])
        if time.monotonic()>=deadline:raise InputError('kernel_timeout' if admitted else 'kernel_admission_timeout')
        if time.monotonic()-last_scan>=.1:
            last_scan=time.monotonic();usage=fs.inventory(directory);_space(directory)
            if usage['bytes']>64*1024**2:raise InputError('kernel_owned_disk_limit')
            for name in ('stdout.bin','stderr.bin'):
                p=directory/name
                if p.exists() and p.stat().st_size>65536:raise InputError('kernel_diagnostic_output_limit')
    try:process=kernel_process.run(directory,guard=guard,on_started=on_started,timeout=1835,memory_bytes=limits['memory_bytes'])
    except (OSError,ValueError) as exc:
        process=dict(status='failed',pid=(current.get('child') or {}).get('pid'),exit_code=None,
            elapsed_seconds=time.monotonic()-started,tree_finished=False,stop_reason='kernel_launcher_failure',
            guard_error=None,failure_message=str(exc)[:512],resource_usage=None)
    controller_finished=time.monotonic();reason=process.get('guard_error') or process.get('stop_reason')
    if admitted is None and (directory/'admitted.json').exists():
        try:admitted=_admission(directory,plan)
        except (OSError,ValueError,KeyError,TypeError):reason='kernel_admission_integrity'
    if reason=='timeout':reason='kernel_timeout'
    if admitted and controller_finished>started+admitted['timeout_seconds']:reason=reason or 'kernel_timeout'
    try:
        if reason or not process['tree_finished'] or process['exit_code']!=0:raise InputError(reason or 'kernel_process_failure')
        response=_response(directory,plan)
    except (OSError,ValueError,KeyError,TypeError):
        reason=reason or 'kernel_process_failure'
        cancelled=reason=='cancelled'
        value=dict(schema_version=1,status='cancelled' if cancelled else 'failed',run_id=admitted.get('run_id') if admitted else None,
            kernel_call_id=call_id,stop_reason=reason,data=None,snapshots=[],evidence=[],truncated=False,
            stop_verified=process['tree_finished'] if os.name=='nt' else False,
            limitations=['Controller failure is not an incident root cause. Sealed operation files are retained; repeat the original operation key or inspect its saved run.'])
        response=_write_response(directory/'error-response.json',value,130 if cancelled else 3,plan)
    worker=_worker_observation(state,admitted.get('run_id') if admitted and action=='run' else None,current.get('child') or {})
    receipt=dict(schema_version=1,call_id=call_id,status='finished',action=action,owner=owner,limits=limits,controller=process,
        response=response,worker_observation=worker,operation_run_id=admitted.get('run_id') if admitted else None,model_tokens=None,harness_memory_bytes=None,
        transport=dict(elapsed_before_delivery_seconds=time.monotonic()-started,full_response_json_decoded=False,
            memory_peak_bytes=None,scope='bounded small metadata and chunked response transport; no separate OS quota for setup/receipt/stream I/O'),
        stop_reason=reason,plan_sha256=fs.digest(plan))
    if (directory/'metrics.json').exists():receipt['controller_metrics']=fs.read(directory/'metrics.json',65536)
    _write_checked(directory/'call-receipt.json',receipt);current.update(status='finished');fs.write(directory/'status.json',current)
    return dict(call_id=call_id,folder=str(directory),response_name=response['name'],exit_code=response['exit_code'])


def inspect_call(state,call_id):
    directory=folder(state,call_id);plan=fs.read(directory/'plan.json',65536)
    if fs.digest(plan)!=fs.read(directory/'plan-receipt.json',8192).get('sha256') or plan.get('call_id')!=call_id:raise InputError('kernel plan integrity mismatch')
    if (directory/'call-receipt.json').exists():
        receipt=_checked(directory/'call-receipt.json',128*1024)
        if receipt.get('plan_sha256')!=fs.digest(plan) or receipt.get('call_id')!=call_id:raise InputError('kernel call receipt integrity mismatch')
        _response(directory,plan,receipt['response']['name'])
        return receipt
    current=fs.read(directory/'status.json',65536)
    if current['status']=='finished':current.update(status='partial',result_availability='incomplete_invocation_receipt')
    return dict(current,observed_owner=fs.inspect_process(current['owner']),
        observed_child=fs.inspect_process(current['child']) if current.get('child') else dict(state='unknown'),
        limits=plan['limits'],model_tokens=None,harness_memory_bytes=None,
        limitations=['Unfinished invocation; no automatic restart or stale-heartbeat takeover.'])


def emit(call,output):
    directory=fs.safe(call['folder']);plan=fs.read(directory/'plan.json',65536)
    receipt=_response(directory,plan,call['response_name'],verify=False)
    decoder=codecs.getincrementaldecoder('utf-8')()
    with fs.safe(directory/receipt['name']).open('rb') as stream:
        identity=_stream_identity(stream,MAX_RESPONSE)
        if any(receipt.get(k)!=v for k,v in identity.items()):raise InputError('kernel response integrity mismatch')
        before=os.fstat(stream.fileno());stream.seek(0)
        while block:=stream.read(CHUNK):output.write(decoder.decode(block))
        output.write(decoder.decode(b'',final=True));output.flush()
        after=os.fstat(stream.fileno())
        if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise InputError('kernel response changed during delivery; do not treat a partial stream as a result')
