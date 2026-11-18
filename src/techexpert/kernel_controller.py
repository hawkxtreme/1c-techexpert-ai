"""Fixed bounded engine process; no runtime arbitrary-code or provider setting."""
import hashlib
import gc
import os
from pathlib import Path
import platform
import signal
import sys
import threading
import time

if __package__ in (None,''):
    sys.path.insert(0,sys.argv[2]);__package__='src.techexpert'

from . import operation_state as fs,kernel_context as context
from .inputs import InputError,read_snapshot,json_value


def main(folder,memory_bytes):
    if os.name!='nt':
        import resource
        inherited=resource.getrlimit(resource.RLIMIT_AS)
        effective_memory=min([memory_bytes]+[n for n in inherited if n!=resource.RLIM_INFINITY])
        resource.setrlimit(resource.RLIMIT_AS,(effective_memory,effective_memory))
    directory=fs.safe(folder);plan=fs.read(directory/'plan.json',65536)
    if fs.digest(plan)!=fs.read(directory/'plan-receipt.json',8192).get('sha256') or plan.get('call_id')!=directory.name:raise InputError('kernel call plan integrity mismatch')
    if os.name!='nt' and os.getsid(0)!=os.getpid():raise InputError('controller session is not owned')
    active=dict(call_id=plan['call_id'],parent=plan['parent'],limits=plan['limits'],deadline=plan['started_monotonic']+plan['limits']['admission_seconds'])
    active['cancel_file']=str(directory/'cancel.json')
    context.install(active)
    def watchdog():
        while True:
            if context.stop():
                time.sleep(3)
                if os.name!='nt':os.killpg(os.getpid(),signal.SIGKILL)
                os._exit(124)
            time.sleep(.05)
    threading.Thread(target=watchdog,daemon=True).start()
    while not (directory/'start-permit.json').exists():
        if context.stop():return 124
        time.sleep(.01)
    permit=fs.read(directory/'start-permit.json',8192)
    if permit.get('plan_sha256')!=fs.digest(plan) or permit.get('child')!=fs.process_identity(os.getpid()):raise InputError('kernel permit process identity mismatch')
    from . import capabilities,operations,kernel
    started=time.monotonic();admitted_at=started;response_limit=kernel.MAX_RESPONSE;run_id=None
    try:
        action=plan['action'];args=kernel._arguments(action,plan['arguments']);request=None;run_id=args.get('run_id')
        timeout=plan['limits']['query_seconds']
        if action=='run':
            request=capabilities.normalize_request(json_value(read_snapshot(args['request'],128*1024).decode('utf-8-sig'),reject_duplicates=True))
            timeout=request['budget']['timeout_seconds'];response_limit=request['budget']['max_result_bytes']
            run_id=hashlib.sha256(request['operation_key'].encode()).hexdigest()
        active['deadline']=plan['started_monotonic']+timeout
        fs.write(directory/'admitted.json',dict(plan_sha256=fs.digest(plan),run_id=run_id,timeout_seconds=timeout))
        admitted_at=time.monotonic()
        if context.stop():raise TimeoutError(context.stop())
        state=Path(plan['state_dir'])
        if action=='run':value=operations.run(state,request)
        elif action=='context-read':
            from .context_disclosure import read
            value=read(state,json_value(args['selection'],reject_duplicates=True))
        elif action=='cancel':value=operations.cancel(state,args['run_id'],executor_id=args['executor_id'])
        elif action=='inspect':value=dict(status='succeeded',call=kernel.inspect_call(state,args['call_id']))
        else:value={'result':operations.result,'status':operations.status,'reconcile':operations.reconcile}[action](state,args['run_id'])
        code={'succeeded':0,'partial':1,'invalid_input':2,'failed':3,'cancelled':130,'interrupted':1}.get(value['status'],1)
    except MemoryError:
        value=dict(status='failed',stop_reason='kernel_memory_limit',run_id=run_id,data=None);code=3
    except TimeoutError as exc:
        cancelled=str(exc)=='cancelled'
        value=dict(status='cancelled' if cancelled else 'failed',stop_reason='cancelled' if cancelled else 'kernel_timeout',run_id=run_id,data=None);code=130 if cancelled else 3
    except (OSError,ValueError,KeyError,TypeError,RecursionError) as exc:
        message='The selected local context view could not be prepared.' if plan['action']=='context-read' else str(exc)[:512]
        value=dict(status='error',message=message,data=None);code=2
    dispatch_finished=time.monotonic()
    try:
        from .responses import normalize
        value=context.attach(normalize(value,operation=request['operation'] if request else None,run_id=run_id))
        if len(fs.encode(value))>response_limit:value=context.attach(dict(status='failed',stop_reason='output_limit',data=None));code=3
        kernel._write_response(directory/'response.json',value,code,plan)
    except MemoryError as exc:
        exc.__traceback__=None;value=None;gc.collect()
        value=context.attach(dict(status='failed',stop_reason='kernel_memory_limit',run_id=run_id,data=None));code=3
        kernel._write_response(directory/'response.json',value,code,plan)
    metrics=dict(python=sys.version.split()[0],platform=platform.platform(),machine=platform.machine(),logical_cpus=os.cpu_count(),
        admission_seconds=admitted_at-started,dispatch_seconds=dispatch_finished-admitted_at,
        response_save_seconds=time.monotonic()-dispatch_finished,model_tokens=None,harness_memory_bytes=None)
    if os.name!='nt':
        own=resource.getrusage(resource.RUSAGE_SELF);children=resource.getrusage(resource.RUSAGE_CHILDREN)
        metrics.update(self_cpu_seconds=own.ru_utime+own.ru_stime,terminated_children_cpu_seconds=children.ru_utime+children.ru_stime,
            peak_self_rss_bytes=own.ru_maxrss*1024,terminated_children_peak_rss_bytes=children.ru_maxrss*1024,
            concurrent_tree_peak_rss_bytes=None,effective_address_space_limit_bytes=effective_memory,
            terminated_children_rss_semantics='largest reaped-child ru_maxrss; not concurrent tree peak',
            scope='Linux self and reaped-child counters; no aggregate tree RSS cap/peak')
    fs.write(directory/'metrics.json',metrics)
    return 0


if __name__=='__main__':raise SystemExit(main(Path(sys.argv[1]),int(sys.argv[3])))
