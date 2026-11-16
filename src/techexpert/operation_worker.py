"""Fixed catalogue worker; own lifetime budget continues without an AI/harness wait."""
import os
from pathlib import Path
import signal
import sys
import threading
import time

if __package__ in (None,''):
    sys.path.insert(0,sys.argv[2]);__package__='src.techexpert'

from . import operation_state as state
from . import __version__,kernel_context
from .capabilities import execute
from .inputs import InputError
from .storage import ROOT,knowledge_revision

def main(folder):
    folder=state.safe(folder);plan=state.plan(folder);request=plan['request'];started=time.monotonic()
    state.write(folder/'worker-identity.json',state.process_identity(os.getpid()))
    deadline=plan['deadline_monotonic']
    if os.name!='nt':
        import resource
        inherited=resource.getrlimit(resource.RLIMIT_AS)
        memory=min([1024**3]+[n for n in inherited if n!=resource.RLIM_INFINITY])
        resource.setrlimit(resource.RLIMIT_AS,(memory,memory))
    def stop():
        if state.safe(folder/'cancel.json').exists():return 'cancelled'
        if plan.get('kernel') and kernel_context.stop(plan['kernel']):return 'timeout'
        if time.monotonic()>=deadline:return 'timeout'
        return None
    def watchdog():
        while True:
            if stop():
                time.sleep(2)
                if os.name=='nt':os._exit(124)
                # Our session/group was created by operation_process, not inherited.
                if os.getsid(0)==os.getpid():os.killpg(os.getpid(),signal.SIGKILL)
                os._exit(124)
            time.sleep(.05)
    threading.Thread(target=watchdog,daemon=True).start()
    while not state.safe(folder/'start-permit.json').exists():
        if stop() or time.monotonic()-started>10:return 124
        time.sleep(.02)
    permit=state.read(folder/'start-permit.json',8192)
    if permit.get('plan_sha256')!=state.digest(plan) or permit.get('child')!=state.process_identity(os.getpid()):
        raise InputError('worker start permit does not match plan and process lifetime')
    if plan['versions']!=dict(product=__version__,rules_inventory_sha256=state.digest(state.read(ROOT/'src/techexpert/assets/bundle-manifest.json',1024**2)),knowledge=knowledge_revision()):
        raise InputError('worker versions/rules differ from the reviewed plan')
    state.write(folder/'worker-started.json',dict(plan_sha256=state.digest(plan),child=state.process_identity(os.getpid()),at=state.stamp()))
    outcome='succeeded';data=None;targets=[];message=None
    try:
        data,targets=execute(request['operation'],request['arguments'],Path(plan['state_dir']),folder/'work-state',stop=stop)
        collection=data.get('result',{}).get('collection_status')
        if collection=='cancelled':outcome='cancelled'
        elif collection and collection!='completed':outcome='partial'
    except (OSError,ValueError,KeyError,TypeError,RecursionError) as exc:
        outcome='invalid_input' if isinstance(exc,(InputError,ValueError)) else 'failed';message=str(exc)[:2048]
    metrics=dict(elapsed_seconds=time.monotonic()-started,model_tokens=None,harness_memory_bytes=None)
    if os.name!='nt':
        usage=resource.getrusage(resource.RUSAGE_SELF);children=resource.getrusage(resource.RUSAGE_CHILDREN)
        metrics.update(self_cpu_seconds=usage.ru_utime+usage.ru_stime,terminated_children_cpu_seconds=children.ru_utime+children.ru_stime,
            peak_self_rss_bytes=usage.ru_maxrss*1024,concurrent_tree_peak_rss_bytes=None,effective_address_space_limit_bytes=memory)
    result=dict(schema_version=1,status=outcome,data=data,targets=targets,message=message,metrics=metrics)
    if len(state.encode(result))>request['budget']['max_result_bytes']:
        result.update(status='failed',data=None,targets=[],stop_reason='output_limit',message='Operation output exceeds result byte limit; owned partial files retained privately.')
    state.write(folder/'worker-result.json',result);state.write(folder/'worker-receipt.json',dict(sha256=state.digest(result)))
    return 0

if __name__=='__main__':raise SystemExit(main(Path(sys.argv[1])))
