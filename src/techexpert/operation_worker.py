"""Fixed catalogue worker; own lifetime budget continues without an AI/harness wait."""
import hashlib
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
from .capabilities import execute,outcome as output_status,PROGRAM_EXECUTIONS
from .inputs import InputError, SnapshotReadError
from .processes import CommandStopped
from .storage import ROOT,knowledge_revision

def main(folder):
    folder=state.safe(folder);plan=state.plan(folder);request=plan['request'];started=time.monotonic()
    state.write(folder/'worker-identity.json',state.process_identity(os.getpid()))
    deadline=plan['deadline_monotonic']
    memory = 1024**3
    if os.name!='nt':
        import resource
        inherited=resource.getrlimit(resource.RLIMIT_AS)
        requested=request['arguments']['resources']['memory_bytes'] if request['operation'] in PROGRAM_EXECUTIONS else 1024**3
        memory=min([requested]+[n for n in inherited if n!=resource.RLIM_INFINITY])
        resource.setrlimit(resource.RLIMIT_AS,(memory,memory))
    def stop():
        if state.safe(folder/'cancel.json').exists():return 'cancelled'
        boundary_stop=kernel_context.stop(plan['kernel']) if plan.get('kernel') else None
        if boundary_stop:return boundary_stop
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
    if request['operation'] in PROGRAM_EXECUTIONS:
        boundary=plan.get('kernel',{})
        markers=list(boundary.get('cancel_files',[]))+[str(folder/'cancel.json')]
        if boundary.get('cancel_file'):markers.append(boundary['cancel_file'])
        kernel_context.install(dict(call_id=boundary.get('call_id',folder.name),deadline=deadline,
            parent=state.process_identity(os.getpid()),cancel_files=list(dict.fromkeys(markers)),
            limits=dict(memory_bytes=request['arguments']['resources']['memory_bytes'])))
    outcome='succeeded';data=None;targets=[];message=None;stop_reason=None;command_stop=None
    from . import profile_journals
    try:
        from .os_observation import execution_arguments
        bound = plan.get('kernel',{}).get('limits',{}).get('memory_bytes',memory)
        args=execution_arguments(request,plan,folder.name)
        operation = request['operation']
        selected_journal = 'profile_journal' in args
        if selected_journal:
            data, targets = profile_journals.execute(operation, args, Path(plan['state_dir']), folder/'work-state',
                                                      plan['context'], stop=stop)
        else:
            data,targets=execute(operation,args,Path(plan['state_dir']),folder/'work-state',
                                 stop=stop, memory_bytes=min(memory,bound))
        if operation in PROGRAM_EXECUTIONS:outcome=data['result_status']
        else:outcome,stop_reason=output_status(operation,data)
        if selected_journal:
            reason = profile_journals.partial_reason(operation, args, data)
            if reason is not None:
                outcome, stop_reason = 'partial', reason
    except CommandStopped as exc:
        outcome='cancelled' if exc.reason=='cancelled' else 'failed';stop_reason=exc.reason
        message='Bounded command stopped: '+exc.reason+'. Private partial output retained; no source artifact created.'
        files=[]
        for name,raw in [('command-partial-stdout.bin',exc.stdout),('command-partial-stderr.bin',exc.stderr)]:
            if not isinstance(raw,bytes) or len(raw)>64*1024**2:raise InputError('invalid bounded command capture')
            with state.safe(folder/name).open('xb') as stream:
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            files.append(dict(path=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
        command_stop=dict(reason=exc.reason,process_started=exc.process_started,returncode=exc.returncode,files=files)
        state.write(folder/'command-stop.json',command_stop)
    except (OSError,ValueError,KeyError,TypeError,RecursionError) as exc:
        outcome='invalid_input' if isinstance(exc,(InputError,ValueError)) else 'failed';message=str(exc)[:2048]
        if isinstance(exc, profile_journals.PreviewChanged):
            stop_reason = 'journal_preview_changed'
        elif (isinstance(exc, SnapshotReadError)
              and request['arguments'].get('profile_journal', {}).get('read_mode') == profile_journals.FIXED_PREFIX):
            stop_reason = profile_journals.PREFIX_FAILURES.get(exc.code)
    metrics=dict(elapsed_seconds=time.monotonic()-started,model_tokens=None,harness_memory_bytes=None)
    if command_stop is not None:metrics['command_stop']=command_stop
    if os.name!='nt':
        usage=resource.getrusage(resource.RUSAGE_SELF);children=resource.getrusage(resource.RUSAGE_CHILDREN)
        metrics.update(self_cpu_seconds=usage.ru_utime+usage.ru_stime,terminated_children_cpu_seconds=children.ru_utime+children.ru_stime,
            peak_self_rss_bytes=usage.ru_maxrss*1024,concurrent_tree_peak_rss_bytes=None,effective_address_space_limit_bytes=memory)
    result=dict(schema_version=1,status=outcome,data=data,targets=targets,message=message,metrics=metrics,stop_reason=stop_reason)
    if len(state.encode(result))>request['budget']['max_result_bytes']:
        result.update(status='failed',data=None,targets=[],stop_reason='output_limit',message='Operation output exceeds result byte limit; owned partial files retained privately.')
    state.write(folder/'worker-result.json',result);state.write(folder/'worker-receipt.json',dict(sha256=state.digest(result)))
    return 0

if __name__=='__main__':raise SystemExit(main(Path(sys.argv[1])))
