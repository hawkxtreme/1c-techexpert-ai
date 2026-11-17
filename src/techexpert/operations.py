"""Durable single-owner SC01 runs. Repeated keys reuse evidence, never repeat work."""
import hashlib
import os
from pathlib import Path
import shutil
import time

from . import __version__
from . import capabilities,operation_state as fs,operation_process,kernel_context
from .inputs import InputError
from .storage import ROOT

TERMINAL={'succeeded','partial','invalid_input','failed','cancelled','interrupted'}
FLOOR=10*1024**3
DISK=256*1024**2

def _semantic(request):return {k:v for k,v in request.items() if k!='executor_id'}
def _space(path):
    for parent in (path,*path.parents):
        if parent.exists():
            if shutil.disk_usage(parent).free<FLOOR:raise InputError('not enough free space; managed operations retain a 10 GiB floor; select a local state volume with space')
            return
    raise InputError('operation volume is unavailable')

def _context(state,request):
    if 'context' not in request:return None
    from .investigations import load
    context=request['context'];doc=load(state,context['investigation_id'])
    if doc['revision']!=context['expected_revision']:raise InputError('investigation revision conflict; reload before a new operation')
    return dict(**context,report_sha256=fs.digest(doc),profile_sha256=doc['profile_sha256'])

def _versions():
    from .storage import knowledge_revision
    manifest=fs.read(ROOT/'src/techexpert/assets/bundle-manifest.json',1024**2)
    return dict(product=__version__,rules_inventory_sha256=fs.digest(manifest),knowledge=knowledge_revision())

def _verify_target(state,kind,identifier,*,inputs=None):
    if kind not in ('cases','artifacts','comparisons') or not isinstance(identifier,str) or len(identifier)!=32 or any(c not in 'abcdef0123456789' for c in identifier):
        raise InputError('invalid operation product identity')
    fs.inventory(fs.safe(Path(state)/kind/identifier))
    if kind=='cases':
        from .storage import verified_case
        return verified_case(state,identifier)
    if kind=='artifacts':
        from .artifacts import load_artifact
        return load_artifact(state,identifier)
    from .storage import load_comparison
    return load_comparison(state,identifier,input_state_dir=inputs)

def _promote(state,folder,worker):
    targets=worker['targets']
    if not isinstance(targets,list) or len(targets)>1:raise InputError('unexpected operation products')
    for target in targets:
        kind=target['kind'];identifier=target['id']
        source=fs.safe(folder/'work-state'/kind/identifier);destination=fs.safe(Path(state)/kind/identifier)
        root=folder/'work-state' if source.exists() else state
        loaded=_verify_target(root,kind,identifier,inputs=state)
        if fs.digest(loaded)!=fs.digest(worker['data']):raise InputError('operation product disagrees with sealed worker output')
        if source.exists():
            if destination.exists():raise InputError('operation product target already exists; refusing replacement')
            fs.private(destination.parent);os.rename(source,destination)
            from .windows_native import protect_directory
            protect_directory(destination)
        _verify_target(state,kind,identifier)

def _snapshots(state,operation,args,data,*,output=None):
    if data is None:return []
    references=[]
    def add(kind,identifier):
        target_state=output if output is not None and (output/kind/identifier).exists() else state
        report=_verify_target(target_state,kind,identifier,inputs=state)
        reference=dict(kind=kind,id=identifier,report_digest=fs.digest(report))
        base=Path(target_state)/kind/identifier
        reference['receipt_digest']=fs.digest(fs.read(base/'receipt.json',8192))
        if reference not in references:references.append(reference)
        return report
    if operation.startswith('case.') and operation!='case.compare':add('cases',data.get('case_id',args.get('case_id')))
    elif operation in ('case.compare','comparison.show'):
        report=add('comparisons',data['comparison_id'])
        for item in report['input_reports']:add('cases',item['case_id'])
    elif operation in ('os.collect','os.import','artifact.show'):add('artifacts',data['artifact_id'])
    elif operation=='code.execute':
        for call in data['calls']:
            for reference in call.get('snapshots',[]):
                add(reference['kind'],reference['id'])
                if reference not in references:raise InputError('CodeMode retained snapshot identity mismatch')
    return references

def _worker(folder):
    value=fs.read(folder/'worker-result.json');receipt=fs.read(folder/'worker-receipt.json',8192)
    if (not isinstance(value,dict) or value.get('schema_version')!=1 or fs.digest(value)!=receipt.get('sha256')
        or value.get('status') not in TERMINAL or not isinstance(value.get('targets'),list)):
        raise InputError('sealed worker result integrity mismatch')
    return value

def _fit_view(view,budget,*,strict=False):
    view=kernel_context.attach(view)
    if len(fs.encode(view))<=budget:return view
    if strict:raise InputError('output_limit')
    review=view.get('current_knowledge_review',{})
    review_status=review.get('status','not_checked')
    if not isinstance(review_status,str) or len(review_status)>64:review_status='unknown'
    snapshots=view.get('snapshots',[]);evidence=view.get('evidence',[])
    execution_status=view.get('execution_status',view['status'])
    small=dict(schema_version=1,run_id=view['run_id'],operation=view['operation'],
        status='partial' if view['status'] in TERMINAL else view['status'],execution_status=execution_status,
        data=None,data_omitted=True,truncated=True,snapshots=snapshots[:3],evidence=evidence[:3],
        omitted_snapshots=max(0,len(snapshots)-3),omitted_evidence=max(0,len(evidence)-3),
        full_result_retained=bool(view.get('integrity_verified')),integrity_verified=bool(view.get('integrity_verified')),
        replayed=bool(view.get('replayed')),limits=view['limits'],stop_verified=view.get('stop_verified',False),
        cancellation_requested=view.get('cancellation_requested',False),
        current_knowledge_review=dict(status=review_status,review_required=review_status!='unchanged',
            technical_truth_judged=False,truncated=True,scope='bounded presentation only; inspect applicable knowledge before reuse'),
        limitations=['Full current presentation exceeds max_result_bytes. Stored result is unchanged; no processing was repeated. Data and review details are omitted.'])
    for key in ('owner','child','cancel_too_late','current_product_version','recovery_previous_reason','kernel_call_id','kernel_limits'):
        if key in view:small[key]=view[key]
    if len(fs.encode(small))>budget:raise InputError('output_limit')
    return small

def _present(state,plan,value,*,replayed,strict=False,recovery_reason=None):
    from .knowledge_review import review_legacy_report,review_use
    data=value['data'] or {};request=plan['request']
    if request['operation']=='artifact.show' and data.get('kind')=='knowledge_use':
        knowledge_review=review_use(state,data['artifact_id'])
    else:
        basis=(data if 'knowledge_revision' in data and not request['operation'].startswith('knowledge.')
            else dict(knowledge_revision=plan['versions'].get('knowledge')))
        knowledge_review=review_legacy_report(basis)
    view=dict(value,integrity_verified=True,replayed=replayed,current_product_version=__version__,current_knowledge_review=knowledge_review,
        cancellation_requested=value.get('cancellation_requested',False) or fs.safe(fs.folder(state,value['run_id'])/'cancel.json').exists())
    if recovery_reason is None:
        recovery_reason=fs.read(fs.folder(state,value['run_id'])/'status.json',64*1024).get('recovery_previous_reason')
    if recovery_reason:
        if not isinstance(recovery_reason,str) or len(recovery_reason)>512:raise InputError('invalid recovery diagnostic')
        view['recovery_previous_reason']=recovery_reason
    return _fit_view(view,request['budget']['max_result_bytes'],strict=strict)

def _nested_stopped(state,folder,plan,current):
    if plan['request']['operation']!='code.execute':return True
    if current.get('process',{}).get('tree_finished') is True and os.name=='nt':return True
    from .code_runtime import nested_observations
    return nested_observations(state,folder.name)['stop_verified']


def _program_guard(state,folder,plan,*,finishing=False,reserve_bytes=0,reserve_files=0):
    if plan['request']['operation']!='code.execute':return None
    from .code_runtime import enforce_owned_limit
    return enforce_owned_limit(state,folder.name,require_audit=finishing,reserve_bytes=reserve_bytes,reserve_files=reserve_files)


def _finish(state,folder,plan,current,worker,*,replayed=False,parent_guard=None):
    request=plan['request'];data=worker['data']
    if not _nested_stopped(state,folder,plan,current):raise InputError('nested program jobs are active or unknown; retain evidence')
    _program_guard(state,folder,plan,finishing=True)
    if request['operation']=='code.execute' and data is not None:
        from .code_runtime import verify_audit
        verify_audit(state,folder.name,data)
    snapshots=_snapshots(state,request['operation'],request['arguments'],data,output=folder/'work-state')
    def truncated(value):
        if isinstance(value,dict):return any((v is True and (k=='truncated' or k.endswith('_truncated') or k=='preview_limited')) or (k=='next_offset' and v is not None) or truncated(v) for k,v in value.items())
        return isinstance(value,list) and any(truncated(v) for v in value)
    collection_status=data.get('result',{}).get('collection_status') if isinstance(data,dict) else None
    stop_reason=worker.get('stop_reason') or ('cancelled' if worker['status']=='cancelled' else collection_status if collection_status not in (None,'completed') else None)
    value=dict(schema_version=1,run_id=folder.name,operation=request['operation'],status=worker['status'],data=data,
        executor_id=request['executor_id'],executor_identity_basis='caller_reported',context=plan['context'],versions=plan['versions'],
        snapshots=snapshots,evidence=[dict(kind=s['kind'],id=s['id'],report_digest=s['report_digest']) for s in snapshots],
        limits=request['budget'],metrics=worker['metrics'],process=current.get('process'),stop_reason=stop_reason,
        stop_verified=True,cancellation_requested=(folder/'cancel.json').exists(),truncated=bool(truncated(data)),
        message=worker.get('message'),limitations=[
            'Tool execution and source checks are not AI diagnosis or historical completeness.',
            'Executor ID is caller-reported; this is a local run registry, not an authorization service.',
            'Model/harness resources are unknown. Disk budgets are monitored, not an atomic filesystem quota.',
            ('Managed CLI controller admission/replay/finalization is bounded and measured separately in kernel-call receipts; thin transport remains outside that process quota.' if kernel_context.current() else 'Direct internal engine: worker limits exclude admission, replay and final control-layer verification/commit.'),
            'Remote SSH/WinRM process stop is unknown after an interrupted connection; the remote probe has its own duration bound.',
            'Source-check and knowledge reads retain their bounded output, not an independent full source snapshot.'])
    prepared_path=folder/'prepared-output.json'
    if prepared_path.exists():
        prepared=fs.read(prepared_path)
        if not isinstance(prepared,dict):raise InputError('prepared output integrity mismatch')
        sealed=prepared.get('value')
        if (prepared.get('schema_version')!=1 or not isinstance(sealed,dict) or type(sealed.get('cancellation_requested')) is not bool
            or prepared.get('sha256')!=fs.digest(sealed) or prepared.get('plan_sha256')!=fs.digest(plan)
            or prepared.get('worker_sha256')!=fs.digest(worker)
            or type(prepared.get('full_reply_bytes')) is not int
            or not 0<prepared['full_reply_bytes']<=request['budget']['max_result_bytes']
            or fs.digest(dict(value,cancellation_requested=sealed['cancellation_requested']))!=fs.digest(sealed)):
            raise InputError('prepared output integrity mismatch')
        value=sealed
        presented=None
    else:
        # Seal the exact first payload only after the entire original view fits.
        # Recovery diagnostics must never grow/rewrite that validated payload.
        presented=_present(state,plan,value,replayed=False,strict=True,recovery_reason='')
        fs.write(prepared_path,dict(schema_version=1,value=value,sha256=fs.digest(value),plan_sha256=fs.digest(plan),
            worker_sha256=fs.digest(worker),full_reply_bytes=len(fs.encode(presented))))
    _program_guard(state,folder,plan,finishing=True)
    recovery_reason=current.get('recovery_previous_reason') or (current.get('stop_reason') if replayed else None)
    if presented is None or replayed:
        presented=_present(state,plan,value,replayed=replayed,recovery_reason=recovery_reason)
    output=folder/'output.json'
    if output.exists() and fs.digest(fs.read(output))!=fs.digest(value):raise InputError('incomplete output disagrees with prepared output; refusing replacement')
    if parent_guard:parent_guard(force=True)
    _promote(state,folder,worker)
    if parent_guard:parent_guard(force=True)
    if _snapshots(state,request['operation'],request['arguments'],data)!=snapshots:raise InputError('promoted snapshot changed before result commit')
    if not output.exists():fs.write(output,value)
    # Leave a bounded64KiB for the receipt and advisory status/journal. Large
    # output/prepared files are measured before any public result receipt.
    _program_guard(state,folder,plan,finishing=True,reserve_bytes=65536,reserve_files=2)
    fs.write(folder/'output-receipt.json',dict(sha256=fs.digest(value)))
    current.update(status=value['status'],finished_at=fs.stamp(),heartbeat_at=fs.stamp(),stop_verified=True,stop_reason=stop_reason)
    if recovery_reason:current['recovery_previous_reason']=recovery_reason
    fs.record(folder,current,'result_verified');return presented

def result(state,run_id):
    folder=fs.folder(state,run_id);plan=fs.plan(folder)
    if not (folder/'output.json').exists() or not (folder/'output-receipt.json').exists():return status(state,run_id)
    value=fs.read(folder/'output.json');receipt=fs.read(folder/'output-receipt.json',8192)
    if value.get('run_id')!=run_id or fs.digest(value)!=receipt.get('sha256'):raise InputError('operation output integrity mismatch')
    if plan['request']['operation']=='code.execute' and value['data'] is not None:
        from .code_runtime import verify_audit
        verify_audit(state,run_id,value['data'])
    for snapshot in value['snapshots']:
        report=_verify_target(state,snapshot['kind'],snapshot['id'])
        if fs.digest(report)!=snapshot['report_digest'] or fs.digest(fs.read(Path(state)/snapshot['kind']/snapshot['id']/'receipt.json',8192))!=snapshot['receipt_digest']:
            raise InputError('operation retained snapshot identity mismatch')
    return _present(state,plan,value,replayed=True)

def status(state,run_id):
    folder=fs.folder(state,run_id);plan=fs.plan(folder);current=fs.read(folder/'status.json',64*1024)
    has_output=(folder/'output.json').exists();has_receipt=(folder/'output-receipt.json').exists()
    if current['status'] in TERMINAL and has_output and has_receipt:return result(state,run_id)
    owner=fs.inspect_process(current['owner']);child=fs.inspect_process(current['child']) if current.get('child') else dict(state='not_recorded')
    view=dict(current,operation=plan['request']['operation'],cancellation_requested=(folder/'cancel.json').exists(),
        observed_processes=dict(owner=owner,child=child),stop_verified=current.get('stop_verified',False),data=None,
        snapshots=[],evidence=[],truncated=False,context=plan['context'],limits=plan['request']['budget'],
        limitations=['Heartbeat age alone does not establish process completion. No request is restarted by status.'])
    if has_output!=has_receipt:
        view.update(status='partial',execution_status=current['status'],result_availability='incomplete_commit')
    return _fit_view(view,plan['request']['budget']['max_result_bytes'])

def cancel(state,run_id,*,executor_id):
    capabilities.validate(executor_id,capabilities.string(128,pattern='[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}'))
    folder=fs.folder(state,run_id);current=status(state,run_id)
    if current['status'] in TERMINAL:return _fit_view(dict(current,cancel_too_late=True),current['limits']['max_result_bytes'])
    path=fs.safe(folder/'cancel.json')
    if not path.exists():fs.write(path,dict(requested_at=fs.stamp(),executor_id=executor_id,reason='user_requested'))
    updated=status(state,run_id)
    if updated['status'] in TERMINAL:updated=dict(updated,cancel_too_late=True)
    return _fit_view(updated,updated['limits']['max_result_bytes'])

def run(state,request,*,parent_guard=None):
    original=request;state=fs.safe(state);request=capabilities.normalize_request(request)
    run_id=hashlib.sha256(request['operation_key'].encode()).hexdigest();folder=fs.folder(state,run_id)
    if folder.exists():
        for _ in range(50):
            if (folder/'plan-receipt.json').exists():break
            time.sleep(.01)
        old=fs.plan(folder)
        if _semantic(old['request'])!=_semantic(request):raise InputError('operation key conflict; a changed request requires a new key')
        return _fit_view(dict(result(state,run_id),replayed=True),request['budget']['max_result_bytes'])
    context=_context(state,request);_space(state);versions=_versions()
    fs.private(folder.parent)
    try:folder.mkdir()
    except FileExistsError:return run(state,original,parent_guard=parent_guard)
    fs.private(folder)
    with fs.writer(folder):
        started=time.monotonic();plan=dict(schema_version=1,request=request,state_dir=str(state),context=context,versions=versions,
            deadline_monotonic=started+request['budget']['timeout_seconds'],created_at=fs.stamp())
        boundary=kernel_context.current()
        if boundary:
            plan['deadline_monotonic']=min(plan['deadline_monotonic'],boundary['deadline'])
            plan['kernel']=dict(call_id=boundary['call_id'],deadline=boundary['deadline'],parent=boundary['parent'])
            if boundary.get('cancel_file'):plan['kernel']['cancel_file']=boundary['cancel_file']
            if boundary.get('cancel_files'):plan['kernel']['cancel_files']=boundary['cancel_files']
            if boundary.get('limits'):plan['kernel']['limits']=boundary['limits']
        fs.write(folder/'plan.json',plan)
        current=dict(schema_version=1,run_id=run_id,status='preparing',owner=fs.process_identity(os.getpid()),child=None,
            executor_id=request['executor_id'],heartbeat_at=fs.stamp(),started_at=fs.stamp(),timeout_seconds=request['budget']['timeout_seconds'],stop_verified=False)
        fs.record(folder,current,'claimed');fs.private(folder/'work-state')
        fs.write(folder/'plan-receipt.json',dict(sha256=fs.digest(plan)))
        stopping=None;last_check=0;last_heartbeat=started
        def stop_reason():
            if (folder/'cancel.json').exists():return 'cancelled'
            boundary_stop=kernel_context.stop()
            if boundary_stop:return boundary_stop
            if time.monotonic()>=plan['deadline_monotonic']:return 'timeout'
        def guard():
            nonlocal stopping,last_check,last_heartbeat
            if parent_guard:parent_guard()
            now=time.monotonic();reason=stop_reason()
            if current['status']=='starting' and (folder/'worker-started.json').exists():
                observed=fs.read(folder/'worker-started.json',8192)
                if observed.get('child')!=current['child'] or observed.get('plan_sha256')!=fs.digest(plan):raise InputError('worker start acknowledgement disagrees with owned process')
                current.update(status='running',heartbeat_at=fs.stamp());fs.record(folder,current,'execution_started')
            if reason:
                if stopping is None:
                    stopping=now;current.update(status='stopping',stop_reason=reason);fs.record(folder,current,'stop_requested')
                if now-stopping>=2:raise InputError(reason)
            if now-last_check>=.2:
                last_check=now;usage=fs.inventory(folder);_space(folder)
                if usage['bytes']>DISK:raise InputError('owned_disk_limit')
                program_usage=_program_guard(state,folder,plan)
                if program_usage is not None:usage=program_usage
                for name in ('stdout.bin','stderr.bin','worker-result.json'):
                    path=folder/name
                    if path.exists() and path.stat().st_size>request['budget']['max_result_bytes']:raise InputError('output_limit')
                current['owned_disk']=usage
            if now-last_heartbeat>=5:
                last_heartbeat=now;current['heartbeat_at']=fs.stamp();fs.record(folder,current,'heartbeat')
        def on_started(pid):
            if _context(state,request)!=context:raise InputError('investigation context changed before launch')
            current.update(status='starting',child=fs.process_identity(pid),heartbeat_at=fs.stamp())
            if current['child']['state']!='running' or not current['child']['lifetime']:raise InputError('worker lifetime identity unknown; execution not permitted')
            fs.record(folder,current,'child_recorded')
            fs.write(folder/'start-permit.json',dict(plan_sha256=fs.digest(plan),child=current['child']))
        try:
            guard()
            reason=stop_reason()
            if reason:
                current.update(status='cancelled' if reason=='cancelled' else 'failed',stop_verified=True,stop_reason=reason,finished_at=fs.stamp())
                fs.record(folder,current,'not_started');return status(state,run_id)
            memory=request['arguments']['resources']['memory_bytes'] if request['operation']=='code.execute' else 1024**3
            process=operation_process.run(folder,guard=guard,on_started=on_started,timeout=request['budget']['timeout_seconds']+3,memory_bytes=memory)
            current['process']=process;current['stop_verified']=process['tree_finished'] and _nested_stopped(state,folder,plan,current)
            if not process['tree_finished']:raise InputError('owned process tree stop is unknown')
            current['stop_reason']=current.get('stop_reason') or process.get('guard_error') or process.get('stop_reason')
            _program_guard(state,folder,plan)
            # Recovery must retain the controller's observed process metrics as
            # well as the worker payload before any promotion can begin.
            fs.record(folder,current,'worker_stopped')
            if process['exit_code']==0 and (folder/'worker-receipt.json').exists():return _finish(state,folder,plan,current,_worker(folder),parent_guard=parent_guard)
            reason=current['stop_reason'] or stop_reason() or 'worker_failed_before_sealed_result'
            current.update(status='cancelled' if reason=='cancelled' else 'failed',stop_reason=reason,finished_at=fs.stamp())
        except (OSError,ValueError,KeyError,TypeError) as exc:
            current.update(status='failed',stop_reason=current.get('stop_reason') or str(exc)[:512],finished_at=fs.stamp())
        fs.record(folder,current,'execution_stopped')
        return status(state,run_id)

def reconcile(state,run_id):
    folder=fs.folder(state,run_id);plan=fs.plan(folder)
    with fs.writer(folder):
        current=fs.read(folder/'status.json',64*1024)
        if current['status'] in TERMINAL and current.get('stop_verified'):
            if (folder/'output.json').exists() and (folder/'output-receipt.json').exists():return result(state,run_id)
            if not (folder/'worker-receipt.json').exists():return status(state,run_id)
        if plan['versions']!=_versions():raise InputError('operation versions/rules changed; use the compatible bundle or an explicitly reviewed migration')
        for identity in (current['owner'],current.get('child')):
            if identity is None:raise InputError('child state unknown; do not restart this key')
            observed=fs.inspect_process(identity)
            if observed['state'] not in ('not_running','different_lifetime'):raise InputError('owner or child is active/unknown; no takeover')
        if os.name!='nt' and fs.inspect_group(current['child'])['state']!='stopped':
            raise InputError('worker group is active/unknown; leader exit does not verify tree stop')
        if not _nested_stopped(state,folder,plan,current):raise InputError('nested program jobs are active or unknown; no reconciliation')
        if (folder/'worker-receipt.json').exists():
            current.update(stop_verified=True,stop_reason=current.get('stop_reason'))
            return _finish(state,folder,plan,current,_worker(folder),replayed=True)
        current.update(status='interrupted',stop_verified=True,stop_reason='no_sealed_result; retain evidence and use an explicitly reviewed new key',finished_at=fs.stamp())
        fs.record(folder,current,'reconciled_interruption');return status(state,run_id)
