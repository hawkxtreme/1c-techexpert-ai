"""Audited capability calls inside a managed program worker; no raw code execution."""
import gc
import hashlib
import os
from pathlib import Path
import sys
import time

from . import operation_state as fs,kernel_context
from .code_values import CodeError
from .inputs import InputError


def _write(path,value):fs.write(path,dict(schema_version=1,value=value,sha256=fs.digest(value)))


def _read(path,limit=2*1024**2):
    doc=fs.read(path,limit)
    if (not isinstance(doc,dict) or doc.get('schema_version')!=1 or not isinstance(doc.get('value'),dict)
        or doc.get('sha256')!=fs.digest(doc['value'])):raise InputError('CodeMode audit integrity mismatch')
    return doc['value']


def _hash_source(source):return hashlib.sha256(source.encode('utf-8')).hexdigest()


def _audit(state,run_id,*,optional=False):
    folder=fs.folder(state,run_id);plan=fs.plan(folder)
    if plan['request']['operation']!='code.execute':raise InputError('selected run is not a CodeMode execution')
    args=plan['request']['arguments'];digest=_hash_source(args['program'])
    source=_read(folder/'code-program.json',256*1024) if (folder/'code-program.json').exists() else None
    journal=_read(folder/'code-journal.json') if (folder/'code-journal.json').exists() else None
    for value in (source,journal):
        if value is not None and (value.get('parent_run_id')!=run_id or value.get('program_sha256')!=digest
            or value.get('request_sha256')!=fs.digest(plan['request'])):raise InputError('CodeMode audit does not match saved plan')
    if source is not None and (source.get('program')!=args['program'] or source.get('language')!=args['language']):raise InputError('saved CodeMode source changed')
    if journal is not None and (not isinstance(journal.get('calls'),list) or len(journal['calls'])>args['resources']['max_calls']+1):raise InputError('invalid saved CodeMode call count')
    if not optional and (source is None or journal is None):raise InputError('CodeMode audit is incomplete; no automatic program restart')
    return folder,plan,source,journal


def verify_audit(state,run_id,data):
    from . import operations
    folder,plan,source,journal=_audit(state,run_id)
    audit=data['audit']
    if (data['program_sha256']!=source['program_sha256'] or audit['program_document_sha256']!=fs.digest(source)
        or audit['journal_document_sha256']!=fs.digest(journal) or data['calls']!=journal['calls']):raise InputError('CodeMode result/audit identity mismatch')
    for call in journal['calls']:
        identifier=call.get('run_id');expected=call.get('output_sha256')
        if not identifier or expected is None:continue
        child=fs.folder(state,identifier);child_plan=fs.plan(child)
        if (fs.digest(child_plan['request'])!=call.get('request_sha256')
            or child_plan['request']['operation_key']!='code-'+run_id+'-'+str(call['index'])):raise InputError('CodeMode child request identity mismatch')
        saved=fs.read(child/'output.json');receipt=fs.read(child/'output-receipt.json',8192)
        if fs.digest(saved)!=expected or receipt.get('sha256')!=expected:raise InputError('CodeMode child output integrity mismatch')
        # Verify its retained bytes as well as the outer references. This does
        # not execute the API or open its original input paths.
        operations.result(state,identifier)
    return journal


def nested_observations(state,run_id):
    try:folder,plan,source,journal=_audit(state,run_id,optional=True)
    except (OSError,ValueError,KeyError,TypeError):return dict(stop_verified=False,status='unknown',calls=None)
    if journal is None:return dict(stop_verified=False,status='unknown',calls=None)
    observations=[]
    for call in journal['calls']:
        identifier=call.get('run_id')
        if not identifier or call.get('launch_state')=='not_created':continue
        try:
            child=fs.folder(state,identifier);child_plan=fs.plan(child)
            if (child_plan['request']['operation_key']!='code-'+run_id+'-'+str(call['index'])
                or fs.digest(child_plan['request'])!=call.get('request_sha256')):raise InputError('child identity mismatch')
            status=fs.read(child/'status.json',65536);identity=status.get('child')
            if identity is None and (child/'worker-identity.json').exists():identity=fs.read(child/'worker-identity.json',8192)
            process=fs.inspect_process(identity) if identity else dict(state='unknown')
            group=fs.inspect_group(identity) if identity and os.name!='nt' else None
            stopped=process['state'] in ('not_running','different_lifetime') and (
                group is not None and group['state']=='stopped' if os.name!='nt' else status.get('process',{}).get('tree_finished') is True)
            observations.append(dict(run_id=identifier,process=process,group=group,stop_verified=stopped))
        except (OSError,ValueError,KeyError,TypeError):observations.append(dict(run_id=identifier,stop_verified=False,state='unknown'))
    verified=all(c['stop_verified'] for c in observations)
    return dict(stop_verified=verified,status='stopped' if verified else 'unknown',calls=observations)


def inspect_program(state,run_id):
    folder,plan,source,journal=_audit(state,run_id,optional=True)
    saved=None
    if (folder/'output.json').exists() and (folder/'output-receipt.json').exists():
        saved=fs.read(folder/'output.json');receipt=fs.read(folder/'output-receipt.json',8192)
        if fs.digest(saved)!=receipt.get('sha256'):raise InputError('CodeMode output integrity mismatch')
        if saved.get('data') is not None:verify_audit(state,run_id,saved['data'])
    return dict(program_sha256=_hash_source(plan['request']['arguments']['program']),program=plan['request']['arguments']['program'],
        language=plan['request']['arguments']['language'],run_id=run_id,calls=journal['calls'] if journal else None,
        audit_available=source is not None and journal is not None,execution_status=journal.get('execution_status') if journal else 'unknown',
        saved_result_available=saved is not None,nested=nested_observations(state,run_id),
        requires_ai_interpretation=True,limitations=['Inspection never restarts a program or collects original sources. Missing audit remains unknown.'])


class Runtime:
    def __init__(self,state,folder,args,stop):
        from . import capabilities
        from .code_policy import Scope
        self.state=Path(state);self.folder=fs.safe(folder);self.plan=fs.plan(self.folder);self.args=args
        if self.plan['request']['operation']!='code.execute' or self.plan['request']['arguments']!=args:raise InputError('CodeMode worker request mismatch')
        identity=fs.process_identity(os.getpid())
        if (fs.read(self.folder/'worker-identity.json',8192)!=identity
            or fs.read(self.folder/'start-permit.json',8192).get('child')!=identity):raise InputError('CodeMode requires its exact isolated managed worker')
        if os.name!='nt' and not sys.platform.startswith('linux'):raise CodeError('isolation_unavailable','CodeMode profile is disabled on this platform.')
        if os.name!='nt':
            import resource
            actual=resource.getrlimit(resource.RLIMIT_AS)[0]
            if actual==resource.RLIM_INFINITY or actual>args['resources']['memory_bytes']:raise CodeError('isolation_unavailable','CodeMode address-space limit was not enforced.')
        self.stop=stop;self.scope=Scope(args['scope'],capabilities.CODE_API);self.resources=args['resources']
        self.started=time.monotonic();self.deadline=self.plan['deadline_monotonic'];self.calls=[];self.inner_paths=[];self.last_guard=0
        self.metrics=dict(calls_attempted=0,calls_started=0,api_response_bytes=0,observed_owned_bytes=0,observed_owned_files=0,steps=0)
        self.digest=_hash_source(args['program']);self.owner=identity
        self.common=dict(schema_version=1,parent_run_id=self.folder.name,program_sha256=self.digest,request_sha256=fs.digest(self.plan['request']))
        self.source=dict(self.common,program=args['program'],language=args['language'])
        _write(self.folder/'code-program.json',self.source);self.flush('preparing')

    def flush(self,status):
        self.journal=dict(self.common,owner=self.owner,calls=self.calls,metrics=dict(self.metrics),execution_status=status)
        _write(self.folder/'code-journal.json',self.journal)

    def guard(self,*,force=False):
        reason=self.stop() if self.stop else kernel_context.stop()
        if reason:raise CodeError('cancelled' if reason=='cancelled' else 'timeout','The program boundary requested a stop.')
        now=time.monotonic()
        if now>=self.deadline:raise CodeError('timeout','The whole program deadline was reached.')
        if not force and now-self.last_guard<.2:return
        self.last_guard=now;paths=[self.folder,*self.inner_paths]
        paths.extend(self.state/t['kind']/t['id'] for t in self.scope.products)
        used=files=0
        for path in dict.fromkeys(paths):
            if not fs.safe(path).exists():continue
            usage=fs.inventory(path);used+=usage['bytes'];files+=usage['files']
        self.metrics.update(observed_owned_bytes=used,observed_owned_files=files)
        if used>self.resources['max_owned_bytes']:raise CodeError('owned_disk_limit','Cumulative program-owned disk limit reached; partial evidence is retained.')
        if files>1000:raise CodeError('owned_file_limit','Cumulative program-owned file limit reached.')

    def api(self,operation,arguments):
        from . import capabilities,operations,responses
        index=len(self.calls)+1
        record=dict(index=index,operation=operation if operation in capabilities.CODE_API else None,status='preparing',run_id=None,
            request_sha256=None,output_sha256=None,snapshots=[],response_bytes=0,launch_state='not_created')
        self.metrics['calls_attempted']+=1;self.calls.append(record);self.flush('running')
        try:
            self.guard(force=True)
            if index>self.resources['max_calls']:raise CodeError('call_limit','The program API-call budget was reached.')
            if operation not in capabilities.CODE_API or operation not in self.scope.operations:raise CodeError('scope_denied','Operation is outside the approved API scope.')
            remaining=self.resources['max_api_bytes']-self.metrics['api_response_bytes']
            seconds=min(capabilities.ROUTES[operation]['timeout_seconds'],self.deadline-time.monotonic())
            if remaining<16384:raise CodeError('api_byte_limit','The cumulative API-result byte budget was reached.')
            if seconds<.1:raise CodeError('timeout','No program time remains for a new API job.')
            request=dict(schema_version=1,operation_key='code-'+self.folder.name+'-'+str(index),executor_id=self.plan['request']['executor_id'],
                operation=operation,arguments=arguments,budget=dict(timeout_seconds=seconds,max_result_bytes=min(remaining,capabilities.MAX_RESULT)))
            if 'context' in self.plan['request']:request['context']=self.plan['request']['context']
            request=capabilities.normalize_request(request);self.scope.authorize(operation,request['arguments'])
            identifier=hashlib.sha256(request['operation_key'].encode()).hexdigest();child=fs.folder(self.state,identifier)
            record.update(run_id=identifier,request_sha256=fs.digest(request),launch_state='dispatching');self.inner_paths.append(child)
            self.flush('running');self.metrics['calls_started']+=1
            value=operations.run(self.state,request,parent_guard=self.guard)
            record.update(status=value['status'],snapshots=value.get('snapshots',[]),response_bytes=len(fs.encode(value)),
                launch_state='created' if child.exists() else 'not_created',truncated=bool(value.get('truncated')),stop_verified=bool(value.get('stop_verified')))
            self.metrics['api_response_bytes']+=record['response_bytes']
            if (child/'output.json').exists() and (child/'output-receipt.json').exists():
                saved=fs.read(child/'output.json');receipt=fs.read(child/'output-receipt.json',8192)
                if fs.digest(saved)!=receipt.get('sha256'):raise CodeError('api_integrity','The API output receipt does not match.')
                record['output_sha256']=receipt['sha256']
            self.scope.produced(operation,value.get('data'));self.flush('running');self.guard(force=True)
            if not value.get('stop_verified'):raise CodeError('api_stop_unknown','API stop is not verified; no further jobs will be issued.')
            return value
        except CodeError as exc:
            record.update(status='denied' if record['run_id'] is None else 'failed',diagnostic=exc.code)
            self.flush('running');raise
        except (OSError,ValueError,KeyError,TypeError,RecursionError) as exc:
            record.update(status='invalid_input',diagnostic='api_error')
            if record['run_id'] is not None:
                record['launch_state']='created' if fs.folder(self.state,record['run_id']).exists() else 'not_created'
            self.flush('running')
            raise CodeError('api_error','API input/state could not be verified; inspect the retained call before another plan.') from exc


def run_program(state,output,args,*,stop=None):
    from .code_language import Machine,parse_program
    runtime=Runtime(state,Path(output).parent,args,stop);machine=None;value=None;diagnostic=None;execution='succeeded'
    try:
        runtime.guard(force=True)
        tree=parse_program(args['program'])
        machine=Machine(tree,args['bindings'],runtime.api,max_steps=args['resources']['max_steps'],
            max_value_bytes=args['resources']['max_value_bytes'],stop=stop)
        value=machine.run();runtime.guard(force=True)
    except MemoryError as exc:
        exc.__traceback__=None;machine=None;gc.collect();execution='failed'
        diagnostic=dict(code='code_memory_limit',message='The isolated program memory limit was reached; prior API facts are retained.')
    except (CodeError,ValueError,TypeError,KeyError,IndexError,ArithmeticError,RecursionError) as exc:
        code=exc.code if isinstance(exc,CodeError) else 'invalid_program'
        execution='cancelled' if code=='cancelled' else 'failed' if code in (
            'step_limit','timeout','owned_disk_limit','owned_file_limit','api_byte_limit','call_limit','api_stop_unknown','value_limit') else 'invalid_input'
        diagnostic=dict(code=code,message=str(exc)[:512] if isinstance(exc,CodeError) else 'Program value or structure is invalid.')
        value=None
    if machine is not None:runtime.metrics['steps']=machine.metrics['steps']
    machine=None;gc.collect();runtime.metrics['elapsed_seconds']=time.monotonic()-runtime.started
    complete=execution=='succeeded' and all(c['status']=='succeeded' for c in runtime.calls)
    has_facts=any(c.get('output_sha256') is not None for c in runtime.calls)
    result_status=('succeeded' if complete else 'cancelled' if execution=='cancelled'
        else 'partial' if has_facts else execution if execution!='succeeded' else 'failed')
    runtime.flush(execution)
    return dict(program_sha256=runtime.digest,language=args['language'],value=value,calls=runtime.calls,execution_status=execution,result_status=result_status,
        diagnostic=diagnostic,metrics=runtime.metrics,resources=args['resources'],requires_ai_interpretation=True,
        audit=dict(program_document_sha256=fs.digest(runtime.source),journal_document_sha256=fs.digest(runtime.journal),run_id=runtime.folder.name),
        limitations=['A program-derived projection is not an independent cause judgment. Each saved API result retains its own coverage and provenance.',
            'API scope is supplied by the authorized caller, not authentication. Approved manifests include their declared sources.',
            'Language has no raw filesystem/network/process/SQL API. Selected trusted source adapters retain their documented access and limits.',
            'Windows program Job covers descendants; Linux address-space limit is per process, aggregate tree RSS remains unknown.',
            'Disk is monitored across owned API runs/products, not an atomic filesystem quota. No automatic restart of a partial program.'])
