"""Pure finite MCP catalogue and framing. No probes, network or SDK dependency."""
from copy import deepcopy
import json

from . import __version__,capabilities as cap,check_history,investigation_task,os_observation,responses
from .inputs import InputError
from .investigation_changes import schema as comparison_schema

MODERN='2026-07-28'
LEGACY='2025-11-25'
VERSIONS=(MODERN,LEGACY)
SERVER=dict(name='1c-techexpert-ai',version=__version__)
IDENTITY=cap.string(128,pattern='[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}')
RUN=cap.string(64,pattern='[a-f0-9]{64}')
CALL=cap.string(32,pattern='[a-f0-9]{32}')
CONTROLS={
    'investigation_progress':('investigation-progress',cap.obj(dict(investigation_id=CALL,comparison=comparison_schema(cap)),['investigation_id']),
        'Resume one investigation, observe bound local checks or compare two committed revisions. Returns status and evidence references.'),
    'operation_status':('status',cap.obj(dict(run_id=RUN),['run_id']),'Inspect run and live ownership. Unknown is not stopped; never take over by age.'),
    'operation_result':('result',cap.obj(dict(run_id=RUN),['run_id']),'Verify and replay a retained result without accessing original sources or repeating work.'),
    'operation_reconcile':('reconcile',cap.obj(dict(run_id=RUN),['run_id']),'Recover sealed work only after verified stop; no worker restart or overwriting a product.'),
    'operation_cancel':('cancel',cap.obj(dict(run_id=RUN,executor_id=IDENTITY),['run_id','executor_id']),'Request cancellation of an explicitly selected run. This is not proof of stop.'),
    'kernel_call':('inspect',cap.obj(dict(call_id=CALL),['call_id']),'Inspect a checked controller receipt, resource scope and ownership; model counters remain unknown.'),
}
OPERATIONS={'techexpert_'+name.replace('.','_'):name for name in cap.ROUTES}
PROFILES=('full','direct','program','context')
CONTEXT_TOOLS=('knowledge.search','knowledge.card','code.context')
CONTEXT_READ='techexpert_context_read'
CONTEXT_INTAKE='techexpert_context_intake'
CONTEXT_ATTACH='techexpert_context_attach'
CONTEXT_TASK='techexpert_investigation_task'
OS_OBSERVATION='techexpert_os_observation'
PROGRESS='techexpert_investigation_progress'
ATTACH_SCHEMA=cap.obj(dict(run_id=RUN,revision=cap.integer(1,1000,1)),('run_id','revision'))


def selected_operations(profile='full'):
    if profile not in PROFILES:raise InputError('Unsupported fixed MCP catalogue profile')
    if profile=='context':
        return {name:operation for name,operation in OPERATIONS.items() if operation in CONTEXT_TOOLS}
    return {name:operation for name,operation in OPERATIONS.items()
        if profile=='full' or (operation in ('code.execute','code.inspect') if profile=='program' else not operation.startswith('code.'))}


def control_names(profile):
    names = {PROGRESS} if profile == 'context' else {'techexpert_'+suffix for suffix in CONTROLS}
    if profile in ('full', 'context'):
        names.update((CONTEXT_READ,CONTEXT_INTAKE,CONTEXT_ATTACH,CONTEXT_TASK))
    if profile=='full':
        names.add(OS_OBSERVATION)
    return names


def tool_input_schema(operation, profile):
    value = input_schema(operation)
    if operation == 'code.context':
        value['required'].append('context')
    elif profile == 'context':
        value['properties'].pop('context')
    return value


def input_schema(operation):
    route=cap.ROUTES[operation]
    fields=dict(operation_key=dict(IDENTITY,description='Stable key for one semantic operation. Repeat after uncertainty; a changed request needs a reviewed new key.'),
        executor_id=dict(IDENTITY,description='Caller label, not authentication.'),arguments=deepcopy(route['input_schema']),
        budget=cap.obj(dict(timeout_seconds=dict(type='number',minimum=.1,maximum=route['timeout_seconds']),
            max_result_bytes=cap.integer(16384,cap.MAX_RESULT,cap.MAX_RESULT))),
        context=cap.obj(dict(investigation_id=cap.CASE,expected_revision=cap.integer(1,1000,1)),['investigation_id','expected_revision']))
    if operation in check_history.READS:
        fields['repeat_reason']=dict(cap.REPEAT_REASON,description='Reason for repeating the same saved investigation read after verified stop. Requires context and a fresh key.')
    if operation=='os.collect':
        fields['observation']=dict(os_observation.binding_schema(),
                                   description='Approved plan and selected source. With this binding, arguments may only tighten duration_seconds, interval_seconds and max_bytes.')
    return cap.obj(fields,['operation_key','executor_id','arguments'])


def intake_schema():
    from .context_intake import OPERATIONS
    from . import profile_journals, tj_time_correction
    properties = input_schema('case.analyze')['properties']
    properties.update(operation=cap.string(64,enum=list(OPERATIONS)),
                      arguments=dict(type='object',maxProperties=32))
    result = cap.obj(properties,('operation','operation_key','executor_id','arguments','context'))
    result['oneOf'] = []
    for op in OPERATIONS:
        modes = [deepcopy(cap.ROUTES[op]['input_schema'])]
        if op in profile_journals.OPERATIONS:
            modes.append(profile_journals.schema(cap, op))
        if op == 'case.analyze':
            modes.append(tj_time_correction.schema(cap))
        schema = dict(anyOf=modes) if len(modes) > 1 else modes[0]
        result['oneOf'].append(dict(properties=dict(operation=dict(const=op), arguments=schema)))
    return result


def tools(profile='full'):
    result=[]
    for name,operation in selected_operations(profile).items():
        route=cap.ROUTES[operation]
        result.append(dict(name=name,title=operation,description=f"{operation}: {route['impact']}. Sources: {'; '.join(route['required_sources'])}. "
            'Same managed CLI operation, private receipts, fixed budgets. Evidence needs interpretation by the current AI harness; partial coverage is not absence of cause.',
            inputSchema=tool_input_schema(operation,profile),outputSchema=deepcopy(route['output_schema']),
            annotations=dict(readOnlyHint=operation not in {'input.inspect','case.analyze','case.compare','os.collect','os.import',cap._fix.OPERATION,cap._apdex.OPERATION,*cap.PROGRAM_EXECUTIONS,*cap._logcfg.OPERATIONS,*cap._remote.OPERATIONS}|cap._diagnostics.CREATORS,destructiveHint=operation=='client.observe',
                idempotentHint=True,openWorldHint=operation in {'input.inspect','source.check','case.analyze','os.collect','os.import','code.execute',*cap._logcfg.OPERATIONS,'remote.inspect','remote.capture'}|cap._diagnostics.CREATORS)))
    controls=control_names(profile)
    for suffix,(action,args,description) in CONTROLS.items():
        if 'techexpert_'+suffix not in controls:
            continue
        result.append(dict(name='techexpert_'+suffix,title=suffix,description=description,inputSchema=deepcopy(args),outputSchema=responses.schema(),
            annotations=dict(readOnlyHint=action not in ('reconcile','cancel'),destructiveHint=False,idempotentHint=True,openWorldHint=False)))
    if CONTEXT_READ in controls:
        from .context_disclosure import argument_schema
        result.append(dict(name=CONTEXT_READ,title='context.read',inputSchema=argument_schema(),outputSchema=responses.schema(),
            description='Read one pinned investigation attachment through its reviewed model disclosure policy. '
                        'Rows contain typed fields and scoped aliases. Each prepared view has a local disclosure receipt.',
            annotations=dict(readOnlyHint=False,destructiveHint=False,idempotentHint=False,openWorldHint=False)))
    if CONTEXT_INTAKE in controls:
        result.append(dict(name=CONTEXT_INTAKE,title='context.intake',inputSchema=intake_schema(),outputSchema=responses.schema(),
            description='Inspect or import selected local sources, prepare APDEX, or verify a change from retained measurements. '
                        'Returns metadata and links saved results to the investigation. Repeat the same operation key after uncertainty.',
            annotations=dict(readOnlyHint=False,destructiveHint=False,idempotentHint=True,openWorldHint=True)))
        result.append(dict(name=CONTEXT_ATTACH,title='context.attach',inputSchema=deepcopy(ATTACH_SCHEMA),outputSchema=responses.schema(),
            description='Link an already saved intake result to an explicit revision of its investigation in the same environment.',
            annotations=dict(readOnlyHint=False,destructiveHint=False,idempotentHint=True,openWorldHint=False)))
    if CONTEXT_TASK in controls:
        result.append(dict(name=CONTEXT_TASK,title=investigation_task.OPERATION,
            inputSchema=investigation_task.argument_schema(),outputSchema=responses.schema(),
            description='Save a task, clarification or occurrence notice from this chat. A notice checks retained attachments and returns bounded identifiers and status.',
            annotations=dict(readOnlyHint=False,destructiveHint=False,idempotentHint=True,openWorldHint=False)))
    if OS_OBSERVATION in controls:
        result.append(dict(name=OS_OBSERVATION,title=os_observation.OPERATION,
            inputSchema=os_observation.argument_schema(),outputSchema=responses.schema(),
            description='Preview, record the exact user-approved OS observation, or read its remaining budget. Does not launch a collection.',
            annotations=dict(readOnlyHint=False,destructiveHint=False,idempotentHint=True,openWorldHint=False)))
    return sorted(result,key=lambda t:t['name'])


def prepare(name,arguments,profile='full'):
    if name == CONTEXT_TASK:
        return investigation_task.ACTION,dict(request='inline-request.json'),investigation_task.normalize(arguments)
    if name == OS_OBSERVATION:
        return os_observation.ACTION,dict(request='inline-request.json'),os_observation.normalize(arguments)
    if name == CONTEXT_READ:
        from .context_disclosure import compact,validate_request
        return 'context-read',dict(selection=compact(validate_request(arguments))),None
    if name == CONTEXT_INTAKE:
        if type(arguments) is not dict or set(arguments)-intake_schema()['properties'].keys():
            raise InputError('unsupported local intake arguments')
        from .context_intake import prepare as prepare_intake
        request=prepare_intake(dict(arguments,schema_version=1))
        return 'context-intake',dict(request='inline-request.json'),request
    if name == CONTEXT_ATTACH:
        args=cap.validate(arguments,ATTACH_SCHEMA)
        return 'context-attach',dict(args,revision=str(args['revision'])),None
    if name in OPERATIONS:
        operation=OPERATIONS[name]
        if not isinstance(arguments,dict):raise InputError('Tool arguments must be an object; inspect tools/list.')
        request=cap.normalize_request(dict(arguments,schema_version=1,operation=operation))
        # Do not let the injected fixed fields hide unexpected caller arguments.
        if set(arguments)-tool_input_schema(operation,profile)['properties'].keys():raise InputError('Unsupported tool argument; inspect tools/list.')
        return 'run',dict(request='inline-request.json'),request
    suffix=name.removeprefix('techexpert_')
    if name.startswith('techexpert_') and suffix in CONTROLS:
        action,schema,_=CONTROLS[suffix]
        selected = cap.validate(arguments,schema)
        if action == 'investigation-progress' and 'comparison' in selected:
            selected['comparison'] = json.dumps(selected['comparison'], separators=(',', ':'))
        return action,selected,None
    raise InputError('Unknown tool; inspect tools/list.')


def result(value,version):
    value=responses.normalize(value)
    frame=dict(content=[dict(type='text',text=json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False))],
        structuredContent=value,isError=value['status'] in ('invalid_input','failed','cancelled','interrupted'))
    if version==MODERN:frame.update(resultType='complete',_meta={'io.modelcontextprotocol/serverInfo':dict(SERVER)})
    return frame


def small_error(message,version):
    return result(dict(status='invalid_input',message=message,limitations=['No source work was started by this request. Inspect tools/list and correct the bounded arguments.']),version)
