"""Pure finite MCP catalogue and framing. No probes, network or SDK dependency."""
from copy import deepcopy
import json

from . import __version__,capabilities as cap,responses
from .inputs import InputError

MODERN='2026-07-28'
LEGACY='2025-11-25'
VERSIONS=(MODERN,LEGACY)
SERVER=dict(name='1c-techexpert-ai',version=__version__)
IDENTITY=cap.string(128,pattern='[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}')
RUN=cap.string(64,pattern='[a-f0-9]{64}')
CALL=cap.string(32,pattern='[a-f0-9]{32}')
CONTROLS={
    'operation_status':('status',cap.obj(dict(run_id=RUN),['run_id']),'Inspect run and live ownership. Unknown is not stopped; never take over by age.'),
    'operation_result':('result',cap.obj(dict(run_id=RUN),['run_id']),'Verify and replay a retained result without accessing original sources or repeating work.'),
    'operation_reconcile':('reconcile',cap.obj(dict(run_id=RUN),['run_id']),'Recover sealed work only after verified stop; no worker restart or overwriting a product.'),
    'operation_cancel':('cancel',cap.obj(dict(run_id=RUN,executor_id=IDENTITY),['run_id','executor_id']),'Request cancellation of an explicitly selected run. This is not proof of stop.'),
    'kernel_call':('inspect',cap.obj(dict(call_id=CALL),['call_id']),'Inspect a checked controller receipt, resource scope and ownership; model counters remain unknown.'),
}
OPERATIONS={'techexpert_'+name.replace('.','_'):name for name in cap.ROUTES}
PROFILES=('full','direct','program')


def selected_operations(profile='full'):
    if profile not in PROFILES:raise InputError('Unsupported fixed MCP catalogue profile')
    return {name:operation for name,operation in OPERATIONS.items()
        if profile=='full' or (operation.startswith('code.') if profile=='program' else not operation.startswith('code.'))}


def input_schema(operation):
    route=cap.ROUTES[operation]
    return cap.obj(dict(operation_key=dict(IDENTITY,description='Stable key for one semantic operation. Repeat after uncertainty; a changed request needs a reviewed new key.'),
        executor_id=dict(IDENTITY,description='Caller label, not authentication.'),arguments=deepcopy(route['input_schema']),
        budget=cap.obj(dict(timeout_seconds=dict(type='number',minimum=.1,maximum=route['timeout_seconds']),
            max_result_bytes=cap.integer(16384,cap.MAX_RESULT,cap.MAX_RESULT))),
        context=cap.obj(dict(investigation_id=cap.CASE,expected_revision=cap.integer(1,1000,1)),['investigation_id','expected_revision'])),
        ['operation_key','executor_id','arguments'])


def tools(profile='full'):
    result=[]
    for name,operation in selected_operations(profile).items():
        route=cap.ROUTES[operation]
        result.append(dict(name=name,title=operation,description=f"{operation}: {route['impact']}. Sources: {'; '.join(route['required_sources'])}. "
            'Same managed CLI operation, private receipts, fixed budgets. Evidence needs interpretation by the current AI harness; partial coverage is not absence of cause.',
            inputSchema=input_schema(operation),outputSchema=deepcopy(route['output_schema']),
            annotations=dict(readOnlyHint=operation not in {'input.inspect','case.analyze','case.compare','os.collect','os.import','code.execute'}|cap._diagnostics.CREATORS,destructiveHint=False,
                idempotentHint=True,openWorldHint=operation in {'input.inspect','source.check','case.analyze','os.collect','os.import','code.execute'}|cap._diagnostics.CREATORS)))
    for suffix,(action,args,description) in CONTROLS.items():
        result.append(dict(name='techexpert_'+suffix,title=suffix,description=description,inputSchema=deepcopy(args),outputSchema=responses.schema(),
            annotations=dict(readOnlyHint=action not in ('reconcile','cancel'),destructiveHint=False,idempotentHint=True,openWorldHint=False)))
    return sorted(result,key=lambda t:t['name'])


def prepare(name,arguments):
    if name in OPERATIONS:
        operation=OPERATIONS[name]
        if not isinstance(arguments,dict):raise InputError('Tool arguments must be an object; inspect tools/list.')
        request=cap.normalize_request(dict(arguments,schema_version=1,operation=operation))
        # Do not let the injected fixed fields hide unexpected caller arguments.
        if set(arguments)-input_schema(operation)['properties'].keys():raise InputError('Unsupported tool argument; inspect tools/list.')
        return 'run',dict(request='inline-request.json'),request
    suffix=name.removeprefix('techexpert_')
    if name.startswith('techexpert_') and suffix in CONTROLS:
        action,schema,_=CONTROLS[suffix]
        return action,cap.validate(arguments,schema),None
    raise InputError('Unknown tool; inspect tools/list.')


def result(value,version):
    value=responses.normalize(value)
    frame=dict(content=[dict(type='text',text=json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False))],
        structuredContent=value,isError=value['status'] in ('invalid_input','failed','cancelled','interrupted'))
    if version==MODERN:frame.update(resultType='complete',_meta={'io.modelcontextprotocol/serverInfo':dict(SERVER)})
    return frame


def small_error(message,version):
    return result(dict(status='invalid_input',message=message,limitations=['No source work was started by this request. Inspect tools/list and correct the bounded arguments.']),version)
