"""Finite executable catalogue shared by managed transports, never arbitrary model code."""
from copy import deepcopy
import math
from pathlib import Path
import re
import sys as _sys

from .inputs import InputError
from .responses import schema as response_schema

MIB=1024**2
MAX_RESULT=16*MIB

def string(limit=2048,**extra):return dict(type='string',minLength=1,maxLength=limit,**extra)
def integer(low,high,default):return dict(type='integer',minimum=low,maximum=high,default=default)
def obj(properties,required=()):return dict(type='object',properties=properties,required=list(required),additionalProperties=False)
def array(items,limit=16):return dict(type='array',items=items,maxItems=limit,default=[])

CASE=string(32,pattern='[a-f0-9]{32}')
SHA256=string(64,pattern='[a-f0-9]{64}')
FILE=string()
WINDOW=obj(dict(start=string(64),end=string(64)),('start','end'))
COVERAGE=dict(window=WINDOW,required_events=array(string(64)),required_fields=array(string(128)))
OS=obj(dict(transport=string(8,enum=['local','ssh','winrm'],default='local'),host=dict(type='string',maxLength=256,default=''),port=integer(1,65535,22),
    duration_seconds=dict(type='number',minimum=1,maximum=1800,default=300),interval_seconds=dict(type='number',minimum=1,maximum=60,default=1),
    max_bytes=integer(16384,8*MIB,8*MIB),node=string(256),role=string(16,enum=['onec','sql','storage','client','terminal','web','other'],default='onec'),python=string(),use_ssl=dict(type='boolean',default=False),
    identity_file=FILE,known_hosts_file=FILE))
OS['properties']['port'].pop('default')
OS['properties']['max_bytes'].pop('default')
from .input_files import LIMITS as _INPUT_LIMITS
from .input_adapters import fields as _input_fields
INPUTS=obj(dict(inputs=dict(type='array',minItems=1,maxItems=16,items=obj(dict(path=FILE,kind=string(16,enum=['file','directory','zip'])),['path','kind'])),
    limits=dict(obj({k:integer(0 if k=='max_depth' else 1,v,v) for k,v in _INPUT_LIMITS.items()}),default={})),['inputs'])
SAVED_SOURCE=obj(dict(kind=string(16,enum=['case','artifact']),id=CASE,source_id=string(16,pattern='s(?:[1-9]|[12][0-9]|3[0-2])')),['kind','id','source_id'])

def route(arguments,required,source,impact,fields,*,timeout=60):
    strings={'case_id','artifact_id','comparison_id','knowledge_revision','content_sha256','id','evidence_id','sha256','body'}
    arrays={'sources','records','matches','input_reports','limitations'}
    data_schema=dict(type='object',required=fields,properties={key:dict(type='string' if key in strings else 'array' if key in arrays else
        ['integer','null'] if key=='next_offset' else 'integer' if key=='matched_count' else 'boolean' if key=='truncated' else 'object') for key in fields},additionalProperties=True)
    return dict(input_schema=obj(arguments,required),required_sources=source,rights=['read explicitly selected inputs','write private operation evidence'],
        scope='explicitly selected supported sources and retained local evidence',timeout_seconds=timeout,max_result_bytes=MAX_RESULT,
        impact=impact,data_schema=data_schema,output_schema=response_schema(data_schema))

ROUTES={
 'case.analyze':dict(route(dict(manifest=FILE,input_plan=CASE,reference_sha256=SHA256),['manifest'],
     ['selected manifest and stable files, explicit bounded TJ prefixes, approved external TJ windows or catalogue members'],
     'private case snapshot; no database connection',['case_id','sources','durations_seconds'],timeout=180),default_timeout_seconds=60),
 'case.show':route(dict(case_id=CASE),['case_id'],['verified saved case'],'read retained case; no original-path access',['case_id','sources']),
 'case.coverage':route(dict(case_id=CASE,**COVERAGE),['case_id'],['verified saved TJ'],'derive coverage from retained bytes',['sources','limitations']),
 'case.events':route(dict(case_id=CASE,source_id=string(16,pattern='s[1-9][0-9]*'),event=string(64),
     window=WINDOW,
     properties=dict(type='object',maxProperties=16,additionalProperties=dict(type='string',maxLength=2048)),
     offset=integer(0,100000,0),limit=integer(1,100,20),linked_run=dict(type='boolean',default=False)),['case_id'],
     ['verified saved TJ'],'read bounded exact page',['case_id','records','matched_count','next_offset']),
 'case.evidence':route(dict(case_id=CASE,evidence_id=string(64,pattern='s[1-9][0-9]*:[1-9][0-9]*')),['case_id','evidence_id'],
     ['verified saved case source'],'read bounded evidence excerpt',['case_id','evidence_id','sha256','truncated']),
 'case.compare':route(dict(before=dict(type='array',items=CASE,minItems=1,maxItems=20),after=dict(type='array',items=CASE,minItems=1,maxItems=20)),
     ['before','after'],['verified saved cases'],'save comparison; no database mutation',['comparison_id','input_reports','performance']),
 'comparison.show':route(dict(comparison_id=CASE),['comparison_id'],['verified saved comparison and case inputs'],'read saved comparison',['comparison_id','input_reports']),
 'source.check':route(dict(manifest=FILE,reference_preview=dict(type='boolean'),**COVERAGE),['manifest'],
     ['explicitly selected manifest and TJ'],'read-only inspection or metadata-only external reference preview',['sources','limitations']),
 'knowledge.search':route(dict(query=string(500),limit=integer(1,20,5)),['query'],['bundled offline knowledge'],'candidate references only; no source fetch',['knowledge_revision','matches']),
 'knowledge.card':route(dict(card_id=string(128),offset=integer(0,65536,0),limit=integer(1,8192,6000)),['card_id'],['bundled authored card'],
     'bounded authored note; no independent diagnosis',['id','body','content_sha256']),
 'os.collect':dict(route(OS['properties'],[],['explicit node and existing local/SSH/WinRM access'],
     'bounded counter collection; no service setup or permission changes',['artifact_id','result','sources'],timeout=1830)),
 'os.import':route(dict(measurements=FILE,**_input_fields(_sys.modules[__name__],single=True)),['measurements'],['provided OS metrics JSON or one approved catalogue member'],'private artifact snapshot',['artifact_id','result','sources']),
 'artifact.show':route(dict(artifact_id=CASE),['artifact_id'],['verified saved artifact'],'read saved evidence',['artifact_id','result','sources']),
}
# Keep the original13-operation compatibility workload separate from additions.
BASE_API=tuple(ROUTES)
ROUTES['sample.describe']=route(dict(inputs=dict(type='array',minItems=1,maxItems=16,
    items=obj(dict(kind=string(16,enum=['case','artifact']),id=CASE),['kind','id'])),operation=string(256),window=WINDOW,
    context=dict(obj({name:string(2048) for name in ('platform_version','workload','launch_conditions','selection_basis')}),default={}),
    reported_normal_seconds=dict(type='number',minimum=0,maximum=31536000),offset=integer(0,100000,0),limit=integer(1,200,20)),
    ['inputs','operation'],['explicit retained execution cases or normalized APDEX measurement artifacts and saved catalogue bindings'],
    'describe observed sample selection and distribution; no original paths, new capture, normality or causal verdict',
    ['inputs','statistics','counts','descriptor','selection','period','exclusions','records','matched_count','next_offset','dependencies','normal_established'])
_sample_data=ROUTES['sample.describe']['data_schema']['properties']
_sample_number=dict(type=['number','null'],minimum=0,maximum=31536000)
_sample_data.update(inputs=dict(type='array',maxItems=16),dependencies=dict(type='array',maxItems=32),
    records=dict(type='array',maxItems=200),normal_established=dict(type='boolean',enum=[False]),independent_runs=dict(type='null'),
    selection_sha256=string(64,pattern='[a-f0-9]{64}'),requires_ai_interpretation=dict(type='boolean'),
    statistics=dict(type='object',required=['count','supplied_count','missing_count','median','percentiles'],properties={
        **{key:dict(_sample_number) for key in ('median','minimum','maximum','range','median_absolute_deviation','interquartile_range')},
        **{key:dict(type='integer',minimum=0,maximum=100000) for key in ('count','supplied_count','missing_count')},
        'percentiles':dict(type='object',required=['values','sample_size','method'],properties=dict(
            values=obj({key:dict(_sample_number) for key in ('25','50','75','90','95')},['25','50','75','90','95']),
            sample_size=dict(type='integer',minimum=0,maximum=100000),method=string(128)),additionalProperties=False)},additionalProperties=True))
ROUTES['sample.describe']['output_schema']=response_schema(ROUTES['sample.describe']['data_schema'])
ROUTES['source.compare']=route(dict(before=SAVED_SOURCE,after=SAVED_SOURCE),['before','after'],
    ['two selected retained case/artifact sources and their bounded saved catalogue dependencies'],
    'read verified saved bytes; no original paths, capture, event merge or cause judgment',
    ['before','after','byte_relation','common_prefix_bytes','observation','input_duplicate','interpretation','framing','counts','dependencies'])
ROUTES['source.compare']['data_schema']['properties'].update(byte_relation=dict(type='string',enum=['identical','extended_prefix','shortened_prefix','changed']),
    common_prefix_bytes=dict(type='integer',minimum=0,maximum=16*MIB),dependencies=dict(type='array',maxItems=4),suggested_after_range=dict(type=['object','null']))
for _side in ('before','after'):
    ROUTES['source.compare']['data_schema']['properties'][_side]=obj(dict(kind=SAVED_SOURCE['properties']['kind'],id=CASE,
        source_id=SAVED_SOURCE['properties']['source_id'],report_digest=string(64,pattern='[a-f0-9]{64}'),
        receipt_digest=string(64,pattern='[a-f0-9]{64}'),context_digest=string(64,pattern='[a-f0-9]{64}'),
        sha256=string(64,pattern='[a-f0-9]{64}'),bytes=dict(type='integer',minimum=0,maximum=16*MIB),crc32=dict(type='integer',minimum=0,maximum=2**32-1)),
        ['kind','id','source_id','report_digest','receipt_digest','context_digest','sha256','bytes','crc32'])

ROUTES['source.compare']['output_schema']=response_schema(ROUTES['source.compare']['data_schema'])
ROUTES['input.inspect']=route(INPUTS['properties'],['inputs'],['explicit files/directories/ZIP metadata'],
    'save private bounded catalogue; no member extraction or analysis',['artifact_id','result','sources'])
from . import diagnostic_adapters as _diagnostics
ROUTES.update(_diagnostics.routes(_sys.modules[__name__]))
ROUTES['investigation.sources']=route(dict(investigation_id=CASE,revision=integer(1,1000,1)),['investigation_id','revision'],
    ['explicit immutable investigation revision and its verified saved evidence'],'read bounded source ownership context; no original-source probes or causal certification',
    ['investigation_id','revision','bindings','links','dependencies','needs_clarification'])
ROUTES['investigation.sources']['data_schema']['properties'].update(investigation_id=dict(type='string'),revision=dict(type='integer'),
    bindings=dict(type='array'),links=dict(type='array'),dependencies=dict(type='array'),needs_clarification=dict(type='boolean'))
ROUTES['investigation.sources']['output_schema']=response_schema(ROUTES['investigation.sources']['data_schema'])
from . import logcfg_api as _logcfg
ROUTES.update(_logcfg.routes(_sys.modules[__name__]))
from . import remote_api as _remote
ROUTES.update(_remote.routes(_sys.modules[__name__]))
CODE_API=tuple(ROUTES)
from .code_policy import schemas as _code_schemas
_code_arguments=_code_schemas(_sys.modules[__name__],CODE_API)
ROUTES['code.execute']=route(_code_arguments,['program'],['explicitly scoped inputs and saved evidence'],
    'bounded capability-language program; private facts and audited API calls',
    ['program_sha256','value','calls','metrics','audit'],timeout=1830)
ROUTES['code.execute']['default_timeout_seconds']=60
ROUTES['code.execute']['data_schema']['properties'].update(program_sha256=dict(type='string'),value={},calls=dict(type='array'))
ROUTES['code.execute']['output_schema']=response_schema(ROUTES['code.execute']['data_schema'])
ROUTES['code.inspect']=route(dict(run_id=string(64,pattern='[a-f0-9]{64}')),['run_id'],['checked saved program and API journal'],
    'read saved program, trace and live nested ownership; never repeat execution',['program_sha256','program','calls'],timeout=30)
ROUTES['code.inspect']['data_schema']['properties'].update(program=dict(type='string'),program_sha256=dict(type='string'),calls=dict(type=['array','null']))
ROUTES['code.inspect']['output_schema']=response_schema(ROUTES['code.inspect']['data_schema'])

def validate(value,schema):
    if schema.get('x_bounded_json'):
        from .code_values import copy_json
        if type(value) is not dict:raise InputError('bounded bindings must be an object')
        return copy_json(value,max_bytes=schema['x_bounded_json'],max_depth=16)
    kind=schema['type']
    correct={'object':type(value) is dict,'array':type(value) is list,'string':type(value) is str,
        'integer':type(value) is int,'number':type(value) in (int,float),'boolean':type(value) is bool}
    if not correct.get(kind,False):raise InputError('operation argument has an invalid type')
    if kind=='object':
        properties=schema.get('properties',{});extra=schema.get('additionalProperties',False)
        if set(schema.get('required',[]))-value.keys() or len(value)>schema.get('maxProperties',64):raise InputError('operation argument properties missing or excessive')
        result={}
        for key,item in value.items():
            if not isinstance(key,str) or not 1<=len(key)<=128 or any(ord(c)<32 for c in key):raise InputError('invalid operation argument property')
            if key not in properties and not isinstance(extra,dict):raise InputError('unsupported operation argument property')
            result[key]=validate(item,properties.get(key,extra))
        for key,item in properties.items():
            if key not in result and 'default' in item:result[key]=deepcopy(item['default'])
        return result
    if kind=='array':
        if not schema.get('minItems',0)<=len(value)<=schema.get('maxItems',64):raise InputError('operation argument list exceeds limits')
        return [validate(v,schema['items']) for v in value]
    if kind=='string':
        if (not schema.get('minLength',0)<=len(value)<=schema.get('maxLength',2048)
            or any(ord(c)<32 and not (schema.get('x_multiline') and c in '\n\r\t') for c in value)
            or 'pattern' in schema and not re.fullmatch(schema['pattern'],value)):
            raise InputError('invalid bounded operation text')
    if kind in ('number','integer'):
        if (not schema.get('minimum',-math.inf)<=value<=schema.get('maximum',math.inf)
            or type(value) is float and not math.isfinite(value)):raise InputError('operation argument outside limits')
    if 'enum' in schema and value not in schema['enum']:raise InputError('unsupported operation argument value')
    return value

def catalogue(operation=None):
    if operation is not None and operation not in ROUTES:raise InputError('unknown registered operation')
    return dict(schema_version=1,operations=[dict(id=key,**deepcopy(value)) for key,value in sorted(ROUTES.items()) if operation is None or key==operation],
        arbitrary_code_execution=False,server_license_required=False,
        limits=dict(memory_bytes=1024*MIB,owned_disk_bytes=256*MIB,free_disk_floor_bytes=10*1024**3,
            memory_enforcement=dict(windows='managed CLI controller and nested local worker Jobs',linux='inherited per-process address space; concurrent tree memory not capped or measured'),
            timeout_scope='managed CLI controller admission/replay/verification/commit and owned workers; deadline from invocation start, bounded cleanup afterward',
            controller_resources='separate kernel-call receipt; Windows controller Job includes nested workers; Linux self/reaped-child counters retain their distinct scope',
            transport_resources='bounded small metadata/chunked bytes; no separate OS quota for setup/receipt/stream I/O',
            direct_internal_engine='worker bounds only; managed CLI controller boundary is not implicit for Python internals',
            disk_enforcement='monitored; bounded polling overshoot possible',model_harness_resources='not controlled or independently measured'),
        managed_transports=['CLI','MCP stdio'],mcp_protocol_versions=['2026-07-28','2025-11-25'],
        not_yet_managed=['source export execution','investigation/profile mutations','knowledge-use','incident drafts'])

def normalize_request(value):
    identity=string(128,pattern='[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}')
    schema=obj(dict(schema_version=dict(type='integer',minimum=1,maximum=1),operation_key=identity,executor_id=identity,operation=string(64),
        arguments=dict(type='object',maxProperties=32,additionalProperties={}),
        budget=obj(dict(timeout_seconds=dict(type='number',minimum=.1,maximum=1830),max_result_bytes=integer(16384,MAX_RESULT,MAX_RESULT))),
        context=obj(dict(investigation_id=CASE,expected_revision=integer(1,1000,1)),('investigation_id','expected_revision'))),
        ('schema_version','operation_key','executor_id','operation','arguments'))
    # Validate the outer object without interpreting arguments until the route is known.
    raw=dict(value) if isinstance(value,dict) else value
    if not isinstance(raw,dict):raise InputError('operation request must be an object')
    arguments=raw.get('arguments');raw['arguments']={}
    result=validate(raw,schema);operation=result['operation']
    if operation not in ROUTES:raise InputError('operation is not in the executable catalogue')
    args=validate(arguments,ROUTES[operation]['input_schema'])
    for key in ('manifest','measurements','identity_file','known_hosts_file'):
        if key in args:args[key]=str(Path(args[key]).absolute())
    if operation in ('source.check','case.coverage'):
        from .source_coverage import validate_request as coverage_request
        args.update(coverage_request(**{k:args[k] for k in COVERAGE if k in args}))
    if operation=='source.check' and args.get('reference_preview') and any(args.get(k) for k in COVERAGE):
        raise InputError('external TJ preview uses the window declared in the manifest without extra filters')
    if operation=='case.events' and 'window' in args:
        from .source_coverage import validate_request as coverage_request
        args['window']=coverage_request(window=args['window'])['window']
    if operation=='case.analyze' and args.get('reference_sha256') and args.get('input_plan'):
        raise InputError('choose external TJ reference review or catalogue intake')
    if operation=='input.inspect':
        from .input_files import normalize
        args=normalize(args['inputs'],args['limits'])
    if operation=='sample.describe':
        from .sample_description import normalize
        args=normalize(**args)
    if operation in _logcfg.OPERATIONS:args=_logcfg.normalize(operation,args)
    if operation in _remote.OPERATIONS:args=_remote.normalize(operation,args)
    if operation=='os.import':
        from .input_adapters import normalize
        args=normalize(args,single=True)
    if operation=='os.collect':
        from .os_metrics import validate_request as os_request
        args=os_request(args)
    if operation=='code.execute':
        from .code_policy import normalize as code_request
        args=code_request(args)
    if operation in _diagnostics.OPERATIONS:args=_diagnostics.normalize(operation,args)
    ceiling=timeout_limit(operation,args)
    timeout=ceiling if operation=='case.analyze' else ROUTES[operation].get('default_timeout_seconds',ceiling)
    if operation=='os.collect':timeout=args.get('duration_seconds',0)+30
    budget=dict(timeout_seconds=timeout,max_result_bytes=MAX_RESULT)
    budget.update(result.get('budget',{}))
    if budget['timeout_seconds']>ceiling:raise InputError('operation timeout exceeds catalogue')
    result.update(arguments={key:value for key,value in args.items() if value is not None},budget=budget)
    return result

def timeout_limit(operation, arguments):
    route = ROUTES[operation]
    if operation == 'case.analyze' and not (isinstance(arguments, dict) and arguments.get('reference_sha256')):
        return route['default_timeout_seconds']
    return route['timeout_seconds']


def execute(operation,args,state,output,*,stop=None,memory_bytes=None):
    from . import storage
    targets=[]
    if operation=='case.analyze':
        if 'input_plan' in args:
            from .input_intake import analyze
            data=analyze(state,output,args['manifest'],args['input_plan'])
        elif 'reference_sha256' in args:
            data=storage.investigate(args['manifest'],output,reference_sha256=args['reference_sha256'],
                                     reference_state=state,should_stop=stop)
        else:data=storage.investigate(args['manifest'],output)
        targets=[dict(kind='cases',id=data['case_id'])]
    elif operation=='input.inspect':
        from .input_intake import inspect
        data=inspect(output,**args);targets=[dict(kind='artifacts',id=data['artifact_id'])]
    elif operation=='case.show':
        from .knowledge_review import review_legacy_report
        data=storage.verified_case(state,args['case_id']);data=dict(data,knowledge_review=review_legacy_report(data))
    elif operation=='source.check' and args.get('reference_preview'):
        from .tj_reference import plan
        preview=plan(args['manifest'],state)
        data=dict(sources=preview['plan']['sources'],reference_preview=preview,
                  limitations=['Preview observes file metadata. The original bytes are verified during capture.'])
    elif operation in ('case.coverage','source.check'):
        from .source_coverage import inspect_case,inspect_manifest
        options={k:args[k] for k in COVERAGE if k in args}
        data=inspect_case(state,args['case_id'],**options) if operation=='case.coverage' else inspect_manifest(args['manifest'],**options)
    elif operation=='source.compare':
        from .source_changes import compare
        data=compare(state,**args)
    elif operation=='sample.describe':
        from .sample_description import describe
        data=describe(state,**args)
    elif operation in _logcfg.OPERATIONS:data,targets=_logcfg.execute(operation,args,state,output)
    elif operation in _remote.OPERATIONS:data,targets=_remote.execute(operation,args,state,output,stop)
    elif operation=='case.events':data=storage.list_native_events(state,**args,index_memory_bytes=memory_bytes)
    elif operation=='case.evidence':data=storage.read_evidence(state,**args)
    elif operation=='case.compare':data=storage.compare_cases(state,args['before'],args['after'],output_state_dir=output);targets=[dict(kind='comparisons',id=data['comparison_id'])]
    elif operation=='comparison.show':data=storage.load_comparison(state,args['comparison_id'])
    elif operation in ('knowledge.search','knowledge.card'):
        from .knowledge import search,get_card
        if operation=='knowledge.search':data=search(**args)
        else:
            data=get_card(args['card_id']);body=data['body'];offset=args['offset'];limit=args['limit']
            data=dict(data,body=body[offset:offset+limit],body_truncated=offset>0 or offset+limit<len(body),body_total_characters=len(body),body_offset=offset)
    elif operation in ('os.collect','os.import'):
        from .os_metrics import collect_os,import_os
        if operation=='os.import' and args.get('input_plan'):
            from .input_adapters import import_selected
            data=import_selected(operation,args,state,output)
        else:data=collect_os(output,args,should_stop=stop) if operation=='os.collect' else import_os(output,args['measurements'])
        targets=[dict(kind='artifacts',id=data['artifact_id'])]
    elif operation=='artifact.show':
        from .artifacts import load_artifact
        data=load_artifact(state,args['artifact_id'])
        if data['kind']=='knowledge_use':
            from .knowledge_review import review_use
            data=dict(data,knowledge_review=review_use(state,args['artifact_id']))
    elif operation=='investigation.sources':
        from .investigations import source_context
        data=source_context(state,**args)
    elif operation in _diagnostics.OPERATIONS:
        data,targets=_diagnostics.execute(operation,args,state,output,stop=stop)
    elif operation in ('code.execute','code.inspect'):
        from .code_runtime import run_program,inspect_program
        data=run_program(state,output,args,stop=stop) if operation=='code.execute' else inspect_program(state,args['run_id'])
    else:raise InputError('unknown executable operation')
    if not isinstance(data,dict) or set(ROUTES[operation]['data_schema']['required'])-data.keys():raise InputError('adapter output does not match registered schema')
    return data,targets


def outcome(operation,data):
    if operation in _remote.OPERATIONS:return _remote.outcome(operation,data)
    if operation in _logcfg.OPERATIONS and data['result']['status']=='needs_review':return 'partial','logcfg_needs_review'
    if operation=='sample.describe':
        if not data['statistics']['count']:return 'partial','sample_no_known_durations'
        if data['statistics']['missing_count']:return 'partial','sample_missing_durations'
    collection=data.get('result',{}).get('collection_status')
    if operation=='os.collect':
        if collection=='cancelled':return 'cancelled','cancelled'
        if collection and collection!='completed':return 'partial',collection
    if operation=='os.import' and collection and collection!='completed':return 'partial','imported_capture_'+collection
    return _diagnostics.result_status(operation,data) if operation in _diagnostics.OPERATIONS else ('succeeded',None)
