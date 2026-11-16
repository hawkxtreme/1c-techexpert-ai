"""Finite executable catalogue shared by managed transports, never arbitrary model code."""
from copy import deepcopy
import math
from pathlib import Path
import re

from .inputs import InputError
from .responses import schema as response_schema

MIB=1024**2
MAX_RESULT=16*MIB

def string(limit=2048,**extra):return dict(type='string',minLength=1,maxLength=limit,**extra)
def integer(low,high,default):return dict(type='integer',minimum=low,maximum=high,default=default)
def obj(properties,required=()):return dict(type='object',properties=properties,required=list(required),additionalProperties=False)
def array(items,limit=16):return dict(type='array',items=items,maxItems=limit,default=[])

CASE=string(32,pattern='[a-f0-9]{32}')
FILE=string()
WINDOW=obj(dict(start=string(64),end=string(64)),('start','end'))
COVERAGE=dict(window=WINDOW,required_events=array(string(64)),required_fields=array(string(128)))
OS=obj(dict(transport=string(8,enum=['local','ssh','winrm'],default='local'),host=dict(type='string',maxLength=256,default=''),port=integer(1,65535,22),
    duration_seconds=dict(type='number',minimum=1,maximum=1800,default=300),interval_seconds=dict(type='number',minimum=1,maximum=60,default=1),
    max_bytes=integer(16384,8*MIB,8*MIB),node=string(256),role=string(16,enum=['onec','sql','storage','client','terminal','web','other'],default='onec'),python=string(),use_ssl=dict(type='boolean',default=False),
    identity_file=FILE,known_hosts_file=FILE))
OS['properties']['port'].pop('default')
OS['properties']['max_bytes'].pop('default')

def route(arguments,required,source,impact,fields,*,timeout=60):
    strings={'case_id','artifact_id','comparison_id','knowledge_revision','content_sha256','id','evidence_id','sha256','body'}
    arrays={'sources','records','matches','input_reports','limitations'}
    data_schema=dict(type='object',required=fields,properties={key:dict(type='string' if key in strings else 'array' if key in arrays else
        ['integer','null'] if key=='next_offset' else 'integer' if key=='matched_count' else 'boolean' if key=='truncated' else 'object') for key in fields},additionalProperties=True)
    return dict(input_schema=obj(arguments,required),required_sources=source,rights=['read explicitly selected inputs','write private operation evidence'],
        scope='SC01 supported file profiles and explicitly selected local state',timeout_seconds=timeout,max_result_bytes=MAX_RESULT,
        impact=impact,data_schema=data_schema,output_schema=response_schema(data_schema))

ROUTES={
 'case.analyze':route(dict(manifest=FILE),['manifest'],['selected manifest and declared stable files'],'private case snapshot; no database connection',['case_id','sources','durations_seconds']),
 'case.show':route(dict(case_id=CASE),['case_id'],['verified saved case'],'read retained case; no original-path access',['case_id','sources']),
 'case.coverage':route(dict(case_id=CASE,**COVERAGE),['case_id'],['verified saved TJ'],'derive coverage from retained bytes',['sources','limitations']),
 'case.events':route(dict(case_id=CASE,source_id=string(16,pattern='s[1-9][0-9]*'),event=string(64),
     properties=dict(type='object',maxProperties=16,additionalProperties=dict(type='string',maxLength=2048)),
     offset=integer(0,100000,0),limit=integer(1,100,20),linked_run=dict(type='boolean',default=False)),['case_id'],
     ['verified saved TJ'],'read bounded exact page',['case_id','records','matched_count','next_offset']),
 'case.evidence':route(dict(case_id=CASE,evidence_id=string(64,pattern='s[1-9][0-9]*:[1-9][0-9]*')),['case_id','evidence_id'],
     ['verified saved case source'],'read bounded evidence excerpt',['case_id','evidence_id','sha256','truncated']),
 'case.compare':route(dict(before=dict(type='array',items=CASE,minItems=1,maxItems=20),after=dict(type='array',items=CASE,minItems=1,maxItems=20)),
     ['before','after'],['verified saved cases'],'save comparison; no database mutation',['comparison_id','input_reports','performance']),
 'comparison.show':route(dict(comparison_id=CASE),['comparison_id'],['verified saved comparison and case inputs'],'read saved comparison',['comparison_id','input_reports']),
 'source.check':route(dict(manifest=FILE,**COVERAGE),['manifest'],['explicitly selected manifest and TJ'],'read-only inspection; source bytes are not retained',['sources','limitations']),
 'knowledge.search':route(dict(query=string(500),limit=integer(1,20,5)),['query'],['bundled offline knowledge'],'candidate references only; no source fetch',['knowledge_revision','matches']),
 'knowledge.card':route(dict(card_id=string(128),offset=integer(0,65536,0),limit=integer(1,8192,6000)),['card_id'],['bundled authored card'],
     'bounded authored note; no independent diagnosis',['id','body','content_sha256']),
 'os.collect':dict(route(OS['properties'],[],['explicit node and existing local/SSH/WinRM access'],
     'bounded counter collection; no service setup or permission changes',['artifact_id','result','sources'],timeout=1830)),
 'os.import':route(dict(measurements=FILE),['measurements'],['provided OS metrics JSON'],'private artifact snapshot',['artifact_id','result','sources']),
 'artifact.show':route(dict(artifact_id=CASE),['artifact_id'],['verified saved artifact'],'read saved evidence',['artifact_id','result','sources']),
}

def validate(value,schema):
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
        if (not schema.get('minLength',0)<=len(value)<=schema.get('maxLength',2048) or any(ord(c)<32 for c in value)
            or 'pattern' in schema and not re.fullmatch(schema['pattern'],value)):
            raise InputError('invalid bounded operation text')
    if kind in ('number','integer'):
        if not math.isfinite(value) or not schema.get('minimum',-math.inf)<=value<=schema.get('maximum',math.inf):raise InputError('operation argument outside limits')
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
        not_yet_managed=['RAC','PostgreSQL','native JR','source snapshots/export','APDEX','investigation/profile mutations','knowledge-use','incident drafts','CodeMode'])

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
    if operation=='os.collect':
        from .os_metrics import validate_request as os_request
        args=os_request(args)
    timeout=args.get('duration_seconds',0)+30 if operation=='os.collect' else ROUTES[operation]['timeout_seconds']
    budget=dict(timeout_seconds=timeout,max_result_bytes=MAX_RESULT)
    budget.update(result.get('budget',{}))
    if budget['timeout_seconds']>ROUTES[operation]['timeout_seconds']:raise InputError('operation timeout exceeds catalogue')
    result.update(arguments={key:value for key,value in args.items() if value is not None},budget=budget)
    return result

def execute(operation,args,state,output,*,stop=None):
    from . import storage
    targets=[]
    if operation=='case.analyze':data=storage.investigate(args['manifest'],output);targets=[dict(kind='cases',id=data['case_id'])]
    elif operation=='case.show':
        from .knowledge_review import review_legacy_report
        data=storage.verified_case(state,args['case_id']);data=dict(data,knowledge_review=review_legacy_report(data))
    elif operation in ('case.coverage','source.check'):
        from .source_coverage import inspect_case,inspect_manifest
        options={k:args[k] for k in COVERAGE if k in args}
        data=inspect_case(state,args['case_id'],**options) if operation=='case.coverage' else inspect_manifest(args['manifest'],**options)
    elif operation=='case.events':data=storage.list_native_events(state,**args)
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
        data=collect_os(output,args,should_stop=stop) if operation=='os.collect' else import_os(output,args['measurements'])
        targets=[dict(kind='artifacts',id=data['artifact_id'])]
    elif operation=='artifact.show':
        from .artifacts import load_artifact
        data=load_artifact(state,args['artifact_id'])
        if data['kind']=='knowledge_use':
            from .knowledge_review import review_use
            data=dict(data,knowledge_review=review_use(state,args['artifact_id']))
    else:raise InputError('unknown executable operation')
    if not isinstance(data,dict) or set(ROUTES[operation]['data_schema']['required'])-data.keys():raise InputError('adapter output does not match registered schema')
    return data,targets
