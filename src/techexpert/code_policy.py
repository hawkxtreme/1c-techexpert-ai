"""Caller-selected capability scope. Program values never grant OS permissions."""
from copy import deepcopy
import os
from pathlib import Path

from .code_values import CodeError,bounded


def schemas(cap,api_operations):
    from .diagnostic_adapters import scope_schemas
    resources=cap.obj(dict(memory_bytes=cap.integer(64*1024**2,1024**3,256*1024**2),
        max_calls=cap.integer(1,64,32),max_steps=cap.integer(1000,2000000,200000),
        max_api_bytes=cap.integer(16384,64*1024**2,64*1024**2),
        max_owned_bytes=cap.integer(1024**2,256*1024**2,256*1024**2),
        max_value_bytes=cap.integer(16384,16*1024**2,16*1024**2)),[])
    from .logcfg_api import scope_schemas as logcfg_schemas
    scope=cap.obj(dict(operations=cap.array(cap.string(64,enum=list(api_operations)),len(api_operations)),
        cases=cap.array(cap.CASE,100),artifacts=cap.array(cap.CASE,100),comparisons=cap.array(cap.CASE,100),
        investigations=cap.array(cap.obj(dict(id=cap.CASE,revision=cap.integer(1,1000,1)),['id','revision']),100),
        manifests=cap.array(cap.FILE,64),measurements=cap.array(cap.FILE,64),
        collectors=cap.array(cap.obj(dict(settings=deepcopy(cap.OS),max_runs=cap.integer(1,5,1)),['settings']),8),
        intakes=cap.array(cap.obj(dict(settings=deepcopy(cap.INPUTS),max_runs=cap.integer(1,5,1)),['settings']),8),**scope_schemas(cap),**logcfg_schemas(cap)))
    return dict(program=dict(type='string',minLength=1,maxLength=65536,x_multiline=True),
        language=cap.string(32,enum=['bounded-python-v1'],default='bounded-python-v1'),
        bindings=dict(type='object',maxProperties=64,additionalProperties=True,default={},x_bounded_json=16384),
        scope=dict(scope,default={}),resources=dict(resources,default={}))


def path_key(value):return os.path.normcase(os.path.normpath(str(Path(value).absolute())))


def normalize(arguments):
    from . import capabilities as cap
    from .os_metrics import validate_request
    result=deepcopy(arguments)
    if len(result['program'].encode('utf-8'))>65536:raise CodeError('program_limit','Program exceeds 64 KiB UTF-8.')
    bounded(result['bindings'],max_bytes=16384,max_depth=16)
    if len(result['bindings'])>64:raise CodeError('invalid_program','At most64 bindings are supported.')
    # Defaults on the optional objects need validation as objects, too.
    properties=cap.ROUTES['code.execute']['input_schema']['properties']
    for field in ('scope','resources'):result[field]=cap.validate(result[field],properties[field])
    for field in ('manifests','measurements'):result['scope'][field]=[str(Path(p).absolute()) for p in result['scope'][field]]
    from .input_files import normalize as intake_request
    for profile in result['scope']['intakes']:profile['settings']=intake_request(profile['settings']['inputs'],profile['settings']['limits'])
    for profile in result['scope']['collectors']:
        settings=validate_request(profile['settings'])
        for field in ('identity_file','known_hosts_file'):
            if field in settings:settings[field]=str(Path(settings[field]).absolute())
        profile['settings']={k:v for k,v in settings.items() if v is not None}
    from . import diagnostic_adapters as drivers
    from . import logcfg_api
    for field,operation in [('logcfg_plans','logcfg.prepare'),('logcfg_rollbacks','logcfg.rollback_plan')]:
        for plan in result['scope'][field]:plan['settings']=logcfg_api.normalize(operation,plan['settings'])
    result['scope']['source_snapshots']=[drivers.normalize_source(p) for p in result['scope']['source_snapshots']]
    result['scope']['journals']=[drivers.normalize('jr.import',p) for p in result['scope']['journals']]
    from .rac import UUID
    for kind in ('rac','postgresql'):
        for profile in result['scope'][kind]:
            profile['settings']=drivers.normalize_connection(kind,profile['settings'])
            if kind=='rac' and any(not UUID.fullmatch(c) for c in profile['clusters']):raise CodeError('invalid_program','Invalid scoped cluster UUID.')
            if kind=='rac' and any(not UUID.fullmatch(c) for c in profile.get('infobases',[])):raise CodeError('invalid_program','Invalid scoped infobase UUID.')
    return result


class Scope:
    def __init__(self,value,api_operations):
        self.value=deepcopy(value);self.operations=set(value['operations']);self.api_operations=set(api_operations)
        self.ids={kind:set(value[kind]) for kind in ('cases','artifacts','comparisons')}
        self.investigations={(item['id'],item['revision']) for item in value.get('investigations',[])}
        self.imported=set();self.collector_runs=[0]*len(value['collectors']);self.products=[]
        self.observation_runs={kind:[0]*len(value[kind]) for kind in ('rac','postgresql')}
        self.intake_runs=[0]*len(value.get('intakes',[]))
        self.logcfg_runs={field:[0]*len(value.get(field,[])) for field in ('logcfg_plans','logcfg_rollbacks')}

    def authorize(self,operation,arguments):
        if operation not in self.api_operations or operation not in self.operations:raise CodeError('scope_denied','Operation is outside the caller-selected API scope.')
        def target(kind,identifier):
            if identifier not in self.ids[kind]:raise CodeError('scope_denied','Target is outside the caller-selected resource scope.')
        def import_key(path):
            base=(operation,path_key(path))
            return base+(arguments['input_plan'],tuple(sorted(arguments['members']))) if arguments.get('input_plan') else base
        if operation in ('jr.import','os.import','apdex.import') and arguments.get('input_plan'):target('artifacts',arguments['input_plan'])
        if operation in ('logcfg.prepare','logcfg.rollback_plan'):
            if operation=='logcfg.rollback_plan':target('artifacts',arguments['proposal_id'])
            field='logcfg_plans' if operation=='logcfg.prepare' else 'logcfg_rollbacks'
            selected=next((i for i,p in enumerate(self.value.get(field,[])) if p['settings']==arguments and self.logcfg_runs[field][i]<p['max_runs']),None)
            if selected is None:raise CodeError('scope_denied','logcfg proposal exceeds exact approved settings, input or repeat count.')
            self.logcfg_runs[field][selected]+=1
        elif operation=='input.inspect':
            selected=next((i for i,p in enumerate(self.value['intakes']) if p['settings']==arguments and self.intake_runs[i]<p['max_runs']),None)
            if selected is None:raise CodeError('scope_denied','Input inspection is outside the exact approved paths, limits or repeat count.')
            self.intake_runs[selected]+=1
        elif operation=='investigation.sources':
            if (arguments['investigation_id'],arguments['revision']) not in self.investigations:raise CodeError('scope_denied','Investigation revision is outside the approved source context.')
        elif operation=='source.compare':
            for ref in (arguments['before'],arguments['after']):target({'case':'cases','artifact':'artifacts'}[ref['kind']],ref['id'])
        elif operation=='sample.describe':
            for ref in arguments['inputs']:target({'case':'cases','artifact':'artifacts'}[ref['kind']],ref['id'])
        elif operation.startswith('case.') and operation not in ('case.analyze','case.compare'):target('cases',arguments['case_id'])
        elif operation=='case.compare':
            for identifier in arguments['before']+arguments['after']:target('cases',identifier)
        elif operation=='comparison.show':target('comparisons',arguments['comparison_id'])
        elif operation=='artifact.show' or operation in ('artifact.evidence','jr.events','jr.record','source.search','source.read'):target('artifacts',arguments['artifact_id'])
        elif operation in ('source.snapshot','jr.import'):
            field='source_snapshots' if operation=='source.snapshot' else 'journals'
            def same(plan):
                return path_key(plan['path'])==path_key(arguments['path']) and {k:v for k,v in plan.items() if k!='path'}=={k:v for k,v in arguments.items() if k not in ('path','input_plan','members')}
            if not any(same(plan) for plan in self.value[field]):raise CodeError('scope_denied','Source profile is outside the approved input plan.')
            identity=import_key(arguments['path'])
            if identity in self.imported:raise CodeError('scope_denied','Repeated source capture requires a separately reviewed plan.')
            self.imported.add(identity)
        elif operation in ('rac.observe','postgresql.observe'):
            kind=operation.split('.')[0];connection={k:v for k,v in arguments.items() if k not in ('query','cluster','infobase')};selected=None
            for index,profile in enumerate(self.value[kind]):
                if profile['settings']!=connection or arguments['query'] not in profile['queries']:continue
                if kind=='rac' and arguments.get('cluster') and not profile['any_cluster'] and arguments['cluster'] not in profile['clusters']:continue
                if kind=='rac' and arguments['query']=='infobase_info' and arguments['infobase'] not in profile.get('infobases',[]):continue
                if self.observation_runs[kind][index]<profile['max_calls']:selected=index;break
            if selected is None:raise CodeError('scope_denied','Connection, query or observation count exceeds the approved source plan.')
            self.observation_runs[kind][selected]+=1
        elif operation=='apdex.import':
            key=path_key(arguments['measurements'])
            if key not in {path_key(p) for p in self.value['measurements']}:raise CodeError('scope_denied','Measurements are outside the approved input scope.')
            identity=import_key(arguments['measurements'])
            if identity in self.imported:raise CodeError('scope_denied','Repeated measurements import requires a separately reviewed plan.')
            self.imported.add(identity)
        elif operation in ('case.analyze','source.check','os.import'):
            if operation=='case.analyze' and arguments.get('input_plan'):target('artifacts',arguments['input_plan'])
            field='measurements' if operation=='os.import' else 'manifests'
            key=path_key(arguments['measurements' if operation=='os.import' else 'manifest'])
            if key not in {path_key(p) for p in self.value[field]}:raise CodeError('scope_denied','Input path is outside the caller-selected source scope.')
            if operation!='source.check':
                identity=import_key(arguments['measurements']) if operation=='os.import' else (operation,key)
                if identity in self.imported:raise CodeError('scope_denied','Repeated import requires a separately reviewed plan, not an automatic new run.')
                self.imported.add(identity)
        elif operation=='os.collect':
            selected=None
            for index,profile in enumerate(self.value['collectors']):
                plan=profile['settings'];variable={'duration_seconds','interval_seconds','max_bytes'}
                if {k:v for k,v in arguments.items() if k not in variable}!={k:v for k,v in plan.items() if k not in variable}:continue
                if (arguments['duration_seconds']>plan['duration_seconds'] or arguments['interval_seconds']<plan['interval_seconds']
                    or arguments['max_bytes']>plan['max_bytes']):continue
                if self.collector_runs[index]<profile['max_runs']:selected=index;break
            if selected is None:raise CodeError('scope_denied','Collector settings or repeat count exceed the approved plan.')
            self.collector_runs[selected]+=1

    def produced(self,operation,data):
        if not isinstance(data,dict):return
        field,kind={'case.analyze':('case_id','cases'),'case.compare':('comparison_id','comparisons'),
            **{op:('artifact_id','artifacts') for op in ('logcfg.prepare','logcfg.rollback_plan','input.inspect','os.collect','os.import','apdex.import','jr.import','source.snapshot','rac.observe','postgresql.observe')}}.get(operation,(None,None))
        if not field:return
        identifier=data.get(field)
        if not isinstance(identifier,str) or len(identifier)!=32 or any(c not in 'abcdef0123456789' for c in identifier):
            raise CodeError('api_integrity','Created resource identity is invalid.')
        self.ids[kind].add(identifier)
        target=dict(kind=kind,id=identifier)
        if target not in self.products:self.products.append(target)
