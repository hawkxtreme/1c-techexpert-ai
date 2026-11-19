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
    from .remote_api import scope_schemas as remote_schemas
    scope=cap.obj(dict(operations=cap.array(cap.string(64,enum=list(api_operations)),len(api_operations)),
        cases=cap.array(cap.CASE,100),artifacts=cap.array(cap.CASE,100),comparisons=cap.array(cap.CASE,100),
        investigations=cap.array(cap.obj(dict(id=cap.CASE,revision=cap.integer(1,1000,1)),['id','revision']),100),
        manifests=cap.array(cap.FILE,64),measurements=cap.array(cap.FILE,64),
        reference_reviews=dict(type='array', maxItems=64, items=cap.obj(dict(manifest=cap.FILE,sha256=cap.SHA256),['manifest','sha256'])),
        collectors=cap.array(cap.obj(dict(settings=deepcopy(cap.OS),max_runs=cap.integer(1,5,1)),['settings']),8),
        intakes=cap.array(cap.obj(dict(settings=deepcopy(cap.INPUTS),max_runs=cap.integer(1,5,1)),['settings']),8),**scope_schemas(cap),**logcfg_schemas(cap),**remote_schemas(cap)))
    return dict(program=dict(type='string',minLength=1,maxLength=65536,x_multiline=True),
        language=cap.string(32,enum=['bounded-python-v1'],default='bounded-python-v1'),
        bindings=dict(type='object',maxProperties=64,additionalProperties=True,default={},x_bounded_json=16384),
        scope=dict(scope,default={}),resources=dict(resources,default={}))


def path_key(value):return os.path.normcase(os.path.normpath(str(Path(value).absolute())))


def normalize(arguments, *, operation='code.execute'):
    from . import capabilities as cap
    from .os_metrics import validate_request
    result=deepcopy(arguments)
    if len(result['program'].encode('utf-8'))>65536:raise CodeError('program_limit','Program exceeds 64 KiB UTF-8.')
    bounded(result['bindings'],max_bytes=16384,max_depth=16)
    if len(result['bindings'])>64:raise CodeError('invalid_program','At most64 bindings are supported.')
    # Defaults on the optional objects need validation as objects, too.
    properties=cap.ROUTES[operation]['input_schema']['properties']
    for field in ('scope','resources'):result[field]=cap.validate(result[field],properties[field])
    if operation=='code.context':
        from .context_program import normalize as normalize_views
        return normalize_views(result)
    for field in ('manifests','measurements','client_episodes'):result['scope'][field]=[str(Path(p).absolute()) for p in result['scope'][field]]
    for item in result['scope'].get('reference_reviews', []):item['manifest']=str(Path(item['manifest']).absolute())
    from .input_files import normalize as intake_request
    for profile in result['scope']['intakes']:profile['settings']=intake_request(profile['settings']['inputs'],profile['settings']['limits'])
    for profile in result['scope']['collectors']:
        settings=validate_request(profile['settings'])
        for field in ('identity_file','known_hosts_file'):
            if field in settings:settings[field]=str(Path(settings[field]).absolute())
        profile['settings']={k:v for k,v in settings.items() if v is not None}
    from . import diagnostic_adapters as drivers
    from . import logcfg_api
    from . import remote_api
    for plan in result['scope']['remote_plans']:plan['settings']=remote_api.normalize('remote.plan',plan['settings'])
    for plan in result['scope']['remote_profile_plans']:plan['settings']=remote_api.normalize('remote.profile_plan',plan['settings'])
    for field,operation in [('logcfg_plans','logcfg.prepare'),('logcfg_rollbacks','logcfg.rollback_plan')]:
        for plan in result['scope'][field]:plan['settings']=logcfg_api.normalize(operation,plan['settings'])
    result['scope']['source_snapshots']=[drivers.normalize_source(p) for p in result['scope']['source_snapshots']]
    result['scope']['journals']=[drivers.normalize('jr.import',p) for p in result['scope']['journals']]
    for plan in result['scope']['testpilot']:plan['settings']=drivers.normalize('client.observe',plan['settings'])
    from .rac import UUID
    for kind in ('rac','postgresql','sqlserver'):
        for profile in result['scope'][kind]:
            profile['settings']=drivers.normalize_connection(kind,profile['settings'])
            if kind=='sqlserver':
                from .sqlserver_queries import normalize_window
                profile['windows']=[normalize_window(w) for w in profile['windows']]
            if kind=='rac' and any(not UUID.fullmatch(c) for c in profile['clusters']):raise CodeError('invalid_program','Invalid scoped cluster UUID.')
            if kind=='rac' and any(not UUID.fullmatch(c) for c in profile.get('infobases',[])):raise CodeError('invalid_program','Invalid scoped infobase UUID.')
    return result


class Scope:
    def __init__(self,value,api_operations):
        self.value=deepcopy(value);self.operations=set(value['operations']);self.api_operations=set(api_operations)
        self.ids={kind:set(value[kind]) for kind in ('cases','artifacts','comparisons')}
        self.investigations={(item['id'],item['revision']) for item in value.get('investigations',[])}
        self.imported=set();self.collector_runs=[0]*len(value['collectors']);self.products=[]
        self.observation_runs={kind:[0]*len(value[kind]) for kind in ('rac','postgresql','sqlserver')}
        self.testpilot_runs=[0]*len(value.get('testpilot',[]))
        self.intake_runs=[0]*len(value.get('intakes',[]))
        self.logcfg_runs={field:[0]*len(value.get(field,[])) for field in ('logcfg_plans','logcfg_rollbacks')}
        self.remote_plan_runs=[0]*len(value.get('remote_plans',[]))
        self.remote_profile_plan_runs=[0]*len(value.get('remote_profile_plans',[]))
        self.remote_calls=[dict(calls=0,protocol=0,retained=0) for _ in value.get('remote_calls',[])]

    def authorize(self,operation,arguments):
        if operation not in self.api_operations or operation not in self.operations:raise CodeError('scope_denied','Operation is outside the caller-selected API scope.')
        def target(kind,identifier):
            if identifier not in self.ids[kind]:raise CodeError('scope_denied','Target is outside the caller-selected resource scope.')
        def import_key(path):
            base=(operation,path_key(path))
            return base+(arguments['input_plan'],tuple(sorted(arguments['members']))) if arguments.get('input_plan') else base
        if operation in ('jr.import','os.import','apdex.import') and arguments.get('input_plan'):target('artifacts',arguments['input_plan'])
        if operation=='remote.parse':target('artifacts',arguments['capture_id'])
        elif operation=='remote.plan':
            selected=next((i for i,p in enumerate(self.value.get('remote_plans',[])) if p['settings']==arguments and self.remote_plan_runs[i]<p['max_runs']),None)
            if selected is None:raise CodeError('scope_denied','Remote preparation exceeds the exact approved offline plan.')
            self.remote_plan_runs[selected]+=1
        elif operation=='remote.profile_plan':
            selected=next((i for i,p in enumerate(self.value.get('remote_profile_plans',[])) if p['settings']==arguments and self.remote_profile_plan_runs[i]<p['max_runs']),None)
            if selected is None:raise CodeError('scope_denied','Profile-derived preparation exceeds exact investigation, sources, limits or repeat count.')
            self.remote_profile_plan_runs[selected]+=1
        elif operation in ('remote.inspect','remote.capture'):
            target('artifacts',arguments['plan_id'])
            if operation=='remote.capture':target('artifacts',arguments['catalog_id'])
            selected=None;retained=arguments.get('max_bytes',0)
            for i,plan in enumerate(self.value.get('remote_calls',[])):
                used=self.remote_calls[i]
                if (plan['plan_id']==arguments['plan_id'] and plan['source_id']==arguments['source_id']
                    and used['calls']<plan['max_calls'] and used['protocol']+arguments['protocol_bytes']<=plan['max_protocol_bytes']
                    and used['retained']+retained<=plan['max_retained_bytes'] and arguments['timeout_seconds']<=plan['max_timeout_seconds']):selected=i;break
            if selected is None:raise CodeError('scope_denied','Remote source, transfer reservations or repeat count exceed the approved plan.')
            used=self.remote_calls[selected];used['calls']+=1;used['protocol']+=arguments['protocol_bytes'];used['retained']+=retained
        elif operation in ('logcfg.prepare','logcfg.rollback_plan'):
            if operation=='logcfg.rollback_plan':target('artifacts',arguments['proposal_id'])
            field='logcfg_plans' if operation=='logcfg.prepare' else 'logcfg_rollbacks'
            selected=next((i for i,p in enumerate(self.value.get(field,[])) if p['settings']==arguments and self.logcfg_runs[field][i]<p['max_runs']),None)
            if selected is None:raise CodeError('scope_denied','logcfg proposal exceeds exact approved settings, input or repeat count.')
            self.logcfg_runs[field][selected]+=1
        elif operation=='input.inspect':
            selected=next((i for i,p in enumerate(self.value['intakes']) if p['settings']==arguments and self.intake_runs[i]<p['max_runs']),None)
            if selected is None:raise CodeError('scope_denied','Input inspection is outside the exact approved paths, limits or repeat count.')
            self.intake_runs[selected]+=1
        elif operation in ('investigation.sources','fix.verify','apdex.prepare'):
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
        elif operation=='client.observe':
            approved=self.value.get('testpilot',[])
            if 'navigation' in arguments and any(self.testpilot_runs[i] and 'navigation' in plan['settings']
                and plan['settings']['endpoint']==arguments['endpoint'] for i,plan in enumerate(approved)):
                raise CodeError('scope_denied','One TestClient navigation per endpoint is allowed in a program, including uncertain outcomes.')
            selected=next((i for i,p in enumerate(approved) if p['settings']==arguments and self.testpilot_runs[i]<p['max_calls']),None)
            if selected is None:raise CodeError('scope_denied','TestClient selection, action or count exceeds the explicit approval.')
            self.testpilot_runs[selected]+=1
        elif operation in ('source.snapshot','jr.import','client.import'):
            if operation=='client.import':
                allowed=[dict(path=p) for p in self.value.get('client_episodes',[])]
            else:
                allowed=self.value['source_snapshots' if operation=='source.snapshot' else 'journals']
            def same(plan):
                return path_key(plan['path'])==path_key(arguments['path']) and {k:v for k,v in plan.items() if k!='path'}=={k:v for k,v in arguments.items() if k not in ('path','input_plan','members')}
            if not any(same(plan) for plan in allowed):raise CodeError('scope_denied','Source profile is outside the approved input plan.')
            identity=import_key(arguments['path'])
            if identity in self.imported:raise CodeError('scope_denied','Repeated source capture requires a separately reviewed plan.')
            self.imported.add(identity)
        elif operation in ('rac.observe','postgresql.observe','sqlserver.observe'):
            kind=operation.split('.')[0];connection={k:v for k,v in arguments.items() if k not in ('query','cluster','infobase','window')};selected=None
            for index,profile in enumerate(self.value[kind]):
                if profile['settings']!=connection or arguments['query'] not in profile['queries']:continue
                if kind=='sqlserver' and arguments['query']=='query_store' and arguments['window'] not in profile['windows']:continue
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
            if operation=='case.analyze' and 'reference_sha256' in arguments:
                if not any(path_key(item['manifest']) == key and item['sha256'] == arguments['reference_sha256']
                           for item in self.value.get('reference_reviews', [])):
                    raise CodeError('scope_denied','External TJ review is outside the caller-selected source scope.')
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
        if operation=='remote.parse':
            field,kind=('case_id','cases') if 'case_id' in data else ('artifact_id','artifacts')
        else:
            field,kind={'case.analyze':('case_id','cases'),'case.compare':('comparison_id','comparisons'),
                **{op:('artifact_id','artifacts') for op in ('remote.plan','remote.profile_plan','remote.inspect','remote.capture','logcfg.prepare','logcfg.rollback_plan','input.inspect','os.collect','os.import','apdex.import','jr.import','source.snapshot','rac.observe','postgresql.observe','sqlserver.observe','client.observe','client.import','fix.verify','apdex.prepare')}}.get(operation,(None,None))
        if not field:return
        identifier=data.get(field)
        if not isinstance(identifier,str) or len(identifier)!=32 or any(c not in 'abcdef0123456789' for c in identifier):
            raise CodeError('api_integrity','Created resource identity is invalid.')
        self.ids[kind].add(identifier)
        target=dict(kind=kind,id=identifier)
        if target not in self.products:self.products.append(target)
