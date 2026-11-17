"""Finite diagnostic adapters; importing schemas never probes a configured source."""
from pathlib import Path

from .inputs import InputError

OPERATIONS=('artifact.evidence','apdex.import','jr.import','jr.events','jr.record',
    'source.snapshot','source.search','source.read','rac.observe','postgresql.observe')
CREATORS={'apdex.import','jr.import','source.snapshot','rac.observe','postgresql.observe'}
ARTIFACT_READS={'artifact.evidence','jr.events','jr.record','source.search','source.read'}
RAC_QUERIES=('clusters','infobases','sessions','connections','processes','servers')
PG_QUERIES=('capabilities','activity','locks','database_stats','statements')


def source_schema(cap):
    return cap.obj(dict(path=cap.FILE,kind=cap.string(16,enum=['catalog','git'],default='catalog'),
        ref=cap.string(200,default='HEAD'),encoding=cap.string(16,enum=['utf-8','cp1251'],default='utf-8')),['path'])


def journal_schema(cap):
    return cap.obj(dict(path=cap.FILE,platform_version=cap.string(32,enum=['8.3.27.1989']),
        utc_offset=cap.string(6),consistency=cap.string(32,enum=['unknown','stopped_writer','provided_snapshot'],default='unknown')),['path','platform_version'])


def connection_schema(cap,kind):
    if kind=='rac':return cap.obj(dict(endpoint=cap.string(300),executable=cap.string(default='rac'),docker_container=cap.string(128)),['endpoint'])
    return cap.obj(dict(database=cap.string(128),host=cap.string(253),port=cap.integer(1,65535,5432),
        user=cap.string(128),executable=cap.string(default='psql'),docker_container=cap.string(128)),['database'])


def scope_schemas(cap):
    profiles={}
    for kind,queries in [('rac',RAC_QUERIES),('postgresql',PG_QUERIES)]:
        fields=dict(settings=connection_schema(cap,kind),queries=cap.array(cap.string(32,enum=list(queries)),len(queries)),max_calls=cap.integer(1,64,len(queries)))
        if kind=='rac':fields.update(clusters=cap.array(cap.string(36),100),any_cluster=dict(type='boolean',default=False))
        profiles[kind]=cap.array(cap.obj(fields,['settings']),8)
    return dict(source_snapshots=cap.array(source_schema(cap),32),journals=cap.array(journal_schema(cap),32),**profiles)


def routes(cap):
    def route(args,required,sources,impact,fields,types=None,timeout=60):
        value=cap.route(args,required,sources,impact,fields,timeout=timeout)
        value['data_schema']['properties'].update(types or {})
        value['output_schema']=cap.response_schema(value['data_schema'])
        return value
    artifact=dict(artifact_id=cap.CASE)
    outputs=['artifact_id','result','sources']
    result={
        'artifact.evidence':route(dict(**artifact,source_id=cap.string(16,pattern='s[1-9][0-9]*')),['artifact_id','source_id'],
            ['verified saved artifact'],'read bounded private evidence; never publish',
            ['artifact_id','source_id','sha256','text','truncated'],dict(source_id=dict(type='string'),text=dict(type='string'))),
        'apdex.import':route(dict(measurements=cap.FILE,target_seconds=dict(type='number',minimum=0,maximum=31536000),
            operation=cap.string(256),start=cap.string(80),end=cap.string(80)),['measurements','target_seconds'],
            ['explicit normalized APDEX measurements and target'],'save measured APDEX; no BSP/native export compatibility claim',outputs),
        'jr.import':route(journal_schema(cap)['properties'],['path','platform_version'],['selected sequential LGF/LGP directory'],
            'save bounded native journal snapshot; no database/run identity inference',outputs),
        'jr.events':route(dict(**artifact,event=cap.string(2000),offset=cap.integer(0,100000,0),limit=cap.integer(1,100,20)),['artifact_id'],
            ['verified native JR artifact'],'read bounded page from saved journal',
            ['artifact_id','records','total_matched','next_offset'],dict(total_matched=dict(type='integer'),next_offset=dict(type=['integer','null']))),
        'jr.record':route(dict(**artifact,record_id=cap.string(64,pattern='s[1-9][0-9]*:r[1-9][0-9]*')),['artifact_id','record_id'],
            ['verified native JR artifact'],'read exact saved record bytes without interpreting serialized1C values',
            ['artifact_id','record','text'],dict(text=dict(type='string'))),
        'source.snapshot':route(source_schema(cap)['properties'],['path'],['selected XML/BSL directory or complete local Git repository'],
            'save static sources; no fetch/hooks/builds/BSL execution',outputs),
        'source.search':route(dict(**artifact,query=cap.string(256),limit=cap.integer(1,100,20)),['artifact_id','query'],
            ['verified saved source artifact'],'literal source search with file/line references',
            ['artifact_id','matches','total_matches','truncated'],dict(total_matches=dict(type='integer'))),
        'source.read':route(dict(**artifact,path=cap.FILE,start=cap.integer(1,8388608,1),limit=cap.integer(1,200,50)),['artifact_id','path'],
            ['verified saved source artifact'],'bounded source lines; static code does not establish runtime execution',
            ['artifact_id','path','sha256','lines','total_lines','has_more'],dict(path=dict(type='string'),lines=dict(type='array'),total_lines=dict(type='integer'),has_more=dict(type='boolean'))),
    }
    for kind,queries in [('rac',RAC_QUERIES),('postgresql',PG_QUERIES)]:
        settings=connection_schema(cap,kind);args=dict(settings['properties'],query=cap.string(32,enum=list(queries)))
        if kind=='rac':args['cluster']=cap.string(36)
        result[kind+'.observe']=route(args,settings['required']+['query'],['explicit existing '+kind+' connection and read rights'],
            'fixed read-only query; private snapshot, unavailable visibility remains unknown',outputs,timeout=35 if kind=='rac' else 25)
    for name,value in result.items():
        if name.startswith('jr.'):
            value['compatibility']=dict(profile='1c-jr-sequential-8.3.27.1989-v1',other_versions='unverified',LGD=False,XML_export=False)
        elif name.startswith('source.'):
            value['compatibility']=dict(profile='onec-source-snapshot-v1',inputs=['XML/BSL directory','complete local Git'],executed_code=False,runtime_correspondence='unknown until separately verified')
        elif name.startswith('apdex.'):
            value['compatibility']=dict(profile='apdex-measurements-v1',native_BSP_export='unverified')
        elif name=='rac.observe':
            value['compatibility']=dict(profile='fixed RAC read catalogue; UTF-8 output',live_RAS_compatibility='requires separate matching-version check')
            value['rights']+=['connect to selected existing RAS endpoint','cluster metadata read permissions for selected commands; authenticated-admin profile not implemented']
        elif name=='postgresql.observe':
            value['compatibility']=dict(profile='PostgreSQL16 fixed monitoring queries',other_versions='unverified',statements='requires existing public.pg_stat_statements views')
            value['rights']+=['connect to selected database with existing libpq account','SELECT monitoring views; pg_read_all_stats optional for wider visibility; no grants or extension setup']
    return result


def normalize_source(args):
    import re
    result=dict(args,path=str(Path(args['path']).absolute()))
    if result['kind']=='catalog' and result['ref']!='HEAD':raise InputError('Git ref is only applicable to a Git snapshot')
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_./-]{0,199}',result['ref']):raise InputError('invalid local Git ref')
    return result


def normalize_connection(kind,args):
    result=dict(args)
    if kind=='rac':
        from .rac import RacClient
        RacClient(**result)
    else:
        from .postgresql import PsqlClient
        PsqlClient(**result)
    return result


def normalize(operation,args):
    result=dict(args)
    if operation=='source.snapshot':return normalize_source(result)
    if operation=='source.read':
        from .source_code import safe_name
        result['path']=safe_name(result['path'])
    elif operation=='jr.import':
        import re
        if 'utc_offset' in result and (not re.fullmatch(r'[+-](?:[01]\d|2[0-3]):[0-5]\d',result['utc_offset']) or result['utc_offset']=='-00:00'):
            raise InputError('journal offset must be explicit and valid, or omitted as unknown')
        result['path']=str(Path(result['path']).absolute())
    elif operation=='apdex.import':
        from .apdex import number,instant
        number(result['target_seconds'],'target_seconds',True)
        lower=instant(result['start']) if 'start' in result else None
        upper=instant(result['end']) if 'end' in result else None
        if lower is not None and upper is not None and lower>=upper:raise InputError('APDEX start must precede end')
        result['measurements']=str(Path(result['measurements']).absolute())
    elif operation in ('rac.observe','postgresql.observe'):
        kind=operation.split('.')[0];query=result['query'];settings={k:v for k,v in result.items() if k not in ('query','cluster')}
        normalize_connection(kind,settings)
        if kind=='rac':
            from .rac import RacClient
            RacClient(**settings).command(query,cluster=result.get('cluster'))
    return result


def execute(operation,args,state,output,*,stop=None):
    if operation=='artifact.evidence':
        from .artifacts import artifact_evidence
        return artifact_evidence(state,**args),[]
    if operation=='apdex.import':
        from .artifacts import import_apdex
        data=import_apdex(output,args['measurements'],args['target_seconds'],**{k:v for k,v in args.items() if k not in ('measurements','target_seconds')})
    elif operation=='jr.import':
        from .native_jr import read_journal
        data=read_journal(output,**args)
    elif operation=='source.snapshot':
        from .source_code import snapshot_source
        data=snapshot_source(output,**args)
    elif operation in ('jr.events','jr.record'):
        from .native_jr import list_events,read_record
        data=list_events(state,**args) if operation=='jr.events' else read_record(state,**args)
        if operation=='jr.events':
            following=args['offset']+len(data['records'])
            data['next_offset']=following if following<data['total_matched'] else None
            data['truncated']=args['offset']>0 or data['next_offset'] is not None
        return data,[]
    elif operation in ('source.search','source.read'):
        from .source_code import search_source,read_source
        data=search_source(state,**args) if operation=='source.search' else read_source(state,**args)
        if operation=='source.read':data['truncated']=args['start']>1 or data['has_more'] or any(row['truncated'] for row in data['lines'])
        return data,[]
    elif operation=='rac.observe':
        from .rac import RacClient,collect_rac
        data=collect_rac(output,RacClient(**{k:v for k,v in args.items() if k not in ('query','cluster')}),args['query'],cluster=args.get('cluster'),should_stop=stop)
    elif operation=='postgresql.observe':
        from .postgresql import PsqlClient,observe
        data=observe(output,PsqlClient(**{k:v for k,v in args.items() if k!='query'}),args['query'],should_stop=stop)
    else:raise InputError('unsupported diagnostic adapter')
    return data,[dict(kind='artifacts',id=data['artifact_id'])]


def result_status(operation,data):
    status=data.get('result',{}).get('status')
    if status=='cancelled' and operation in ('rac.observe','postgresql.observe'):return 'cancelled','cancelled'
    if (operation=='apdex.import' and status in ('empty','incomplete') or operation=='jr.import' and status=='partial'
        or operation in ('rac.observe','postgresql.observe') and status=='unavailable'):
        return 'partial',operation.split('.')[0]+'_'+status
    return 'succeeded',None
