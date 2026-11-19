"""Finite diagnostic adapters; importing schemas never probes a configured source."""
from pathlib import Path

from .inputs import InputError
from .sqlserver_queries import OPERATIONS as SQL_QUERIES

OPERATIONS=('artifact.evidence','apdex.import','jr.import','jr.events','jr.record',
    'source.snapshot','source.search','source.read','rac.observe','postgresql.observe','sqlserver.observe',
    'client.import','client.observe')
CREATORS={'apdex.import','jr.import','source.snapshot','rac.observe','postgresql.observe','sqlserver.observe',
          'client.import','client.observe'}
ARTIFACT_READS={'artifact.evidence','jr.events','jr.record','source.search','source.read'}
RAC_QUERIES=('clusters','infobases','sessions','connections','processes','servers','infobase_info')
PG_QUERIES=('capabilities','activity','locks','database_stats','statements')


def source_schema(cap):
    return cap.obj(dict(path=cap.FILE,kind=cap.string(16,enum=['catalog','git'],default='catalog'),
        ref=cap.string(200,default='HEAD'),encoding=cap.string(16,enum=['utf-8','cp1251'],default='utf-8')),['path'])


def journal_schema(cap):
    from .native_jr import PLATFORM_VERSION
    return cap.obj(dict(path=cap.FILE,platform_version=cap.string(32,pattern=PLATFORM_VERSION),
        utc_offset=cap.string(6),consistency=cap.string(32,enum=['unknown','stopped_writer','provided_snapshot'],default='unknown')),['path'])


def testpilot_schema(cap):
    endpoint=cap.obj(dict(port=dict(type='integer',minimum=1,maximum=65535),pid=dict(type='integer',minimum=1,maximum=2**32-1),
                          lifetime=cap.string(20,pattern='[1-9][0-9]{0,19}')),['port','pid','lifetime'])
    navigation=cap.obj(dict(link=cap.string(300),ready_form=cap.string(300)),['link','ready_form'])
    return cap.obj(dict(endpoint=endpoint,python=cap.FILE,database_mode=cap.string(16,enum=['file','server','unknown'],default='unknown'),
                        navigation=navigation),['endpoint','python'])


def connection_schema(cap,kind):
    if kind=='rac':return cap.obj(dict(endpoint=cap.string(300),executable=cap.string(default='rac'),docker_container=cap.string(128)),['endpoint'])
    if kind=='sqlserver':return cap.obj(dict(database=cap.string(128),host=cap.string(253),port=cap.integer(1,65535,1433),
        user=cap.string(128),auth=cap.string(16,enum=['integrated','sql'],default='integrated'),executable=cap.string(1024,default='sqlcmd'),
        docker_container=cap.string(128),client_variant=cap.string(16,enum=['auto','go','odbc18'],default='auto'),
        trust_server_certificate=dict(type='boolean',default=False)),['database','host'])
    return cap.obj(dict(database=cap.string(128),host=cap.string(253),port=cap.integer(1,65535,5432),
        user=cap.string(128),executable=cap.string(default='psql'),docker_container=cap.string(128)),['database'])


def scope_schemas(cap):
    profiles={}
    for kind,queries in [('rac',RAC_QUERIES),('postgresql',PG_QUERIES),('sqlserver',SQL_QUERIES)]:
        fields=dict(settings=connection_schema(cap,kind),queries=cap.array(cap.string(32,enum=list(queries)),len(queries)),max_calls=cap.integer(1,64,6 if kind=='rac' else len(queries)))
        if kind=='rac':fields.update(clusters=cap.array(cap.string(36),100),any_cluster=dict(type='boolean',default=False),infobases=dict(type='array',items=cap.string(36),maxItems=100))
        if kind=='sqlserver':fields['windows']=cap.array(cap.WINDOW,16)
        profiles[kind]=cap.array(cap.obj(fields,['settings']),8)
    testpilot=cap.array(cap.obj(dict(settings=testpilot_schema(cap),max_calls=cap.integer(1,5,1)),['settings']),8)
    return dict(source_snapshots=cap.array(source_schema(cap),32),journals=cap.array(journal_schema(cap),32),
                client_episodes=cap.array(cap.FILE,32),testpilot=testpilot,**profiles)


def routes(cap):
    from .input_adapters import fields as input_fields
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
            ['artifact_id','source_id','sha256','text','truncated'],dict(source_id=dict(type='string'),text=dict(type='string'),file_path=dict(type='string'))),
        'apdex.import':route(dict(measurements=cap.FILE,target_seconds=dict(type='number',minimum=0,maximum=31536000),
            inventory_only=dict(type='boolean',description='Inventory normalized measurements ahead of target selection.'),
            operation=cap.string(256),start=cap.string(80),end=cap.string(80),**input_fields(cap,single=True)),['measurements'],
            ['explicit normalized measurements and either a target or inventory_only'],
            'retain measurements or calculate APDEX using a selected target; no native export conversion',outputs),
        'jr.import':route(dict(journal_schema(cap)['properties'],**input_fields(cap)),['path'],['selected LGF/LGP group or verified standalone LGD snapshot'],
            'save bounded native journal snapshot; no database/run identity inference',outputs),
        'jr.events':route(dict(**artifact,event=cap.string(2000),window=cap.WINDOW,offset=cap.integer(0,100000,0),limit=cap.integer(1,100,20)),['artifact_id'],
            ['verified native JR artifact'],'read bounded page and observe timestamps in an optional half-open interval',
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
        'client.import':route(dict(path=cap.FILE),['path'],['selected normalized client-episode-v1 file'],
            'retain a private supplied Testpilot projection or operator markers, with independent readiness and counter status',outputs),
        'client.observe':route(testpilot_schema(cap)['properties'],['endpoint','python'],
            ['explicit existing local Windows thin TestClient and separately installed Testpilot environment'],
            'read active client and session counters or perform one explicitly selected local list navigation; no application readiness or cause inference',outputs,timeout=50),
    }
    result['apdex.import']['input_schema']['oneOf'] = [
        dict(required=['target_seconds'], properties=dict(inventory_only=dict(const=False))),
        dict(required=['inventory_only'], properties=dict(inventory_only=dict(const=True)),
             **{'not': dict(required=['target_seconds'])}),
    ]
    for kind,queries in [('rac',RAC_QUERIES),('postgresql',PG_QUERIES),('sqlserver',SQL_QUERIES)]:
        settings=connection_schema(cap,kind);args=dict(settings['properties'],query=cap.string(32,enum=list(queries)))
        if kind=='rac':args.update(cluster=cap.string(36),infobase=cap.string(36))
        if kind=='sqlserver':args['window']=cap.WINDOW
        result[kind+'.observe']=route(args,settings['required']+['query'],['explicit existing '+kind+' connection and read rights'],
            'fixed read-only query; private snapshot, unavailable visibility remains unknown',outputs,timeout=35 if kind=='rac' else 25)
    for name,value in result.items():
        if name.startswith('jr.'):
            from .native_jr import PROFILE, lgd
            value['compatibility']=dict(profile=PROFILE,other_versions='unverified',XML_export=False,
                LGD=dict(profile=lgd.PROFILE,input='standalone supplied snapshot',writer_build='unknown'))
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
        elif name=='sqlserver.observe':
            value['compatibility']=dict(profile='sqlserver-2022-monitor-v1',other_versions='unverified',clients='Go sqlcmd1.10.x or ODBC sqlcmd18; fixed version probe')
            value['rights']+=['existing SQLCMDPASSWORD session profile or current integrated account; no password argument',
                'SQL2022 VIEW SERVER PERFORMANCE STATE for server DMVs; VIEW DATABASE PERFORMANCE STATE for Query Store; no grants or setup']
        elif name=='client.observe':
            value['compatibility']=dict(profile='Windows thin TestClient 8.3.27.1989 with Testpilot 1.9.2',
                                        endpoint='verified local IPv4 listener identity',
                                        navigation='existing closed-list local e1cib link with exact form predicate')
            value['rights']+=['existing selected test-client access under current Windows account',
                             'navigation may run application handlers and requires explicit approval for the selected link']
        elif name=='client.import':
            value['compatibility']=dict(profile='client-episode-v1',network=False,origins=['testpilot','manual'])
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
    elif kind=='sqlserver':
        from .sqlserver import SqlcmdClient
        SqlcmdClient(**result)
    else:
        from .postgresql import PsqlClient
        PsqlClient(**result)
    return result


def normalize(operation,args):
    result=dict(args)
    if operation=='source.snapshot':return normalize_source(result)
    if operation=='client.observe':
        from .testpilot_capture import normalize as testpilot
        return testpilot(result)
    if operation=='client.import':return dict(path=str(Path(result['path']).absolute()))
    if operation=='source.read':
        from .source_code import safe_name
        result['path']=safe_name(result['path'])
    elif operation=='jr.import':
        import re
        from .input_adapters import normalize as normalize_intake
        result=normalize_intake(result)
        if 'utc_offset' in result and (not re.fullmatch(r'[+-](?:[01]\d|2[0-3]):[0-5]\d',result['utc_offset']) or result['utc_offset']=='-00:00'):
            raise InputError('journal offset must be explicit and valid, or omitted as unknown')
        result['path']=str(Path(result['path']).absolute())
    elif operation=='jr.events' and 'window' in result:
        from .source_coverage import validate_request
        result['window']=validate_request(window=result['window'])['window']
    elif operation=='apdex.import':
        from .input_adapters import normalize as normalize_intake
        result=normalize_intake(result,single=True)
        from .apdex import validate_target_selection, instant
        validate_target_selection(result.get('target_seconds'), result.get('inventory_only', False))
        lower=instant(result['start']) if 'start' in result else None
        upper=instant(result['end']) if 'end' in result else None
        if lower is not None and upper is not None and lower>=upper:raise InputError('APDEX start must precede end')
        result['measurements']=str(Path(result['measurements']).absolute())
    elif operation in ('rac.observe','postgresql.observe','sqlserver.observe'):
        kind=operation.split('.')[0];query=result['query'];settings={k:v for k,v in result.items() if k not in ('query','cluster','infobase','window')}
        normalize_connection(kind,settings)
        if kind=='sqlserver':
            from .sqlserver_queries import script,normalize_window
            script(query,window=result.get('window'))
            if 'window' in result:result['window']=normalize_window(result['window'])
        if kind=='rac':
            from .rac import RacClient
            RacClient(**settings).command(query,cluster=result.get('cluster'),infobase=result.get('infobase'))
    return result


def execute(operation,args,state,output,*,stop=None):
    if operation in ('jr.import','apdex.import') and args.get('input_plan'):
        from .input_adapters import import_selected
        data=import_selected(operation,args,state,output)
        return data,[dict(kind='artifacts',id=data['artifact_id'])]
    if operation=='artifact.evidence':
        from .artifacts import artifact_evidence
        return artifact_evidence(state,**args),[]
    if operation=='apdex.import':
        from .artifacts import import_apdex
        data=import_apdex(output,args['measurements'],**{k:v for k,v in args.items() if k!='measurements'})
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
            data['truncated']=args['offset']>0 or data['next_offset'] is not None
        return data,[]
    elif operation in ('source.search','source.read'):
        from .source_code import search_source,read_source
        data=search_source(state,**args) if operation=='source.search' else read_source(state,**args)
        if operation=='source.read':data['truncated']=args['start']>1 or data['has_more'] or any(row['truncated'] for row in data['lines'])
        return data,[]
    elif operation=='rac.observe':
        from .rac import RacClient,collect_rac
        data=collect_rac(output,RacClient(**{k:v for k,v in args.items() if k not in ('query','cluster','infobase')}),args['query'],cluster=args.get('cluster'),infobase=args.get('infobase'),should_stop=stop)
    elif operation=='postgresql.observe':
        from .postgresql import PsqlClient,observe
        data=observe(output,PsqlClient(**{k:v for k,v in args.items() if k!='query'}),args['query'],should_stop=stop)
    elif operation=='sqlserver.observe':
        from .sqlserver import SqlcmdClient,observe
        data=observe(output,SqlcmdClient(**{k:v for k,v in args.items() if k not in ('query','window')}),args['query'],window=args.get('window'),should_stop=stop)
    elif operation=='client.import':
        from .client_episode import import_episode
        data=import_episode(output,args['path'])
    elif operation=='client.observe':
        from .testpilot_capture import observe
        data=observe(output,lock_state=state,should_stop=stop,**args)
    else:raise InputError('unsupported diagnostic adapter')
    return data,[dict(kind='artifacts',id=data['artifact_id'])]


def result_status(operation,data):
    status=data.get('result',{}).get('status')
    if operation in ('client.observe','client.import'):
        if status=='cancelled':return 'cancelled','cancelled'
        if status in ('partial','unavailable'):return 'partial','client_'+status
    if status=='cancelled' and operation in ('rac.observe','postgresql.observe','sqlserver.observe'):return 'cancelled','cancelled'
    if (operation=='apdex.import' and status in ('empty','incomplete') or operation=='jr.import' and status=='partial'
        or operation in ('rac.observe','postgresql.observe','sqlserver.observe') and status=='unavailable'):
        return 'partial',operation.split('.')[0]+'_'+status
    return 'succeeded',None
