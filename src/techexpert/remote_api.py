"""Finite remote-acquisition schemas, dispatch and retained dependency pins."""
from . import remote_budget,remote_sources,remote_transfers,remote_intake,operation_state as fs
from .inputs import InputError

OPERATIONS=('remote.plan','remote.inspect','remote.capture','remote.parse')


def plan_schema(cap):
    caps={name:cap.integer(low,high,default) for name,(low,high,default) in remote_budget.CAPS.items()}
    connection=cap.obj(dict(host=cap.string(320),port=cap.integer(1,65535,22),known_hosts_file=cap.FILE,identity_file=cap.FILE,node=cap.string(256),root=cap.FILE),['host','known_hosts_file','node','root'])
    source=cap.obj(dict(id=cap.string(64,pattern='[A-Za-z][A-Za-z0-9_-]{0,63}'),connection=connection,**caps),['id','connection'])
    return cap.obj(dict(investigation_id=cap.CASE,revision=cap.integer(1,1000,1),sources=dict(type='array',minItems=1,maxItems=8,items=source),**caps),['investigation_id','revision','sources'])


def routes(cap):
    source_id=cap.string(64,pattern='[A-Za-z][A-Za-z0-9_-]{0,63}')
    protocol=cap.integer(16384,256*1024**2,1024**2)
    inspect_args=dict(plan_id=cap.CASE,source_id=source_id,protocol_bytes=protocol,timeout_seconds=cap.integer(1,120,30),
        limits=dict(cap.obj({key:cap.integer(0 if key=='max_depth' else 1,value,value) for key,value in remote_sources.LIMITS.items()}),default={}))
    capture_args=dict(plan_id=cap.CASE,source_id=source_id,catalog_id=cap.CASE,members=dict(type='array',minItems=1,maxItems=32,items=cap.string(4,pattern='m[1-9][0-9]{0,2}')),
        protocol_bytes=cap.integer(16384,256*1024**2,64*1024**2),max_bytes=cap.integer(1,64*1024**2,16*1024**2),timeout_seconds=cap.integer(1,120,60))
    outputs=['artifact_id','result','sources']
    result={
        'remote.plan':cap.route(plan_schema(cap)['properties'],['investigation_id','revision','sources'],['explicit investigation revision, source connection references and bounded budgets'],
            'offline private transfer plan; no connection, collector or service',outputs),
        'remote.inspect':cap.route(inspect_args,['plan_id','source_id'],['approved saved SFTP source plan and existing verified access'],
            'bounded read-only remote metadata; consumes durable source/investigation reservation',outputs,timeout=150),
        'remote.capture':cap.route(capture_args,['plan_id','source_id','catalog_id','members'],['matching saved remote catalogue and finite source plan'],
            'readonly complete-file acquisition with conservative quotas; partial bytes are not a completed source',outputs,timeout=150),
        'remote.parse':cap.route(dict(capture_id=cap.CASE,adapter=cap.string(16,enum=['case','jr','os','apdex']),settings=dict(type='object',additionalProperties=True,x_bounded_json=1024**2)),
            ['capture_id','adapter','settings'],['verified retained complete remote capture and explicit parser settings'],
            'derive case/JR/OS/APDEX from saved bytes only; no reconnect, model or native1C',['sources'])}
    result['remote.parse']['data_schema']['properties'].update(case_id=dict(type='string'),artifact_id=dict(type='string'))
    result['remote.parse']['output_schema']=cap.response_schema(result['remote.parse']['data_schema'])
    return result


def normalize(operation,args):
    if operation=='remote.plan':return remote_budget.normalize(**args)
    if operation=='remote.inspect':return dict(args,limits=remote_sources.bounds(args['limits']))
    if operation=='remote.parse':return dict(args,settings=remote_intake.normalize(args['adapter'],args['settings']))
    if len(set(args['members']))!=len(args['members']):raise InputError('duplicate remote capture member')
    return args


def scope_schemas(cap):
    source=cap.obj(dict(plan_id=cap.CASE,source_id=cap.string(64,pattern='[A-Za-z][A-Za-z0-9_-]{0,63}'),
        max_calls=cap.integer(1,16,1),max_protocol_bytes=cap.integer(16384,512*1024**2,64*1024**2),
        max_retained_bytes=cap.integer(1,64*1024**2,16*1024**2),max_timeout_seconds=cap.integer(1,120,60)),['plan_id','source_id'])
    return dict(remote_plans=cap.array(cap.obj(dict(settings=plan_schema(cap),max_runs=cap.integer(1,5,1)),['settings']),8),remote_calls=cap.array(source,16))


def execute(operation,args,state,output,stop=None):
    if operation=='remote.plan':data=remote_transfers.prepare(state,output,**args)
    elif operation=='remote.inspect':data=remote_transfers.inspect(state,output,**args,stop=stop)
    elif operation=='remote.capture':data=remote_transfers.capture(state,output,**args,stop=stop)
    else:
        data=remote_intake.parse(state,output,**args)
        return data,[dict(kind='cases' if args['adapter']=='case' else 'artifacts',id=data['case_id' if args['adapter']=='case' else 'artifact_id'])]
    return data,[dict(kind='artifacts',id=data['artifact_id'])]


def _tag(state,report):return remote_transfers.dependency(state,report)


def pin(state,operation,args,data,add):
    if operation=='remote.parse':
        kind='cases' if args['adapter']=='case' else 'artifacts';key='case_id' if kind=='cases' else 'artifact_id'
        report=add(kind,data[key]);parent=add('artifacts',args['capture_id']);remote_intake.validate_capture(parent)
        intake=report.get('input_intake') if kind=='cases' else report['result'].get('input_intake')
        if type(intake) is not dict or intake.get('artifact_id')!=args['capture_id'] or intake.get('plan_report_digest')!=fs.digest(parent):raise InputError('remote parser capture binding changed')
        return
    report=add('artifacts',data['artifact_id'])
    if operation=='remote.plan':plan=report
    else:
        plan=add('artifacts',args['plan_id'])
        if report['result'].get('plan')!=_tag(state,plan) or report['result'].get('source_id')!=args['source_id']:raise InputError('remote plan/source changed before result commit')
        if operation=='remote.capture':
            catalogue=add('artifacts',args['catalog_id'])
            if report['result'].get('catalogue')!=_tag(state,catalogue):raise InputError('remote catalogue changed before result commit')
            if report['result']['capture_complete']:remote_intake.validate_capture(report)
    inv=plan['result']['investigation'];current=add('investigations',inv['id'],inv['revision'])
    from .investigations import revision_folder
    receipt=fs.digest(fs.read(revision_folder(state,inv['id'],inv['revision'])/'receipt.json',8192))
    if inv['report_digest']!=fs.digest(current) or inv['receipt_digest']!=receipt:raise InputError('remote plan investigation snapshot changed')


def outcome(operation,data):
    if operation in ('remote.inspect','remote.capture'):
        status=data['result']['transfer_status']
        if status=='cancelled':return 'cancelled','cancelled'
        if status!='completed':return 'partial','remote_transfer_incomplete'
        if operation=='remote.inspect' and not data['result']['listing_complete']:return 'partial','remote_catalogue_incomplete'
    if operation=='remote.parse':
        from .diagnostic_adapters import result_status
        mapped=dict(apdex='apdex.import',native_jr='jr.import',os_metrics='os.import')
        if data.get('kind')=='native-jr':return result_status('jr.import',data)
        if data.get('kind')=='apdex':return result_status('apdex.import',data)
        if data.get('kind')=='os_metrics' and data['result'].get('collection_status') not in (None,'completed'):return 'partial','imported_capture_'+data['result']['collection_status']
    return 'succeeded',None
