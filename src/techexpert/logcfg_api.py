"""Finite offline configuration capabilities, schemas and exact programme grants."""
from pathlib import Path

from . import logcfg
from .inputs import InputError

OPERATIONS=('logcfg.prepare','logcfg.rollback_plan')


def arguments(cap):
    return dict(current_file=cap.FILE,current_absent=dict(type='boolean',default=False),node=cap.string(256),
        os=cap.string(16,enum=['windows','linux']),mode=cap.string(16,enum=['file','server']),
        process=cap.string(16,enum=['client','terminal','web','rphost','rmngr','ragent']),platform_version=cap.string(32,enum=['8.3.27.1989']),
        config_path=cap.FILE,log_location=cap.FILE,events=dict(type='array',items=cap.string(32,enum=list(logcfg.EVENTS)),minItems=1,maxItems=len(logcfg.EVENTS)),
        history_hours=cap.integer(1,168,1),duration_seconds=cap.integer(1,604800,300),max_bytes=cap.integer(16384,1024**3,16*1024**2),purpose=cap.string())


def routes(cap):
    required=['node','os','mode','process','platform_version','config_path','log_location','events','purpose']
    result={
        'logcfg.prepare':cap.route(arguments(cap),required,['explicit supplied local logcfg copy OR caller-reported absence; declared target and finite collection plan'],
            'prepare private XML and diff only; no target probe, apply, service or collection',['artifact_id','result','sources']),
        'logcfg.rollback_plan':cap.route(dict(proposal_id=cap.CASE,current_file=cap.FILE),['proposal_id','current_file'],
            ['verified prepared proposal and explicitly supplied current copy'],
            'prepare conditional rollback only; preserve unrelated edits and refuse changed owned block',['artifact_id','result','sources'])}
    return result


def normalize(operation,args):
    if operation=='logcfg.prepare':return logcfg.normalize(**args)
    return dict(args,current_file=str(Path(args['current_file']).absolute()))


def scope_schemas(cap):
    plans=routes(cap)
    return {field:cap.array(cap.obj(dict(settings=plans[operation]['input_schema'],max_runs=cap.integer(1,5,1)),['settings']),16)
            for field,operation in [('logcfg_plans','logcfg.prepare'),('logcfg_rollbacks','logcfg.rollback_plan')]}


def execute(operation,args,state,output):
    data=logcfg.prepare(output,**args) if operation=='logcfg.prepare' else logcfg.rollback_plan(state,output_state=output,**args)
    return data,[dict(kind='artifacts',id=data['artifact_id'])]


def pin(state,operation,args,data,add):
    report=add('artifacts',data['artifact_id'])
    if operation=='logcfg.rollback_plan':
        from . import operation_state as fs
        parent=add('artifacts',args['proposal_id'])
        receipt=fs.digest(fs.read(logcfg.artifacts.artifact_folder(state,args['proposal_id'])/'receipt.json',8192))
        if report.get('result',{}).get('parent')!=dict(id=args['proposal_id'],report_digest=fs.digest(parent),receipt_digest=receipt):
            raise InputError('logcfg rollback parent changed before result commit')
