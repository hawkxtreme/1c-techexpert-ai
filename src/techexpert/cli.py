"""JSON boundary for the user's existing AI harness."""
import argparse
import json
import sys
from pathlib import Path

from .inputs import InputError
from .profiles import doctor, load_profile
from .storage import (ROOT, default_state_dir, investigate, load_case, read_evidence, list_native_events,
                      compare_cases, load_comparison)


def emit(value):
    print(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False), flush=True)


def main(argv=None):
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description='1C TechExpert AI: local evidence tools for your AI harness')
    parser.add_argument('--state-dir', type=Path, default=default_state_dir())
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('doctor')
    commands.add_parser('profile')
    commands.add_parser('demo')
    analyze = commands.add_parser('analyze')
    analyze.add_argument('manifest', type=Path)
    show = commands.add_parser('show')
    show.add_argument('case_id')
    compare=commands.add_parser('compare')
    compare.add_argument('--before',nargs='+',required=True)
    compare.add_argument('--after',nargs='+',required=True)
    comparison=commands.add_parser('comparison')
    comparison.add_argument('comparison_id')
    proof = commands.add_parser('evidence')
    proof.add_argument('case_id')
    proof.add_argument('evidence_id')
    events = commands.add_parser('events')
    events.add_argument('case_id')
    events.add_argument('--source')
    events.add_argument('--event')
    events.add_argument('--property', action='append', default=[], dest='properties')
    events.add_argument('--offset', type=int, default=0)
    events.add_argument('--limit', type=int, default=20)
    events.add_argument('--linked-run', action='store_true', help='only records inside the verified job marker window')
    init = commands.add_parser('init')
    init.add_argument('--open-browser', action='store_true')
    init.add_argument('--ttl', type=int, default=900)
    knowledge = commands.add_parser('knowledge')
    knowledge.add_argument('query')
    apdex = commands.add_parser('apdex')
    apdex.add_argument('measurements',type=Path)
    apdex.add_argument('--target',type=float,required=True)
    apdex.add_argument('--operation')
    apdex.add_argument('--start')
    apdex.add_argument('--end')
    artifact = commands.add_parser('artifact')
    artifact.add_argument('artifact_id')
    artifact.add_argument('--source')
    rac = commands.add_parser('rac')
    rac.add_argument('operation',choices=('clusters','infobases','sessions','connections','processes','servers'))
    rac.add_argument('--endpoint',required=True)
    rac.add_argument('--cluster')
    rac.add_argument('--executable',default='rac')
    rac.add_argument('--docker-container')
    for name in ('os-plan','os-collect'):
        os_command=commands.add_parser(name)
        os_command.add_argument('--duration',type=float,default=300)
        os_command.add_argument('--interval',type=float,default=1)
        os_command.add_argument('--transport',choices=('local','ssh','winrm'),default='local')
        os_command.add_argument('--host',default='')
        os_command.add_argument('--port',type=int)
        os_command.add_argument('--node')
        os_command.add_argument('--role',choices=('onec','sql','storage','client','terminal','web','other'),default='onec')
        os_command.add_argument('--python')
        os_command.add_argument('--use-ssl',action='store_true')
        os_command.add_argument('--identity-file')
        os_command.add_argument('--known-hosts-file')
    os_import=commands.add_parser('os-import')
    os_import.add_argument('measurements',type=Path)
    pg=commands.add_parser('postgresql')
    pg.add_argument('operation',choices=('capabilities','activity','locks','database_stats','statements'))
    pg.add_argument('--database',required=True)
    pg.add_argument('--host')
    pg.add_argument('--port',type=int,default=5432)
    pg.add_argument('--user')
    pg.add_argument('--executable',default='psql')
    pg.add_argument('--docker-container')
    source_snapshot=commands.add_parser('source-snapshot')
    source_snapshot.add_argument('path',type=Path)
    source_snapshot.add_argument('--kind',choices=('catalog','git'),default='catalog')
    source_snapshot.add_argument('--ref',default='HEAD')
    source_snapshot.add_argument('--encoding',choices=('utf-8','cp1251'),default='utf-8')
    source_search=commands.add_parser('source-search')
    source_search.add_argument('artifact_id');source_search.add_argument('query')
    source_search.add_argument('--limit',type=int,default=20)
    source_read=commands.add_parser('source-read')
    source_read.add_argument('artifact_id');source_read.add_argument('path')
    source_read.add_argument('--start',type=int,default=1);source_read.add_argument('--limit',type=int,default=50)
    args = parser.parse_args(argv)
    try:
        if args.command == 'doctor':
            result = doctor(args.state_dir)
        elif args.command == 'profile':
            result = load_profile(args.state_dir) or dict(status='not_configured', next_step='init')
        elif args.command in ('demo','analyze'):
            result = investigate(ROOT / 'examples/sc01/case.json' if args.command=='demo' else args.manifest, args.state_dir)
        elif args.command == 'show':
            result = load_case(args.state_dir, args.case_id)
        elif args.command == 'compare':
            result = compare_cases(args.state_dir,args.before,args.after)
        elif args.command == 'comparison':
            result = load_comparison(args.state_dir,args.comparison_id)
        elif args.command == 'evidence':
            result = read_evidence(args.state_dir, args.case_id, args.evidence_id)
        elif args.command == 'events':
            filters = {}
            for item in args.properties:
                key, separator, value = item.partition('=')
                if not separator or not key or key in filters:
                    raise InputError('each property filter requires a unique NAME=VALUE')
                filters[key] = value
            result = list_native_events(args.state_dir, args.case_id, source_id=args.source, event=args.event,
                                        properties=filters, offset=args.offset, limit=args.limit, linked_run=args.linked_run)
        elif args.command == 'init':
            from .gui import run_gui
            run_gui(args.state_dir, open_browser=args.open_browser, ttl=args.ttl)
            return 0
        elif args.command == 'apdex':
            from .artifacts import import_apdex
            result=import_apdex(args.state_dir,args.measurements,args.target,operation=args.operation,start=args.start,end=args.end)
        elif args.command == 'artifact':
            from .artifacts import load_artifact, artifact_evidence
            result=(artifact_evidence(args.state_dir,args.artifact_id,args.source) if args.source
                    else load_artifact(args.state_dir,args.artifact_id))
        elif args.command == 'rac':
            from .rac import RacClient,collect_rac
            result=collect_rac(args.state_dir,RacClient(args.endpoint,executable=args.executable,
                docker_container=args.docker_container),args.operation,cluster=args.cluster)
        elif args.command in ('os-plan','os-collect'):
            from .os_metrics import validate_request,collect_os
            request=dict(transport=args.transport,host=args.host,duration_seconds=args.duration,
                         interval_seconds=args.interval,node=args.node,role=args.role,use_ssl=args.use_ssl)
            if args.port is not None:request['port']=args.port
            if args.python is not None:request['python']=args.python
            if args.identity_file is not None:request['identity_file']=args.identity_file
            if args.known_hosts_file is not None:request['known_hosts_file']=args.known_hosts_file
            request=validate_request(request)
            result=(dict(status='planned_not_started',request=request,
                         prerequisites='Existing SSH/WinRM access and Python on remote nodes; no service or permission changes are automatic.')
                    if args.command=='os-plan' else collect_os(args.state_dir,request))
        elif args.command=='os-import':
            from .os_metrics import import_os
            result=import_os(args.state_dir,args.measurements)
        elif args.command=='postgresql':
            from .postgresql import PsqlClient,observe
            result=observe(args.state_dir,PsqlClient(database=args.database,host=args.host,port=args.port,
                user=args.user,executable=args.executable,docker_container=args.docker_container),args.operation)
        elif args.command=='source-snapshot':
            from .source_code import snapshot_source
            result=snapshot_source(args.state_dir,args.path,kind=args.kind,ref=args.ref,encoding=args.encoding)
        elif args.command=='source-search':
            from .source_code import search_source
            result=search_source(args.state_dir,args.artifact_id,args.query,limit=args.limit)
        elif args.command=='source-read':
            from .source_code import read_source
            result=read_source(args.state_dir,args.artifact_id,args.path,start=args.start,limit=args.limit)
        else:
            from .knowledge import search
            result=search(args.query)
        emit(result)
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        emit(dict(status='error', code='input_or_state_error', message=str(exc)))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
