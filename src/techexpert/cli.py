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
    args = parser.parse_args(argv)
    try:
        if args.command == 'doctor':
            result = doctor()
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
        else:
            terms = args.query.casefold().split()
            matches = []
            for path in sorted((ROOT / 'knowledge').rglob('*.md')):
                body = path.read_text(encoding='utf-8')
                score = sum(term in body.casefold() for term in terms)
                if score:
                    matches.append(dict(path=str(path), score=score, excerpt=body[:5000], truncated=len(body)>5000))
            result = dict(matches=sorted(matches,key=lambda x:-x['score'])[:5],
                          scope='bundled_local_materials', material_status='inspect_each_card')
        emit(result)
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        emit(dict(status='error', code='input_or_state_error', message=str(exc)))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
