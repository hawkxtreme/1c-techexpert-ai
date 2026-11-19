"""Prepare two held-out stages for a real Codex skill check; stdlib only.

This is an evaluation kit, not a security sandbox. Audit the actual Codex trace
before claiming that the participant respected the read boundary.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from scripts.sc01_kit import copy_toolkit,KNOWLEDGE
from scripts.sc01_trial import prepare,release,status,verify_prepared,digest,inventory,fingerprints,materialize
from scripts.sc01_verification import finalize


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    first=sub.add_parser('prepare')
    first.add_argument('--output',required=True,type=Path)
    first.add_argument('--before',nargs='+',required=True,type=Path)
    first.add_argument('--after',nargs='+',required=True,type=Path)
    second=sub.add_parser('release')
    second.add_argument('--output',required=True,type=Path)
    second.add_argument('--response',required=True,type=Path)
    final=sub.add_parser('finalize')
    final.add_argument('--output',required=True,type=Path)
    final.add_argument('--response',type=Path)
    view=sub.add_parser('status');view.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    try:
        if args.command=='finalize':
            print(json.dumps(finalize(args.output,args.response),ensure_ascii=True))
            return 0
        result=prepare(ROOT,args.output,args.before,args.after) if args.command=='prepare' else release(args.output,args.response) if args.command=='release' else status(args.output)
    except (OSError,ValueError,KeyError,TypeError,RecursionError) as exc:
        print(json.dumps(dict(status='error',code='trial_input_or_state_error',message=str(exc)),ensure_ascii=True))
        return 2
    print(json.dumps(dict(status='prepared' if args.command=='prepare' else 'released' if args.command=='release' else result['release_status'],
                         workspace=str(args.output.absolute()/'diagnosis'),prompt='verification/prompt.txt' if args.command=='release' else 'prompt.txt',
                         receipt_sha256=digest(json.dumps(result,sort_keys=True).encode())),ensure_ascii=True))
    return 0


if __name__=='__main__':raise SystemExit(main())
