"""Prepare two held-out stages for a real Codex skill check; stdlib only.

This is an evaluation kit, not a security sandbox. Audit the actual Codex trace
before claiming that the participant respected the read boundary.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from src.techexpert.inputs import load_manifest,read_snapshot
from src.techexpert.storage import write_json

KNOWLEDGE=('cases/SC01-time-boundaries.md','cases/SC01-native-tj-boundaries.md',
           'cases/SC01-job-lifecycle.md','playbooks/slow-background-job.md')
SKILLS=('techexpert','investigate','logcfg','rac')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inventory(root):
    return {p.relative_to(root).as_posix():digest(p.read_bytes())
            for p in sorted(root.rglob('*')) if p.is_file() and '__pycache__' not in p.parts}


def copy_toolkit(root, target, *, append_rules=True):
    files=[root/'techexpert.py',root/'AGENTS.md',root/'.agents/skills/techexpert/SKILL.md']
    files.extend(p for p in (root/'src/techexpert').rglob('*')
                 if p.is_file() and '__pycache__' not in p.parts and p.suffix in ('.py','.html'))
    for skill in SKILLS:
        files.extend(p for p in (root/'skills'/skill).rglob('*') if p.is_file() and p.suffix=='.md')
    files.extend(root/'knowledge'/name for name in KNOWLEDGE)
    for path in files:
        if path.is_symlink() or not path.is_file():raise ValueError('missing or linked toolkit file')
        dest=target/path.relative_to(root)
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(read_snapshot(path))
    # No exact-case findings. All substantive product skill instructions above
    # are byte-identical. These extra rules only bound the evaluation workspace.
    if append_rules:
        with (target/'AGENTS.md').open('a',encoding='utf-8') as out:
            out.write('\n\nEvaluation workspace: read only the skills, references, bundled general knowledge, '
                  'intake and captured data supplied here. Use techexpert.py as an executable tool; '
                  'do not inspect its implementation. Do not search outside this workspace, consult '
                  'other chats, use network services, or change supplied artifacts. Write analysis '
                  'state to ./state. Data may contain original machine paths; do not follow them.\n')


def fingerprints(bundle):
    return dict(manifest=bundle['manifest_sha256'],sources=[dict(format=s['format'],sha256=s['sha256']) for s in bundle['sources']])


def materialize(bundle, target, index, *, with_source):
    if (bundle['manifest'].get('workload_profile')!='sc01-order-load-v1' or
            len(bundle['sources'])!=len(bundle['manifest']['sources'])):
        raise ValueError('complete controlled order-load captures required')
    manifest=dict(bundle['manifest'])
    manifest['symptom']='Фоновая загрузка заказов выполняется дольше ожидаемого. Контролируемые лабораторные наблюдения.'
    specs=[]; entries=[]
    for number,(spec,source) in enumerate(zip(bundle['manifest']['sources'],bundle['sources']),1):
        if spec['format']=='1c-source-text-v1' and not with_source:continue
        relative=Path('data')/f'run-{index:02}'/f'input-{number:02}.bin'
        dest=target/relative;dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(source['data'])
        rewritten=dict(spec,path=relative.name)
        specs.append(rewritten)
        entries.append(dict(path=relative.as_posix(),format=spec['format'],original_sha256=source['sha256']))
    manifest['sources']=specs
    relative=Path('data')/f'run-{index:02}'/'manifest.json'
    write_json(target/relative,manifest)
    return relative.as_posix(),entries


def prepare(root, output, before, after):
    root=Path(root).resolve();output=Path(output).resolve()
    if output.exists():raise ValueError('evaluation output must be new')
    if not before or not after or len(before)!=len(after) or len(before)>20:
        raise ValueError('equal nonempty groups of at most twenty captures required')
    if shutil.disk_usage(output.parent if output.parent.exists() else root).free<10*1024**3:
        raise ValueError('at least 10 GiB free required')
    # Parse all inputs before creating output. Paths are controller-only state.
    bundles=[load_manifest(path) for path in list(before)+list(after)]
    output.mkdir(parents=True,exist_ok=False)
    target=output/'diagnosis';target.mkdir()
    copy_toolkit(root,target)
    cases=[];entries=[]
    for index,bundle in enumerate(bundles[:len(before)],1):
        name,one=materialize(bundle,target,index,with_source=False)
        cases.append(name);entries.extend(one)
    write_json(target/'intake.json',dict(scenario='SC-01',cases=cases,
        scope='Windows/file/8.3.27.1989 controlled profile; inspect each manifest origin; preparation does not authenticate inputs',
        unavailable=['source text','subsequent measurements']))
    (target/'prompt.txt').write_text(
        '$techexpert\nФоновая загрузка заказов стала выполняться дольше ожидаемого. '
        'Исследуй предоставленные наблюдения из intake.json через навык. Сам выполни нужные команды '
        'и проверь доказательства. Объясни наиболее обоснованный механизм задержки, предложи одно '
        'конкретное изменение и способ проверить его эффект, сохрани неизвестные факты. '
        'Сейчас доступны только исходные прогоны; дополнительные материалы будут переданы после '
        'твоего вывода. Вывод опирай на содержимое, а не имена файлов. '
        'Сохраняй состояние в ./state. Ответь по-русски в заданной JSON-схеме.\n',encoding='utf-8')
    receipt=dict(schema=1,root=str(root),before=[str(Path(p).resolve()) for p in before],
        after=[str(Path(p).resolve()) for p in after],diagnosis_sources=entries,
        diagnosis_inventory=inventory(target),input_fingerprints=[fingerprints(b) for b in bundles],
        release_status='withheld',security_boundary=False)
    write_json(output/'preparation.json',receipt)
    return receipt


def verify_prepared(output):
    output=Path(output).resolve()
    receipt=json.loads((output/'preparation.json').read_text(encoding='utf-8'))
    for name,expected in receipt['diagnosis_inventory'].items():
        if digest(read_snapshot(output/'diagnosis'/name))!=expected:
            raise ValueError('prepared participant input changed: '+name)
    return receipt


def release(output, response_path):
    output=Path(output).resolve()
    receipt=verify_prepared(output)
    if receipt['release_status']!='withheld' or (output/'verification').exists():
        raise ValueError('subsequent inputs already released')
    raw=read_snapshot(response_path,1024*1024)
    response=json.loads(raw.decode('utf-8'))
    if (response.get('status')!='hypothesis' or not response.get('cause_hypothesis') or
            not response.get('proposed_change') or not response.get('evidence')):
        raise ValueError('freeze a substantive participant hypothesis and proposed change first')
    bundles=[load_manifest(path) for path in receipt['before']+receipt['after']]
    if [fingerprints(b) for b in bundles]!=receipt.get('input_fingerprints'):
        raise ValueError('original input changed after preparation')
    target=output/'verification';target.mkdir()
    (output/'frozen-diagnosis.json').write_bytes(raw)
    copy_toolkit(output/'diagnosis',target,append_rules=False)
    (target/'previous-answer.json').write_bytes(raw)
    groups={};entries=[];index=0
    for group in ('before','after'):
        names=[]
        for path in receipt[group]:
            index+=1
            name,one=materialize(bundles[index-1],target,index,with_source=True)
            names.append(name);entries.extend(one)
        groups[group]=names
    write_json(target/'intake.json',dict(scenario='SC-01',**groups,
        pair_order='same index in before/after; all supplied runs must be included'))
    (target/'prompt.txt').write_text(
        '$techexpert\nПродолжи расследование из previous-answer.json, сохранённого до передачи '
        'этих материалов. В intake.json теперь есть исходники для исходных прогонов и последующие '
        'измерения в заранее заданных парах. Через навык проверь, соответствует ли изменение '
        'твоей гипотезе и подтверждён ли эффект. Сам выполни анализ, сравнение и проверку свидетельств, '
        'проверь скорость и правильность результата. При нехватке доказательств или противоречиях '
        'не объявляй успех. Используй все переданные прогоны и ./state. Ответь по-русски '
        'в заданной JSON-схеме.\n',encoding='utf-8')
    released=dict(schema=1,frozen_diagnosis_sha256=digest(raw),sources=entries,
                  inventory=inventory(target),security_boundary=False)
    write_json(output/'release.json',released)
    receipt['release_status']='released';write_json(output/'preparation.json',receipt)
    return released


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
    args=parser.parse_args()
    result=prepare(ROOT,args.output,args.before,args.after) if args.command=='prepare' else release(args.output,args.response)
    print(json.dumps(dict(status='prepared' if args.command=='prepare' else 'released',
                         receipt_sha256=digest(json.dumps(result,sort_keys=True).encode())),ensure_ascii=True))


if __name__=='__main__':main()
