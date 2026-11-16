"""Maintain the local release integrity inventory; no signature or publication."""
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.techexpert import __version__
from src.techexpert.knowledge import package_members

TARGET='src/techexpert/assets/bundle-manifest.json'

def canonical(data):
    return data.decode('utf-8').replace('\r\n','\n').encode('utf-8')

def generate():
    groups=dict(runtime=['techexpert.py','.codex-plugin/plugin.json'],instructions=['AGENTS.md'],
        catalogues=[],knowledge=[],demo=['examples/sc01/case.json','examples/sc01/events.jsonl'])
    for relative,category in (('src/techexpert','runtime'),('skills','instructions')):
        for current,dirs,files in os.walk(ROOT/relative,followlinks=False):
            dirs[:]=sorted(name for name in dirs if name!='__pycache__')
            for name in dirs+files:
                path=Path(current)/name
                if path.is_symlink() or getattr(path.lstat(),'st_file_attributes',0)&0x400:
                    raise ValueError('linked bundle inventory member: '+str(path))
            for name in sorted(files):
                path=Path(current)/name;member=path.relative_to(ROOT).as_posix()
                if path.suffix not in ('.py','.md','.html','.json') or member==TARGET:continue
                group='catalogues' if member in ('src/techexpert/assets/incident-templates.json','src/techexpert/assets/source-help.json') else category
                groups[group].append(member)
    groups['instructions'].append('.agents/skills/techexpert/SKILL.md')
    groups['knowledge']=['knowledge/'+name for name in package_members(ROOT/'knowledge')]
    members={name:hashlib.sha256(canonical((ROOT/name).read_bytes())).hexdigest() for names in groups.values() for name in names}
    return dict(schema_version=1,product_version=__version__,normalization='utf8-lf-v1',
        components={key:sorted(value) for key,value in groups.items()},members=dict(sorted(members.items())))

if __name__=='__main__':
    if sys.argv[1:] not in ([],['--write']):raise SystemExit('Usage: python scripts/generate_bundle_manifest.py [--write]')
    data=(json.dumps(generate(),ensure_ascii=False,indent=2)+'\n').encode('utf-8')
    target=ROOT/TARGET
    if sys.argv[1:]==['--write']:
        target.write_bytes(data)
        print('Wrote '+TARGET)
    elif not target.is_file() or canonical(target.read_bytes())!=data:
        raise SystemExit('Bundle inventory is stale; run python scripts/generate_bundle_manifest.py --write after reviewed edits.')
    else:print('Bundle inventory matches this checkout.')
