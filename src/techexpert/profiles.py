"""Local readiness and reusable source configuration; no connection side effects."""
import configparser
import hashlib
import json
import os
import platform
import re
import shutil
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from . import __version__
from .inputs import InputError, read_snapshot, json_value
from .storage import write_json, default_state_dir


def doctor(state_dir=None):
    installations = []
    if os.name == 'nt':
        for root in (Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / '1cv8',
                     Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)')) / '1cv8'):
            if root.is_dir():
                for binary in root.glob('*/bin/1cv8.exe'):
                    installations.append(dict(path=str(binary), directory_version=binary.parent.parent.name,
                                              license='not_checked', compatibility='not_verified'))
    return dict(product_version=__version__, python=sys.version.split()[0], python_executable=sys.executable,
                os=platform.platform(), ai_harness_required=True,
                state_dir=str(default_state_dir() if state_dir is None else Path(state_dir).resolve()),
                onec_installations=installations,
                commands={x: shutil.which(x) for x in ('git', 'rac', 'ras', 'ssh', 'psql', 'sqlcmd')},
                capabilities=dict(sc01_normalized_evidence='ready', synthetic_demo='ready',
                                  source_profile='ready', native_tj='text_8.3.27.1989_only',
                                  job_correlation='controlled_file_job_markers_8.3.27.1989_only', native_jr='not_implemented',
                                  order_load='controlled_windows_file_8.3.27.1989_only',
                                  fix_comparison='sc01_order_load_five_pairs_only',
                                  sql='not_implemented', remote_os_collection='not_implemented', testpilot='not_implemented'))


def read_starter(path):
    data = read_snapshot(path, 1024*1024)
    try:
        text = data.decode('utf-8-sig')
    except UnicodeDecodeError:
        text = data.decode('cp1251')
    parser = configparser.RawConfigParser(strict=True, interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        raise InputError('unsupported or ambiguous starter list') from exc
    bases = []
    for section in parser.sections():
        connection = parser.get(section, 'Connect', fallback='')
        if not connection:
            continue
        values = {m.group(1).lower(): m.group(2).replace('""', '"') for m in
                  re.finditer(r'(\w+)\s*=\s*"((?:[^"\r\n]|"")*)"\s*;?', connection)}
        mode, clean = 'unknown', ''
        if values.get('file'):
            mode, clean = 'file', values['file']
        elif values.get('srvr') and values.get('ref'):
            mode, clean = 'server', f"Srvr={values['srvr']};Ref={values['ref']}"
        elif values.get('ws'):
            url = urlsplit(values['ws'])
            host = url.hostname or ''
            if ':' in host:
                host = '[' + host + ']'
            if url.port:
                host += ':' + str(url.port)
            clean = urlunsplit((url.scheme, host, url.path, '', ''))
        identity = hashlib.sha256((str(Path(path).resolve()) + '\0' + section).encode()).hexdigest()[:16]
        bases.append(dict(id=identity, name=section, mode=mode, connection=clean))
    return bases


def validate_profile(value):
    if not isinstance(value, dict) or value.get('schema_version') != 1:
        raise InputError('profile schema_version=1 required')
    # Never accept arbitrary persisted properties from an HTTP client.
    if set(value) - {'schema_version', 'name', 'bases', 'sources', 'revision', 'capability_status'}:
        raise InputError('unknown profile property')
    def field(obj, key, limit=2048, empty=False):
        val = obj.get(key, '')
        if not isinstance(val, str) or len(val)>limit or (not empty and not val.strip()) or any(ord(c)<32 for c in val):
            raise InputError(f'invalid {key}')
        if re.search(r'(?i)(?:pwd|password|token|secret|authorization)\s*[=:]', val) or re.search(r'://[^/]*@', val):
            raise InputError('credentials must not be saved in profiles')
        return val.strip()
    name = field(value, 'name', 120)
    bases, sources = value.get('bases'), value.get('sources')
    if not isinstance(bases, list) or not 1 <= len(bases) <= 100 or not isinstance(sources, list) or len(sources)>100:
        raise InputError('profile requires 1..100 bases and at most 100 sources')
    clean_bases, clean_sources, ids = [], [], set()
    for base in bases:
        if not isinstance(base, dict) or set(base)-{'id','name','mode','connection'}:
            raise InputError('invalid base properties')
        bid, mode = field(base, 'id', 80), base.get('mode')
        if bid in ids or mode not in ('file','server','unknown'):
            raise InputError('duplicate base id or invalid mode')
        ids.add(bid)
        clean_bases.append(dict(id=bid,name=field(base,'name',120),mode=mode,connection=field(base,'connection',empty=True)))
    source_ids = set()
    for source in sources:
        if not isinstance(source, dict) or set(source)-{'id','type','path','host','base_ids','status'}:
            raise InputError('invalid source properties')
        sid, kind, path = field(source,'id',80), source.get('type'), field(source,'path')
        linked = source.get('base_ids')
        if sid in source_ids or kind not in ('tj','jr','source','sql','os'):
            raise InputError('duplicate source id or unknown type')
        if not isinstance(linked,list) or not linked or any(not isinstance(x,str) or x not in ids for x in linked) or len(set(linked))!=len(linked):
            raise InputError('source must link existing bases')
        if kind == 'sql' and any(base['mode']!='server' for base in clean_bases if base['id'] in linked):
            raise InputError('SQL applies only to confirmed server databases')
        suffix = Path(path).suffix.lower()
        if kind=='jr' and suffix=='.xml':
            raise InputError('JR requires a native directory or consistent snapshot, not XML')
        if kind=='source' and suffix in ('.zip','.7z','.rar','.tar','.gz','.cf','.cfe'):
            raise InputError('1C sources require a directory or Git repository')
        clean_sources.append(dict(id=sid,type=kind,path=path,host=field(source,'host',256,empty=True),base_ids=linked,status='not_checked'))
        source_ids.add(sid)
    return dict(schema_version=1,name=name,bases=clean_bases,sources=clean_sources,capability_status='configured_not_connected')


def save_profile(state_dir, profile):
    clean = validate_profile(profile)
    folder = Path(state_dir) / 'profiles'
    folder.mkdir(parents=True, exist_ok=True)
    lock = folder / 'write.lock'
    try:
        with lock.open('x', encoding='ascii') as stream:
            stream.write(str(os.getpid()))
    except FileExistsError as exc:
        raise InputError('profile is being saved; retry after the current writer completes') from exc
    try:
        revisions = [int(p.stem) for p in folder.glob('*.json') if p.stem.isdecimal()]
        clean['revision'] = max(revisions, default=0) + 1
        if len((json.dumps(clean,ensure_ascii=False,indent=2)+'\n').encode('utf-8')) > 1024*1024:
            raise InputError('profile exceeds 1 MiB; reduce its size before saving')
        write_json(folder / f"{clean['revision']}.json", clean)
        write_json(folder / 'current.json', clean)
    finally:
        lock.unlink()
    return clean


def load_profile(state_dir):
    path = Path(state_dir) / 'profiles/current.json'
    if not path.exists():
        return None
    value = json_value(read_snapshot(path, 1024*1024).decode('utf-8'))
    validate_profile(value)
    return value
