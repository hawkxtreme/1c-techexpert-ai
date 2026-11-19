"""Bounded, stable local input inspection; links and scan errors are not absence."""
import hashlib
import os
from pathlib import Path
import stat
import unicodedata

from .inputs import InputError

MIB=1024**2
LIMITS=dict(max_files=128,max_depth=8,max_file_bytes=16*MIB,max_total_bytes=64*MIB)
MAX_ENTRIES=256
MAX_ARCHIVE_BYTES=65*MIB
CODE_SUFFIXES={'.bsl','.os','.cf','.cfe','.dt','.1cd'}
ARCHIVE_SUFFIXES=('.zip','.7z','.rar','.tar','.gz','.tgz','.bz2','.xz','.zst')
RESERVED_NAMES={'con','prn','aux','nul','conin$','conout$',
    *('com'+c for c in '123456789¹²³'),*('lpt'+c for c in '123456789¹²³')}


def limits(value=None):
    if value is None:value={}
    if type(value) is not dict or set(value)-LIMITS.keys():raise InputError('unsupported input limits')
    result=dict(LIMITS)
    for key,n in value.items():
        if type(n) is not int or not (0 if key=='max_depth' else 1)<=n<=LIMITS[key]:raise InputError('input limit outside supported bounds')
        result[key]=n
    return result


def normalize(inputs,chosen_limits=None):
    bound=limits(chosen_limits)
    if type(inputs) is not list or not 1<=len(inputs)<=16:raise InputError('select1..16 explicit input roots')
    result=[];seen=set()
    for item in inputs:
        if (type(item) is not dict or set(item)!={'path','kind'} or item['kind'] not in ('file','directory','zip')
            or type(item['path']) is not str or not 1<=len(item['path'])<=2048 or any(ord(c)<32 for c in item['path'])):raise InputError('invalid selected input root')
        path=Path(item['path'])
        if '..' in path.parts:raise InputError('parent traversal in selected input root')
        path=path.absolute();identity=os.path.normcase(str(path))
        if identity in seen:raise InputError('duplicate selected input root')
        seen.add(identity);result.append(dict(path=str(path),kind=item['kind']))
    return dict(inputs=result,limits=bound)


def name_parts(name):
    if type(name) is not str or not 1<=len(name.encode('utf-8'))<=512 or '\\' in name or any(ord(c)<32 or ord(c)==127 for c in name):raise InputError('unsafe or unsupported input member name')
    parts=name.split('/')
    for part in parts:
        if (not part or part in ('.','..') or len(part.encode('utf-8'))>240 or part[-1] in '. '
            or any(c in part for c in ':<>"|?*') or part.split('.',1)[0].rstrip(' ').casefold() in RESERVED_NAMES):raise InputError('unsafe or ambiguous input member name')
    return parts


def name_key(name):return unicodedata.normalize('NFC',name).casefold()


def chain(path):
    result=[]
    for component in reversed((path,*path.parents)):
        info=component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise InputError('linked input paths are unsupported')
        result.append((str(component),info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode)))
    return tuple(result)


def signature(info):return info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns


def _observation(ancestry, info):
    from .operation_state import digest

    if not stat.S_ISREG(info.st_mode) or not info.st_ino:
        raise InputError('ordinary input with observable identity required')
    return dict(device=str(info.st_dev), inode=str(info.st_ino), bytes=info.st_size,
                mtime_ns=str(info.st_mtime_ns), ctime_ns=str(info.st_ctime_ns), chain_sha256=digest(ancestry))


def observe(path):
    return _observation(chain(path), path.lstat())


def read(path,maximum,*,keep=False,expected=None,observed=None):
    path=Path(path);before_chain=chain(path);before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size>maximum:raise InputError('input file exceeds supported type or byte limit')
    if observed is not None and _observation(before_chain, before) != observed:
        raise InputError('input identity or metadata changed since preview')
    descriptor=os.open(path,os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0));parts=[];digest=hashlib.sha256();count=0
    with os.fdopen(descriptor,'rb') as stream:
        if signature(os.fstat(stream.fileno()))!=signature(before):raise InputError('input changed before reading')
        while True:
            data=stream.read(min(65536,maximum+1-count))
            if not data:break
            count+=len(data)
            if count>maximum:raise InputError('input file exceeds byte limit')
            digest.update(data)
            if keep:parts.append(data)
        if signature(os.fstat(stream.fileno()))!=signature(before):raise InputError('input changed while reading')
    if chain(path)!=before_chain or signature(path.lstat())!=signature(before) or count!=before.st_size:raise InputError('input changed while reading')
    if observed is not None and observe(path) != observed:
        raise InputError('input identity or metadata changed while reading')
    value=dict(bytes=count,sha256=digest.hexdigest())
    if expected is not None and value!=expected:raise InputError('input changed since preview')
    return (b''.join(parts) if keep else None),value


def local(root,bound):
    path=Path(root['path']);kind=root['kind'];chain(path);before=path.lstat();members=[];entries=0
    def walk(folder,relative,depth):
        nonlocal entries
        if depth>bound['max_depth']:raise InputError('input directory depth limit')
        prior=chain(folder);stamp=signature(folder.lstat());children=[]
        with os.scandir(folder) as stream:
            for entry in stream:
                entries+=1
                if entries>MAX_ENTRIES:raise InputError('input directory entry limit')
                children.append(entry.name)
        aliases=set()
        for name in sorted(children):
            name_parts(name);key=name_key(name)
            if key in aliases:raise InputError('ambiguous input directory member')
            aliases.add(key);child=folder/name;rel=relative+[name];info=child.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise InputError('linked input member unsupported')
            if stat.S_ISDIR(info.st_mode):walk(child,rel,depth+1)
            elif stat.S_ISREG(info.st_mode):add(child,'/'.join(rel))
            else:raise InputError('special input member unsupported')
        if chain(folder)!=prior or signature(folder.lstat())!=stamp:raise InputError('input directory changed while inspecting')
    def add(file,name):
        if len(members)>=bound['max_files']:raise InputError('input file count limit')
        _,metadata=read(file,bound['max_file_bytes']);members.append(dict(relative_path=name,**metadata,importable=True))
        if sum(m['bytes'] for m in members)>bound['max_total_bytes']:raise InputError('expanded input byte limit')
    if kind=='directory':
        if not stat.S_ISDIR(before.st_mode):raise InputError('selected input is not a directory')
        walk(path,[],0)
    elif kind=='file':name_parts(path.name);add(path,path.name)
    else:raise InputError('unsupported local input kind')
    return members
