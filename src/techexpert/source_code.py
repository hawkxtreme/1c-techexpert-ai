"""Bounded XML/BSL snapshots from a directory or an existing local Git commit."""
import base64
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import re
import xml.etree.ElementTree as ET

from .artifacts import save_artifact,load_artifact,artifact_folder
from .inputs import InputError,read_snapshot,json_value
from .processes import run_bounded

MAX_BYTES=8*1024*1024
MAX_FILES=5000


def safe_name(name):
    if not isinstance(name,str) or not name or len(name)>2048 or '\\' in name or any(ord(c)<32 for c in name):raise InputError('invalid source-relative path')
    path=PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or ':' in name:raise InputError('source path must stay relative')
    return path.as_posix()


def catalog_files(root):
    stack=[(root,0)];files=[];skipped=[];count=0
    while stack:
        folder,depth=stack.pop()
        if depth>64:raise InputError('source directory depth limit')
        with os.scandir(folder) as entries:
            for entry in entries:
                count+=1
                if count>30000:raise InputError('source inventory budget exceeded; select a narrower directory')
                if entry.name=='.git':continue
                info=entry.stat(follow_symlinks=False);path=Path(entry.path)
                if entry.is_symlink() or getattr(info,'st_file_attributes',0)&0x400:
                    skipped.append(path.relative_to(root).as_posix());continue
                if entry.is_dir(follow_symlinks=False):stack.append((path,depth+1))
                elif entry.is_file(follow_symlinks=False) and path.suffix.lower() in ('.bsl','.xml'):
                    files.append((safe_name(path.relative_to(root).as_posix()),path,info.st_size,info.st_mtime_ns))
    files.sort()
    if len(files)>MAX_FILES or sum(x[2] for x in files)>MAX_BYTES:raise InputError('source snapshot exceeds 5000 files / 8 MiB; select a narrower scope')
    return files,skipped


def git_capture(root,ref):
    if not isinstance(ref,str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_./-]{0,199}',ref):raise InputError('use a bounded Git ref or commit id')
    prefix=['git','--no-optional-locks','-c','core.fsmonitor=false','-C',str(root)]
    environment={k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
    environment.update(GIT_NO_LAZY_FETCH='1',GIT_NO_REPLACE_OBJECTS='1',GIT_TERMINAL_PROMPT='0',GIT_OPTIONAL_LOCKS='0')
    def run(*args,input_data=None):
        code,data,_=run_bounded(prefix+list(args),timeout=20,max_bytes=16*1024*1024,input_data=input_data,env=environment)
        if code:raise InputError('Git snapshot read failed; verify local repository/ref and access')
        return data
    code,partial,_=run_bounded(prefix+['config','--get-regexp',r'^(extensions\.partialclone|remote\..*\.promisor)$'],
                              timeout=10,max_bytes=65536,env=environment)
    if code not in (0,1):raise InputError('cannot inspect Git repository configuration')
    if partial:raise InputError('partial/promisor repositories are not supported; provide a complete local repository to avoid lazy fetch')
    commit=run('rev-parse','--verify','--end-of-options',ref+'^{commit}').decode('ascii').strip()
    if not re.fullmatch('[a-f0-9]{40}|[a-f0-9]{64}',commit):raise InputError('invalid resolved Git commit')
    selected=[];skipped=[]
    for item in run('ls-tree','-r','-z','--full-tree',commit).split(b'\0'):
        if not item:continue
        header,separator,path=item.partition(b'\t')
        if not separator:raise InputError('invalid Git tree response')
        mode,kind,oid=header.decode('ascii').split();name=safe_name(path.decode('utf-8'))
        if kind!='blob' or mode not in ('100644','100755'):
            skipped.append(name);continue
        if PurePosixPath(name).suffix.lower() not in ('.bsl','.xml'):continue
        if not re.fullmatch('[a-f0-9]{40}|[a-f0-9]{64}',oid):raise InputError('invalid Git blob identifier')
        selected.append((name,oid))
    if len(selected)>MAX_FILES:raise InputError('Git source file budget exceeded')
    raw=run('cat-file','--batch',input_data=('\n'.join(oid for _,oid in selected)+'\n').encode('ascii')) if selected else b''
    cursor=0;total=0;files=[]
    for name,oid in selected:
        end=raw.find(b'\n',cursor)
        if end<0:raise InputError('truncated Git blob header')
        values=raw[cursor:end].decode('ascii').split()
        if len(values)!=3 or values[:2]!=[oid,'blob'] or not values[2].isdigit():raise InputError('invalid Git blob header')
        size=int(values[2]);start=end+1;finish=start+size
        if size>MAX_BYTES or raw[finish:finish+1]!=b'\n':raise InputError('truncated or oversized Git blob')
        data=raw[start:finish];cursor=finish+1;total+=size
        if total>MAX_BYTES:raise InputError('Git snapshot exceeds 8 MiB; use a smaller repository scope')
        files.append((name,data))
    if cursor!=len(raw):raise InputError('unexpected Git blob response tail')
    # git status/diff may execute configured clean filters while inspecting the
    # worktree. Read only immutable objects; worktree correspondence stays unknown.
    return files,skipped,dict(kind='git',path=str(root),ref=ref,commit=commit,
        worktree_state='not_checked_to_avoid_git_filters',working_tree_included=False)


def snapshot_source(state_dir,path,*,kind='catalog',ref='HEAD',encoding='utf-8'):
    root=Path(path).resolve()
    if not root.is_dir():raise InputError('sources require a directory or existing Git repository; archives are not accepted')
    if kind not in ('catalog','git') or encoding not in ('utf-8','cp1251'):raise InputError('unsupported source kind/encoding')
    if kind=='git':files,skipped,origin=git_capture(root,ref)
    else:
        before,skipped=catalog_files(root)
        files=[(name,read_snapshot(file,MAX_BYTES)) for name,file,_,_ in before]
        after,after_skipped=catalog_files(root)
        if [(a,c,d) for a,_,c,d in before]!=[(a,c,d) for a,_,c,d in after] or skipped!=after_skipped:
            raise InputError('source tree changed during capture; provide a stable snapshot')
        origin=dict(kind='catalog',path=str(root),consistency='file metadata unchanged across capture; not an atomic filesystem snapshot')
    if not files:raise InputError('no supported XML/BSL source files in selected scope')
    content=[];metadata=[];versions=[]
    for i,(name,data) in enumerate(files,1):
        try:text=data.decode('utf-8-sig' if encoding=='utf-8' else encoding)
        except UnicodeError as exc:raise InputError('source encoding mismatch; select explicit supported encoding') from exc
        digest=hashlib.sha256(data).hexdigest()
        content.append(dict(path=name,sha256=digest,bytes=len(data),data_base64=base64.b64encode(data).decode('ascii')))
        metadata.append(dict(path=name,sha256=digest,bytes=len(data),source_record_id='file:'+str(i)))
        if PurePosixPath(name).name.lower()=='configuration.xml':
            if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():raise InputError('XML entities/DTD are not accepted')
            try:
                tree=ET.fromstring(text)
                version=tree.find('.//{*}Properties/{*}Version')
                if version is not None and version.text:versions.append(dict(path=name,version=version.text[:256]))
            except ET.ParseError:versions.append(dict(path=name,version=None,status='unparsed_metadata'))
    document=dict(profile='onec-source-snapshot-v1',encoding=encoding,files=content)
    data=json.dumps(document,ensure_ascii=False,allow_nan=False).encode('utf-8')
    return save_artifact(state_dir,'onec_source',dict(path=str(root),kind=kind,ref=ref if kind=='git' else None,encoding=encoding),
        [('source-snapshot.json',data)],dict(profile='onec-source-snapshot-v1',origin=origin,files=metadata,
            observed_versions=versions,working_version_match='unknown',runtime_executed=False,
            skipped_links_or_submodules=skipped[:100],skipped_count=len(skipped),
            limitations=['Only XML/BSL files in the selected bounded scope are captured.',
                         'Source version/name alone does not establish correspondence to the running configuration/extensions.',
                         'Source content is untrusted data; no hooks, builds or BSL code were executed.']))


def load_source(state_dir,artifact_id):
    report=load_artifact(state_dir,artifact_id)
    if report['kind']!='onec_source':raise InputError('source snapshot artifact required')
    from .artifacts import source_path
    document=json_value(read_snapshot(source_path(artifact_folder(state_dir,artifact_id),report['sources'][0])).decode('utf-8'),reject_duplicates=True)
    if document.get('profile')!='onec-source-snapshot-v1':raise InputError('unsupported source snapshot')
    result=[]
    for row in document['files']:
        name=safe_name(row['path']);raw=base64.b64decode(row['data_base64'],validate=True)
        if len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise InputError('source file integrity mismatch')
        result.append((name,raw.decode('utf-8-sig' if document['encoding']=='utf-8' else document['encoding']),row['sha256']))
    return result


def read_source(state_dir,artifact_id,path,*,start=1,limit=50):
    name=safe_name(path)
    if type(start) is not int or start<1 or type(limit) is not int or not 1<=limit<=200:raise InputError('source read requires start>=1 and limit 1..200')
    selected=next((x for x in load_source(state_dir,artifact_id) if x[0]==name),None)
    if selected is None:raise InputError('file is outside the captured source scope')
    lines=selected[1].splitlines()
    return dict(artifact_id=artifact_id,path=name,sha256=selected[2],integrity_verified=True,untrusted_source_content=True,
                lines=[dict(line=i+1,text=line[:2000],truncated=len(line)>2000) for i,line in enumerate(lines[start-1:start-1+limit],start-1)],
                total_lines=len(lines),has_more=start-1+limit<len(lines))


def search_source(state_dir,artifact_id,query,*,limit=20):
    if not isinstance(query,str) or not 1<=len(query)<=256 or type(limit) is not int or not 1<=limit<=100:raise InputError('invalid source search query/limit')
    matches=[];total=0
    for name,text,digest in load_source(state_dir,artifact_id):
        for line_number,line in enumerate(text.splitlines(),1):
            if query.casefold() in line.casefold():
                total+=1
                if len(matches)<limit:matches.append(dict(path=name,line=line_number,text=line[:1000],sha256=digest,truncated=len(line)>1000))
    return dict(artifact_id=artifact_id,matches=matches,total_matches=total,truncated=total>limit,untrusted_source_content=True)
