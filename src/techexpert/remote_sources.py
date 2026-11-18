"""Read-only bounded SFTP catalogues and stable complete-file captures."""
import hashlib
import os
from pathlib import Path
import posixpath
import shutil
import stat
import uuid

from . import input_files,operation_state as fs
from .inputs import InputError
from .remote_budget import root_path

MIB=1024**2
LIMITS=dict(max_entries=256,max_files=128,max_depth=8,max_file_bytes=16*MIB,max_total_bytes=64*MIB)


def bounds(values):
    if type(values) is not dict or set(values)-LIMITS.keys():raise InputError('unsupported remote catalogue limits')
    result=dict(LIMITS)
    for key,value in values.items():
        if type(value) is not int or not (0 if key=='max_depth' else 1)<=value<=LIMITS[key]:raise InputError('remote catalogue limit outside bounds')
        result[key]=value
    return result


def signature(attributes):
    if (type(attributes) is not dict or any(type(attributes.get(k)) is not int for k in ('size','permissions','mtime'))
        or not 0<=attributes['size']<2**64 or not 0<=attributes['permissions']<2**32 or not 0<=attributes['mtime']<2**32):
        raise InputError('remote attributes do not establish supported file type/size/time')
    return {key:attributes[key] for key in ('size','permissions','mtime')}


def path(root,relative):
    root_path(root);parts=input_files.name_parts(relative)
    result=posixpath.join(root,*parts)
    if root!='/' and not result.startswith(root+'/'):raise InputError('remote member escapes selected root')
    return result


def chain(client,root,relative=None):
    root_path(root)
    selected=root if relative is None else path(root,relative)
    result=[];current='/'
    parts=selected.strip('/').split('/') if selected!='/' else []
    for index,part in enumerate(['']+parts):
        if part:current=posixpath.join(current,part)
        attributes=signature(client.lstat(current));kind=stat.S_IFMT(attributes['permissions'])
        if kind!=stat.S_IFDIR and (relative is None or index<len(parts)):
            raise InputError('remote root/ancestor is not an unlinked directory')
        if kind not in (stat.S_IFDIR,stat.S_IFREG):raise InputError('unsupported remote symlink/special file')
        result.append((current,attributes))
    if client.realpath(selected)!=selected:raise InputError('remote canonical path differs from explicit selected path')
    return result


def inspect_tree(client,root,**limits):
    bound=bounds(limits);initial=chain(client,root);members=[];excluded=[];count=0;total=0;truncated=False
    def walk(folder,relative,depth):
        nonlocal count,total,truncated
        before=signature(client.lstat(folder));handle=client.opendir(folder);names=set()
        try:
            while not truncated:
                entries=client.readdir(handle)
                if entries is None:break
                for entry in entries:
                    name=entry['name']
                    if name in ('.','..'):continue
                    if count>=bound['max_entries'] or len(members)>=bound['max_files']:truncated=True;break
                    count+=1
                    try:
                        if len(input_files.name_parts(name))!=1:raise InputError('remote directory entry is not a leaf')
                        key=input_files.name_key(name)
                        if key in names:raise InputError('ambiguous remote directory member')
                        names.add(key)
                    except InputError:
                        excluded.append(dict(path=posixpath.join(relative,name),reason='unsupported_or_ambiguous_name'));continue
                    rel=posixpath.join(relative,name) if relative else name;selected=path(root,rel)
                    attributes=signature(client.lstat(selected))
                    if signature(entry['attributes'])!=attributes:raise InputError('remote directory member changed during listing')
                    kind=stat.S_IFMT(attributes['permissions'])
                    if kind==stat.S_IFDIR:
                        if depth>=bound['max_depth']:excluded.append(dict(path=rel,reason='directory_depth_limit'));continue
                        walk(selected,rel,depth+1)
                    elif kind==stat.S_IFREG:
                        importable=attributes['size']<=bound['max_file_bytes'] and total+attributes['size']<=bound['max_total_bytes']
                        members.append(dict(id='m'+str(len(members)+1),relative_path=rel,bytes=attributes['size'],attributes=attributes,importable=importable))
                        if importable:total+=attributes['size']
                    else:excluded.append(dict(path=rel,reason='unsupported_file_type'))
                    if truncated:break
        finally:client.close_handle(handle)
        if before!=signature(client.lstat(folder)):raise InputError('remote directory changed while listing')
    walk(root,'',0)
    if chain(client,root)!=initial:raise InputError('remote root changed during inspection')
    return dict(schema_version=1,members=members,excluded=excluded,listing_complete=not truncated and not excluded,truncated=truncated,
        inspected_entries=count,file_count=len(members),expanded_bytes=total,limits=bound,collection_coverage='unknown',
        file_payload_downloaded=False,metadata_only=True,identity_scope='observed SFTPv3 metadata; not an atomic directory snapshot or database/run ownership')


def capture_files(client,root,members,output):
    if type(members) is not list or not 1<=len(members)<=32:raise InputError('select1..32 remote files')
    selected=[];names=set();total=0
    for member in members:
        if type(member) is not dict or member.get('importable') is not True:raise InputError('remote member is not importable')
        name=member['relative_path'];path(root,name)
        if name in names:raise InputError('duplicate remote capture member')
        names.add(name);attributes=signature(member['attributes'])
        if attributes['size']!=member['bytes'] or not 0<=member['bytes']<=16*MIB:raise InputError('remote file exceeds capture byte limit')
        if stat.S_IFMT(attributes['permissions'])!=stat.S_IFREG:raise InputError('remote member is not a regular file')
        total+=member['bytes'];selected.append(member)
    if total>64*MIB:raise InputError('remote total capture byte limit')
    ancestor=Path(output).absolute()
    while not ancestor.exists():ancestor=ancestor.parent
    if shutil.disk_usage(ancestor).free-total*2-2*MIB<10*1024**3:raise InputError('insufficient private space above disk floor')
    stage=fs.private(Path(output)/'remote-stage'/uuid.uuid4().hex);captured=[]
    for number,member in enumerate(selected,1):
        acquisition_started=fs.stamp()
        before=chain(client,root,member['relative_path']);expected=signature(member['attributes'])
        if before[-1][1]!=expected:raise InputError('remote file metadata changed since preview')
        handle=client.open(path(root,member['relative_path']));destination=stage/('s'+str(number)+'.bin')
        try:
            if signature(client.fstat(handle))!=expected:raise InputError('remote opened file changed before capture')
            hashes=[]
            for repeat in range(2):
                digest=hashlib.sha256();at=0
                with destination.open('xb' if repeat==0 else 'rb') as stream:
                    while at<member['bytes']:
                        data=client.read(handle,at,min(32768,member['bytes']-at))
                        if data is None or not data:raise InputError('remote file ended before complete transfer')
                        if len(data)>min(32768,member['bytes']-at):raise InputError('remote read exceeded requested range')
                        if repeat==0:stream.write(data)
                        elif stream.read(len(data))!=data:raise InputError('remote file bytes changed between reads')
                        digest.update(data);at+=len(data)
                    if repeat==0:stream.flush();os.fsync(stream.fileno())
                    if client.read(handle,at,1) is not None:raise InputError('remote file grew during capture')
                hashes.append(digest.hexdigest())
                if signature(client.fstat(handle))!=expected:raise InputError('remote file metadata changed during capture')
            if hashes[0]!=hashes[1] or chain(client,root,member['relative_path'])!=before:raise InputError('remote file changed while capturing')
            captured.append(dict(member_id=member['id'],relative_path=member['relative_path'],path=str(destination),bytes=member['bytes'],sha256=hashes[0],
                acquisition_started=acquisition_started,acquisition_ended=fs.stamp(),
                attributes=expected,complete=True,atomic_snapshot=False,consistency='two_equal_complete_reads_and_unchanged_observed_SFTP_metadata',
                limitations='SFTPv3 has no stable file ID or atomic open-at confinement here; second-resolution time, hostile server, ABA and unseen writer changes remain unknown'))
        finally:client.close_handle(handle)
    return captured
