"""Private checked run documents, kernel writer locks and lifetime-scoped observations."""
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
from datetime import datetime,timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat

from .inputs import InputError,read_snapshot,json_value
from .storage import write_json

MAX_DOCUMENT=17*1024**2
PROMOTION_BLOCKED = 'promotion_blocked'

def stamp():return datetime.now(timezone.utc).isoformat()
def encode(value):return (json.dumps(value,ensure_ascii=False,sort_keys=True,allow_nan=False,indent=2)+'\n').encode('utf-8')
def digest(value):return hashlib.sha256(encode(value)).hexdigest()

def safe(path):
    path=Path(path).absolute()
    if '..' in path.parts or str(path).startswith('\\\\'):raise InputError('operation state requires local paths without parent traversal')
    for component in (path,*path.parents):
        try:info=component.lstat()
        except FileNotFoundError:continue
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise InputError('linked operation state rejected')
    return path

def private(path):
    path=safe(path);path.mkdir(parents=True,exist_ok=True)
    from .windows_native import protect_directory
    protect_directory(path)
    return path

def folder(state,run_id):
    if not isinstance(run_id,str) or not re.fullmatch('[a-f0-9]{64}',run_id):raise InputError('invalid operation run ID')
    return safe(Path(state)/'operations'/run_id)

def read(path,limit=MAX_DOCUMENT):return json_value(read_snapshot(safe(path),limit,share_delete=True).decode('utf-8'),reject_duplicates=True)
def write(path,value):
    if len(encode(value))>MAX_DOCUMENT:raise InputError('operation document exceeds limit')
    if os.name=='nt':
        from .windows_native import replace_shared_metadata
        write_json(safe(path),value,replacer=replace_shared_metadata)
    else:write_json(safe(path),value)

def plan(folder):
    value=read(folder/'plan.json',128*1024);receipt=read(folder/'plan-receipt.json',8192)
    return checked_plan(folder,value,receipt)

def plan_schema(request):
    if request.get('operation') == 'case.analyze' and 'retained_tj' in request['arguments']:
        return 2
    if request.get('operation') == 'os.collect' and 'storage_path' in request['arguments']:
        return 2
    if request.get('operation') != 'code.context':
        return 1
    from .context_disclosure import VIEW_READER_CAPABILITIES
    views = request.get('arguments', {}).get('scope', {}).get('views', [])
    # Older readers must stop before opening a protected result they cannot verify.
    return max((VIEW_READER_CAPABILITIES.get(view['kind'], 2) for view in views), default=2)

def checked_plan(folder,value,receipt):
    version=value.get('schema_version')
    if (digest(value)!=receipt.get('sha256') or type(version) is not int
        or version!=plan_schema(value['request'])
        or hashlib.sha256(value['request']['operation_key'].encode()).hexdigest()!=folder.name):raise InputError('operation plan integrity mismatch')
    return value

def record(folder,value,event):
    path=safe(folder/'journal.jsonl')
    row=encode(dict(at=stamp(),event=event,status=value['status'],pid=os.getpid(),run_id=folder.name,
        stop_reason=value.get('stop_reason'),owned_disk=value.get('owned_disk'),
        process_elapsed_seconds=value.get('process',{}).get('elapsed_seconds'))).decode().replace('\n','')+'\n'
    if path.exists() and path.stat().st_size+len(row.encode())>1024**2:raise InputError('operation journal exceeds limit')
    with path.open('a',encoding='utf-8',newline='\n') as stream:stream.write(row);stream.flush();os.fsync(stream.fileno())
    write(folder/'status.json',value)

def _writer_lock(descriptor, *, unlock=False):
    if os.name == 'nt':
        import msvcrt
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK if unlock else msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(descriptor, fcntl.LOCK_UN if unlock else fcntl.LOCK_EX | fcntl.LOCK_NB)


def writer_active(folder):
    """Observe an existing lock without creating a marker or changing its contents."""
    path = safe(folder / 'writer.lock')
    try:
        expected = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(expected.st_mode) or expected.st_nlink != 1:
        raise InputError('operation writer marker is not an ordinary file')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not os.path.samestat(expected, opened):
            raise InputError('operation writer marker changed during inspection')
        try:
            _writer_lock(descriptor)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                return True
            raise
        _writer_lock(descriptor, unlock=True)
        if not os.path.samestat(opened, path.lstat()):
            raise InputError('operation writer marker changed during inspection')
        return False
    finally:
        os.close(descriptor)


@contextmanager
def writer(folder):
    path=safe(folder/'writer.lock')
    with path.open('a+b') as stream:
        if stream.seek(0,2)==0:stream.write(b'0');stream.flush()
        try:
            _writer_lock(stream.fileno())
        except (OSError,BlockingIOError) as exc:raise InputError('operation writer is active; read status without takeover') from exc
        try:yield
        finally:
            _writer_lock(stream.fileno(), unlock=True)

def process_identity(pid):
    result=dict(pid=pid,hostname=socket.gethostname(),platform=os.name,lifetime=None,state='unknown')
    if type(pid) is not int or pid<1:return result
    if os.name=='nt':
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];kernel.OpenProcess.restype=wintypes.HANDLE
        kernel.CloseHandle.argtypes=[wintypes.HANDLE];kernel.CloseHandle.restype=wintypes.BOOL
        kernel.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD];kernel.WaitForSingleObject.restype=wintypes.DWORD
        kernel.GetProcessTimes.argtypes=[wintypes.HANDLE,*([ctypes.POINTER(wintypes.FILETIME)]*4)];kernel.GetProcessTimes.restype=wintypes.BOOL
        handle=kernel.OpenProcess(0x101000,False,pid)
        if not handle:
            if ctypes.get_last_error()==87:result['state']='not_running'
            return result
        try:
            values=[wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle,*(ctypes.byref(v) for v in values)):return result
            result['lifetime']=str((values[0].dwHighDateTime<<32)|values[0].dwLowDateTime)
            observed=kernel.WaitForSingleObject(handle,0)
            result['state']='running' if observed==258 else 'not_running' if observed==0 else 'unknown'
            return result
        finally:kernel.CloseHandle(handle)
    try:result['pid_namespace']=str(Path('/proc/self/ns/pid').stat().st_ino)
    except OSError:return result
    try:
        text=Path('/proc',str(pid),'stat').read_text(encoding='ascii');fields=text[text.rfind(')')+2:].split()
        boot=Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
        result.update(lifetime=boot+':'+fields[19],state='not_running' if fields[0]=='Z' else 'running')
    except FileNotFoundError:result['state']='not_running'
    except (OSError,ValueError,IndexError,UnicodeError):pass
    return result

def same_process_scope(identity):
    if (not isinstance(identity,dict) or identity.get('hostname')!=socket.gethostname()
        or identity.get('platform')!=os.name):return False
    if os.name=='nt':return True
    try:return identity.get('pid_namespace')==str(Path('/proc/self/ns/pid').stat().st_ino)
    except OSError:return False


def inspect_process(identity):
    if not same_process_scope(identity) or not identity.get('lifetime'):
        return dict(state='unknown')
    current=process_identity(identity.get('pid'))
    if current['state']=='running' and current['lifetime']!=identity['lifetime']:current['state']='different_lifetime'
    return current

def inspect_group(identity):
    """Observe a Linux session created for our worker; leader death is insufficient."""
    if os.name=='nt' or not same_process_scope(identity) or not identity.get('lifetime'):
        return dict(state='unknown')
    pid=identity.get('pid')
    if type(pid) is not int or pid<1:return dict(state='unknown')
    try:os.killpg(pid,0)
    except ProcessLookupError:return dict(state='stopped',basis='group_no_longer_exists')
    except OSError:return dict(state='unknown',basis='group_access_error')
    observed=inspect_process(identity)
    if observed['state']=='different_lifetime':return dict(state='unknown',basis='group_identifier_may_have_been_reused')
    # A surviving group may contain zombies. Only a complete privileged /proc
    # observation can distinguish those from inaccessible living members.
    if os.geteuid()!=0:return dict(state='unknown',basis='group_exists_visibility_not_complete')
    members=[];count=0
    try:
        for entry in Path('/proc').iterdir():
            if not entry.name.isdecimal():continue
            count+=1
            if count>65536:return dict(state='unknown',basis='process_scan_limit')
            try:
                with (entry/'stat').open(encoding='ascii') as stream:text=stream.read(8193)
            except FileNotFoundError:continue  # Process disappeared; never counted as a live member.
            if len(text)>8192:return dict(state='unknown',basis='process_stat_limit')
            fields=text[text.rfind(')')+2:].split()
            if int(fields[2])==pid:members.append(dict(pid=int(entry.name),state=fields[0]))
    except (OSError,ValueError,IndexError,UnicodeError):return dict(state='unknown',basis='incomplete_process_scan')
    if members and all(m['state'] in ('Z','X') for m in members):return dict(state='stopped',basis='only_observed_dead_members',members=members)
    return dict(state='running' if members else 'unknown',basis='observed_group_members' if members else 'group_exists_no_visible_members',members=members)

def _inventory_once(root):
    count=used=disappeared=0
    def failed(error):raise error
    for current,dirs,files in os.walk(safe(root),followlinks=False,onerror=failed):
        for name in dirs+files:
            path=safe(Path(current)/name)
            try:info=path.lstat()
            except FileNotFoundError:
                if name in files and re.fullmatch(r'.+\.[a-f0-9]{32}\.tmp',name):disappeared+=1;continue
                raise
            if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise InputError('linked operation state rejected')
            count+=1
            if count>1000:raise InputError('owned operation file limit')
            if stat.S_ISREG(info.st_mode):used+=info.st_size
            elif not stat.S_ISDIR(info.st_mode):raise InputError('unsupported owned operation member')
    return dict(bytes=used,files=count,transient_files_disappeared=disappeared,measurement='non_atomic_live_inventory')


def _promoted_member_missing(root,error):
    """Recognize only a sealed owned product already at its verified destination."""
    if not isinstance(error.filename,str):return False
    try:parts=Path(error.filename).absolute().relative_to(root).parts
    except ValueError:return False
    if (len(parts)<3 or parts[0]!='work-state' or parts[1] not in ('cases','artifacts','comparisons')
        or not re.fullmatch('[a-f0-9]{32}',parts[2]) or root.parent.name!='operations' or not re.fullmatch('[a-f0-9]{64}',root.name)):return False
    source=safe(root.joinpath(*parts[:3]))
    try:source.lstat()
    except FileNotFoundError:pass
    else:return False
    plan(root)  # Ownership key and sealed admission must still agree.
    from .operations import _worker
    worker=_worker(root)
    if len(worker['targets'])!=1 or worker['targets'][0].get('kind')!=parts[1] or worker['targets'][0].get('id')!=parts[2]:return False
    destination=safe(root.parent.parent/parts[1]/parts[2]);info=destination.lstat()
    if not stat.S_ISDIR(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise InputError('invalid promoted inventory product')
    report=read(destination/'report.json')
    key={'cases':'case_id','artifacts':'artifact_id','comparisons':'comparison_id'}[parts[1]]
    if report.get(key)!=parts[2] or digest(report)!=digest(worker['data']):raise InputError('promoted inventory product disagrees with sealed output')
    return True


def inventory(root):
    """Retry a complete live scan when an owned product moves during promotion.

    Partial attempts never contribute totals. Permission, link and root-identity
    failures remain unknown and fail closed; retries do not restart operations.
    """
    root=Path(root).absolute()
    def identity():
        info=safe(root).lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise InputError('linked operation state rejected')
        if not stat.S_ISDIR(info.st_mode):raise InputError('owned inventory root is not a directory')
        return info.st_dev,info.st_ino
    original=identity();last=None
    for attempt in range(3):
        if attempt and (not original[1] or identity()!=original):raise InputError('owned inventory root identity changed or is unavailable')
        try:
            result=_inventory_once(root)
            if identity()!=original:raise InputError('owned inventory root identity changed')
        except FileNotFoundError as exc:
            if not _promoted_member_missing(root,exc):raise
            last=exc;continue
        result['scan_retries']=attempt
        return result
    raise InputError('owned inventory unstable after three complete scan attempts') from last
