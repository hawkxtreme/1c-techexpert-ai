"""Windows-only native process ownership and shared-read source capture.

No global process termination, service setup, license handling, or shell commands.
The caller supplies file/space budgets; these monitors are not an OS sandbox.
"""
import ctypes as c
from ctypes import wintypes as w
import hashlib
import os
from pathlib import Path
import shutil
import re
import stat
import subprocess
import threading
import time

from .inputs import InputError


class _BasicLimits(c.Structure):
    _fields_=[('process_time',c.c_longlong),('job_time',c.c_longlong),('flags',w.DWORD),('min_ws',c.c_size_t),
        ('max_ws',c.c_size_t),('active_limit',w.DWORD),('affinity',c.c_size_t),('priority',w.DWORD),('scheduling',w.DWORD)]


class _Io(c.Structure):
    _fields_=[(key,c.c_ulonglong) for key in ('read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes')]


class _Limits(c.Structure):
    _fields_=[('basic',_BasicLimits),('io',_Io),('process_memory',c.c_size_t),('job_memory',c.c_size_t),('peak_process',c.c_size_t),('peak_job',c.c_size_t)]


class _Accounting(c.Structure):
    _fields_=[(key,c.c_longlong) for key in ('user','kernel','period_user','period_kernel')]+[(key,w.DWORD) for key in ('page_faults','total','active','terminated')]


class _Startup(c.Structure):
    _fields_=[('cb',w.DWORD),('reserved',w.LPWSTR),('desktop',w.LPWSTR),('title',w.LPWSTR),
        *[(key,w.DWORD) for key in ('x','y','width','height','chars_x','chars_y','fill','flags')],
        ('show',w.WORD),('reserved_size',w.WORD),('reserved_bytes',c.POINTER(w.BYTE)),('stdin',w.HANDLE),('stdout',w.HANDLE),('stderr',w.HANDLE)]


class _StartupEx(c.Structure):
    _fields_=[('base',_Startup),('attributes',c.c_void_p)]


class _Process(c.Structure):
    _fields_=[('process',w.HANDLE),('thread',w.HANDLE),('pid',w.DWORD),('tid',w.DWORD)]


class _FileInfo(c.Structure):
    _fields_=[('attributes',w.DWORD),('created',w.FILETIME),('accessed',w.FILETIME),('written',w.FILETIME),
        *[(key,w.DWORD) for key in ('volume','size_high','size_low','links','index_high','index_low')]]


class _FileId(c.Structure):
    _fields_=[('volume',c.c_ulonglong),('identifier',c.c_ubyte*16)]


_SPAWN_LOCK=threading.Lock()


def _kernel():
    if os.name!='nt':raise InputError('native Designer export requires the verified Windows profile; use preparation instructions on other systems')
    dll=c.WinDLL('kernel32',use_last_error=True)
    signatures={
        'CreateJobObjectW':([c.c_void_p,w.LPCWSTR],w.HANDLE),
        'SetInformationJobObject':([w.HANDLE,c.c_int,c.c_void_p,w.DWORD],w.BOOL),
        'QueryInformationJobObject':([w.HANDLE,c.c_int,c.c_void_p,w.DWORD,c.c_void_p],w.BOOL),
        'AssignProcessToJobObject':([w.HANDLE,w.HANDLE],w.BOOL),
        'TerminateJobObject':([w.HANDLE,w.UINT],w.BOOL),
        'TerminateProcess':([w.HANDLE,w.UINT],w.BOOL),
        'CloseHandle':([w.HANDLE],w.BOOL),
        'ResumeThread':([w.HANDLE],w.DWORD),
        'WaitForSingleObject':([w.HANDLE,w.DWORD],w.DWORD),
        'GetExitCodeProcess':([w.HANDLE,c.POINTER(w.DWORD)],w.BOOL),
        'InitializeProcThreadAttributeList':([c.c_void_p,w.DWORD,w.DWORD,c.POINTER(c.c_size_t)],w.BOOL),
        'UpdateProcThreadAttribute':([c.c_void_p,w.DWORD,c.c_size_t,c.c_void_p,c.c_size_t,c.c_void_p,c.c_void_p],w.BOOL),
        'DeleteProcThreadAttributeList':([c.c_void_p],None),
        'CreateProcessW':([w.LPCWSTR,w.LPWSTR,c.c_void_p,c.c_void_p,w.BOOL,w.DWORD,c.c_void_p,w.LPCWSTR,c.c_void_p,c.POINTER(_Process)],w.BOOL),
        'CreateFileW':([w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE],w.HANDLE),
        'GetFileInformationByHandle':([w.HANDLE,c.POINTER(_FileInfo)],w.BOOL),
        'GetFileInformationByHandleEx':([w.HANDLE,c.c_int,c.c_void_p,w.DWORD],w.BOOL),
        'LocalFree':([c.c_void_p],c.c_void_p),
    }
    for name,(args,result) in signatures.items():
        function=getattr(dll,name);function.argtypes=args;function.restype=result
    return dll


def _security():
    _kernel();dll=c.WinDLL('advapi32',use_last_error=True)
    signatures={
        'ConvertStringSecurityDescriptorToSecurityDescriptorW':([w.LPCWSTR,w.DWORD,c.POINTER(c.c_void_p),c.POINTER(w.DWORD)],w.BOOL),
        'ConvertSecurityDescriptorToStringSecurityDescriptorW':([c.c_void_p,w.DWORD,w.DWORD,c.POINTER(w.LPWSTR),c.POINTER(w.DWORD)],w.BOOL),
        'GetSecurityDescriptorDacl':([c.c_void_p,c.POINTER(w.BOOL),c.POINTER(c.c_void_p),c.POINTER(w.BOOL)],w.BOOL),
        'GetFileSecurityW':([w.LPCWSTR,w.DWORD,c.c_void_p,w.DWORD,c.POINTER(w.DWORD)],w.BOOL),
        'SetNamedSecurityInfoW':([w.LPWSTR,c.c_int,w.DWORD,c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p],w.DWORD),
    }
    for name,(args,result) in signatures.items():
        function=getattr(dll,name);function.argtypes=args;function.restype=result
    return dll


def directory_policy(path):
    if os.name!='nt':return dict(protected=Path(path).stat().st_mode&0o777==0o700,allow=['owner'])
    kernel=_kernel();security=_security();size=w.DWORD()
    security.GetFileSecurityW(str(path),4,None,0,c.byref(size))
    if not 0<size.value<=65536:raise InputError('private directory access could not be read')
    descriptor=c.create_string_buffer(size.value)
    if not security.GetFileSecurityW(str(path),4,descriptor,size,c.byref(size)):raise c.WinError(c.get_last_error())
    text=w.LPWSTR()
    if not security.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor,1,4,c.byref(text),None):raise c.WinError(c.get_last_error())
    try:sddl=text.value
    finally:kernel.LocalFree(c.cast(text,c.c_void_p))
    aliases={'OW':'owner','BA':'administrators','SY':'system','S-1-3-4':'owner','S-1-5-32-544':'administrators','S-1-5-18':'system'};allow=set()
    for ace in re.findall(r'\(([^()]*)\)',sddl):
        fields=ace.split(';')
        if len(fields)!=6 or fields[0]!='A' or fields[2] not in ('FA','0x1f01ff') or fields[5] not in aliases:raise InputError('private directory has unexpected access rules')
        allow.add(aliases[fields[5]])
    if allow!=set(aliases.values()):raise InputError('private directory access is incomplete')
    return dict(protected=sddl.startswith('D:P'),allow=sorted(allow))


def protect_directory(path):
    """Restrict a newly owned directory; never use this on user source trees."""
    path=Path(path);info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise InputError('private directory must be a nonlinked owned directory')
    if os.name!='nt':path.chmod(0o700);return directory_policy(path)
    kernel=_kernel();security=_security();descriptor=c.c_void_p()
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW('D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)',1,c.byref(descriptor),None):raise c.WinError(c.get_last_error())
    try:
        present=w.BOOL();defaulted=w.BOOL();dacl=c.c_void_p()
        if not security.GetSecurityDescriptorDacl(descriptor,c.byref(present),c.byref(dacl),c.byref(defaulted)) or not present or not dacl:raise InputError('private directory ACL could not be prepared')
        error=security.SetNamedSecurityInfoW(str(path),1,0x80000004,None,None,dacl,None)
        if error:raise c.WinError(error)
    finally:kernel.LocalFree(descriptor)
    policy=directory_policy(path)
    if not policy['protected']:raise InputError('private directory inheritance was not restricted')
    return policy


def _handle_identity(kernel,handle):
    info=_FileInfo();file_id=_FileId()
    if not kernel.GetFileInformationByHandle(handle,c.byref(info)):raise c.WinError(c.get_last_error())
    if info.attributes&(0x10|0x400):raise InputError('source must be a regular nonlinked file')
    if not kernel.GetFileInformationByHandleEx(handle,18,c.byref(file_id),c.sizeof(file_id)):
        raise InputError('full Windows file identity unavailable; use a supported local filesystem')
    def ticks(value):return (value.dwHighDateTime<<32)|value.dwLowDateTime
    return dict(bytes=(info.size_high<<32)|info.size_low,volume_serial=file_id.volume,file_id=bytes(file_id.identifier).hex(),
        creation_filetime_100ns=ticks(info.created),write_filetime_100ns=ticks(info.written),time_epoch='1601-01-01T00:00:00Z')


def file_identity(path):
    if os.name!='nt':
        # Portable orchestration tests substitute the Windows runtime boundary;
        # real native planning is rejected by file_version on other systems.
        info=Path(path).stat()
        return dict(bytes=info.st_size,mtime_ns=info.st_mtime_ns,device=info.st_dev,inode=info.st_ino)
    kernel=_kernel();handle=kernel.CreateFileW(str(path),0x80,7,None,3,0x00200000,None)
    if handle==c.c_void_p(-1).value:raise c.WinError(c.get_last_error())
    try:return _handle_identity(kernel,handle)
    finally:kernel.CloseHandle(handle)


def file_version(path):
    _kernel()
    dll=c.WinDLL('version',use_last_error=True)
    dll.GetFileVersionInfoSizeW.argtypes=[w.LPCWSTR,c.c_void_p];dll.GetFileVersionInfoSizeW.restype=w.DWORD
    dll.GetFileVersionInfoW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p];dll.GetFileVersionInfoW.restype=w.BOOL
    dll.VerQueryValueW.argtypes=[c.c_void_p,w.LPCWSTR,c.POINTER(c.c_void_p),c.POINTER(w.UINT)];dll.VerQueryValueW.restype=w.BOOL
    size=dll.GetFileVersionInfoSizeW(str(path),None)
    if not size:raise InputError('platform version metadata is unavailable')
    buffer=c.create_string_buffer(size)
    if not dll.GetFileVersionInfoW(str(path),0,size,buffer):raise c.WinError(c.get_last_error())
    pointer=c.c_void_p();length=w.UINT()
    if not dll.VerQueryValueW(buffer,'\\',c.byref(pointer),c.byref(length)) or length.value<16:raise InputError('invalid platform version metadata')
    data=c.cast(pointer,c.POINTER(w.DWORD))
    if data[0]!=0xFEEF04BD:raise InputError('invalid platform version signature')
    return '.'.join(map(str,(data[2]>>16,data[2]&0xffff,data[3]>>16,data[3]&0xffff)))


def copy_locked(source,target,*,max_bytes,deadline,space_floor):
    """Hold a Windows shared-read/no-write handle during the bounded copy."""
    kernel=_kernel()
    import msvcrt
    source=Path(source);target=Path(target)
    handle=kernel.CreateFileW(str(source),0x80000000,1,None,3,0x00200000|0x08000000,None)
    if handle==c.c_void_p(-1).value:raise InputError('source cannot be opened with shared read and no writers; close the file IB or provide a closed copy')
    fd=None
    try:
        before=_handle_identity(kernel,handle)
        fd=msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY);handle=None
        with os.fdopen(fd,'rb') as original:
            fd=None
            if before['bytes']>max_bytes:raise InputError('source IB exceeds planned copy limit; provide a smaller closed test copy or existing XML/BSL')
            digest=hashlib.sha256();total=0
            with target.open('xb') as destination:
                while True:
                    if time.monotonic()>deadline:raise InputError('source copy timeout')
                    if shutil.disk_usage(target.parent).free<space_floor:raise InputError('source copy stopped at free space floor')
                    data=original.read(1024*1024)
                    if not data:break
                    total+=len(data)
                    if total>max_bytes:raise InputError('source copy exceeds byte limit')
                    destination.write(data);digest.update(data)
            after=_handle_identity(kernel,msvcrt.get_osfhandle(original.fileno()))
            if before!=after or total!=before['bytes']:raise InputError('source changed during copy')
        return dict(bytes=total,sha256=digest.hexdigest(),source_identity=before,consistency='Windows shared-read handle denied writers during capture')
    finally:
        if fd is not None:os.close(fd)
        if handle is not None:kernel.CloseHandle(handle)


def open_shared_read(path):
    """Read one old-or-new metadata file without blocking atomic replacement."""
    import msvcrt
    kernel=_kernel();handle=kernel.CreateFileW(str(path),0x80000000,7,None,3,0x00200080,None);fd=None
    if handle==c.c_void_p(-1).value:raise c.WinError(c.get_last_error())
    try:
        info=_FileInfo()
        if not kernel.GetFileInformationByHandle(handle,c.byref(info)):raise c.WinError(c.get_last_error())
        if info.attributes&(0x10|0x400):raise InputError('shared metadata reader requires a regular non-reparse file')
        fd=msvcrt.open_osfhandle(int(handle),os.O_RDONLY|os.O_BINARY);handle=None
        stream=os.fdopen(fd,'rb');fd=None;return stream
    finally:
        if fd is not None:os.close(fd)
        if handle is not None:kernel.CloseHandle(handle)


def replace_shared_metadata(source,target):
    """Same-directory metadata rename with consenting delete-shared old readers."""
    source=Path(source).absolute();target=Path(target).absolute()
    if source.parent!=target.parent or '..' in source.parts or '..' in target.parts:raise InputError('metadata replacement requires sibling local files')
    for path in (source,target):
        try:info=path.lstat()
        except FileNotFoundError:continue
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise InputError('linked metadata replacement rejected')
    kernel=_kernel()
    kernel.SetFileInformationByHandle.argtypes=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD]
    kernel.SetFileInformationByHandle.restype=w.BOOL
    class Rename(c.Structure):_fields_=[('flags',w.DWORD),('root',w.HANDLE),('length',w.DWORD),('name',w.WCHAR*1)]
    handle=kernel.CreateFileW(str(source),0x10080,7,None,3,0x00200080,None)
    if handle==c.c_void_p(-1).value:raise c.WinError(c.get_last_error())
    try:
        info=_FileInfo()
        if not kernel.GetFileInformationByHandle(handle,c.byref(info)):raise c.WinError(c.get_last_error())
        if info.attributes&(0x10|0x400):raise InputError('metadata replacement requires a regular non-reparse file')
        name=str(target).encode('utf-16-le');buffer=c.create_string_buffer(Rename.name.offset+len(name)+2)
        rename=c.cast(buffer,c.POINTER(Rename)).contents;rename.flags=3;rename.root=None;rename.length=len(name)
        c.memmove(c.addressof(buffer)+Rename.name.offset,name,len(name))
        # FileRenameInfoEx: REPLACE_IF_EXISTS | POSIX_SEMANTICS. No ignore-ACL/read-only flags.
        if not kernel.SetFileInformationByHandle(handle,22,buffer,len(buffer)):raise c.WinError(c.get_last_error())
    finally:kernel.CloseHandle(handle)


def run(argv,*,cwd,guard,timeout,on_started=None,memory_bytes=None):
    """Launch suspended, bind to an owned job, then resume. Keep no descendants."""
    kernel=_kernel()
    import msvcrt
    if not isinstance(argv,list) or not argv or any(not isinstance(x,str) or '\0' in x for x in argv):raise InputError('native argv must be explicit strings')
    if type(timeout) not in (int,float) or not 0<timeout<=3600:raise InputError('invalid native timeout')
    if memory_bytes is not None and (type(memory_bytes) is not int or not 64*1024**2<=memory_bytes<=2*1024**3):raise InputError('invalid job memory bound')
    cwd=Path(cwd);job=kernel.CreateJobObjectW(None,None)
    if not job:raise c.WinError(c.get_last_error())
    limits=_Limits();limits.basic.flags=0x2000
    if memory_bytes is not None:limits.basic.flags|=0x200;limits.job_memory=memory_bytes
    process=_Process();assigned=False;reason=None;guard_error=None;started=time.monotonic();tree_finished=False;exit_code=None
    def active():
        accounting=_Accounting()
        if not kernel.QueryInformationJobObject(job,1,c.byref(accounting),c.sizeof(accounting),None):raise c.WinError(c.get_last_error())
        return accounting.active
    try:
        if not kernel.SetInformationJobObject(job,9,c.byref(limits),c.sizeof(limits)):raise c.WinError(c.get_last_error())
        with (cwd/'stdout.bin').open('xb') as stdout,(cwd/'stderr.bin').open('xb') as stderr,open(os.devnull,'rb') as stdin:
            handles=(w.HANDLE*3)(*(msvcrt.get_osfhandle(f.fileno()) for f in (stdin,stdout,stderr)))
            size=c.c_size_t();kernel.InitializeProcThreadAttributeList(None,2,0,c.byref(size))
            attributes=c.create_string_buffer(size.value)
            if not kernel.InitializeProcThreadAttributeList(attributes,2,0,c.byref(size)):raise c.WinError(c.get_last_error())
            try:
                if not kernel.UpdateProcThreadAttribute(attributes,0,0x20002,handles,c.sizeof(handles),None,None):raise c.WinError(c.get_last_error())
                jobs=(w.HANDLE*1)(job)
                # Assign at CreateProcess itself: a parent death immediately
                # after creation must not leave an unassigned suspended child.
                if not kernel.UpdateProcThreadAttribute(attributes,0,0x2000D,jobs,c.sizeof(jobs),None,None):raise c.WinError(c.get_last_error())
                startup=_StartupEx();startup.base.cb=c.sizeof(startup);startup.base.flags=0x100|1;startup.base.show=0
                startup.base.stdin,startup.base.stdout,startup.base.stderr=handles
                startup.attributes=c.cast(attributes,c.c_void_p)
                command=c.create_unicode_buffer(subprocess.list2cmdline(argv))
                with _SPAWN_LOCK:
                    try:
                        for handle in handles:os.set_handle_inheritable(handle,True)
                        if not kernel.CreateProcessW(argv[0],command,None,None,True,0x00080000|4|0x08000000,None,str(cwd),c.byref(startup),c.byref(process)):
                            raise c.WinError(c.get_last_error())
                    finally:
                        for handle in handles:os.set_handle_inheritable(handle,False)
            finally:kernel.DeleteProcThreadAttributeList(attributes)
            assigned=True
            if on_started is not None:on_started(process.pid)
            if kernel.ResumeThread(process.thread)==0xffffffff:raise c.WinError(c.get_last_error())
            kernel.CloseHandle(process.thread);process.thread=None
            try:
                while True:
                    if time.monotonic()-started>=timeout:reason='timeout';break
                    try:guard()
                    except (OSError,ValueError) as exc:reason='guard_failed';guard_error=str(exc)[:512];break
                    wait=kernel.WaitForSingleObject(process.process,50)
                    if wait==0:
                        # Allow kernel accounting to settle before classifying a
                        # still-active child as unfinished work.
                        settle=time.monotonic()+.1
                        while active() and time.monotonic()<settle:time.sleep(.01)
                        if active():reason='descendants_after_parent_exit'
                        break
                    if wait!=258:raise c.WinError(c.get_last_error())
            except KeyboardInterrupt:reason='cancelled'
            if reason:kernel.TerminateJobObject(job,1)
            finish=time.monotonic()+5
            while active() and time.monotonic()<finish:time.sleep(.02)
            tree_finished=active()==0
            code=w.DWORD()
            if kernel.GetExitCodeProcess(process.process,c.byref(code)):exit_code=code.value
            else:reason=reason or 'exit_code_unknown'
            if not tree_finished:reason=reason or 'owned_tree_state_unknown'
            accounting=_Accounting();memory=_Limits()
            cpu_known=kernel.QueryInformationJobObject(job,1,c.byref(accounting),c.sizeof(accounting),None)
            memory_known=kernel.QueryInformationJobObject(job,9,c.byref(memory),c.sizeof(memory),None)
            resource_usage=dict(user_cpu_seconds=accounting.user/10000000 if cpu_known else None,
                kernel_cpu_seconds=accounting.kernel/10000000 if cpu_known else None,
                peak_job_memory_bytes=memory.peak_job if memory_known else None,scope='owned Windows Job processes')
    finally:
        if process.process:
            if assigned:kernel.TerminateJobObject(job,1)
            else:kernel.TerminateProcess(process.process,1)  # Still suspended: no child can have started.
            kernel.WaitForSingleObject(process.process,5000)
            kernel.CloseHandle(process.process)
        if process.thread:kernel.CloseHandle(process.thread)
        kernel.CloseHandle(job)
    return dict(status='stopped' if reason else 'completed',exit_code=exit_code,elapsed_seconds=round(time.monotonic()-started,3),
        pid=process.pid,tree_finished=tree_finished,stop_reason=reason,guard_error=guard_error,resource_usage=resource_usage)
