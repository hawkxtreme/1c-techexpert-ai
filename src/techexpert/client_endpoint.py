"""Passive identification of the selected local Windows TestClient listener."""
import ctypes as c
from ctypes import wintypes as w
import os
from pathlib import Path
import socket
import struct

from .inputs import InputError
from .operation_state import process_identity
from .windows_native import file_version


BUILD='8.3.27.1989'
_ROW=struct.Struct('<6I')
_LISTENERS=3     # TCP_TABLE_OWNER_PID_LISTENER
_CONNECTIONS=4   # TCP_TABLE_OWNER_PID_CONNECTIONS
_LOOPBACK=struct.unpack('<I',socket.inet_aton('127.0.0.1'))[0]


def _rows(table_class):
    if os.name!='nt':
        raise InputError('live Testpilot endpoint inspection requires Windows')
    table=c.WinDLL('iphlpapi',use_last_error=True).GetExtendedTcpTable
    table.argtypes=[c.c_void_p,c.POINTER(w.DWORD),w.BOOL,w.ULONG,c.c_int,w.ULONG]
    table.restype=w.DWORD
    size=w.DWORD()
    if table(None,c.byref(size),False,socket.AF_INET,table_class,0)!=122:
        raise InputError('local TCP owner table unavailable')
    for _ in range(3):
        if not 4<=size.value<=16*1024**2:
            raise InputError('local TCP owner table exceeds its bound')
        buffer=c.create_string_buffer(size.value)
        code=table(buffer,c.byref(size),False,socket.AF_INET,table_class,0)
        if code==0:
            break
        if code!=122:
            raise InputError('local TCP owner table unavailable')
    else:
        raise InputError('local TCP owner table changed during lookup')
    count=struct.unpack_from('<I',buffer)[0]
    if count>(len(buffer)-4)//_ROW.size:
        raise InputError('invalid local TCP owner table')
    for offset in range(4,4+count*_ROW.size,_ROW.size):
        state,address,local_port,peer,peer_port,pid=_ROW.unpack_from(buffer,offset)
        yield state,address,socket.ntohs(local_port&0xffff),peer,socket.ntohs(peer_port&0xffff),pid


def listener(port):
    if type(port) is not int or not 1<=port<=65535:
        raise InputError('invalid TestClient port')
    matches=[]
    for state,address,local_port,_,_,pid in _rows(_LISTENERS):
        if state==2 and local_port==port and address in (0,_LOOPBACK):
            matches.append(dict(pid=pid,address='127.0.0.1' if address else '0.0.0.0'))
    if len(matches)!=1 or matches[0]['pid']<1:
        raise InputError('selected loopback port does not have one observable listener')
    return matches[0]


def _image_path(pid):
    kernel=c.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD]
    kernel.OpenProcess.restype=w.HANDLE
    kernel.CloseHandle.argtypes=[w.HANDLE]
    kernel.CloseHandle.restype=w.BOOL
    query=kernel.QueryFullProcessImageNameW
    query.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,c.POINTER(w.DWORD)]
    query.restype=w.BOOL
    handle=kernel.OpenProcess(0x1000,False,pid)
    if not handle:
        raise InputError('selected TestClient process image unavailable')
    try:
        path=c.create_unicode_buffer(32768)
        size=w.DWORD(len(path))
        if not query(handle,0,path,c.byref(size)):
            raise InputError('selected TestClient process image unavailable')
        return Path(path.value)
    finally:
        kernel.CloseHandle(handle)


def inspect_endpoint(port):
    selected=listener(port)
    pid=selected['pid']
    identity=process_identity(pid)
    if identity['state']!='running' or not identity['lifetime']:
        raise InputError('selected TestClient process lifetime unavailable')
    path=_image_path(pid)
    if path.name.casefold()!='1cv8c.exe' or file_version(path)!=BUILD:
        raise InputError('supported Windows thin TestClient build required')
    if process_identity(pid)!=identity or listener(port)!=selected:
        raise InputError('selected TestClient ownership changed during inspection')
    return dict(port=port,pid=pid,lifetime=identity['lifetime'])


def verify_connection(endpoint,caller_pid):
    """Match both established IPv4 TCP endpoints to the approved process."""
    port=endpoint['port']
    pid=endpoint['pid']
    identity=process_identity(pid)
    if identity['state']!='running' or identity['lifetime']!=endpoint['lifetime']:
        raise InputError('selected TestClient process changed')
    connections=[(local,remote,owner) for state,address,local,peer,remote,owner in _rows(_CONNECTIONS)
        if state==5 and address==peer==_LOOPBACK and port in (local,remote)]
    outgoing=[local for local,remote,owner in connections if local!=port and remote==port and owner==caller_pid]
    if len(outgoing)!=1 or connections.count((port,outgoing[0],pid))!=1 or process_identity(pid)!=identity:
        raise InputError('selected TestClient does not own the established loopback peer')
