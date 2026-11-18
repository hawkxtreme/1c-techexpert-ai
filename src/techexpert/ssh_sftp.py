"""Bounded SFTPv3 over a fixed OpenSSH subsystem, no remote command or crypto."""
import os
from pathlib import Path
import queue
import re
import selectors
import struct
import subprocess
import threading
import time

from .inputs import InputError
from . import sftp_wire as wire


def connection(value):
    if type(value) is not dict or set(value)-{'host','port','known_hosts_file','identity_file','node','root'}:raise InputError('unsupported SFTP connection settings')
    result=dict(value);host=result.get('host')
    if type(host) is not str or not re.fullmatch(r'(?:[A-Za-z_][A-Za-z0-9_.-]{0,63}@)?(?:[A-Za-z0-9][A-Za-z0-9_.-]{0,252}|\[[a-fA-F0-9:]+\])',host):raise InputError('invalid SFTP SSH destination')
    port=result.setdefault('port',22)
    if type(port) is not int or not 1<=port<=65535:raise InputError('invalid SFTP port')
    for name in ('known_hosts_file','identity_file'):
        if name not in result:
            if name=='known_hosts_file':raise InputError('explicit verified known_hosts file required')
            continue
        path=result[name]
        if type(path) is not str or not 1<=len(path)<=2048 or any(ord(c)<32 or c in '"%$' for c in path):raise InputError('invalid SFTP local credential-file reference')
        result[name]=str(Path(path).absolute())
    for name in ('node','root'):
        if type(result.get(name)) is not str or not 1<=len(result[name])<=2048 or any(ord(c)<32 for c in result[name]):raise InputError('explicit SFTP node and allowed root required')
    return result


def ssh_command(settings):
    value=connection(settings)
    options=['BatchMode=yes','StrictHostKeyChecking=yes','UpdateHostKeys=no','ConnectTimeout=10',
        'ConnectionAttempts=1','ServerAliveInterval=5','ServerAliveCountMax=1','GlobalKnownHostsFile=none',
        'UserKnownHostsFile="'+value['known_hosts_file']+'"','ProxyCommand=none','ProxyJump=none',
        'ControlMaster=no','ControlPath=none','PermitLocalCommand=no','ClearAllForwardings=yes',
        'ForwardAgent=no','ForwardX11=no','Tunnel=no','PasswordAuthentication=no',
        'KbdInteractiveAuthentication=no','PreferredAuthentications=publickey','PKCS11Provider=none']
    argv=['ssh','-F','none','-T','-s','-a']
    if 'identity_file' in value:argv+=['-i',value['identity_file'],'-o','IdentitiesOnly=yes']
    for option in options:argv+=['-o',option]
    return argv+['-p',str(value['port']),value['host'],'sftp']


class Session:
    def __init__(self,argv,*,max_bytes,timeout,should_stop=None):
        if (type(argv) is not list or not argv or any(type(a) is not str or '\0' in a for a in argv)
            or type(max_bytes) is not int or not 16384<=max_bytes<=256*1024**2
            or type(timeout) not in (int,float) or not .1<=timeout<=120):raise InputError('invalid SFTP session limits')
        self.argv=argv;self.maximum=max_bytes;self.timeout=timeout;self.stop=should_stop
        self.lock=threading.Lock();self.done=threading.Event();self.replies=queue.Queue(maxsize=1)
        self.sent=self.received=self.stderr_count=self.identifier=0;self.stderr=bytearray();self.reason=None;self.closed=False;self.process=None;self.selector=None

    def metrics(self):
        return dict(protocol_bytes=self.sent+self.received+self.stderr_count,sent_bytes=self.sent,received_bytes=self.received,
            stderr_bytes=self.stderr_count,requests=self.identifier,scope='bounded SFTP/diagnostic pipe admission; pending/failed writes may be conservatively charged; encrypted TCP/SSH handshake overhead unknown')

    def _account(self,count,field):
        with self.lock:
            if self.sent+self.received+self.stderr_count+count>self.maximum:raise InputError('SFTP protocol byte budget exceeded')
            setattr(self,field,getattr(self,field)+count)

    def _abort(self,reason):
        with self.lock:
            if self.reason is None:self.reason=reason
        if self.process is not None and self.process.poll() is None:
            try:self.process.kill()
            except OSError:pass

    def _offer(self,value):
        while not self.done.is_set():
            try:self.replies.put(value,timeout=.05);return
            except queue.Full:pass

    def _read_exact(self,count):
        parts=[]
        while count:
            wanted=self._read_grant(min(count,65536),'received')
            data=self.process.stdout.read(wanted)
            with self.lock:self.received-=wanted-len(data)
            if not data:raise InputError('SFTP stream ended before a complete response')
            parts.append(data);count-=len(data)
        return b''.join(parts)

    def _read_grant(self,wanted,field):
        with self.lock:
            remaining=self.maximum-self.sent-self.received-self.stderr_count
            if remaining<=0:raise InputError('SFTP protocol byte budget exhausted before pipe read')
            count=min(wanted,remaining);setattr(self,field,getattr(self,field)+count)
            return count

    def _reader(self):
        try:
            while not self.done.is_set():
                count=struct.unpack('>I',self._read_exact(4))[0]
                if not 1<=count<=wire.MAX_PACKET:raise InputError('SFTP packet length outside supported bounds')
                if count>self.maximum-self.sent-self.received-self.stderr_count:raise InputError('SFTP response exceeds remaining protocol budget')
                self._offer(self._read_exact(count))
        except (OSError,ValueError,struct.error) as exc:
            if not self.done.is_set():self._offer(exc);self._abort('incomplete_or_invalid_response')

    def _errors(self):
        try:
            while not self.done.is_set():
                wanted=self._read_grant(4096,'stderr_count');data=self.process.stderr.read(wanted)
                with self.lock:self.stderr_count-=wanted-len(data)
                if not data:break
                if len(self.stderr)+len(data)>65536:raise InputError('SSH diagnostic byte limit')
                self.stderr.extend(data)
        except (OSError,ValueError):self._abort('ssh_diagnostic_limit')

    def _watch(self):
        while not self.done.wait(.03):
            try:reason=self.stop() if self.stop else None
            except Exception:self._abort('stop_callback_failed');return
            if reason:self._abort('cancelled' if reason is True else str(reason));return
            if time.monotonic()>=self.deadline:self._abort('timeout');return

    def _send(self,raw):
        if self.reason:raise InputError('SFTP stopped: '+self.reason)
        self._account(len(raw),'sent')
        try:
            remaining=memoryview(raw)
            while remaining:
                if self.reason:raise InputError('SFTP stopped: '+self.reason)
                count=self.process.stdin.write(remaining)
                if type(count) is not int or not 1<=count<=len(remaining):raise InputError('SSH subsystem input made no verified progress; completion unknown')
                remaining=remaining[count:]
            self.process.stdin.flush()
        except (OSError,ValueError) as exc:raise InputError('SSH subsystem input closed; completion unknown') from exc

    def _receive(self):
        if self.selector is not None:return self._receive_selected()
        while True:
            if self.reason:raise InputError('SFTP stopped: '+self.reason)
            try:raw=self.replies.get(timeout=.05);break
            except queue.Empty:continue
        if isinstance(raw,Exception):raise InputError('SFTP response incomplete: '+str(raw)) from raw
        return raw

    def _receive_selected(self):
        # POSIX pipe readiness keeps one bounded packet in this thread instead
        # of allocating two extra thread stacks/arenas under inherited RLIMIT_AS.
        received=bytearray();expected=4;header=True
        while True:
            if self.reason:raise InputError('SFTP stopped: '+self.reason)
            for key,_ in sorted(self.selector.select(.03),key=lambda event:event[0].data!='stderr_count'):
                diagnostic=key.data=='stderr_count'
                wanted=self._read_grant(4096 if diagnostic else expected-len(received),key.data)
                data=key.fileobj.read(wanted)
                with self.lock:setattr(self,key.data,getattr(self,key.data)-wanted+len(data))
                if not data:
                    if diagnostic:self.selector.unregister(key.fileobj);continue
                    raise InputError('SFTP stream ended before a complete response')
                if diagnostic:
                    if len(self.stderr)+len(data)>65536:self._abort('ssh_diagnostic_limit');raise InputError('SSH diagnostic byte limit')
                    self.stderr.extend(data);break
                received.extend(data)
                if len(received)!=expected:continue
                if not header:return bytes(received)
                expected=struct.unpack('>I',received)[0]
                if not 1<=expected<=wire.MAX_PACKET:raise InputError('SFTP packet length outside supported bounds')
                if expected>self.maximum-self.sent-self.received-self.stderr_count:raise InputError('SFTP response exceeds remaining protocol budget')
                received.clear();header=False

    def __enter__(self):
        self.deadline=time.monotonic()+self.timeout
        try:
            reason=self.stop() if self.stop else None
            if reason:
                self.reason='cancelled' if reason is True else str(reason)
                raise InputError('SFTP stopped before launch: '+self.reason)
            self.process=subprocess.Popen(self.argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                shell=False,bufsize=0,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
            if os.name=='posix':
                self.selector=selectors.DefaultSelector()
                self.selector.register(self.process.stdout,selectors.EVENT_READ,'received')
                self.selector.register(self.process.stderr,selectors.EVENT_READ,'stderr_count')
                functions=(self._watch,)
            else:functions=(self._reader,self._errors,self._watch)
            self.threads=[threading.Thread(target=fn,daemon=True) for fn in functions]
            try:
                for thread in self.threads:thread.start()
            except RuntimeError as exc:
                self._abort('local_thread_start_failed')
                raise InputError('SFTP local reader could not start; completion unknown') from exc
            self._send(wire.frame(b'\x01'+wire.u32(3)))
            raw=self._receive()
            if raw[0]!=2:raise InputError('expected SFTP version handshake')
            reader=wire.Reader(raw[1:])
            if reader.uint32()!=3:raise InputError('only SFTPv3 is supported')
            count=0
            while reader.at<len(reader.raw):
                count+=1
                if count>64:raise InputError('too many SFTP server extensions')
                reader.bytes(4096);reader.bytes(4096)
            reader.end();return self
        except BaseException:
            self.close();raise

    def close(self):
        if self.closed:return
        self.done.set()
        if self.process is not None:
            try:self.process.stdin.close()
            except (OSError,ValueError):pass
            try:self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.process.kill();self.process.wait(timeout=2)
            deadline=time.monotonic()+1
            for thread in getattr(self,'threads',[]):
                if thread.ident is not None:thread.join(max(0,deadline-time.monotonic()))
            if self.selector is not None:self.selector.close()
            self.process.stdout.close();self.process.stderr.close()
            if any(thread.is_alive() for thread in getattr(self,'threads',[])):raise InputError('SSH reader cleanup is unverified')
        self.closed=True

    def __exit__(self,*_):self.close()

    def call(self,operation,payload,expected,*,eof=False):
        self.identifier+=1
        if self.identifier>10000:raise InputError('SFTP request count budget exceeded')
        self._send(wire.request(operation,self.identifier,payload))
        raw=self._receive();reader=wire.Reader(raw[1:])
        if reader.uint32()!=self.identifier:raise InputError('SFTP response identifier mismatch')
        if raw[0]==101:
            code=reader.status();reader.end()
            if code==1 and eof:return None
            if code==0 and expected==101:return reader
            raise InputError('SFTP status '+str(code)+'; access/coverage is not established')
        if raw[0]!=expected:raise InputError('unexpected SFTP response type')
        return reader

    def lstat(self,path):
        reader=self.call(7,wire.string(path),105);value=reader.attrs();reader.end();return value

    def fstat(self,handle):
        reader=self.call(8,wire.string(handle),105);value=reader.attrs();reader.end();return value

    def realpath(self,path):
        reader=self.call(16,wire.string(path),104)
        if reader.uint32()!=1:raise InputError('ambiguous SFTP canonical path')
        value=reader.text();reader.bytes(8192);reader.attrs();reader.end();return value

    def _handle(self,operation,payload):
        reader=self.call(operation,payload,102);handle=reader.bytes(256);reader.end()
        if not handle:raise InputError('empty SFTP handle')
        return handle

    def open(self,path):return self._handle(3,wire.string(path)+wire.u32(1)+wire.u32(0))
    def opendir(self,path):return self._handle(11,wire.string(path))

    def close_handle(self,handle):self.call(4,wire.string(handle),101).end()

    def read(self,handle,offset,count):
        if type(count) is not int or not 1<=count<=32768:raise InputError('invalid SFTP read size')
        reader=self.call(5,wire.string(handle)+wire.u64(offset)+wire.u32(count),103,eof=True)
        if reader is None:return None
        data=reader.bytes(count);reader.end()
        if not data:raise InputError('empty SFTP data response without EOF')
        return data

    def readdir(self,handle):
        reader=self.call(12,wire.string(handle),104,eof=True)
        if reader is None:return None
        count=reader.uint32()
        if not 1<=count<=256:raise InputError('SFTP directory response count exceeds bounds')
        values=[]
        for _ in range(count):
            name=reader.text(512);reader.bytes(8192);values.append(dict(name=name,attributes=reader.attrs()))
        reader.end();return values
