"""Real child-pipe framing and fixed SSH invocation, without a network service."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from src.techexpert.inputs import InputError
from src.techexpert import ssh_sftp as client

PEER=r'''
import struct,sys,time
mode=sys.argv[1]
def n(v):return struct.pack('>I',v)
def s(v):return n(len(v))+v
def send(v):sys.stdout.buffer.write(n(len(v))+v);sys.stdout.buffer.flush()
def exact(count):
    value=b''
    while len(value)<count:
        part=sys.stdin.buffer.read(count-len(value))
        if not part:return None
        value+=part
    return value
if mode=='stderr':sys.stderr.buffer.write(b'x'*70000);sys.stderr.buffer.flush()
while True:
    head=exact(4)
    if not head:break
    raw=exact(struct.unpack('>I',head)[0])
    if raw[0]==1:
        if mode=='stall':time.sleep(20)
        if mode=='huge':sys.stdout.buffer.write(n(2**30));sys.stdout.buffer.flush();time.sleep(20)
        send(b'\x02'+n(4 if mode=='version' else 3));continue
    op=raw[0];identifier=struct.unpack('>I',raw[1:5])[0]+(1 if mode=='id' else 0)
    status=lambda code:b'\x65'+n(identifier)+n(code)+s(b'')+s(b'')
    attrs=n(13)+struct.pack('>Q',3)+n(0o100600)+n(10)+n(20)
    if op==7 or op==8:reply=b'\x69'+n(identifier)+attrs
    elif op==16:reply=b'\x68'+n(identifier)+n(1)+s(b'/logs')+s(b'')+n(0)
    elif op in (3,11):reply=b'\x66'+n(identifier)+s(b'handle') if mode!='deny' else status(3)
    elif op==12:reply=status(1)
    elif op==4:reply=status(0)
    elif op==5:
        at=struct.unpack('>Q',raw[-12:-4])[0];count=struct.unpack('>I',raw[-4:])[0]
        data=b'abc'[at:at+count]
        reply=b'\x67'+n(identifier)+s(data) if data else status(1)
    else:reply=status(8)
    send(reply)
'''


class SftpClientTests(unittest.TestCase):
    def settings(self,**changes):
        value=dict(host='reader@example.test',port=22,known_hosts_file='D:/keys/known_hosts',identity_file='D:/keys/id',node='reported-node',root='/logs')
        value.update(changes);return value

    def session(self,mode='ok',**kw):
        return client.Session([sys.executable,'-B','-u','-c',PEER,mode],max_bytes=65536,timeout=kw.get('timeout',2),should_stop=kw.get('should_stop'))

    def test_fixed_subsystem_has_no_config_proxy_forwarding_password_or_remote_shell(self):
        argv=client.ssh_command(self.settings())
        self.assertIn('none',argv)
        self.assertIn('StrictHostKeyChecking=yes',argv)
        self.assertIn('UpdateHostKeys=no',argv)
        self.assertIn('BatchMode=yes',argv)
        self.assertIn('ProxyCommand=none',argv)
        self.assertEqual(argv[-2:],['reader@example.test','sftp'])
        self.assertIn('-s',argv)
        self.assertNotIn('/logs',argv)
        for host in ('-ProxyCommand=x','node;whoami','a$(x)','ssh://node','a\n'):
            with self.subTest(host=host),self.assertRaises(InputError):client.ssh_command(self.settings(host=host))

    def test_real_pipes_parse_attrs_read_only_open_read_eof_and_close(self):
        with self.session() as session:
            self.assertEqual(session.realpath('/logs'),'/logs')
            self.assertEqual(session.lstat('/logs/a.log')['size'],3)
            handle=session.open('/logs/a.log')
            self.assertEqual(session.read(handle,0,2),b'ab')
            self.assertEqual(session.read(handle,2,2),b'c')
            self.assertEqual(session.read(handle,3,1),None)
            session.close_handle(handle)
            self.assertEqual(session.readdir(session.opendir('/logs')),None)
        self.assertTrue(session.closed)
        self.assertIsNone(session.reason,'Normal subsystem EOF during owned close must not become a failed transfer')
        self.assertEqual(session.process.returncode,0)
        self.assertGreater(session.metrics()['protocol_bytes'],0)

    def test_bad_version_identifier_length_and_stderr_flood_are_rejected_and_stopped(self):
        for mode in ('version','id','huge','stderr'):
            with self.subTest(mode=mode):
                session=self.session(mode)
                with self.assertRaises(InputError):
                    with session:session.lstat('/logs/a')
                self.assertTrue(session.closed)
                self.assertIsNotNone(session.process.poll())
                self.assertLessEqual(session.metrics()['protocol_bytes'],session.maximum)

    def test_permission_failure_is_typed_and_not_an_empty_directory(self):
        with self.session('deny') as session:
            with self.assertRaisesRegex(InputError,'status 3'):session.open('/logs/private')

    def test_pipe_reads_never_consume_bytes_beyond_the_shared_admitted_allowance(self):
        import io
        from types import SimpleNamespace
        session=self.session();stream=io.BytesIO(b'abcdefgh')
        session.process=SimpleNamespace(stdout=stream)
        session.sent=session.maximum-4
        with self.assertRaises(InputError):session._read_exact(8)
        self.assertEqual(stream.tell(),4)
        self.assertLessEqual(session.metrics()['protocol_bytes'],session.maximum)
        errors=io.BytesIO(b'abcdefgh');session.process=SimpleNamespace(stderr=errors,poll=lambda:0)
        session.sent=session.maximum;session.received=0
        session._errors()
        self.assertEqual(errors.tell(),0)

    def test_stalled_peer_and_cancellation_have_bounded_cleanup(self):
        for stop in (None,lambda:True):
            session=self.session('stall',timeout=.15,should_stop=stop);started=time.monotonic()
            with self.assertRaises(InputError):
                with session:pass
            self.assertLess(time.monotonic()-started,3)
            self.assertTrue(session.closed)

    def test_already_cancelled_call_never_creates_a_local_ssh_process(self):
        from unittest.mock import patch
        session=self.session(should_stop=lambda:True)
        with patch.object(client.subprocess,'Popen',side_effect=RuntimeError('SSH must not be launched')) as launch:
            with self.assertRaises(InputError):
                with session:pass
            launch.assert_not_called()
        self.assertTrue(session.closed)

    def test_actual_child_pipe_does_not_prefetch_unadmitted_stdout_or_stderr(self):
        from unittest.mock import patch
        import struct
        for channel in ('stdout','stderr'):
            script='import sys; s=sys.'+channel+'.buffer; s.write(b"z"*4096); s.flush(); s.close(); sys.stdin.buffer.read()'
            session=client.Session([sys.executable,'-B','-u','-c',script],max_bytes=16384,timeout=2)
            with patch.object(session,'_reader',return_value=None),patch.object(session,'_errors',return_value=None),patch.object(session,'_receive',return_value=b'\x02'+struct.pack('>I',3)):
                with session:
                    session.sent=session.maximum-4;session.received=0;session.stderr_count=0
                    if channel=='stdout':self.assertEqual(session._read_exact(4),b'zzzz')
                    else:client.Session._errors(session)
                    stream=getattr(session.process,channel)
                    raw=stream.detach() if hasattr(stream,'detach') else stream
                    setattr(session.process,channel,raw)
                    self.assertEqual(len(raw.read(4096)),4092,'Buffered pipe consumed bytes beyond the admitted4')

    def test_unbuffered_partial_stdin_writes_are_completed_or_fail_explicitly(self):
        from types import SimpleNamespace
        class ShortWriter:
            def __init__(self):self.data=bytearray()
            def write(self,raw):self.data.extend(raw[:2]);return min(2,len(raw))
            def flush(self):pass
        writer=ShortWriter();session=self.session();session.process=SimpleNamespace(stdin=writer)
        session._send(b'abcdefgh')
        self.assertEqual(bytes(writer.data),b'abcdefgh')
        for progress in (None,0,-1,True,20):
            with self.subTest(progress=progress):
                session=self.session()
                session.process=SimpleNamespace(stdin=SimpleNamespace(write=lambda _:progress,flush=lambda:None))
                with self.assertRaises(InputError):session._send(b'abcdefgh')

    def test_reader_start_failure_closes_its_process_and_reports_typed_incomplete_work(self):
        from unittest.mock import patch
        session=self.session()
        with patch.object(client.threading.Thread,'start',side_effect=RuntimeError('thread resources unavailable')):
            with self.assertRaises(InputError):
                with session:pass
        self.assertTrue(session.closed)
        self.assertIsNotNone(session.process.poll())

    @unittest.skipUnless(os.name=='posix','Linux program address-space limit')
    def test_real_session_fits_default_program_address_space_without_quota_expansion(self):
        code='''import os,resource,sys,threading
from src.techexpert.ssh_sftp import Session
from src.techexpert import operation_worker,operation_state as fs
resource.setrlimit(resource.RLIMIT_AS,(268435456,268435456))
done=threading.Event();ready=threading.Event()
def watchdog():
    while not done.is_set():
        fs.process_identity(os.getpid());ready.set();done.wait(.03)
def stop():fs.process_identity(os.getpid())
watch=threading.Thread(target=watchdog);watch.start();assert ready.wait(1)
try:
    with Session([sys.executable,'-B','-u','-c',sys.argv[1],'ok'],max_bytes=65536,timeout=2,should_stop=stop) as session:
        assert session.lstat('/logs/file')['size']==3
finally:done.set();watch.join()
assert session.closed and session.process.returncode==0
'''
        result=subprocess.run([sys.executable,'-B','-c',code,PEER],capture_output=True,timeout=8)
        self.assertEqual(result.returncode,0,result.stderr.decode('utf-8','replace'))


if __name__=='__main__':unittest.main()
