"""Bounded subprocess capture without shell evaluation or unbounded pipe buffers."""
import os
import subprocess
import threading
import time

from .inputs import InputError


def run_bounded(argv,*,timeout=20,max_bytes=2*1024*1024,input_data=None,env=None):
    if not isinstance(argv,list) or not argv or any(not isinstance(x,str) or '\0' in x for x in argv):
        raise InputError('explicit command arguments required')
    if not 0<timeout<=3600 or not 0<max_bytes<=64*1024*1024:raise InputError('invalid command budget')
    flags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0
    process=subprocess.Popen(argv,stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,env=env,creationflags=flags)
    output=[bytearray(),bytearray()];overflow=threading.Event();failures=[]
    def read(stream,slot):
        try:
            while chunk:=stream.read(65536):
                if len(output[slot])+len(chunk)>max_bytes:
                    overflow.set();break
                output[slot].extend(chunk)
        except OSError as error:failures.append(error)
        finally:stream.close()
    workers=[threading.Thread(target=read,args=(stream,i),daemon=True) for i,stream in enumerate((process.stdout,process.stderr))]
    for worker in workers:worker.start()
    def send():
        try:process.stdin.write(input_data);process.stdin.close()
        except (BrokenPipeError,OSError):pass
    writer=None
    if input_data is not None:
        if not isinstance(input_data,bytes) or len(input_data)>16*1024*1024:
            process.kill();process.wait();raise InputError('command input exceeds budget')
        writer=threading.Thread(target=send,daemon=True);writer.start()
    deadline=time.monotonic()+timeout;reason=None
    try:
        while process.poll() is None:
            if overflow.is_set():reason='output_limit';break
            if time.monotonic()>=deadline:reason='timeout';break
            time.sleep(.02)
    finally:
        if process.poll() is None:process.kill()
        process.wait(timeout=5)
        for worker in workers:worker.join(5)
        if writer:writer.join(5)
    if overflow.is_set():reason='output_limit'
    if any(w.is_alive() for w in workers) or failures:raise InputError('command output could not be captured completely')
    if reason:raise InputError('command stopped: '+reason)
    return process.returncode,bytes(output[0]),bytes(output[1])
