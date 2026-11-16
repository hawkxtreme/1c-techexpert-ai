"""One owned bounded worker tree. Never terminate a process found by a stale PID."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from .inputs import InputError
from .storage import ROOT

def run(folder,*,guard,on_started,timeout):
    argv=[sys.executable,'-X','utf8','-m','src.techexpert.operation_worker',str(folder)]
    if os.name=='nt':
        from .windows_native import run as native_run
        # The native runner's cwd also owns its bounded stdout/stderr files.
        argv=[sys.executable,'-X','utf8',str(Path(__file__).with_name('operation_worker.py')),str(folder),str(ROOT)]
        return native_run(argv,cwd=folder,guard=guard,on_started=on_started,timeout=timeout,memory_bytes=1024**3)
    started=time.monotonic();reason=None;error=None;tree_finished=False
    with (folder/'stdout.bin').open('xb') as output,(folder/'stderr.bin').open('xb') as diagnostics:
        process=subprocess.Popen(argv,cwd=ROOT,stdin=subprocess.DEVNULL,stdout=output,stderr=diagnostics,start_new_session=True)
        try:
            on_started(process.pid)
            # Keep the leader unreaped until its owned group has been stopped.
            while os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
                if time.monotonic()-started>=timeout:reason='timeout';break
                try:guard()
                except (OSError,ValueError) as exc:reason='guard_failed';error=str(exc)[:512];break
                time.sleep(.05)
        finally:
            # This new session belongs only to the Popen we just created. No PID discovery.
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait(timeout=5)
            try:os.killpg(process.pid,0)
            except ProcessLookupError:tree_finished=True
    return dict(status='stopped' if reason else 'completed',pid=process.pid,exit_code=process.returncode,
        elapsed_seconds=time.monotonic()-started,tree_finished=tree_finished,stop_reason=reason,guard_error=error,
        resource_usage=dict(scope='worker reports self and terminated children; concurrent process-group peak memory unknown'))
