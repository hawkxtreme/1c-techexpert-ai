"""Fixed managed controller launch; only a freshly owned Popen/session/Job is stopped."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from .storage import ROOT


def controller_argv(folder,memory):
    return [sys.executable,'-X','utf8',str(Path(__file__).with_name('kernel_controller.py')),str(folder),str(ROOT),str(memory)]


def run(folder,*,guard,on_started,timeout,memory_bytes):
    argv=controller_argv(folder,memory_bytes)
    if os.name=='nt':
        from .windows_native import run as native_run
        return native_run(argv,cwd=folder,guard=guard,on_started=on_started,timeout=timeout,memory_bytes=memory_bytes)
    started=time.monotonic();reason=error=None;tree_finished=False
    with (folder/'stdout.bin').open('xb') as output,(folder/'stderr.bin').open('xb') as diagnostics:
        process=subprocess.Popen(argv,cwd=ROOT,stdin=subprocess.DEVNULL,stdout=output,stderr=diagnostics,start_new_session=True)
        try:
            on_started(process.pid)
            # WNOWAIT reserves the leader PID through group cleanup; poll()
            # would reap it and make the numeric group ID reusable too soon.
            while os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
                if time.monotonic()-started>=timeout:reason='timeout';break
                try:guard()
                except (OSError,ValueError) as exc:reason='guard_failed';error=str(exc)[:512];break
                time.sleep(.03)
        except KeyboardInterrupt:reason='cancelled'
        finally:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait(timeout=5)
            try:os.killpg(process.pid,0)
            except ProcessLookupError:tree_finished=True
    return dict(status='stopped' if reason else 'completed',pid=process.pid,exit_code=process.returncode,
        elapsed_seconds=time.monotonic()-started,tree_finished=tree_finished,stop_reason=reason,guard_error=error,
        resource_usage=dict(scope='controller metrics report self/terminated children; aggregate tree memory unknown'))
