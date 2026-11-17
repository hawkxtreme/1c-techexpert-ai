"""Runtime client stops are not malformed inputs; bounded private bytes survive."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]

DRIVER=r'''
import hashlib,os,sys,time
from pathlib import Path
from unittest.mock import patch
from src.techexpert import capabilities,operations,operation_state as fs,operation_worker
from src.techexpert.processes import run_bounded
root=Path(sys.argv[1]);reason=sys.argv[2];sources=root/'sources';sources.mkdir()
request=capabilities.normalize_request(dict(schema_version=1,operation_key='checked-client-stop',executor_id='worker-test',
    operation='source.snapshot',arguments=dict(path=str(sources),kind='git')))
folder=fs.private(root/'state/operations'/hashlib.sha256(request['operation_key'].encode()).hexdigest())
plan=dict(schema_version=1,request=request,state_dir=str(root/'state'),context=None,versions=operations._versions(),deadline_monotonic=time.monotonic()+60)
fs.write(folder/'plan.json',plan);fs.write(folder/'plan-receipt.json',dict(sha256=fs.digest(plan)))
fs.write(folder/'start-permit.json',dict(plan_sha256=fs.digest(plan),child=fs.process_identity(os.getpid())))
fs.private(folder/'work-state')
def stopped_client(*args,**kwargs):
    started=time.monotonic()
    if reason=='output_limit':
        code='import os,time;os.write(2,b"bounded-before-stop\\n");os.close(2);os.write(1,b"x"*100000);time.sleep(5)'
    else:code='import time;print("bounded-before-stop",flush=True);time.sleep(5)'
    return run_bounded([sys.executable,'-u','-c',code],timeout=.3 if reason=='timeout' else 3,max_bytes=128,
        should_stop=(lambda:'cancelled' if time.monotonic()-started>.3 else None) if reason=='cancelled' else None)
with patch('src.techexpert.source_code.run_bounded',side_effect=stopped_client):
    raise SystemExit(operation_worker.main(folder))
'''


class WorkerCommandStopTests(unittest.TestCase):
    def test_checked_worker_keeps_partial_client_bytes_and_distinguishes_runtime_stops(self):
        for reason in ('timeout','cancelled','output_limit'):
            with self.subTest(reason=reason),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                run=subprocess.run([sys.executable,'-X','utf8','-c',DRIVER,str(root),reason],cwd=ROOT,capture_output=True,timeout=15)
                self.assertEqual(run.returncode,0,run.stderr.decode('utf-8','replace'))
                folder=root/'state/operations'/hashlib.sha256(b'checked-client-stop').hexdigest()
                result=json.loads((folder/'worker-result.json').read_text(encoding='utf-8'))
                self.assertEqual(result['status'],'cancelled' if reason=='cancelled' else 'failed')
                self.assertEqual(result['stop_reason'],reason)
                self.assertIsNone(result['data']);self.assertEqual(result['targets'],[])
                stop=json.loads((folder/'command-stop.json').read_text(encoding='utf-8'))
                self.assertEqual(result['metrics']['command_stop'],stop)
                self.assertNotIn('bounded-before-stop',json.dumps(result))
                self.assertEqual(stop['reason'],reason);self.assertTrue(stop['process_started'])
                self.assertIsNotNone(stop['returncode'])
                retained=b''
                for part in stop['files']:
                    raw=(folder/part['path']).read_bytes();retained+=raw
                    self.assertEqual(len(raw),part['bytes'])
                    self.assertEqual(hashlib.sha256(raw).hexdigest(),part['sha256'])
                self.assertIn(b'bounded-before-stop',retained)
                from src.techexpert import operation_state as fs
                receipt=fs.read(folder/'worker-receipt.json')
                self.assertEqual(receipt['sha256'],fs.digest(result))
