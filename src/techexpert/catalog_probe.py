"""Bounded loopback-only catalog used by the isolated SC-01 experiment."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import socket
import threading
import time
import uuid
from datetime import datetime, timezone

from .storage import write_json

CATALOG = {f'SKU{i:03}':100+5*i for i in range(10)}
REVISION = 'sc01-catalog-v1'


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


def identifier(value):
    if not isinstance(value,str) or not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',value):
        raise ValueError('UUID required')
    parsed=uuid.UUID(value)
    if not parsed.int:
        raise ValueError('nonzero UUID required')
    return str(parsed)


class _Server(HTTPServer):
    allow_reuse_address=False

    def get_request(self):
        sock,address=super().get_request()
        # Short idle timeout also bounds Windows reads after a concurrent shutdown.
        sock.settimeout(0.2)
        with self.probe.active_lock:
            self.probe.requests+=1
            self.probe.active_socket=sock
            self.probe.request_deadline=time.monotonic()+2
        return sock,address

    def shutdown_request(self, request):
        try:
            super().shutdown_request(request)
        finally:
            with self.probe.active_lock:
                if self.probe.active_socket is request:
                    self.probe.active_socket=None


class CatalogProbe:
    def __init__(self, output_dir, *, delay_ms=40, max_requests=3000, ttl_seconds=300):
        if type(delay_ms) is not int or not 0<=delay_ms<=100:
            raise ValueError('delay_ms must be an integer between 0 and 100')
        if type(max_requests) is not int or not 1<=max_requests<=5000:
            raise ValueError('max_requests must be an integer between 1 and 5000')
        if type(ttl_seconds) not in (int,float) or not 0<ttl_seconds<=300:
            raise ValueError('ttl_seconds must be positive and at most 300')
        self.output=Path(output_dir).resolve()
        if not self.output.is_dir() or any(self.output.iterdir()):
            raise ValueError('output directory must already exist and be empty')
        self.delay_ms=delay_ms
        self.max_requests=max_requests
        self.ttl_seconds=ttl_seconds
        self.instance=str(uuid.uuid4())
        self.stopping=threading.Event()
        self.finished=threading.Event()
        self.active_lock=threading.Lock()
        self.active_socket=None
        self.request_deadline=0
        self.stop_reason='stopped'
        self.requests=0
        self.rejected=0
        self.runs={}
        self.seen=set()
        self.server=_Server(('127.0.0.1',0),_Handler)
        self.server.probe=self
        self.server.timeout=0.2
        self.port=self.server.server_port

    def stop(self):
        self.stopping.set()
        self.interrupt_connection()

    def interrupt_connection(self):
        with self.active_lock:
            if self.active_socket is not None:
                try:self.active_socket.shutdown(socket.SHUT_RDWR)
                except OSError:pass

    def enforce_deadlines(self, deadline):
        while not self.finished.wait(0.02):
            if time.monotonic()>=deadline:
                self.stop_reason='ttl'
                self.stop()
            elif self.stopping.is_set() or (self.output/'stop.request').exists():
                self.stop()
            else:
                with self.active_lock:
                    if self.active_socket is not None and time.monotonic()>=self.request_deadline:
                        try:self.active_socket.shutdown(socket.SHUT_RDWR)
                        except OSError:pass

    def serve(self):
        deadline=time.monotonic()+self.ttl_seconds
        reason='stopped'
        watchdog=threading.Thread(target=self.enforce_deadlines,args=(deadline,))
        watchdog.start()
        ready=dict(schema=1,service_instance=self.instance,host='127.0.0.1',port=self.port,
                   catalog_revision=REVISION,delay_ms=self.delay_ms,ttl_seconds=self.ttl_seconds,
                   max_requests=self.max_requests,pid=__import__('os').getpid())
        try:
            write_json(self.output/'ready.json',ready)
            while not self.stopping.is_set() and not (self.output/'stop.request').exists():
                if time.monotonic()>=deadline:
                    reason='ttl';break
                if self.requests>=self.max_requests:
                    reason='request_limit';break
                if sum(p.stat().st_size for p in self.output.glob('*.json'))>16*1024*1024:
                    reason='byte_limit';break
                self.server.handle_request()
        finally:
            self.finished.set()
            self.interrupt_connection()
            watchdog.join()
            self.server.server_close()
            if self.stop_reason=='ttl':reason='ttl'
            write_json(self.output/'service.json',dict(ready,finished_utc=stamp(),stop_reason=reason,
                                                      total_requests=self.requests,rejected_requests=self.rejected))


class _Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.0'
    server_version='SC01Lab/1'

    def log_message(self, *args):
        pass

    def handle(self):
        try:super().handle()
        except OSError:
            if not getattr(self,'rejection_counted',False):
                self.server.probe.rejected+=1
                self.rejection_counted=True

    def send_error(self, code, message=None, explain=None):
        if not getattr(self,'rejection_counted',False):
            self.server.probe.rejected+=1
            self.rejection_counted=True
        try:super().send_error(code,message,explain)
        except OSError:pass

    def do_GET(self):
        probe=self.server.probe
        try:
            match=re.fullmatch(r'/catalog/(SKU[0-9]{3})',self.path)
            if not match or match[1] not in CATALOG or self.headers.get('Content-Length','0')!='0':
                raise ValueError('unsupported request')
            sku=match[1]
            values=[self.headers.get_all('X-SC01-'+name,[]) for name in ('Job','Nonce','Request','Batch')]
            if any(len(v)!=1 for v in values):
                raise ValueError('one identity header of each kind required')
            job,nonce,request,batch=(identifier(v[0]) for v in values)
        except ValueError:
            self.send_error(400,'Invalid controlled probe request')
            return
        run=probe.runs.get(job)
        if request in probe.seen or (run and (run['nonce'],run['batch_id'])!=(nonce,batch)):
            self.send_error(409,'Duplicate request or conflicting run identity')
            return
        if run is None:
            run=dict(schema=1,origin='controlled_loopback_http_service',service_instance=probe.instance,
                     host='127.0.0.1',port=probe.port,delay_ms=probe.delay_ms,catalog_revision=REVISION,
                     catalog=CATALOG.copy(),job_uuid=job,nonce=nonce,batch_id=batch,requests=[])
            probe.runs[job]=run
        probe.seen.add(request)
        start_ns=time.monotonic_ns()
        started=stamp()
        response=json.dumps(dict(sku=sku,price=CATALOG[sku],catalog_revision=REVISION,request_id=request),
                            sort_keys=True,separators=(',',':')).encode('utf-8')
        completed=False
        status=200
        try:
            if probe.stopping.wait(probe.delay_ms/1000):
                status=503
                self.send_error(status,'Probe stopped')
            else:
                self.send_response(status)
                self.send_header('Content-Type','application/json; charset=utf-8')
                self.send_header('Content-Length',str(len(response)))
                self.send_header('Connection','close')
                self.end_headers()
                self.wfile.write(response)
                self.wfile.flush()
                completed=True
        except (OSError,TimeoutError):
            completed=False
        finally:
            end_ns=time.monotonic_ns()
            run['requests'].append(dict(request_id=request,job_uuid=job,nonce=nonce,batch_id=batch,
                sku=sku,price=CATALOG[sku],catalog_revision=REVISION,status=status,completed=completed,
                started_utc=started,finished_utc=stamp(),started_monotonic_ns=start_ns,finished_monotonic_ns=end_ns,
                elapsed_us=(end_ns-start_ns)//1000,response_sha256=hashlib.sha256(response).hexdigest()))
            write_json(probe.output/(job+'.json'),run)

    def do_POST(self):
        self.send_error(405,'Only controlled catalog GET is supported')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',required=True,type=Path)
    parser.add_argument('--delay-ms',type=int,default=40)
    parser.add_argument('--max-requests',type=int,default=3000)
    parser.add_argument('--ttl',type=float,default=300)
    args=parser.parse_args()
    probe=CatalogProbe(args.output_dir,delay_ms=args.delay_ms,max_requests=args.max_requests,ttl_seconds=args.ttl)
    probe.serve()


if __name__=='__main__':
    main()
