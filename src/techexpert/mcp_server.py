"""Local MCP stdio transport. Finite tools only; no listener or model provider."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
import queue
import sys
import threading

from . import kernel,mcp_tools as tools
from .inputs import InputError,json_value

MAX_LINE=256*1024
MAX_IN_FLIGHT=10
INSTRUCTIONS=('Use the current harness to interpret the selected technical incident. Tools compute observations, not an independent diagnosis. '
    'Select explicit source paths; retain evidence, unknowns and adapter coverage limits. '
    'Use stable operation_key values; after uncertainty inspect/replay, never change keys just to retry. '
    'Collection requires an already authorized plan. Cancel request is not verified stop. '
    'Program tools use a bounded capability language with explicit scope and resource limits. '
    'No server licensing, arbitrary Python/SQL, source changes or publication is provided here.')


class RPCError(ValueError):
    def __init__(self,code,message,data=None):self.code=code;self.message=message;self.data=data


def _compact(value):return json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')


def _identifier(value):
    return type(value) is int and abs(value)<=2**53-1 or type(value) is str and 1<=len(value)<=128 and all(ord(c)>=32 for c in value)


def _bounded(value,depth=0,counter=None):
    counter=[0] if counter is None else counter;counter[0]+=1
    if depth>32 or counter[0]>16384:raise InputError('MCP message exceeds structural limits')
    if isinstance(value,dict):
        for k,v in value.items():_bounded(k,depth+1,counter);_bounded(v,depth+1,counter)
    elif isinstance(value,list):
        for v in value:_bounded(v,depth+1,counter)
    elif isinstance(value,str):
        if len(value)>65536:raise InputError('MCP string exceeds limits')
        value.encode('utf-8')  # Reject escaped lone surrogates before dispatch or framing.


class _FramedOutput:
    """Hold the RPC prefix until kernel.emit has verified the response bytes."""
    def __init__(self,write,identifier):self.write_bytes=write;self.identifier=identifier;self.started=False
    def write(self,text):
        if not self.started:
            self.write_bytes(b'{"jsonrpc":"2.0","id":'+_compact(self.identifier)+b',"result":');self.started=True
        self.write_bytes(text.encode('utf-8'))
    def flush(self):pass
    def finish(self):self.write_bytes(b'}\n')


class Server:
    def __init__(self,state,input_stream,output_fd,*,profile='full'):
        self.state=state;self.input=input_stream;self.output_fd=output_fd
        self.profile=profile;self.tool_names=tools.selected_operations(profile).keys() | tools.control_names(profile)
        self.closed=threading.Event();self.lock=threading.Lock();self.pending={}
        self.outgoing=queue.Queue(maxsize=16);self.pool=ThreadPoolExecutor(max_workers=2,thread_name_prefix='mcp-tool')
        self.incoming=queue.Queue(maxsize=2)
        self.legacy_initialized=False;self.legacy_ready=False

    def stop(self):
        self.closed.set()
        with self.lock:
            for entry in self.pending.values():entry['cancel'].set()

    def _write(self,data):
        view=memoryview(data)
        while view:
            count=os.write(self.output_fd,view)
            if count<=0:raise BrokenPipeError('MCP output closed')
            view=view[count:]

    def send(self,value,entry=None):
        if self.closed.is_set():return
        try:self.outgoing.put_nowait((value,entry))
        except queue.Full:self.stop()

    def _release(self,entry):
        if entry:
            with self.lock:
                if self.pending.get(entry['id']) is entry:self.pending.pop(entry['id'])

    def writer(self):
        while not self.closed.is_set():
            try:value,entry=self.outgoing.get(timeout=.1)
            except queue.Empty:continue
            try:
                if entry and entry['cancel'].is_set():continue
                if isinstance(value,tuple):
                    call,identifier=value;framed=_FramedOutput(self._write,identifier)
                    try:kernel.emit(call,framed)
                    except (OSError,ValueError,KeyError,TypeError,UnicodeError):
                        if framed.started:raise BrokenPipeError('Invalid partial MCP result')
                        self._write(_compact(dict(jsonrpc='2.0',id=identifier,error=dict(code=-32603,message='Retained result verification failed. Inspect the saved run; no work was repeated.')))+b'\n')
                    else:framed.finish()
                else:self._write(_compact(value)+b'\n')
            except (OSError,ValueError,KeyError,TypeError):self.stop()
            finally:self._release(entry)

    def error(self,identifier,code,message,data=None):
        error=dict(code=code,message=message)
        if data is not None:error['data']=data
        value=dict(jsonrpc='2.0',error=error)
        if _identifier(identifier):value['id']=identifier
        self.send(value)

    def complete(self,identifier,value,version,*,cache=False):
        if version==tools.MODERN:value=dict(value,resultType='complete',_meta={'io.modelcontextprotocol/serverInfo':dict(tools.SERVER)})
        if cache and version==tools.MODERN:value.update(cacheScope='public',ttlMs=0)
        self.send(dict(jsonrpc='2.0',id=identifier,result=value))

    def version(self,method,params):
        meta=params.get('_meta',{})
        if not isinstance(meta,dict):raise RPCError(-32602,'_meta must be an object.')
        version=meta.get('io.modelcontextprotocol/protocolVersion')
        if 'io.modelcontextprotocol/protocolVersion' in meta:
            if not isinstance(version,str) or len(version)>32:raise RPCError(-32602,'Protocol version must be a bounded string.')
            if version!=tools.MODERN:raise RPCError(-32022,'Unsupported per-request protocol version.',dict(supported=[tools.MODERN],requested=version))
            if not isinstance(meta.get('io.modelcontextprotocol/clientCapabilities'),dict):raise RPCError(-32602,'Every modern request requires clientCapabilities in _meta.')
            return tools.MODERN
        if method=='initialize':return tools.LEGACY
        if method!='server/discover' and self.legacy_initialized and self.legacy_ready:return tools.LEGACY
        raise RPCError(-32602,'Supply per-request protocolVersion/clientCapabilities or complete the supported legacy initialize handshake.')

    def launch(self,identifier,params,version):
        if set(params)-{'name','arguments','_meta'} or not isinstance(params.get('name'),str):raise RPCError(-32602,'Expected tools/call name and arguments.')
        name=params['name'];arguments=params.get('arguments',{})
        if name not in self.tool_names:raise RPCError(-32602,'Unknown tool; inspect tools/list.')
        try:action,arguments,request=tools.prepare(name,arguments,self.profile)
        except (ValueError,TypeError,KeyError):
            self.send(dict(jsonrpc='2.0',id=identifier,result=tools.small_error('Invalid tool arguments; inspect this tool inputSchema and use bounded values.',version)));return
        with self.lock:
            if len(self.pending)>=MAX_IN_FLIGHT:raise RPCError(-32603,'Local MCP capacity reached (2 running, 8 pending). Retry after a result; keep the same operation key.')
            entry=dict(id=identifier,cancel=threading.Event());self.pending[identifier]=entry
        def run():
            if entry['cancel'].is_set():self._release(entry);return
            try:
                call=kernel.invoke(self.state,action,arguments,wire_version=version,request_document=request,cancel_event=entry['cancel'])
                value=(call,identifier)
            except (OSError,ValueError,KeyError,TypeError,RecursionError) as exc:
                if action == 'context-read' and isinstance(exc, PermissionError):
                    from .context_disclosure import state_access_denied
                    failure = state_access_denied()
                else:
                    failure = dict(status='failed', message='Local invocation could not complete. Inspect retained operation state before retrying the same key.')
                value = dict(jsonrpc='2.0', id=identifier, result=tools.result(failure,version))
            if entry['cancel'].is_set() or self.closed.is_set():self._release(entry)
            else:self.send(value,entry)
        self.pool.submit(run)

    def handle(self,message):
        identifier=message.get('id') if isinstance(message,dict) else None
        if (not isinstance(message,dict) or set(message)-{'jsonrpc','id','method','params'} or message.get('jsonrpc')!='2.0'
            or not isinstance(message.get('method'),str) or not 1<=len(message['method'])<=128
            or 'id' in message and not _identifier(identifier)):
            self.error(identifier,-32600,'Invalid JSON-RPC request.');return
        method=message['method'];params=message.get('params',{})
        if identifier is None:
            if method=='notifications/initialized' and self.legacy_initialized:self.legacy_ready=True
            elif method=='notifications/cancelled' and isinstance(params,dict) and _identifier(params.get('requestId')):
                with self.lock:
                    entry=self.pending.get(params['requestId'])
                    if entry:entry['cancel'].set()
            return
        try:
            if not isinstance(params,dict):raise RPCError(-32602,'Request params must be an object.')
            with self.lock:
                if identifier in self.pending:raise RPCError(-32600,'Request ID is already in flight.')
            version=self.version(method,params)
            if method=='initialize':
                if version!=tools.LEGACY or self.legacy_initialized:raise RPCError(-32600,'Unexpected initialize request.')
                if (not isinstance(params.get('protocolVersion'),str) or not isinstance(params.get('capabilities'),dict)
                    or not isinstance(params.get('clientInfo'),dict)):raise RPCError(-32602,'Invalid initialize params.')
                self.legacy_initialized=True
                self.complete(identifier,dict(protocolVersion=tools.LEGACY,capabilities=dict(tools=dict(listChanged=False)),serverInfo=tools.SERVER,instructions=INSTRUCTIONS),version)
            elif method=='server/discover':
                if set(params)-{'_meta'}:raise RPCError(-32602,'Discovery accepts only request metadata.')
                self.complete(identifier,dict(supportedVersions=[tools.MODERN],capabilities=dict(tools=dict(listChanged=False)),instructions=INSTRUCTIONS),version,cache=True)
            elif method=='ping':self.complete(identifier,{},version)
            elif method=='tools/list':
                if set(params)-{'_meta'}:raise RPCError(-32602,'This finite catalogue has no continuation cursor.')
                self.complete(identifier,dict(tools=tools.tools(self.profile)),version,cache=True)
            elif method=='tools/call':self.launch(identifier,params,version)
            else:raise RPCError(-32601,'Method is not supported; only discovery, tools and ping are provided.')
        except RPCError as exc:self.error(identifier,exc.code,exc.message,exc.data)

    def run(self):
        def reader():
            # Raw fd reads do not hold a Python buffered-stream lock during
            # shutdown. A blocked client cannot prevent the main loop exiting.
            while not self.closed.is_set():
                try:block=os.read(self.input.fileno(),65536)
                except OSError:block=b''
                while not self.closed.is_set():
                    try:self.incoming.put(block,timeout=.1);break
                    except queue.Full:pass
                if not block:return
        threading.Thread(target=reader,daemon=True,name='mcp-reader').start()
        threading.Thread(target=self.writer,daemon=True,name='mcp-writer').start()
        pending=b'';discarding=False
        try:
            while not self.closed.is_set():
                try:block=self.incoming.get(timeout=.1)
                except queue.Empty:continue
                if not block:break
                for part in block.splitlines(keepends=True):
                    # Only LF terminates a frame; other Unicode/ASCII line
                    # separators remain JSON bytes and are parsed normally.
                    ends=part.endswith(b'\n')
                    if not discarding:
                        pending+=part
                        if len(pending)>MAX_LINE:
                            pending=b'';discarding=True;self.error(None,-32700,'MCP message exceeds 256 KiB.')
                    if not ends:continue
                    if not discarding:
                        try:
                            message=json_value(pending.decode('utf-8'),reject_duplicates=True);_bounded(message)
                        except (ValueError,UnicodeError,RecursionError):self.error(None,-32700,'Invalid bounded UTF-8 JSON message.')
                        else:self.handle(message)
                    pending=b'';discarding=False
        finally:
            self.stop();self.pool.shutdown(wait=True,cancel_futures=False)
        return 0


def serve(state,*,profile='full'):
    try:return Server(state,sys.stdin.buffer,sys.stdout.fileno(),profile=profile).run()
    except (OSError,ValueError,KeyError,TypeError,RecursionError):
        print('MCP transport stopped; inspect retained operation state before retrying.',file=sys.stderr);return 2
