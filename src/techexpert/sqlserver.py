"""Bounded sqlcmd observations. No arbitrary SQL, setup or cause inference."""
from datetime import datetime,timezone
import json
import math
import os
import re

from .artifacts import save_artifact
from .inputs import InputError,json_value
from .processes import run_bounded,CommandStopped
from .sqlserver_queries import OPERATIONS,PROFILE,normalize_window,script

MAX_WIRE=4*1024**2
ROW_LIMITS={'capabilities':0,'requests':200,'waits':200,'locks':200,'query_store':100}


class ClientUnavailable(InputError):
    def __init__(self,reason):
        self.reason=reason
        super().__init__(reason)


def _scalar(value):
    if type(value) is float:return math.isfinite(value)
    if type(value) is int:return -(2**63)<=value<2**63
    if type(value) is str:
        value.encode('utf-8')  # Reject unpaired surrogate escapes before saving evidence.
        return True
    return value is None or type(value) is bool


def _flat_row(value):
    return type(value) is dict and all(_scalar(key) and _scalar(item) for key,item in value.items())


def decode_packet(raw,operation):
    if operation not in OPERATIONS:raise InputError('unsupported SQLServer operation')
    if type(raw) is not bytes or len(raw)>MAX_WIRE:raise InputError('SQLServer wire exceeds budget')
    try:
        lines=[line.strip() for line in raw.decode('ascii').splitlines() if line.strip()]
        if len(lines)<3 or lines[0]!='TECHEXPERT_SQLSERVER_V1' or lines[-1]!='TECHEXPERT_END':raise ValueError()
        hextext=''.join(lines[1:-1])
        if len(hextext)>2*1024**2 or not re.fullmatch('[0-9A-Fa-f]+',hextext) or len(hextext)%4:raise ValueError()
        response=json_value(bytes.fromhex(hextext).decode('utf-16-le'),reject_duplicates=True)
        if (type(response) is not dict or set(response)!={'profile','operation','metadata','rows'}
            or response['profile']!=PROFILE or response['operation']!=operation):raise ValueError()
        meta=response['metadata']
        rows=response['rows']
        if (type(meta) is not dict or type(meta.get('product_major_version')) is not int or meta['product_major_version']!=16
            or type(meta.get('database')) is not str or not meta['database']
            or type(meta.get('database_id')) is not int or meta['database_id']<=0
            or type(meta.get('captured_at_utc')) is not str or not meta['captured_at_utc'].endswith('Z')):raise ValueError()
        options=meta.get('query_store_options')
        if options is not None and not _flat_row(options):raise ValueError()
        if not _flat_row({key:value for key,value in meta.items() if key!='query_store_options'}):raise ValueError()
        if type(rows) is not list or len(rows)>ROW_LIMITS[operation] or not all(_flat_row(row) for row in rows):raise ValueError()
        return response
    except (ValueError,UnicodeError,RecursionError):raise InputError('invalid or unsupported SQLServer response') from None


class SqlcmdClient:
    def __init__(self,*,database,host,port=1433,user=None,auth='integrated',executable='sqlcmd',docker_container=None,
                 client_variant='auto',trust_server_certificate=False):
        for value in (database,user):
            if value is not None and (type(value) is not str or not re.fullmatch(r'[\w][\w .-]{0,127}',value)):
                raise InputError('database and login must be plain names, not connection strings')
        if type(database) is not str or not database:raise InputError('explicit database required')
        if type(host) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}',host):raise InputError('invalid explicit SQLServer host')
        if type(port) is not int or not 1<=port<=65535:raise InputError('invalid SQLServer port')
        if auth not in ('integrated','sql') or (auth=='sql' and not user) or (auth=='integrated' and user is not None):raise InputError('unsupported SQLServer credential profile')
        if client_variant not in ('auto','go','odbc18') or type(trust_server_certificate) is not bool:raise InputError('unsupported SQLServer client profile')
        if type(executable) is not str or not 1<=len(executable)<=1024 or '\0' in executable or executable.startswith('-'):raise InputError('invalid sqlcmd executable')
        if docker_container is not None and (type(docker_container) is not str or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',docker_container)):raise InputError('invalid Docker container')
        if docker_container and (executable!='sqlcmd' or client_variant=='go'):
            raise InputError('Docker SQLServer profile uses the fixed ODBC18 executable')
        self.scope=dict(database=database,host=host,port=port,user=user,auth=auth,transport='docker_exec' if docker_container else 'local_process',
            docker_container=docker_container,client_executable='/opt/mssql-tools18/bin/sqlcmd' if docker_container else executable,
            client_variant=client_variant,client_version=None,trust_server_certificate=trust_server_certificate)
        self.requested_variant=client_variant

    def _prefix(self,credential=False):
        if not self.scope['docker_container']:return [self.scope['client_executable']]
        return ['docker','exec','-i','--env','SQLCMDPASSWORD' if credential else 'SQLCMDPASSWORD=',
            '--env','MSSQL_SA_PASSWORD=','--env','SQLCMDINI=','--env','OSQLPASSWORD=',
            self.scope['docker_container'],'timeout','--kill-after=2','9',self.scope['client_executable']]

    def execute(self,operation,*,window=None,should_stop=None):
        sql=script(operation,window=window)
        environment={k:v for k,v in os.environ.items() if not k.upper().startswith(('SQLCMD','OSQL'))}
        secret=os.environ.get('SQLCMDPASSWORD') or ''
        if self.scope['auth']=='sql' and (not secret or len(secret)>4096 or '\0' in secret):raise ClientUnavailable('credential_profile_unavailable')
        code,out,err=run_bounded(self._prefix()+['-?'],env=environment,timeout=5,max_bytes=65536,should_stop=should_stop)
        banner=(out+b'\n'+err).decode('utf-8','replace')
        go=re.search(r'Version:\s*v?(1\.10\.\d+)\b',banner)
        odbc=re.search(r'Version\s+(18\.\d+(?:\.\d+){1,2})\b',banner)
        variant='go' if go else 'odbc18' if odbc else None
        if code or variant is None or self.requested_variant not in ('auto',variant):raise ClientUnavailable('unsupported_client_profile')
        self.scope.update(client_variant=variant,client_version=(go or odbc).group(1))
        environment=dict(environment)
        if self.scope['auth']=='sql':environment['SQLCMDPASSWORD']=secret
        options=['-S','tcp:'+self.scope['host']+','+str(self.scope['port']),'-d',self.scope['database'],
            *(['-U',self.scope['user']] if self.scope['auth']=='sql' else ['-E']),
            '-N',*(['true'] if variant=='go' else []),*(['-C'] if self.scope['trust_server_certificate'] else []),
            *(['-X1'] if variant=='odbc18' else []),'-x','-b','-r','1','-h','-1','-W','-w','65535','-l','5','-t','5','-Q',sql]
        argv=self._prefix(self.scope['auth']=='sql')+options
        if sum(len(a)+3 for a in argv)>24000:raise InputError('SQLServer command exceeds argument budget')
        return run_bounded(argv,timeout=13,max_bytes=MAX_WIRE,env=environment,should_stop=should_stop)


def observe(state_dir,client,operation,*,window=None,should_stop=None):
    script(operation,window=window)
    selected=normalize_window(window) if window is not None else None
    started=datetime.now(timezone.utc).isoformat()
    secret=os.environ.get('SQLCMDPASSWORD') or ''
    variants=sorted({secret,*(json.dumps(secret,ensure_ascii=ascii_only)[1:-1] for ascii_only in (False,True))},key=len,reverse=True) if secret else ()
    redacted=False

    def clean(value, *, private_keys=False):
        nonlocal redacted
        if not variants:return value
        if isinstance(value,str):
            for variant in variants:
                if variant in value:
                    redacted=True
                    value=value.replace(variant,'[redacted operator credential]')
        if isinstance(value,list):return [clean(item,private_keys=private_keys) for item in value]
        if isinstance(value,dict):
            if private_keys and any(variant in key for key in value for variant in variants):
                redacted=True
                raise InputError('client field names overlap an operator credential')
            return {key:clean(item,private_keys=private_keys) for key,item in value.items()}
        return value

    code=1;data=b'';error=b'';reason=None;response=None;stopped=None
    try:
        code,data,error=client.execute(operation,window=selected,should_stop=should_stop)
        if not code:
            response=decode_packet(data,operation)
            if response['metadata']['database']!=client.scope['database']:raise InputError('SQLServer database differs from requested database')
            # Keep the fixed envelope separate from untrusted observation fields.
            response=dict(response,metadata=clean(response['metadata'],private_keys=True),
                          rows=clean(response['rows'],private_keys=True))
            # Retain decoded normalized evidence, never opaque original HEX.
            data=json.dumps(response,ensure_ascii=False,allow_nan=False).encode('utf-8')
    except ClientUnavailable as exc:reason=exc.reason
    except CommandStopped as exc:
        code=1;data=exc.stdout;error=exc.stderr;stopped=exc.reason;reason='command_'+exc.reason
    except (OSError,ValueError,RecursionError):
        code=1;response=None;reason='invalid_or_unsupported_response_or_invocation'
    if code:
        # Incomplete HEX/escaped diagnostics cannot be reliably sanitized by
        # substring replacement. Discard both streams when a secret is known.
        if secret and (data or error):data=b'';error=b'Client output withheld because an operator credential was in use.';redacted=True
    elif error and secret:error=b'Client diagnostics withheld because an operator credential was in use.';redacted=True
    sources=[('sqlserver-response.json' if not code else 'sqlserver-response.txt',data)]
    if error:sources.append(('sqlserver-diagnostics.txt',error))
    scope=clean(dict(client.scope))
    metadata=response['metadata'] if not code else None
    permission='database' if operation=='query_store' else 'server'
    visibility=permission+'_performance_permission_reported' if metadata and metadata.get('view_'+permission+'_performance_state') is True else 'permission_limited_or_unknown'
    result=dict(operation=operation,connection_scope=scope,status='cancelled' if stopped=='cancelled' else 'unavailable' if code else 'observed',
        rows=response['rows'] if not code else None,database=metadata['database'] if metadata else None,metadata=metadata,
        started_at=started,finished_at=datetime.now(timezone.utc).isoformat(),window=selected,
        temporal_scope='query_store_interval_aggregates' if operation=='query_store' else 'current_snapshot_only',
        historical_window_coverage=None,visibility=visibility,
        cause=None,requires_ai_interpretation=True,operator_credential_redacted=redacted,
        credential_filter_scope='Known session SQLCMDPASSWORD only; failed/partial streams withheld when it is in use. Not anonymity certification.',
        limits=dict(query_timeout_seconds=5,login_timeout_seconds=5,lock_timeout_ms=500,max_wire_bytes=MAX_WIRE,max_rows=ROW_LIMITS[operation]),
        units=dict(wait_time_ms='milliseconds',wait_duration_ms='milliseconds',cpu_time_ms='milliseconds',total_elapsed_time_ms='milliseconds',avg_duration_us='microseconds',min_duration_us='microseconds',max_duration_us='microseconds',avg_cpu_time_us='microseconds'),
        limitations=['Returned server and login names are reported SQL metadata, not proof of physical host or infobase ownership.',
            'Current DMVs do not reconstruct a past incident; invisible rows/NULLs/denied reads remain unknown.',
            'A waiting task qualifies by session with an active request in the selected database; its request and database ownership are unresolved.',
            'DMV datetime values are server-local; captured UTC/current offset does not prove historical clock alignment.',
            'Query Store selects complete overlapping intervals with count-weighted aggregates, not exact-window or individual executions.',
            'First/last Query Store execution times are end times; current OFF/empty/retention settings do not prove historical absence.',
            'Each operation is a separate observation, not one cross-query atomic snapshot. Text is bounded to1000 characters.',
            'Remote query stop after transport loss is unknown. This adapter never changes grants, Query Store or data.'])
    if not code:result['rows_may_be_truncated']=operation!='capabilities' and len(response['rows'])>=result['limits']['max_rows']
    else:result['reason']=reason or 'connection_permission_or_capability_error'
    result['operator_credential_redacted']=redacted
    return save_artifact(state_dir,'sqlserver',dict(operation=operation,window=selected,**scope),sources,result)
