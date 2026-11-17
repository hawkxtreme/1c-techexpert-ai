"""Read-only RAC catalogue. Current observations never reconstruct past identity."""
from datetime import datetime, timezone
import re

from .artifacts import save_artifact
from .inputs import InputError
from .processes import run_bounded,CommandStopped

CATALOGUE={'clusters':['cluster','list'], 'infobases':['infobase','summary','list'],
           'sessions':['session','list'], 'connections':['connection','list'],
           'processes':['process','list'], 'servers':['server','list'], 'infobase_info':['infobase','info']}
UUID=re.compile(r'[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}')


def parse_rows(text):
    if not isinstance(text,str) or len(text.encode('utf-8'))>2*1024*1024:raise InputError('RAC response exceeds limit')
    result=[];row={}
    for line in text.splitlines()+['']:
        if not line.strip():
            if row:
                result.append(row);row={}
                if len(result)>10000:raise InputError('RAC row budget exceeded')
            continue
        key,separator,value=line.partition(':');key=key.strip();value=value.strip()
        if not separator or not re.fullmatch('[a-z][a-z0-9-]*',key) or key in row:
            raise InputError('unparsed or ambiguous RAC output')
        if value.startswith('"') and value.endswith('"'):value=value[1:-1].replace('\\"','"')
        row[key]=value
        if len(result)>10000:raise InputError('RAC row budget exceeded')
    return result


def project_infobase_info(text,infobase):
    """Keep needed configuration fields, never admin credentials/bypass codes."""
    rows=parse_rows(text)
    if len(rows)!=1 or rows[0].get('infobase','').lower()!=infobase.lower():raise InputError('RAC response does not identify the selected infobase')
    fields={'infobase','name','dbms','db-server','db-name'}
    rows=[{k:v for k,v in rows[0].items() if k in fields}]
    selected='\n'.join(line for line in text.splitlines() if not line.strip() or line.partition(':')[0].strip() in fields)+'\n'
    return rows,selected


class RacClient:
    def __init__(self,endpoint,*,executable='rac',docker_container=None):
        if not isinstance(endpoint,str) or not re.fullmatch(r'(?:[A-Za-z0-9][A-Za-z0-9_.-]*|\[[0-9a-fA-F:]+\]):[0-9]{1,5}',endpoint):
            raise InputError('RAS endpoint requires host:port')
        if not 1<=int(endpoint.rsplit(':',1)[1])<=65535:raise InputError('invalid RAS port')
        if docker_container is not None and not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',docker_container):
            raise InputError('invalid Docker container')
        self.endpoint=endpoint
        self.scope=dict(endpoint=endpoint,transport='docker_exec' if docker_container else 'local_process',
            docker_container=docker_container,client_executable='/opt/1cv8/current/rac' if docker_container else str(executable),client_version=None)
        self.prefix=(['docker','exec',docker_container,'timeout','--kill-after=2','18','/opt/1cv8/current/rac']
                     if docker_container else [str(executable)])

    def command(self,operation,*,cluster=None,infobase=None):
        if operation not in CATALOGUE:raise InputError('operation is not in the read-only RAC catalogue')
        args=self.prefix+CATALOGUE[operation]
        if operation!='clusters':
            if not isinstance(cluster,str) or not UUID.fullmatch(cluster):raise InputError('cluster UUID required')
            args+=['--cluster='+cluster]
        elif cluster is not None:raise InputError('clusters operation does not accept cluster selection')
        if operation=='infobase_info':
            if not isinstance(infobase,str) or not UUID.fullmatch(infobase):raise InputError('infobase UUID required')
            args+=['--infobase='+infobase]
        elif infobase is not None:raise InputError('infobase selection is only applicable to infobase_info')
        return args+[self.endpoint]

    def execute(self,operation,cluster=None,*,infobase=None,should_stop=None,timeout_seconds=23):
        if type(timeout_seconds) not in (int,float) or not 0<timeout_seconds<=23:raise InputError('invalid RAC command time limit')
        code,raw,_stderr=run_bounded(self.command(operation,cluster=cluster,infobase=infobase),timeout=timeout_seconds,should_stop=should_stop)
        if code:raise InputError('RAC observation failed; check endpoint, tool version and read permissions')
        try:return raw.decode('utf-8-sig')
        except UnicodeError as exc:raise InputError('RAC output is not UTF-8; use a supported locale/profile') from exc


def collect_rac(state_dir,client,operation,*,cluster=None,infobase=None,should_stop=None):
    selection={} if infobase is None else dict(infobase=infobase)
    client.command(operation,cluster=cluster,**selection)
    started=datetime.now(timezone.utc).isoformat()
    status='observed';reason=None;rows=None
    try:
        text=(client.execute(operation,cluster=cluster,should_stop=should_stop,**selection) if should_stop is not None
            else client.execute(operation,cluster=cluster,**selection))
        rows=parse_rows(text)
        if operation=='infobase_info':
            rows,text=project_infobase_info(text,infobase)
        sources=[('rac-'+operation+'.txt',text.encode('utf-8'))]
    except CommandStopped as exc:
        status='cancelled' if exc.reason=='cancelled' else 'unavailable';reason='command_'+exc.reason;rows=None
        sources=[('rac-partial.txt',b'RAC infobase metadata command stopped before a complete selected observation.' if operation=='infobase_info' else exc.stdout)]
    except (OSError,ValueError,UnicodeError):
        status='unavailable';reason='connection_tool_permission_or_format_error';rows=None
        sources=[('rac-unavailable.txt',b'RAC observation unavailable; no complete rows were established.')]
    return save_artifact(state_dir,'rac',dict(operation=operation,**client.scope,cluster=cluster,**selection),
        sources,
        dict(operation=operation,endpoint=client.endpoint,connection_scope=client.scope,cluster=cluster,rows=rows,status=status,reason=reason,
             started_at=started,finished_at=datetime.now(timezone.utc).isoformat(),
             temporal_scope='current_snapshot_only',historical_identity_established=False,
             **(dict(infobase=infobase,evidence_projection='selected_infobase_metadata_fields') if infobase is not None else {}),
             limitations=['Snapshot time is the capture interval, not a historical incident window.',
                          'RAC access does not grant SQL, OS or filesystem access.']))
