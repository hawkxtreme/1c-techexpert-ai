"""Read-only RAC catalogue. Current observations never reconstruct past identity."""
from datetime import datetime, timezone
import re

from .artifacts import save_artifact
from .inputs import InputError
from .processes import run_bounded

CATALOGUE={'clusters':['cluster','list'], 'infobases':['infobase','summary','list'],
           'sessions':['session','list'], 'connections':['connection','list'],
           'processes':['process','list'], 'servers':['server','list']}
UUID=re.compile(r'[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}')


def parse_rows(text):
    if not isinstance(text,str) or len(text.encode('utf-8'))>2*1024*1024:raise InputError('RAC response exceeds limit')
    result=[];row={}
    for line in text.splitlines()+['']:
        if not line.strip():
            if row:result.append(row);row={}
            continue
        key,separator,value=line.partition(':');key=key.strip();value=value.strip()
        if not separator or not re.fullmatch('[a-z][a-z0-9-]*',key) or key in row:
            raise InputError('unparsed or ambiguous RAC output')
        if value.startswith('"') and value.endswith('"'):value=value[1:-1].replace('\\"','"')
        row[key]=value
        if len(result)>10000:raise InputError('RAC row budget exceeded')
    return result


class RacClient:
    def __init__(self,endpoint,*,executable='rac',docker_container=None):
        if not isinstance(endpoint,str) or not re.fullmatch(r'(?:[A-Za-z0-9][A-Za-z0-9_.-]*|\[[0-9a-fA-F:]+\]):[0-9]{1,5}',endpoint):
            raise InputError('RAS endpoint requires host:port')
        if not 1<=int(endpoint.rsplit(':',1)[1])<=65535:raise InputError('invalid RAS port')
        if docker_container is not None and not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',docker_container):
            raise InputError('invalid Docker container')
        self.endpoint=endpoint
        self.prefix=(['docker','exec',docker_container,'timeout','--kill-after=2','18','/opt/1cv8/current/rac']
                     if docker_container else [str(executable)])

    def command(self,operation,*,cluster=None):
        if operation not in CATALOGUE:raise InputError('operation is not in the read-only RAC catalogue')
        args=self.prefix+CATALOGUE[operation]
        if operation!='clusters':
            if not isinstance(cluster,str) or not UUID.fullmatch(cluster):raise InputError('cluster UUID required')
            args+=['--cluster='+cluster]
        elif cluster is not None:raise InputError('clusters operation does not accept cluster selection')
        return args+[self.endpoint]

    def execute(self,operation,cluster=None):
        code,raw,_stderr=run_bounded(self.command(operation,cluster=cluster),timeout=23)
        if code:raise InputError('RAC observation failed; check endpoint, tool version and read permissions')
        try:return raw.decode('utf-8-sig')
        except UnicodeError as exc:raise InputError('RAC output is not UTF-8; use a supported locale/profile') from exc


def collect_rac(state_dir,client,operation,*,cluster=None):
    started=datetime.now(timezone.utc).isoformat()
    text=client.execute(operation,cluster=cluster)
    rows=parse_rows(text)
    return save_artifact(state_dir,'rac',dict(operation=operation,endpoint=client.endpoint,cluster=cluster),
        [('rac-'+operation+'.txt',text.encode('utf-8'))],
        dict(operation=operation,endpoint=client.endpoint,cluster=cluster,rows=rows,
             started_at=started,finished_at=datetime.now(timezone.utc).isoformat(),
             temporal_scope='current_snapshot_only',historical_identity_established=False,
             limitations=['Snapshot time is the capture interval, not a historical incident window.',
                          'RAC access does not grant SQL, OS or filesystem access.']))
