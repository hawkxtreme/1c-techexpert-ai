"""Explicit bounded discovery of configured registrations, not runtime ownership."""
import configparser
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import urlsplit,urlunsplit

from .inputs import InputError,read_snapshot

PARAMETER=re.compile(r'\s*([A-Za-z][A-Za-z0-9_]*)\s*=\s*(?:"((?:[^"\r\n]|"")*)"|([^;"\r\n]*))\s*(?:;|$)')


def default_starter_path():
    """A suggested location only. Never inspect its existence or follow lists."""
    if os.name=='nt':return Path(os.environ.get('APPDATA',Path.home()/'AppData/Roaming'))/'1C/1CEStart/ibases.v8i'
    if os.name=='posix':return Path.home()/'.1C/1cestart/ibases.v8i'
    return None


def _text(value,limit=2048,*,empty=False):
    if not isinstance(value,str) or len(value)>limit or any(ord(c)<32 for c in value) or (not empty and not value.strip()):raise InputError('invalid discovery field')
    return value.strip()


def connection_parameters(connection):
    """Parse the whole description; unknown options are never returned as data."""
    connection=_text(connection,16384,empty=True);offset=0;values={}
    while offset<len(connection):
        match=PARAMETER.match(connection,offset)
        if match is None:raise InputError('unsupported or ambiguous connection description')
        key=match[1].lower()
        if key in values:raise InputError('duplicate connection parameter')
        values[key]=match[2].replace('""','"') if match[2] is not None else match[3].strip()
        offset=match.end()
    return {k:v for k,v in values.items() if k in ('file','srvr','ref','ws')}


def _render(key,value):
    # Keep existing simple Srvr/Ref addresses, quote values with delimiters.
    if re.fullmatch(r'[\w.\[\]:,/-]+',value):return key+'='+value
    return key+'="'+value.replace('"','""')+'"'


def describe_connection(connection):
    params=connection_parameters(connection)
    if sum((bool(params.get('file')),bool(params.get('srvr') or params.get('ref')),bool(params.get('ws'))))>1:raise InputError('ambiguous storage/connection description')
    if params.get('file'):return dict(mode='file',connection=_text(params['file']))
    if params.get('ws'):
        try:
            url=urlsplit(params['ws']);host=url.hostname or '';port=url.port
            if url.scheme not in ('http','https') or not host:raise ValueError('unsupported publication URL')
            if ':' in host:host='['+host+']'
            if port is not None:host+=':'+str(port)
            address=urlunsplit((url.scheme,host,url.path,'',''))
        except ValueError as exc:raise InputError('invalid publication URL') from exc
        return dict(mode='unknown',connection=_text(address))
    present=[(key,params[key]) for key in ('srvr','ref') if params.get(key)]
    return dict(mode='server' if len(present)==2 else 'unknown',connection=';'.join(_render('Srvr' if k=='srvr' else 'Ref',_text(v)) for k,v in present))


def inspect_starter(path):
    """Read exactly the selected list, including explicitly selected shared lists."""
    source=os.path.abspath(os.fspath(path));_text(source)
    data=read_snapshot(path,1024*1024)
    try:text=data.decode('utf-8-sig');encoding='utf-8'
    except UnicodeDecodeError:text=data.decode('cp1251');encoding='cp1251_legacy'
    parser=configparser.RawConfigParser(strict=True,interpolation=None,delimiters=('=',))
    try:parser.read_string(text)
    except configparser.Error as exc:raise InputError('unsupported or ambiguous starter list') from exc
    if len(parser.sections())>1000:raise InputError('starter registration count exceeds limit')
    bases=[];registrations={};seen=set();digest=hashlib.sha256(data).hexdigest();captured=datetime.now(timezone.utc).isoformat()
    for section in parser.sections():
        connection=parser.get(section,'Connect',fallback='')
        if not connection:continue
        name=_text(section,120);entry_id=_text(parser.get(section,'ID',fallback=''),128,empty=True)
        if entry_id and entry_id.casefold() in seen:raise InputError('duplicate or ambiguous starter entry ID')
        if entry_id:seen.add(entry_id.casefold())
        description=describe_connection(connection)
        identity=hashlib.sha256((source+'\0'+('ID='+entry_id.casefold() if entry_id else section)).encode()).hexdigest()[:16]
        bases.append(dict(id=identity,name=name,**description))
        registrations[identity]=[dict(kind='starter',source_path=source,source_sha256=digest,entry_id=entry_id,entry_name=name,
            mode=description['mode'],connection=description['connection'],captured_at=captured)]
    result=dict(schema_version=1,bases=bases,registrations=registrations,encoding=encoding,connections_opened=False,source_files_read=1,
        limitations=['Starter entry IDs are scoped to their selected list; they are not cluster infobase UUIDs.',
                     'No common-list reference, publication, database, log path or source repository was opened.'])
    if len(json.dumps(result,ensure_ascii=False).encode())>8*1024*1024:raise InputError('starter discovery result exceeds limit')
    return result


def inspect_ras(endpoint,*,executable='rac',docker_container=None,cluster=None,infobase=None):
    """Inspect one explicit RAS scope with a total30s deadline; no SQL contact."""
    from .rac import RacClient,UUID,parse_rows,project_infobase_info
    if Path(executable).name.lower() not in ('rac','rac.exe'):raise InputError('choose the installed rac executable')
    client=RacClient(endpoint,executable=executable,docker_container=docker_container);deadline=time.monotonic()+30
    if cluster is not None:client.command('infobase_info' if infobase else 'infobases',cluster=cluster,infobase=infobase)
    elif infobase is not None:raise InputError('selected infobase requires a cluster UUID')
    started=datetime.now(timezone.utc).isoformat()
    def execute(operation):
        remaining=min(23,deadline-time.monotonic())
        if remaining<=0:raise InputError('RAS discovery time budget exceeded')
        options=dict(timeout_seconds=remaining)
        if operation=='infobase_info':options['infobase']=infobase
        return client.execute(operation,cluster=cluster if operation!='clusters' else None,**options)
    def uid(value):
        if not isinstance(value,str) or not UUID.fullmatch(value):raise InputError('invalid identity in RAS response')
        return value
    def clusters(text):
        rows=parse_rows(text)
        if len(rows)>100:raise InputError('RAS cluster count exceeds limit')
        result=[]
        for row in rows:
            value=dict(cluster=uid(row.get('cluster')),name=_text(row.get('name',''),120,empty=True),host=_text(row.get('host',''),256,empty=True))
            if row.get('port'):
                if not row['port'].isdecimal() or not 1<=int(row['port'])<=65535:raise InputError('invalid cluster port in RAS response')
                value['port']=int(row['port'])
            result.append(value)
        if len({r['cluster'].lower() for r in result})!=len(result):raise InputError('ambiguous duplicate RAS cluster')
        return result
    common=dict(schema_version=1,endpoint=endpoint,bases=[],registrations={},resources=dict(nodes=[],clusters=[],connections=[]),
        temporal_scope='current_snapshot_only',started_at=started,sql_connected=False)
    if cluster is None:
        return dict(common,clusters=clusters(execute('clusters')),finished_at=datetime.now(timezone.utc).isoformat())
    namespace=dict(endpoint=endpoint,docker_container=docker_container,executable=str(executable))
    def identity(kind,*parts):return 'discovery-'+hashlib.sha256(json.dumps([kind,namespace,*parts],sort_keys=True,ensure_ascii=False).encode()).hexdigest()[:24]
    def base_id(ib):
        key=endpoint+'\0'+cluster+'\0'+ib
        if docker_container:key+='\0docker:'+docker_container
        return hashlib.sha256(key.encode()).hexdigest()[:24]
    def registration(kind,ib,ref,connection,**extra):
        return dict(kind=kind,endpoint=endpoint,cluster_id=cluster,infobase_id=ib,docker_container=docker_container,executable=str(executable),
            entry_name=ref,mode='server',connection=connection,captured_at=datetime.now(timezone.utc).isoformat(),ras_connection_sha256=connection_signature,**extra)
    def locator(ib):return 'RAS='+endpoint+';Cluster='+cluster+';IB='+ib
    rid=identity('ras-connection');cid=identity('cluster',cluster)
    common['resources']['connections']=[dict(id=rid,kind='rac',name=('RAS '+endpoint)[:120],address=endpoint,credential_ref='',
        settings=dict(executable=str(executable),**(dict(docker_container=docker_container) if docker_container else {})))]
    from .registrations import ras_connection_signature
    connection_signature=ras_connection_signature(common['resources']['connections'][0])
    if infobase is not None:
        rows,projected=project_infobase_info(execute('infobase_info'),infobase);properties=rows[0]
        name=_text(properties.get('name',''),120)
        common['resources']['clusters']=[dict(id=cid,name='Кластер '+cluster,node_ids=[],ras_connection_id=rid,reported_identity=cluster)]
        common['bases']=[dict(id=base_id(infobase),name=name,mode='server',connection=locator(infobase))]
        common['registrations'][base_id(infobase)]=[registration('ras_info',infobase,name,locator(infobase),properties=properties,snapshot_sha256=hashlib.sha256(projected.encode()).hexdigest())]
        return dict(common,cluster=cluster,properties=properties,finished_at=datetime.now(timezone.utc).isoformat(),
            limitations=['Selected current cluster metadata is not SQL access or historical source ownership.'])
    rows=parse_rows(execute('infobases'))
    if len(rows)>1000:raise InputError('RAS infobase count exceeds limit')
    observed=[]
    for row in rows:observed.append(dict(infobase=uid(row.get('infobase')),name=_text(row.get('name',''),120)))
    if len({r['infobase'].lower() for r in observed})!=len(observed):raise InputError('ambiguous duplicate RAS infobase')
    cluster_row=None;availability=dict(infobases='observed',cluster_properties='unavailable',nodes='unavailable')
    try:
        selected=[row for row in clusters(execute('clusters')) if row['cluster'].lower()==cluster.lower()]
        if len(selected)==1:cluster_row=selected[0];availability['cluster_properties']='observed'
    except (OSError,ValueError):pass
    nodes=None
    try:
        server_rows=parse_rows(execute('servers'))
        if len(server_rows)>200:raise InputError('RAS node count exceeds limit')
        candidate=[]
        for row in server_rows:
            sid=uid(row.get('server'));host=_text(row.get('agent-host') or row.get('host',''),256)
            candidate.append(dict(id=identity('node',cluster,sid),name=host,reported_identity=sid))
        if len({n['id'] for n in candidate})!=len(candidate):raise InputError('ambiguous duplicate RAS node')
        nodes=candidate;availability['nodes']='observed'
    except (OSError,ValueError):pass
    common['resources']['nodes']=nodes or []
    common['resources']['clusters']=[dict(id=cid,name=(cluster_row or {}).get('name') or 'Кластер '+cluster,node_ids=[n['id'] for n in nodes or []],ras_connection_id=rid,reported_identity=cluster)]
    host=(cluster_row or {}).get('host','');port=(cluster_row or {}).get('port')
    if host and ':' in host and not host.startswith('['):host='['+host+']'
    summary_digest=hashlib.sha256(json.dumps(dict(infobases=observed,cluster=cluster_row,nodes=nodes),sort_keys=True,ensure_ascii=False).encode()).hexdigest()
    for row in observed:
        ib=row['infobase'];address=';'.join((_render('Srvr',host+':'+str(port)),_render('Ref',row['name']))) if host and port else locator(ib)
        common['bases'].append(dict(id=base_id(ib),name=row['name'],mode='server',connection=address))
        common['registrations'][base_id(ib)]=[registration('ras',ib,row['name'],address,cluster_host=host,cluster_port=port,snapshot_sha256=summary_digest)]
    result=dict(common,cluster=cluster,availability=availability,node_observations=nodes,finished_at=datetime.now(timezone.utc).isoformat(),
        limitations=['Discovery calls are separate current observations, not one atomic snapshot.',
                     'Missing node/cluster properties remain unknown. Configured links do not prove historical ownership or SQL rights.'])
    if len(json.dumps(result,ensure_ascii=False).encode())>8*1024*1024:raise InputError('RAS discovery result exceeds limit')
    return result
