"""Configured environment graph; pure transformations, never runtime ownership proof."""
from copy import deepcopy
import hashlib
import json
import re
from urllib.parse import urlsplit

from .inputs import InputError
from . import profile_ssh

RESOURCE_KINDS=('nodes','connections','clusters','dbms_instances','database_bindings')
COMMON={
    'sql':frozenset(('engine','port','user','executable','docker_container')),
    'rac':frozenset(('executable','docker_container')),
    'os':frozenset(('transport','port','python','use_ssl','identity_file','known_hosts_file'))}
OWN_OS=frozenset(('duration_seconds','interval_seconds','max_bytes','role'))


def _object(value,allowed,required=()):
    if type(value) is not dict or set(value)-set(allowed) or set(required)-set(value):raise InputError('invalid shared profile properties')
    return value


def _text(value,limit=2048,empty=False):
    if type(value) is not str or len(value)>limit or (not empty and not value.strip()) or any(ord(c)<32 for c in value):raise InputError('invalid shared profile text')
    if re.search(r'(?i)(?:pwd|password|token|secret|authorization)\s*[=:]|://[^/]*@',value):raise InputError('credentials must not be saved in profiles')
    return value.strip()


def _rows(value,limit=200):
    if type(value) is not list or len(value)>limit:raise InputError('shared profile collection exceeds limit')
    ids=set()
    for row in value:
        if type(row) is not dict:raise InputError('invalid shared profile row')
        identity=_text(row.get('id'),80)
        if identity in ids:raise InputError('duplicate shared profile identifier')
        ids.add(identity)
    return value


def _ref(value,rows,optional=True):
    if value is None and optional:return None
    if type(value) is not str or value not in rows:raise InputError('shared profile reference is absent')
    return value


def _refs(value,rows):
    if type(value) is not list or len(value)>100 or len({v for v in value if type(v) is str})!=len(value):raise InputError('invalid shared profile references')
    return [_ref(v,rows,False) for v in value]


def _origin(value,known):
    if value is None:return dict(basis='reported' if known else 'unknown',origin='configured_profile')
    _object(value,('basis','origin'),('basis','origin'))
    if value['basis']!=('reported' if known else 'unknown'):raise InputError('configured mode/method cannot claim an observed origin')
    return dict(basis=value['basis'],origin=_text(value['origin'],120))


def _connection(value):
    from .profiles import validate_source_settings
    _object(value,('id','name','kind','address','credential_ref','settings'),('id','name','kind','address'))
    kind=value['kind'];settings=deepcopy(value.get('settings',{}))
    if type(kind) is not str:raise InputError('invalid shared connection kind')
    if type(settings) is not dict:raise InputError('connection settings must be an object')
    credential=_text(value.get('credential_ref',''),empty=True)
    if kind=='ssh':
        if credential:raise InputError('SSH credentials use explicit key-file references, not credential text')
        settings=profile_ssh.settings(value['address'],settings)
    elif kind in COMMON:
        if set(settings)-COMMON[kind]:raise InputError('unsupported common connection settings')
        checked=validate_source_settings(kind,settings,[])
        settings={k:v for k,v in checked.items() if k in COMMON[kind]}
    elif kind=='onec':
        _object(settings,('method',),('method',))
        if settings['method'] not in ('direct','web','unknown'):raise InputError('invalid application connection method')
    elif kind in ('files','git'):_object(settings,())
    else:raise InputError('unknown shared connection kind')
    return dict(id=_text(value['id'],80),name=_text(value['name'],120),kind=kind,address=_text(value['address'],empty=True),credential_ref=credential,settings=settings)


def validate(value):
    """Validate schema2 without accessing any configured file, host or executable."""
    from .profiles import _validate_legacy_profile,validate_source_settings
    from .source_passports import interval
    _object(value,('schema_version','name','revision','capability_status','bases','sources','registration_decisions',*RESOURCE_KINDS),('schema_version','name','bases','sources'))
    if type(value['schema_version']) is not int or value['schema_version']!=2:raise InputError('profile schema_version=2 required')
    rows={kind:_rows(value.get(kind,[]),500 if kind=='database_bindings' else 200) for kind in RESOURCE_KINDS}
    nodes=[]
    for row in rows['nodes']:
        _object(row,('id','name','reported_identity'),('id','name'))
        nodes.append(dict(id=_text(row['id'],80),name=_text(row['name'],256),reported_identity=_text(row.get('reported_identity',''),empty=True)))
    node_map={r['id']:r for r in nodes};connections=[_connection(r) for r in rows['connections']];connection_map={r['id']:r for r in connections}
    clusters=[]
    for row in rows['clusters']:
        _object(row,('id','name','node_ids','ras_connection_id','reported_identity'),('id','name'))
        cid=_ref(row.get('ras_connection_id'),connection_map)
        if cid is not None and connection_map[cid]['kind']!='rac':raise InputError('cluster requires a RAS connection')
        clusters.append(dict(id=_text(row['id'],80),name=_text(row['name'],120),node_ids=_refs(row.get('node_ids',[]),node_map),ras_connection_id=cid,reported_identity=_text(row.get('reported_identity',''),empty=True)))
    cluster_map={r['id']:r for r in clusters};instances=[]
    for row in rows['dbms_instances']:
        _object(row,('id','name','node_id','connection_id','reported_identity'),('id','name','connection_id'))
        cid=_ref(row['connection_id'],connection_map,False)
        if connection_map[cid]['kind']!='sql':raise InputError('DBMS instance requires a SQL connection')
        instances.append(dict(id=_text(row['id'],80),name=_text(row['name'],120),node_id=_ref(row.get('node_id'),node_map),connection_id=cid,reported_identity=_text(row.get('reported_identity',''),empty=True)))
    instance_map={r['id']:r for r in instances};bases=[]
    for row in _rows(value['bases'],100):
        _object(row,('id','name','mode','connection_method','connection_id','connection_parameters','mode_origin','connection_origin','applicability','node_id','cluster_id','reported_identity','registrations'),('id','name','mode'))
        mode=row['mode'];cid=_ref(row.get('connection_id'),connection_map)
        if mode not in ('file','server','unknown'):raise InputError('invalid infobase storage mode')
        if cid is not None and connection_map[cid]['kind']!='onec':raise InputError('infobase requires an application connection')
        method=row.get('connection_method',connection_map[cid]['settings']['method'] if cid else 'unknown')
        if method not in ('direct','web','unknown') or (cid and method!=connection_map[cid]['settings']['method']) or (cid is None and method!='unknown'):raise InputError('infobase method disagrees with its connection')
        params=_object(row.get('connection_parameters',{}),('ref','file_path','publication'))
        params={key:_text(item,empty=True) for key,item in params.items()}
        if (params and cid is None) or ('publication' in params and method!='web') or (set(params)&{'ref','file_path'} and method!='direct') or ('ref' in params and 'file_path' in params):raise InputError('invalid infobase connection parameters')
        if 'ref' in params and re.search(r'[;="\r\n]',params['ref']):raise InputError('invalid infobase reference')
        if method=='web':
            url=urlsplit(connection_map[cid]['address'])
            if url.scheme not in ('http','https') or not url.netloc or url.path not in ('','/') or url.query or url.fragment or (params.get('publication') and not params['publication'].startswith('/')):raise InputError('web connection requires an origin and a separate publication path')
        cluster_id=_ref(row.get('cluster_id'),cluster_map)
        if mode=='file' and cluster_id is not None:raise InputError('file infobase cannot claim a server cluster')
        bases.append(dict(id=_text(row['id'],80),name=_text(row['name'],120),mode=mode,connection_method=method,connection_id=cid,connection_parameters=params,
            mode_origin=_origin(row.get('mode_origin'),mode!='unknown'),connection_origin=_origin(row.get('connection_origin'),method!='unknown'),applicability=interval(row.get('applicability',{})),
            node_id=_ref(row.get('node_id'),node_map),cluster_id=cluster_id,reported_identity=_text(row.get('reported_identity',''),empty=True)))
        if 'registrations' in row:
            from .registrations import validate_registrations
            bases[-1]['registrations']=validate_registrations(row['registrations'])
    if not bases:raise InputError('profile requires at least one infobase')
    base_map={r['id']:r for r in bases};databases=[]
    for row in rows['database_bindings']:
        _object(row,('id','base_id','instance_id','name','permission_scope'),('id','base_id','instance_id','name'))
        bid=_ref(row['base_id'],base_map,False)
        if base_map[bid]['mode']!='server':raise InputError('SQL mapping requires a confirmed server infobase')
        name=_text(row['name'],128)
        if not re.fullmatch(r'[\w][\w.-]{0,127}',name):raise InputError('SQL database requires a plain name')
        databases.append(dict(id=_text(row['id'],80),base_id=bid,instance_id=_ref(row['instance_id'],instance_map,False),name=name,permission_scope=_text(row.get('permission_scope','not_checked'),empty=True)))
    database_map={r['id']:r for r in databases};sources=[]
    for row in _rows(value['sources'],100):
        _object(row,('id','type','path','base_ids','node_id','cluster_id','connection_id','dbms_instance_id','database_ids','settings','status'),('id','type','base_ids'))
        kind=row['type']
        if kind not in ('tj','jr','source','sql','os','rac'):raise InputError('unknown source type')
        bid=_refs(row['base_ids'],base_map)
        if not bid:raise InputError('source requires an infobase association')
        cid=_ref(row.get('connection_id'),connection_map);instance_id=_ref(row.get('dbms_instance_id'),instance_map);dids=_refs(row.get('database_ids',[]),database_map)
        if kind=='sql':
            if instance_id is None or cid is not None:raise InputError('SQL source refers to a DBMS instance, not a duplicate connection')
            mapped=[database_map[k] for k in dids]
            if any(d['instance_id']!=instance_id or d['base_id'] not in bid for d in mapped) or len({d['base_id'] for d in mapped})!=len(mapped):raise InputError('source SQL mappings do not match its instance/infobases')
        elif instance_id is not None or dids:raise InputError('SQL references belong only to SQL sources')
        if kind in ('os','rac') and (cid is None or connection_map[cid]['kind']!=kind and not (kind=='os' and connection_map[cid]['kind']=='ssh')):raise InputError('source requires a matching shared connection')
        if kind in ('tj','jr','source') and cid is not None and connection_map[cid]['kind'] not in ('files','git') and not (kind in ('tj','jr') and profile_ssh.is_ssh(connection_map[cid])):raise InputError('file source requires file/Git or supported journal SSH access')
        settings=deepcopy(row.get('settings',{}))
        if type(settings) is not dict or (kind in ('sql','rac') and settings) or (kind=='os' and set(settings)-OWN_OS):raise InputError('common source settings belong to its connection')
        if kind in ('tj','jr') and set(settings)&profile_ssh.JOURNAL_KEYS:raise InputError('common journal access belongs to its connection')
        if kind not in ('sql','rac','os'):settings=validate_source_settings(kind,settings,bid)
        cluster_id=_ref(row.get('cluster_id'),cluster_map)
        if kind=='rac' and cluster_id is not None and cluster_map[cluster_id]['ras_connection_id'] not in (None,cid):raise InputError('source RAS connection disagrees with its cluster')
        sources.append(dict(id=_text(row['id'],80),type=kind,path=_text(row.get('path',''),empty=kind in ('os','rac','sql')),base_ids=bid,node_id=_ref(row.get('node_id'),node_map),cluster_id=cluster_id,
            connection_id=cid,dbms_instance_id=instance_id,database_ids=dids,settings=settings,status='not_checked'))
    result=dict(schema_version=2,name=_text(value['name'],120),nodes=nodes,connections=connections,clusters=clusters,dbms_instances=instances,bases=bases,database_bindings=databases,sources=sources,capability_status='configured_not_connected')
    if 'registration_decisions' in value:
        decisions=value['registration_decisions']
        if type(decisions) is not dict or len(decisions)>100 or any(not re.fullmatch('match-[a-f0-9]{20}',key) or item!='separate' for key,item in decisions.items()):raise InputError('invalid registration decision')
        result['registration_decisions']=dict(decisions)
    # Reuse the existing bounded adapter/settings validation on a pure projection.
    view=_validate_legacy_profile(_project(result))
    for source,effective in zip(result['sources'],view['sources']):
        if source['type']=='os':source['settings']={k:v for k,v in effective['settings'].items() if k in OWN_OS}
    if len((json.dumps(result,ensure_ascii=False,allow_nan=False,indent=2)+'\n').encode('utf-8'))>1024*1024:raise InputError('shared profile exceeds 1 MiB')
    return result


def _project(value):
    nodes={r['id']:r for r in value['nodes']};connections={r['id']:r for r in value['connections']};instances={r['id']:r for r in value['dbms_instances']};clusters={r['id']:r for r in value['clusters']};databases={r['id']:r for r in value['database_bindings']}
    bases=[]
    for base in value['bases']:
        connection=connections.get(base['connection_id']);params=base['connection_parameters'];address=''
        if connection:
            address=connection['address']
            if base['connection_method']=='web':address=address.rstrip('/')+params.get('publication','')
            elif base['connection_method']=='direct':
                if 'file_path' in params:address=params['file_path']
                elif params.get('ref'):address='Srvr='+address+';Ref='+params['ref']
        elif base['cluster_id'] and base['reported_identity']:
            cluster=clusters[base['cluster_id']];ras=connections.get(cluster['ras_connection_id'])
            if ras and cluster['reported_identity']:address='RAS='+ras['address']+';Cluster='+cluster['reported_identity']+';IB='+base['reported_identity']
        bases.append(dict(id=base['id'],name=base['name'],mode=base['mode'],connection=address))
    sources=[]
    for source in value['sources']:
        kind=source['type'];connection=connections.get(source['connection_id']);settings=deepcopy(source['settings']);host=nodes[source['node_id']]['name'] if source['node_id'] else '';path=source['path']
        if kind=='sql':connection=connections[instances[source['dbms_instance_id']]['connection_id']]
        if connection and kind in ('sql','os','rac'):
            settings=dict(deepcopy(connection['settings']),**settings)
            if connection['kind']=='ssh':
                settings['transport']='ssh';settings.setdefault('python','python3');settings.setdefault('use_ssl',False)
            if connection['credential_ref'] and kind in ('sql','rac'):settings['credential_ref']=connection['credential_ref']
            if kind in ('sql','os'):host=connection['address']
            else:path=connection['address']
        if kind=='sql':settings['databases']={databases[k]['base_id']:databases[k]['name'] for k in source['database_ids']}
        if kind in ('tj','jr') and profile_ssh.is_ssh(connection):
            settings=dict(profile_ssh.journal_settings(connection),**settings);host=connection['address']
        sources.append(dict(id=source['id'],type=kind,path=path,host=host,base_ids=list(source['base_ids']),status='not_checked',settings=settings))
    return dict(schema_version=1,name=value['name'],bases=bases,sources=sources,capability_status='configured_not_connected')


def effective_profile(value):
    """Ephemeral legacy adapter view. Never save it over the canonical graph."""
    from .profiles import _validate_legacy_profile
    if type(value) is not dict:raise InputError('profile must be an object')
    if value.get('schema_version')==1:
        _validate_legacy_profile(value);return deepcopy(value)
    result=_project(validate(value))
    if 'revision' in value:result['revision']=value['revision']
    return result


def _application_parameters(address):
    pattern=re.compile(r'\s*(File|Srvr|Ref)\s*=\s*(?:"((?:[^"]|"")*)"|([^;]*?))\s*(?:;|$)',re.I)
    result={};offset=0
    while offset<len(address):
        match=pattern.match(address,offset)
        if match is None or match[1].lower() in result:return {}
        result[match[1].lower()]=(match[2].replace('""','"') if match[2] is not None else match[3]).strip();offset=match.end()
    return result


def upgrade_profile(value):
    """Explicit deterministic conversion; equality groups configuration, not servers."""
    from .profiles import _validate_legacy_profile
    if type(value) is not dict:raise InputError('profile must be an object')
    if value.get('schema_version')==2:result=validate(value)
    else:
        legacy=_validate_legacy_profile(value)
        result=dict(schema_version=2,name=legacy['name'],nodes=[],connections=[],clusters=[],dbms_instances=[],bases=[],database_bindings=[],sources=[])
        def add(kind,row):
            raw=json.dumps(row,sort_keys=True,ensure_ascii=False,separators=(',',':'))
            identity=kind[:12]+'-'+hashlib.sha256(raw.encode()).hexdigest()[:24]
            if not any(r['id']==identity for r in result[kind]):result[kind].append(dict(id=identity,**row))
            return identity
        def connection(kind,address,settings,credential=''):
            return add('connections',dict(name=(kind+' · '+(address or 'local'))[:120],kind=kind,address=address,settings=settings,credential_ref=credential))
        for base in legacy['bases']:
            address=base['connection'];params={};method='unknown';cid=None;cluster_id=None;reported_identity=''
            ras=re.fullmatch(r'RAS=([^;]+);Cluster=([^;]+);IB=([^;]+)',address)
            direct=_application_parameters(address)
            if ras:
                rid=connection('rac',ras[1],{})
                cluster_id=add('clusters',dict(name='Кластер '+ras[2],node_ids=[],ras_connection_id=rid,reported_identity=ras[2]));reported_identity=ras[3]
            elif re.match(r'https?://',address):
                url=urlsplit(address);method='web';params=dict(publication=url.path+('?' + url.query if url.query else '')+('#'+url.fragment if url.fragment else ''));address=url.scheme+'://'+url.netloc
            elif set(direct)=={'srvr','ref'} and not re.search(r'[;="]',direct['ref']):method='direct';params=dict(ref=direct['ref']);address=direct['srvr']
            elif set(direct)=={'file'}:method='direct';params=dict(file_path=direct['file']);address=''
            elif base['mode']=='file' and not re.match(r'\w+=',address):method='direct';params=dict(file_path=address);address=''
            if not ras:cid=connection('onec',address,dict(method=method))
            result['bases'].append(dict(id=base['id'],name=base['name'],mode=base['mode'],connection_method=method,connection_id=cid,connection_parameters=params,cluster_id=cluster_id,reported_identity=reported_identity,
                mode_origin=dict(basis='reported' if base['mode']!='unknown' else 'unknown',origin='legacy_profile'),connection_origin=dict(basis='reported' if method!='unknown' else 'unknown',origin='legacy_profile')))
        for source in legacy['sources']:
            kind=source['type'];settings=deepcopy(source['settings']);node=add('nodes',dict(name=source['host'])) if source['host'] else None
            row=dict(id=source['id'],type=kind,path=source['path'],base_ids=list(source['base_ids']),node_id=node,settings=settings)
            if kind in ('tj','jr') and settings.get('transport')=='sftp':
                common={k:settings.pop(k) for k in list(settings) if k in profile_ssh.JOURNAL_KEYS};common.pop('transport')
                row['connection_id']=connection('ssh',source['host'],common)
            if kind in COMMON:
                common={k:settings.pop(k) for k in list(settings) if k in COMMON[kind]};credential=settings.pop('credential_ref','')
                cid=connection(kind,source['path'] if kind=='rac' else source['host'],common,credential)
                if kind=='sql':
                    instance=add('dbms_instances',dict(name='СУБД · '+(source['host'] or 'local'),node_id=node,connection_id=cid));row['dbms_instance_id']=instance
                    mapping=settings.pop('databases',{});single=settings.pop('database',None);row['database_ids']=[]
                    for bid in source['base_ids']:
                        database=mapping.get(bid,single)
                        if database:row['database_ids'].append(add('database_bindings',dict(base_id=bid,instance_id=instance,name=database,permission_scope='not_checked')))
                else:
                    row['connection_id']=cid
                    if kind=='rac':row['path']=''
            result['sources'].append(row)
        result=validate(result)
    if 'revision' in value:result['revision']=value['revision']
    return result


def editor_context(profile):
    graph=upgrade_profile(profile)
    connections={r['id']:r for r in graph['connections']};instances={r['id']:r for r in graph['dbms_instances']}
    bindings={s['id']:(instances[s['dbms_instance_id']]['connection_id'] if s['type']=='sql' else s['connection_id']) for s in graph['sources'] if s['type'] in COMMON or s['type'] in ('tj','jr')}
    return dict(profile=graph,view=effective_profile(graph),connection_bindings=bindings,connections=list(connections.values()),scope='configuration_only_not_connected')


def prepare_editor_profile(saved, edit):
    """Prepare the same canonical graph for the browser and chat-based setup."""
    options = ('connection_bindings', 'connection_edits', 'base_registrations',
               'discovery_resources', 'base_merge', 'registration_decisions')
    _object(edit, ('view', 'draft_profile', *options), ('view',))
    before = edit.get('draft_profile')
    result = compose_profile(saved if before is None else before, edit['view'],
                             **{key: edit[key] for key in options if key in edit})
    profile = retain_editor_resources(result['profile'], saved)
    return dict(result, profile=profile, editor=editor_context(profile), impact=resource_impact(saved, profile))


def compose_profile(before,view,*,connection_bindings=None,connection_edits=None,base_registrations=None,discovery_resources=None,base_merge=None,registration_decisions=None):
    """Compile the simple GUI view without discarding the canonical graph.

    Shared edits are explicit. A changed per-card endpoint cannot silently change
    a whole group or be discarded. None means an explicitly separate connection.
    """
    from .profiles import _validate_legacy_profile
    flat=_validate_legacy_profile(view);fresh=upgrade_profile(flat)
    original=upgrade_profile(before) if before is not None else deepcopy(fresh)
    result=deepcopy(original);bindings={} if connection_bindings is None else connection_bindings;edits={} if connection_edits is None else connection_edits
    if type(bindings) is not dict or len(bindings)>100 or type(edits) is not dict or len(edits)>200:raise InputError('invalid shared editor choices')
    source_ids={s['id'] for s in flat['sources'] if s['type'] in COMMON or s['type'] in ('tj','jr')}
    if set(bindings)-source_ids:raise InputError('editor connection refers to an absent source')
    lookup=lambda doc,kind,identity:next((r for r in doc[kind] if r['id']==identity),None)
    def fingerprint(connection):
        return profile_ssh.fingerprint(connection)
    old_views=effective_profile(original);old_sources={r['id']:r for r in original['sources']};old_flat={r['id']:r for r in old_views['sources']};changed_connections=set()
    for identity,patch in edits.items():
        target=lookup(result,'connections',identity)
        if target is None:raise InputError('edited shared connection is absent')
        _object(patch,('name','address','credential_ref','settings'))
        merged=dict(target,**deepcopy(patch))
        if 'settings' in patch:
            if type(patch['settings']) is not dict:raise InputError('invalid shared connection settings')
            merged['settings']=dict(target['settings'],**patch['settings'])
        clean=_connection(merged)
        if target['kind']=='onec' and target['settings']['method']!=clean['settings']['method']:raise InputError('application method changes require separate infobase parameters')
        if fingerprint(clean)!=fingerprint(target):changed_connections.add(identity)
        target.clear();target.update(clean)
    # Identity claims and applicability are not transferred to a changed endpoint.
    invalidated=[];old_deps=_dependencies(original)
    changed_addresses={cid for cid in changed_connections if profile_ssh.endpoint(lookup(original,'connections',cid))!=profile_ssh.endpoint(lookup(result,'connections',cid))}
    changed_nodes={r['node_id'] for r in result['dbms_instances'] if r['connection_id'] in changed_addresses and r['node_id']}
    changed_nodes.update(s['node_id'] for s in result['sources'] if s['connection_id'] in changed_addresses and s['node_id'])
    for node in result['nodes']:
        if node['id'] in changed_nodes:
            if node['reported_identity']:invalidated.append(dict(kind='nodes',id=node['id']))
            node['reported_identity']=''
    for instance in result['dbms_instances']:
        if instance['connection_id'] in changed_connections:
            if instance['reported_identity']:invalidated.append(dict(kind='dbms_instances',id=instance['id']))
            instance['reported_identity']=''
            for database in result['database_bindings']:
                if database['instance_id']==instance['id']:database['permission_scope']='not_checked'
    for cluster in result['clusters']:
        if cluster['ras_connection_id'] in changed_connections:cluster['reported_identity']=''
    for base in result['bases']:
        if any(('connections',cid) in old_deps[0][base['id']] for cid in changed_connections):
            if base['reported_identity']:invalidated.append(dict(kind='bases',id=base['id']))
            base['reported_identity']='';base['applicability']=dict(start=None,end=None)
    edited_views=effective_profile(result);edited_bases={r['id']:r for r in edited_views['bases']};original_bases={r['id']:r for r in old_views['bases']};edited_sources={r['id']:r for r in edited_views['sources']}
    def copy_resource(kind,identity):
        if identity is None:return None
        row=lookup(fresh,kind,identity)
        if row is None:raise InputError('new configured resource is absent')
        existing=lookup(result,kind,identity)
        if existing is not None:
            ignored={'reported_identity','permission_scope'}|({'name'} if kind!='database_bindings' else set())
            if {k:v for k,v in existing.items() if k not in ignored}!={k:v for k,v in row.items() if k not in ignored}:raise InputError('new resource identifier conflicts with existing configuration')
            return identity
        if kind=='clusters':
            for node in row['node_ids']:copy_resource('nodes',node)
            copy_resource('connections',row['ras_connection_id'])
        elif kind=='dbms_instances':copy_resource('connections',row['connection_id']);copy_resource('nodes',row['node_id'])
        elif kind=='database_bindings':copy_resource('dbms_instances',row['instance_id'])
        result[kind].append(deepcopy(row));return identity
    def generated(kind,row,salt):
        identity='editor-'+hashlib.sha256(json.dumps([kind,salt,row],sort_keys=True,ensure_ascii=False).encode()).hexdigest()[:24]
        existing=lookup(result,kind,identity)
        if existing is None:result[kind].append(dict(id=identity,**deepcopy(row)))
        elif existing!=dict(id=identity,**row):raise InputError('editor resource identifier conflict')
        return identity
    result['name']=flat['name'];bases=[]
    for item in flat['bases']:
        old=lookup(result,'bases',item['id']);baseline=original_bases.get(item['id']);current=edited_bases.get(item['id'])
        if old is not None and item['mode']==old['mode'] and item['connection'] in (baseline['connection'],current['connection']):bases.append(dict(deepcopy(old),name=item['name']))
        else:
            row=deepcopy(lookup(fresh,'bases',item['id']))
            row['mode_origin']['origin']='configured_input'
            row['connection_origin']['origin']='configured_input'
            if old is not None:
                row['mode_origin']=deepcopy(old['mode_origin']) if item['mode']==old['mode'] else dict(basis=row['mode_origin']['basis'],origin='user_override')
                row['connection_origin']['origin']='user_override'
            copy_resource('connections',row['connection_id']);copy_resource('clusters',row['cluster_id']);copy_resource('nodes',row['node_id'])
            bases.append(row)
    result['bases']=bases;base_ids={r['id'] for r in bases}
    result['database_bindings']=[d for d in result['database_bindings'] if d['base_id'] in base_ids and next(b for b in bases if b['id']==d['base_id'])['mode']=='server']
    def source_connection(doc,source):
        if source['type']=='sql':return lookup(doc,'dbms_instances',source['dbms_instance_id'])['connection_id']
        return source['connection_id']
    sources=[]
    for item in flat['sources']:
        sid=item['id'];new=lookup(fresh,'sources',sid);old=old_sources.get(sid)
        if old and old['type']!=item['type']:old=None
        row=deepcopy(old or new);row.update(base_ids=list(item['base_ids']),settings=deepcopy(new['settings']),path=new['path'])
        if old is None or item['host'] not in (old_flat[sid]['host'],edited_sources[sid]['host']):
            row['node_id']=copy_resource('nodes',new['node_id'])
        if item['type'] in ('tj','jr'):
            fresh_connection=lookup(fresh,'connections',new['connection_id']) if new['connection_id'] else None
            if sid in bindings and bindings[sid] is None:
                if fresh_connection is None:cid=None
                else:
                    conn=deepcopy(fresh_connection);conn.pop('id');cid=generated('connections',conn,sid)
            elif sid in bindings:cid=_ref(bindings[sid],{r['id']:r for r in result['connections']},False)
            elif old is not None:
                cid=old['connection_id'];previous=lookup(original,'connections',cid) if cid else None
                current=lookup(result,'connections',cid) if cid else None
                if profile_ssh.is_ssh(previous)!=profile_ssh.is_ssh(fresh_connection):raise InputError('journal access change requires an explicit connection choice')
                if fresh_connection and profile_ssh.fingerprint(fresh_connection,journal_only=True) not in (profile_ssh.fingerprint(previous,journal_only=True),profile_ssh.fingerprint(current,journal_only=True)):raise InputError('per-card journal access conflicts with shared connection')
            else:cid=copy_resource('connections',new['connection_id'])
            row['connection_id']=cid
        elif item['type'] in COMMON:
            fresh_connection=lookup(fresh,'connections',source_connection(fresh,new))
            if sid in bindings and bindings[sid] is None:
                conn=deepcopy(fresh_connection);conn.pop('id');cid=generated('connections',conn,sid)
            elif sid in bindings:
                cid=_ref(bindings[sid],{r['id']:r for r in result['connections']},False)
            elif old is not None:cid=source_connection(original,old)
            else:cid=copy_resource('connections',fresh_connection['id'])
            connection=lookup(result,'connections',cid)
            if connection['kind']!=item['type'] and not (item['type']=='os' and connection['kind']=='ssh'):raise InputError('editor source requires matching shared connection kind')
            if sid not in bindings and old is not None:
                previous=lookup(original,'connections',source_connection(original,old))
                if fingerprint(fresh_connection) not in (fingerprint(previous),fingerprint(connection)):raise InputError('per-card change conflicts with shared connection; edit the common resource or choose separate')
            if item['type']=='sql':
                instance=lookup(result,'dbms_instances',old['dbms_instance_id']) if old else None
                if instance is None or instance['connection_id']!=cid:
                    candidates=[r for r in result['dbms_instances'] if r['connection_id']==cid]
                    instance=candidates[0] if len(candidates)==1 else None
                iid=instance['id'] if instance else generated('dbms_instances',dict(name=connection['name'],node_id=row['node_id'],connection_id=cid,reported_identity=''),sid)
                if sid in bindings and old is not None and source_connection(original,old)!=cid:
                    row['node_id']=lookup(result,'dbms_instances',iid)['node_id']
                row.update(connection_id=None,dbms_instance_id=iid,database_ids=[])
                old_database_ids=old['database_ids'] if old else []
                for did in new['database_ids']:
                    wanted=lookup(fresh,'database_bindings',did);candidates=[d for d in result['database_bindings'] if d['base_id']==wanted['base_id'] and d['instance_id']==iid and d['name']==wanted['name']]
                    matching=[d for d in candidates if d['id'] in old_database_ids]
                    database=matching[0] if len(matching)==1 else candidates[0] if len(candidates)==1 else None
                    row['database_ids'].append(database['id'] if database else generated('database_bindings',dict(base_id=wanted['base_id'],instance_id=iid,name=wanted['name'],permission_scope='not_checked'),sid))
            else:row['connection_id']=cid
        elif old is None:copy_resource('connections',row['connection_id']);copy_resource('clusters',row['cluster_id'])
        sources.append(row)
    result['sources']=sources
    from .registrations import apply_registration_claims,merge_discovery_resources,candidate_matches,merge_profile_bases,source_suggestions
    result=validate(apply_registration_claims(merge_discovery_resources(result,discovery_resources),base_registrations,previous=original if before is not None else None))
    if base_merge is not None:
        if type(base_merge) is not dict or set(base_merge)!={'keep_id','remove_ids'}:raise InputError('invalid candidate merge choice')
        result=merge_profile_bases(result,base_merge['keep_id'],base_merge['remove_ids'])
    if registration_decisions is not None:
        candidate_ids={row['id'] for row in candidate_matches(result)['groups']}
        if type(registration_decisions) is not dict or set(registration_decisions)-candidate_ids:raise InputError('registration decision refers to changed candidates')
        result['registration_decisions']=dict(registration_decisions);result=validate(result)
    return dict(profile=result,impact=resource_impact(before,result),invalidated_claims=invalidated,editor=editor_context(result),matches=candidate_matches(result),source_suggestions=source_suggestions(result),saved=False,connected=False)


def _references(row):
    return [(kind,row[field]) for field,kind in [('node_id','nodes'),('cluster_id','clusters'),('connection_id','connections'),('dbms_instance_id','dbms_instances')] if row.get(field)]


def _walk_resources(value,initial):
    maps={kind:{r['id']:r for r in value[kind]} for kind in RESOURCE_KINDS}
    found=set();pending=list(initial)
    while pending:
        key=pending.pop()
        if key in found:continue
        found.add(key);kind,identity=key;row=maps[kind][identity]
        if kind=='clusters':
            pending.extend(('nodes',k) for k in row['node_ids'])
            if row['ras_connection_id']:pending.append(('connections',row['ras_connection_id']))
        elif kind=='dbms_instances':
            pending.append(('connections',row['connection_id']))
            if row['node_id']:pending.append(('nodes',row['node_id']))
        elif kind=='database_bindings':pending.append(('dbms_instances',row['instance_id']))
    return found


def retain_editor_resources(profile,saved_profile):
    """Drop abandoned draft resources; retain every still-valid saved resource."""
    result=validate(profile);saved=upgrade_profile(saved_profile) if saved_profile is not None else {k:[] for k in RESOURCE_KINDS}
    present={kind:{r['id'] for r in result[kind]} for kind in RESOURCE_KINDS}
    roots=[(kind,row['id']) for kind in RESOURCE_KINDS for row in saved[kind] if row['id'] in present[kind]]
    roots.extend(key for row in result['bases']+result['sources'] for key in _references(row))
    roots.extend(('database_bindings',did) for source in result['sources'] for did in source['database_ids'])
    needed=_walk_resources(result,roots)
    for kind in RESOURCE_KINDS:result[kind]=[r for r in result[kind] if (kind,r['id']) in needed]
    return validate(result)


def _dependencies(value):
    """Configured graph reachability; does not certify real host/IB identity."""
    bases={}
    for base in value['bases']:
        initial=_references(base)+[('database_bindings',d['id']) for d in value['database_bindings'] if d['base_id']==base['id']]
        bases[base['id']]=_walk_resources(value,initial)
    sources={s['id']:_walk_resources(value,_references(s)+[('database_bindings',k) for k in s['database_ids']]) for s in value['sources']}
    return bases,sources


def resource_impact(before,after):
    old=upgrade_profile(before) if before is not None else {k:[] for k in (*RESOURCE_KINDS,'bases','sources')}
    new=upgrade_profile(after);old_deps=_dependencies(old);new_deps=_dependencies(new);changes=[];associations=[];affected_bases=set();affected_sources=set()
    for kind in RESOURCE_KINDS:
        left={r['id']:r for r in old[kind]};right={r['id']:r for r in new[kind]}
        for identity in sorted(left.keys()|right.keys()):
            if left.get(identity)==right.get(identity):continue
            key=(kind,identity)
            bids=sorted({bid for deps in (old_deps[0],new_deps[0]) for bid,keys in deps.items() if key in keys})
            sids=sorted({sid for deps in (old_deps[1],new_deps[1]) for sid,keys in deps.items() if key in keys})
            if kind!='database_bindings':
                bids=sorted(set(bids)|{bid for doc in (old,new) for source in doc['sources'] if source['id'] in sids for bid in source['base_ids']})
            affected_bases.update(bids);affected_sources.update(sids)
            changes.append(dict(kind=kind,id=identity,change='added' if identity not in left else 'removed' if identity not in right else 'changed',affected_base_ids=bids,affected_source_ids=sids))
    for kind in ('bases','sources'):
        left={row['id']:row for row in old[kind]};right={row['id']:row for row in new[kind]}
        for identity in sorted(left.keys()|right.keys()):
            if left.get(identity)==right.get(identity):continue
            if kind=='bases':
                bids=[identity];sids=sorted({s['id'] for doc in (old,new) for s in doc['sources'] if identity in s['base_ids']})
            else:
                bids=sorted({bid for row in (left.get(identity),right.get(identity)) if row for bid in row['base_ids']});sids=[identity]
            affected_bases.update(bids);affected_sources.update(sids)
            associations.append(dict(kind=kind,id=identity,change='added' if identity not in left else 'removed' if identity not in right else 'changed',affected_base_ids=bids,affected_source_ids=sids))
    return dict(schema_version=1,changed_resources=changes,changed_associations=associations,affected_base_ids=sorted(affected_bases),affected_source_ids=sorted(affected_sources),connected=False,applied=False,scope='configured_dependencies_only_not_runtime_ownership')
