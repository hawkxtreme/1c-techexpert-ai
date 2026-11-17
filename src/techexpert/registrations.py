"""Private configuration provenance; registration IDs are not runtime identities."""
from copy import deepcopy
from datetime import datetime
import hashlib
import json
import ntpath
import posixpath
import re
from urllib.parse import urlsplit

from .inputs import InputError
from .discovery import connection_parameters,describe_connection


def _field(value,limit=2048,empty=False):
    if (not isinstance(value,str) or len(value)>limit or any(ord(c)<32 for c in value) or (not empty and not value.strip())
        or re.search(r'(?i)(?:pwd|password|token|secret|authorization)\s*[=:]',value) or re.search(r'://[^/]*@',value)):raise InputError('invalid or secret-bearing registration field')
    return value.strip()


def validate_registration(value):
    fields={'kind','source_path','source_sha256','entry_id','entry_name','mode','connection','captured_at'}
    if type(value) is not dict:raise InputError('unsupported registration metadata')
    if value.get('kind') in ('ras','ras_info'):return _validate_ras(value)
    if set(value)!=fields or value.get('kind')!='starter':raise InputError('unsupported registration metadata')
    result={key:_field(item,128 if key=='entry_id' else 120 if key=='entry_name' else 80 if key=='captured_at' else 2048,empty=key in ('entry_id','connection')) for key,item in value.items()}
    if not re.fullmatch('[a-f0-9]{64}',result['source_sha256']):raise InputError('invalid registration source digest')
    try:at=datetime.fromisoformat(result['captured_at'].replace('Z','+00:00'))
    except ValueError as exc:raise InputError('invalid registration capture time') from exc
    if at.tzinfo is None:raise InputError('registration capture time requires an explicit timezone')
    if result['mode'] not in ('file','server','unknown'):raise InputError('invalid registration mode')
    if result['mode']=='server':
        description=describe_connection(result['connection'])
        if description['mode']!='server':raise InputError('registration mode disagrees with connection parameters')
        result['connection']=description['connection']
    elif result['mode']=='unknown' and result['connection'].startswith(('http://','https://')):
        url=urlsplit(result['connection'])
        if not url.hostname or url.query or url.fragment:raise InputError('registration publication requires a clean URL')
    return result


def validate_registrations(values):
    if not isinstance(values,list) or not 1<=len(values)<=8:raise InputError('registration reference count exceeds limit')
    result=[validate_registration(value) for value in values]
    keys=[registration_key(value) for value in result]
    if len(keys)!=len(set(keys)):raise InputError('duplicate registration reference')
    return result


def registration_key(value):
    if value['kind']=='starter':return ('starter',value['source_path'],value['entry_id'].casefold() or value['entry_name'])
    return (value['kind'],value['endpoint'],value['cluster_id'].lower(),value['infobase_id'].lower(),value['docker_container'],value['executable'])


def ras_connection_signature(connection):
    from .profiles import validate_source_settings
    if connection.get('kind')!='rac':raise InputError('registration requires a RAC connection')
    settings=validate_source_settings('rac',connection.get('settings',{}),[])
    settings.setdefault('executable','rac')
    fields=dict(address=connection['address'],credential_ref=connection.get('credential_ref',''),settings=settings)
    return hashlib.sha256(json.dumps(fields,sort_keys=True,ensure_ascii=False).encode()).hexdigest()


def _validate_ras(value):
    from .rac import UUID,RacClient
    fields={'kind','endpoint','cluster_id','infobase_id','docker_container','executable','entry_name','mode','connection','captured_at','snapshot_sha256','ras_connection_sha256'}
    fields|={'cluster_host','cluster_port'} if value['kind']=='ras' else {'properties'}
    if set(value)!=fields or value['mode']!='server':raise InputError('unsupported RAS registration metadata')
    result={key:_field(item,120 if key=='entry_name' else 80 if key=='captured_at' else 2048,empty=key=='cluster_host')
        for key,item in value.items() if key not in ('docker_container','cluster_port','properties')}
    result['docker_container']=value['docker_container']
    if value['docker_container'] is not None:_field(value['docker_container'],128)
    RacClient(result['endpoint'],executable=result['executable'],docker_container=result['docker_container'])
    if not UUID.fullmatch(result['cluster_id']) or not UUID.fullmatch(result['infobase_id']):raise InputError('invalid RAS registration identity')
    for key in ('snapshot_sha256','ras_connection_sha256'):
        if not re.fullmatch('[a-f0-9]{64}',result[key]):raise InputError('invalid RAS registration digest')
    try:at=datetime.fromisoformat(result['captured_at'].replace('Z','+00:00'))
    except ValueError as exc:raise InputError('invalid RAS registration time') from exc
    if at.tzinfo is None:raise InputError('RAS registration time requires timezone')
    locator='RAS='+result['endpoint']+';Cluster='+result['cluster_id']+';IB='+result['infobase_id']
    if value['kind']=='ras':
        port=value['cluster_port']
        if port is not None and (type(port) is not int or not 1<=port<=65535):raise InputError('invalid RAS application port')
        result['cluster_port']=port
        if result['connection']!=locator:
            params=connection_parameters(result['connection'])
            if not result['cluster_host'] or port is None or params!={'srvr':result['cluster_host']+':'+str(port),'ref':result['entry_name']}:raise InputError('RAS application parameters disagree with registration')
    else:
        if result['connection']!=locator:raise InputError('RAS info requires its scoped locator')
        props=value['properties'];allowed={'infobase','name','dbms','db-server','db-name'}
        if type(props) is not dict or set(props)-allowed:raise InputError('RAS info does not identify the registered infobase')
        result['properties']={key:_field(item,512 if key=='db-server' else 128,empty=key not in ('infobase','name')) for key,item in props.items()}
        if result['properties'].get('infobase','').lower()!=result['infobase_id'].lower():raise InputError('RAS info does not identify the registered infobase')
        if result['properties'].get('name')!=result['entry_name']:raise InputError('RAS info name disagrees with registration')
    return result


def merge_discovery_resources(profile,fragment):
    """Add configured RAS resources without overwriting user labels/access refs."""
    result=deepcopy(profile)
    if fragment is None:return result
    if type(fragment) is not dict or set(fragment)!={'nodes','clusters','connections'}:raise InputError('invalid discovery resources')
    for kind,rows in fragment.items():
        if not isinstance(rows,list) or len(rows)>200 or any(type(row) is not dict or not isinstance(row.get('id'),str) for row in rows):raise InputError('invalid discovery resource rows')
        if len({r['id'] for r in rows})!=len(rows):raise InputError('duplicate discovery resource')
        if kind=='connections' and any(r.get('kind')!='rac' for r in rows):raise InputError('discovery resources may contain only RAC connections')
    from .profile_resources import validate
    checked=validate(dict(schema_version=2,name='Discovery resources',**deepcopy(fragment),dbms_instances=[],database_bindings=[],
        bases=[dict(id='discovery-validation',name='Validation',mode='unknown')],sources=[]))
    fragment={kind:checked[kind] for kind in fragment}
    for kind in ('nodes','connections','clusters'):
        present={row['id']:row for row in result[kind]}
        for row in fragment[kind]:
            existing=present.get(row['id'])
            if existing is None:result[kind].append(deepcopy(row));present[row['id']]=result[kind][-1]
            elif kind=='clusters' and existing.get('ras_connection_id')==row.get('ras_connection_id'):
                connection=next(c for c in result['connections'] if c['id']==existing['ras_connection_id'])
                incoming=next(c for c in fragment['connections'] if c['id']==row['ras_connection_id'])
                if ras_connection_signature(connection)==ras_connection_signature(incoming):existing['node_ids']=list(dict.fromkeys([*existing['node_ids'],*row['node_ids']]))
    return result


def candidate_matches(profile):
    """Find configuration candidates, never silently join registrations."""
    import ipaddress
    from .profile_resources import validate,effective_profile
    from .rac import UUID
    graph=validate(profile);views={b['id']:b for b in effective_profile(graph)['bases']}
    bases={b['id']:b for b in graph['bases']};clusters={c['id']:c for c in graph['clusters']};connections={c['id']:c for c in graph['connections']}
    buckets={};identities={};namespaces={}
    for bid,base in bases.items():
        key=configuration_key(base['mode'],views[bid]['connection'])
        if key is not None:buckets.setdefault(('application_parameters',key),[]).append(bid)
        cluster=clusters.get(base['cluster_id']);connection=connections.get(cluster['ras_connection_id']) if cluster else None
        if (cluster and connection and UUID.fullmatch(cluster['reported_identity']) and UUID.fullmatch(base['reported_identity'])):
            identity=(ras_connection_signature(connection),cluster['reported_identity'].lower(),base['reported_identity'].lower())
            identities[bid]=identity;namespaces[bid]=connection['settings'].get('docker_container')
            buckets.setdefault(('scoped_ras_identity',identity),[]).append(bid)
    combined={}
    for (basis,key),ids in buckets.items():
        if len(ids)<2:continue
        ids=tuple(sorted(ids));reasons=[]
        if len(ids)>2:reasons.append('multiple_candidates')
        if any(bases[bid]['mode']=='unknown' for bid in ids) or len({bases[bid]['mode'] for bid in ids})>1:reasons.append('storage_mode_unresolved')
        scoped={identities[bid] for bid in ids if bid in identities}
        if len(scoped)>1:reasons.append('different_ras_identities_or_namespaces')
        app_keys={configuration_key(bases[bid]['mode'],views[bid]['connection']) for bid in ids}
        if basis=='scoped_ras_identity' and len(app_keys-{None})>1:reasons.append('application_parameters_differ')
        credentials={connections[bases[bid]['connection_id']]['credential_ref'] for bid in ids if bases[bid]['connection_id']}
        if len(credentials)>1:reasons.append('connection_access_refs_differ')
        if basis=='application_parameters' and key[0]=='server' and any(namespaces.get(bid) for bid in ids):
            host=key[1].strip('[]')
            try:loopback=ipaddress.ip_address(host).is_loopback
            except ValueError:loopback=host=='localhost' or host.endswith('.localhost')
            if loopback and any(bid not in identities for bid in ids):reasons.append('loopback_namespace_unresolved')
        if basis=='application_parameters' and key[0]=='file' and len({bases[bid]['node_id'] for bid in ids if bases[bid]['node_id']})>1:reasons.append('file_node_scope_differs')
        group=combined.setdefault(ids,dict(base_ids=list(ids),basis=[],reasons=[]))
        group['basis'].append(basis);group['reasons']=list(dict.fromkeys([*group['reasons'],*reasons]))
    groups=[]
    for ids,row in sorted(combined.items()):
        conditions=[(bid,bases[bid]['mode'],configuration_key(bases[bid]['mode'],views[bid]['connection']),identities.get(bid),bases[bid]['node_id']) for bid in ids]
        identity='match-'+hashlib.sha256(json.dumps([conditions,row['basis'],row['reasons']],sort_keys=True).encode()).hexdigest()[:20]
        status='ambiguous' if row['reasons'] else 'candidate'
        if graph.get('registration_decisions',{}).get(identity)=='separate':status='separate'
        row.update(id=identity,status=status)
        groups.append(row)
    return dict(groups=groups,automatic_merges=0,runtime_identity_proven=False)


def source_suggestions(profile):
    """Propose SQL configuration from current scoped info; never connect or apply."""
    from .profile_resources import validate
    graph=validate(profile);clusters={r['id']:r for r in graph['clusters']};connections={r['id']:r for r in graph['connections']}
    suggestions={}
    for base in graph['bases']:
        cluster=clusters.get(base['cluster_id']);connection=connections.get(cluster['ras_connection_id']) if cluster else None
        if base['mode']!='server' or connection is None:continue
        usable=[r for r in base.get('registrations',[]) if r['kind']=='ras_info'
            and r['infobase_id'].lower()==base['reported_identity'].lower() and r['cluster_id'].lower()==cluster['reported_identity'].lower()
            and r['ras_connection_sha256']==ras_connection_signature(connection)]
        if len(usable)!=1:continue
        record=usable[0];props=record['properties'];engine={'PostgreSQL':'postgresql','MSSQLServer':'sqlserver'}.get(props.get('dbms'))
        host=props.get('db-server','');name=props.get('db-name','')
        # Composite/instance/port syntax is displayed as metadata, never guessed.
        if engine is None or not name or re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}',host) is None:continue
        key=(engine,host.casefold(),record['docker_container'])
        row=suggestions.setdefault(key,dict(type='sql',host=host,path='',base_ids=[],settings=dict(engine=engine,port=5432 if engine=='postgresql' else 1433,databases={}),
            basis='reported_selected_ras_info',port_basis='default_requires_confirmation',connected=False,captured_at=record['captured_at'],namespace=record['docker_container']))
        row['base_ids'].append(base['id']);row['settings']['databases'][base['id']]=name
    return list(suggestions.values())


def merge_profile_bases(profile,keep_id,remove_ids):
    """Apply one explicit candidate choice to a new configuration only."""
    from .profile_resources import validate
    result=validate(profile)
    if (not isinstance(keep_id,str) or not isinstance(remove_ids,list) or not remove_ids or len(remove_ids)>99
        or any(not isinstance(bid,str) for bid in remove_ids) or keep_id in remove_ids or len(set(remove_ids))!=len(remove_ids)):raise InputError('invalid infobase merge selection')
    ids={keep_id,*remove_ids}
    if not any(set(group['base_ids'])==ids and not group['reasons'] for group in candidate_matches(result)['groups']):raise InputError('ambiguous or unsupported infobase merge requires separate configuration')
    bases={base['id']:base for base in result['bases']};keeper=bases[keep_id];removed=[bases[bid] for bid in remove_ids]
    mappings={}
    for row in result['database_bindings']:
        if row['base_id'] in ids:mappings.setdefault(row['instance_id'],set()).add((row['name'],row['permission_scope']))
    if any(len(names)>1 for names in mappings.values()):raise InputError('conflicting SQL database mappings require separate configuration')
    # Prefer the keeper's existing binding when equivalent references collapse.
    ordered=sorted(result['database_bindings'],key=lambda r:0 if r['base_id']==keep_id else 1)
    canonical={};redirect={};bindings=[]
    for row in ordered:
        row=deepcopy(row)
        if row['base_id'] in ids:row['base_id']=keep_id
        key=(row['base_id'],row['instance_id'],row['name'],row['permission_scope'])
        if key in canonical:redirect[row['id']]=canonical[key]
        else:canonical[key]=row['id'];bindings.append(row)
    result['database_bindings']=bindings
    for source in result['sources']:
        source['base_ids']=list(dict.fromkeys(keep_id if bid in ids else bid for bid in source['base_ids']))
        source['database_ids']=list(dict.fromkeys(redirect.get(bid,bid) for bid in source['database_ids']))
    if keeper['connection_method']=='unknown':
        direct=next((b for b in removed if b['connection_method']!='unknown'),None)
        if direct:
            for field in ('connection_id','connection_method','connection_parameters','connection_origin'):keeper[field]=deepcopy(direct[field])
    identified=next((b for b in [keeper,*removed] if b['reported_identity'] and b['cluster_id']),None)
    if identified:keeper['reported_identity']=identified['reported_identity'];keeper['cluster_id']=identified['cluster_id']
    if keeper['node_id'] is None:keeper['node_id']=next((b['node_id'] for b in removed if b['node_id']),None)
    records=[]
    for base in [keeper,*removed]:
        if base.get('registrations'):records=merge_registrations(records,base['registrations'])
    if records:keeper['registrations']=records
    keeper['mode_origin']=dict(basis='reported' if keeper['mode']!='unknown' else 'unknown',origin='user_confirmed_configuration_merge')
    result['bases']=[base for base in result['bases'] if base['id'] not in remove_ids]
    if result.get('registration_decisions'):
        current_ids={row['id'] for row in candidate_matches(result)['groups']}
        result['registration_decisions']={key:item for key,item in result['registration_decisions'].items() if key in current_ids}
    return validate(result)


def merge_registrations(previous,incoming):
    result=[];indices={}
    for value in [*previous,*incoming]:
        item=validate_registration(value);key=registration_key(item)
        if key in indices:result[indices[key]]=item
        else:indices[key]=len(result);result.append(item)
    return validate_registrations(result)


def configuration_key(mode,connection):
    """Equality of explicitly configured parameters; no DNS/filesystem lookup."""
    if connection.startswith(('http://','https://')):
        try:
            url=urlsplit(connection)
            if not url.hostname or url.username or url.query or url.fragment:return None
            return ('web',url.scheme,url.hostname.casefold(),url.port or (443 if url.scheme=='https' else 80),url.path)
        except ValueError:return None
    if mode=='file':
        if re.match(r'^[A-Za-z]:[\\/]',connection) or connection.startswith('\\\\'):return ('file',ntpath.normcase(ntpath.normpath(connection)))
        if connection.startswith('/'):return ('file',posixpath.normpath(connection))
        return None
    if mode=='server':
        try:params=connection_parameters(connection)
        except InputError:return None
        if set(params)!= {'srvr','ref'} or not params['srvr'] or not params['ref']:return None
        endpoint=re.fullmatch(r'(\[[0-9A-Fa-f:]+\]|[\w.-]+)(?::([0-9]{1,5}))?',params['srvr'])
        if endpoint is None or not 1<=int(endpoint[2] or '1541')<=65535:return None
        return ('server',endpoint[1].casefold(),int(endpoint[2] or '1541'),params['ref'])
    return None


def apply_registration_claims(profile,updates=None,*,previous=None):
    """Retain references in a proposed new profile; every saved value is reported."""
    from .profile_resources import effective_profile
    result=deepcopy(profile);updates={} if updates is None else updates
    if type(updates) is not dict or len(updates)>100:raise InputError('invalid registration update map')
    current={base['id']:base for base in effective_profile(profile)['bases']};old={base['id']:base for base in (previous or {}).get('bases',[])}
    if set(updates)-set(current):raise InputError('registration update refers to an unselected infobase')
    updates={bid:validate_registrations(rows) for bid,rows in updates.items()}
    clusters={row['id']:row for row in result['clusters']};connections={row['id']:row for row in result['connections']}
    def ras_context(base,record):
        if base['mode']!='server':return None
        bound=clusters.get(base['cluster_id']) if base['cluster_id'] else None
        candidates=[bound] if bound and base['id'] in old else list(reversed(clusters.values()))
        for item in candidates:
            connection=connections.get(item.get('ras_connection_id'))
            if connection is None or ras_connection_signature(connection)!=record['ras_connection_sha256']:continue
            if item['reported_identity'] and item['reported_identity'].lower()==record['cluster_id'].lower():return item
        return None
    def same(record,view):
        if record['mode']!=view['mode']:return False
        key=configuration_key(view['mode'],view['connection'])
        return configuration_key(record['mode'],record['connection'])==key if key is not None else record['connection']==view['connection']
    for base in result['bases']:
        history=base.get('registrations',old.get(base['id'],{}).get('registrations',[]));incoming=updates.get(base['id'],[])
        if not history and not incoming:continue
        view=current[base['id']]
        if base['id'] in updates:
            retained={registration_key(r):r for r in history}
            incoming=[r for r in incoming if not (registration_key(r) in retained and same(retained[registration_key(r)],view) and not same(r,view))]
        records=merge_registrations(history,incoming);base['registrations']=records
        target=configuration_key(view['mode'],view['connection'])
        connected=[r for r in records if (configuration_key(r['mode'],r['connection'])==target if target is not None else r['connection']==view['connection'])]
        connected=[r for r in connected if r['kind']=='starter' or ras_context(base,r) is not None]
        # Selected info may enrich a known direct connection only through an
        # already bound UUID and the unchanged, scoped RAC connection.
        connected += [r for r in records if r['kind']=='ras_info' and r not in connected and ras_context(base,r) is not None
            and base['reported_identity'].lower()==r['infobase_id'].lower()]
        identified=[r for r in connected if r['kind'] in ('ras','ras_info')]
        if identified:
            ids={(r['cluster_id'].lower(),r['infobase_id'].lower(),r['ras_connection_sha256']) for r in identified}
            if len(ids)>1:raise InputError('conflicting RAS registration identities require separate configuration')
            record=identified[-1];base['cluster_id']=ras_context(base,record)['id'];base['reported_identity']=record['infobase_id']
        mode_matches=[r for r in connected if r['mode']==base['mode']]
        def origin(record):
            if record['kind']!='starter':return 'ras_cluster_list' if record['kind']=='ras' else 'ras_selected_infobase_info'
            return 'starter_connect_file' if record['mode']=='file' else 'starter_srvr_ref' if record['mode']=='server' else 'starter_publication'
        base['mode_origin']=dict(basis='reported' if base['mode']!='unknown' else 'unknown',origin=origin(mode_matches[-1]) if mode_matches else 'user_override')
        base['connection_origin']=dict(basis='reported' if base['connection_method']!='unknown' else 'unknown',origin=origin(connected[-1]) if connected else 'user_override')
    return result
