"""Pure configured SSH projections. Never inspect trust, keys, hosts or paths."""
import hashlib
from .inputs import InputError
from .ssh_sftp import connection
from .remote_budget import root_path

KEYS=frozenset(('port','identity_file','known_hosts_file','python'))
JOURNAL_KEYS=frozenset(('transport','port','identity_file','known_hosts_file'))


def is_ssh(value):
    return value is not None and (value['kind']=='ssh' or value['kind']=='os' and value['settings'].get('transport')=='ssh')


def settings(address,value):
    if type(value) is not dict or set(value)-KEYS:raise InputError('unsupported shared SSH settings')
    value={k:v for k,v in value.items() if k!='identity_file' or v!=''}
    checked=connection(dict(host=address,node='configured',root='/',**{k:v for k,v in value.items() if k!='python'}))
    result={k:v for k,v in checked.items() if k in KEYS}
    if 'python' in value:
        item=value['python']
        if type(item) is not str or not 1<=len(item)<=2048 or any(ord(c)<32 for c in item):raise InputError('invalid configured SSH Python reference')
        result['python']=item
    return result


def journal_settings(value):
    return dict(transport='sftp',**{k:v for k,v in settings(value['address'],{k:v for k,v in value['settings'].items() if k in KEYS}).items() if k!='python'})


def journal(path,host,value):
    root_path(path)
    return settings(host,{k:v for k,v in value.items() if k in KEYS})


def endpoint(value):
    return ('ssh',value['address'],value['settings'].get('port',22)) if is_ssh(value) else ('address',value['address'])


def fingerprint(value,*,journal_only=False):
    if is_ssh(value):
        configured=value['settings']
        keys=KEYS-{'python'} if journal_only else KEYS
        return dict(kind='configured_ssh',address=value['address'],settings={key:configured.get(key,22 if key=='port' else 'python3' if key=='python' else '') for key in keys})
    return {key:value[key] for key in ('kind','address','settings','credential_ref') if key!='credential_ref' or value['kind']!='os'}


def selected_sources(profile,source_ids,limits):
    from .profile_resources import validate
    if type(profile) is not dict or profile.get('schema_version')!=2:raise InputError('A saved shared environment profile is required; configure it in init first')
    configured=validate(profile)
    sources={s['id']:s for s in configured['sources']};connections={c['id']:c for c in configured['connections']};nodes={n['id']:n for n in configured['nodes']}
    result=[];bindings=[];groups={}
    for identifier in source_ids:
        source=sources.get(identifier)
        if source is None or source['type'] not in ('tj','jr'):raise InputError('Select existing configured TJ/JR sources for SFTP acquisition')
        access=connections.get(source['connection_id'])
        if not is_ssh(access):raise InputError('Selected journal has local access; configure an explicit shared SSH connection first')
        journal(source['path'],access['address'],journal_settings(access))
        group=(access['id'],source['path'])
        if group not in groups:
            identity='source-'+hashlib.sha256((access['id']+'\0'+source['path']).encode('utf-8')).hexdigest()[:24]
            groups[group]=identity
            node=nodes[source['node_id']]['name'] if source['node_id'] else access['address']
            connection_value=dict(host=access['address'],node=node,root=source['path'],**{k:v for k,v in journal_settings(access).items() if k!='transport'})
            result.append(dict(id=identity,connection=connection_value,**limits))
        bindings.append(dict(configured_source_id=identifier,plan_source_id=groups[group],connection_id=access['id'],source_type=source['type'],
            path=source['path'],base_ids=list(source['base_ids']),parser_settings=dict(source['settings']),identity_basis='configured_profile_not_observed'))
    return result,bindings
