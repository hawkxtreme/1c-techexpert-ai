"""Durable conservative transfer admission, scoped by investigation/declared source."""
from contextlib import contextmanager
import os
from pathlib import Path
import posixpath
import re

from .inputs import InputError
from . import operation_state as fs
from .ssh_sftp import connection

MIB=1024**2
CAPS=dict(max_connections=(1,32,8),max_protocol_bytes=(16384,512*MIB,128*MIB),max_retained_bytes=(1,64*MIB,64*MIB))


def root_path(value):
    if (type(value) is not str or not value.startswith('/') or '\\' in value or '..' in value.split('/')
        or posixpath.normpath(value)!=value or value.startswith('//') or any(ord(c)<32 or ord(c)==127 for c in value)
        or not 1<=len(value.encode('utf-8'))<=2048):raise InputError('SFTP root must be an explicit normalized absolute POSIX directory')
    return value


def source_key(settings):
    # A declared connection domain, not proof of physical host/IB identity.
    return fs.digest({name:settings[name] for name in ('host','port','root')})


def _caps(values):
    result={}
    if type(values) is not dict or set(values)-CAPS.keys():raise InputError('invalid remote budget properties')
    for name,(low,high,default) in CAPS.items():
        value=values.get(name,default)
        if type(value) is not int or not low<=value<=high:raise InputError('remote '+name+' limit outside supported bounds')
        result[name]=value
    return result


def normalize(*,investigation_id,revision,sources,**values):
    if type(investigation_id) is not str or not re.fullmatch('[a-f0-9]{32}',investigation_id) or type(revision) is not int or not 1<=revision<=1000:raise InputError('remote plan requires exact investigation revision')
    if type(sources) is not list or not 1<=len(sources)<=8:raise InputError('select1..8 declared remote sources')
    result=[];ids=set();keys=set()
    for source in sources:
        if type(source) is not dict or set(source)-{'id','connection',*CAPS}:raise InputError('invalid remote source plan')
        identifier=source.get('id')
        if type(identifier) is not str or not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,63}',identifier) or identifier in ids:raise InputError('invalid or duplicate remote source ID')
        settings=connection(source.get('connection'));root_path(settings['root']);key=source_key(settings)
        if key in keys:raise InputError('duplicate declared SFTP connection root')
        ids.add(identifier);keys.add(key)
        result.append(dict(id=identifier,connection=settings,**_caps({k:v for k,v in source.items() if k in CAPS})))
    return dict(investigation_id=investigation_id,revision=revision,sources=result,**_caps(values))


def _read(path):
    try:
        doc=fs.read(path,65536)
        if type(doc) is not dict or set(doc)!={'schema_version','value','sha256'} or doc['schema_version']!=1 or fs.digest(doc['value'])!=doc['sha256']:raise InputError('remote budget integrity mismatch')
        return doc['value']
    except (OSError,ValueError,KeyError,TypeError) as exc:raise InputError('remote budget state is incomplete or corrupt; consumption is unknown') from exc


def _document(value):
    raw=fs.encode(dict(schema_version=1,value=value,sha256=fs.digest(value)))
    if len(raw)>65536:raise InputError('remote budget record exceeds limit')
    return raw


def _new(path,value):
    raw=_document(value)
    with fs.safe(path).open('xb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())


def _replace(path,value):
    _document(value)
    fs.write(path,dict(schema_version=1,value=value,sha256=fs.digest(value)))


def _ledger(state,identifier,configuration):
    root=fs.safe(Path(state)/'remote-budgets');folder=fs.safe(root/identifier)
    authority=fs.private(Path(state)/'remote-budget-authority');index=authority/'index.json'
    with fs.writer(authority):
        if index.exists():
            registered=_read(index)
            if (type(registered) is not dict or len(registered)>1024
                or any(not re.fullmatch('[a-f0-9]{32}',key) or type(value) is not str or not re.fullmatch('[a-f0-9]{64}',value)
                       for key,value in registered.items())):raise InputError('remote budget authority inventory is unknown')
            if registered and not root.is_dir():raise InputError('remote budget history missing; consumption unknown')
        else:
            if root.exists():raise InputError('remote budget authority missing; previous consumption unknown')
            registered={}
        tag=fs.digest(configuration)
        if identifier in registered:
            if registered[identifier]!=tag:raise InputError('remote budget configuration already fixed for this investigation; no implicit expansion/reset')
            if not folder.is_dir():raise InputError('registered remote budget history missing; consumption unknown')
        else:
            if folder.exists() or len(registered)>=1024:raise InputError('remote budget history is unregistered or authority limit reached')
            # Register first: a crash during initialization must remain unknown, never a fresh budget.
            _replace(index,dict(registered,**{identifier:tag}))
            fs.private(folder);fs.private(folder/'charges')
            _new(folder/'configuration.json',configuration)
            _new(folder/'inventory.json',dict(configuration_digest=tag,charges={}))
    return folder


@contextmanager
def reserve(state,settings,source_id,run_id,protocol_bytes,retained_bytes):
    settings=normalize(**settings)
    if type(run_id) is not str or not re.fullmatch('[a-f0-9]{64}',run_id):raise InputError('remote transfer requires a managed run identity')
    if type(protocol_bytes) is not int or not 16384<=protocol_bytes<=256*MIB or type(retained_bytes) is not int or not 0<=retained_bytes<=64*MIB:raise InputError('invalid per-call transfer reservation')
    selected=next((s for s in settings['sources'] if s['id']==source_id),None)
    if selected is None:raise InputError('source outside selected remote plan')
    configuration={k:v for k,v in settings.items() if k!='revision'}
    folder=_ledger(state,settings['investigation_id'],configuration);charges=fs.safe(folder/'charges')
    domain=fs.private(Path(state)/'remote-source-locks'/source_key(selected['connection']))
    with fs.writer(folder),fs.writer(domain):
        if _read(folder/'configuration.json')!=configuration:raise InputError('remote budget configuration integrity mismatch')
        inventory=_read(folder/'inventory.json');tag=fs.digest(configuration)
        if (type(inventory) is not dict or set(inventory)!={'configuration_digest','charges'} or inventory['configuration_digest']!=tag
            or type(inventory['charges']) is not dict or len(inventory['charges'])>32
            or any(not re.fullmatch('[a-f0-9]{64}',key) or type(value) is not str or not re.fullmatch('[a-f0-9]{64}',value)
                   for key,value in inventory['charges'].items()) or not charges.is_dir()):raise InputError('remote budget charge inventory missing or invalid; consumption unknown')
        records=[]
        with os.scandir(charges) as entries:
            seen=set()
            for entry in entries:
                if len(records)>=32 or not re.fullmatch(r'[a-f0-9]{64}\.json',entry.name):raise InputError('remote budget charge inventory is unknown or excessive')
                record=_read(charges/entry.name)
                key=entry.name[:-5];seen.add(key)
                if (type(record) is not dict or record.get('run_id')!=key or inventory['charges'].get(key)!=fs.digest(record) or record.get('configuration_digest')!=tag
                    or record.get('source_id') not in {s['id'] for s in settings['sources']}
                    or type(record.get('reserved_protocol_bytes')) is not int or not 16384<=record['reserved_protocol_bytes']<=256*MIB
                    or type(record.get('reserved_retained_bytes')) is not int or not 0<=record['reserved_retained_bytes']<=64*MIB):raise InputError('invalid retained remote reservation; consumption unknown')
                if record['run_id']==run_id:raise InputError('remote operation already reserved; verify saved outcome, never reconnect')
                records.append(record)
        if seen!=set(inventory['charges']):raise InputError('remote budget charge history missing; consumption unknown')
        selected_records=[r for r in records if r['source_id']==source_id]
        for owner,previous in ((settings,records),(selected,selected_records)):
            if len(previous)+1>owner['max_connections']:raise InputError('remote connection budget exhausted')
            if sum(r['reserved_protocol_bytes'] for r in previous)+protocol_bytes>owner['max_protocol_bytes']:raise InputError('remote protocol budget exhausted')
            if sum(r['reserved_retained_bytes'] for r in previous)+retained_bytes>owner['max_retained_bytes']:raise InputError('remote retained byte budget exhausted')
        value=dict(schema_version=1,run_id=run_id,source_id=source_id,configuration_digest=fs.digest(configuration),
            reserved_protocol_bytes=protocol_bytes,reserved_retained_bytes=retained_bytes,charged_connections=1,
            owner=fs.process_identity(os.getpid()),created_at=fs.stamp(),unused_allowance_refunded=False,
            accounting_scope='per investigation and declared connection root; reservations remain consumed after success/failure/uncertainty')
        # Commit expected membership before the immutable charge. Any partial write fails closed.
        _replace(folder/'inventory.json',dict(configuration_digest=tag,charges=dict(inventory['charges'],**{run_id:fs.digest(value)})))
        path=charges/(run_id+'.json');_new(path,value)
        yield dict(value,reservation_file=str(path),reservation_digest=fs.digest(value),max_parallel_connections=1)
