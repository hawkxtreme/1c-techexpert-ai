"""Explicit offline plans, metadata previews and complete bounded SFTP captures."""
import hashlib
from pathlib import Path
import uuid

from . import artifacts,input_files,investigations,operation_state as fs,remote_budget,remote_sources
from .inputs import InputError,read_snapshot
from .ssh_sftp import Session,ssh_command

PLAN='sftp-transfer-plan-v1'
CATALOG='sftp-v3-catalogue-v1'
LIMITATIONS=[
    'Source node, allowed path and process/IB ownership remain caller-reported; SSH host-key checks are not database/run identity.',
    'SFTPv3 checks visible paths/metadata and repeated bytes, not atomic root confinement, an atomic multi-file snapshot, clock alignment or absence of ABA/unseen writes.',
    'The server account must have appropriate read access; the client does not grant permissions or prove server-side read-only confinement.',
    'Reservations bound SFTP framing, SSH diagnostics and retained bytes. Encrypted network/SSH handshake overhead is unknown; no exact total TCP traffic claim.',
    'One connection per investigation and declared connection root. Reserved allowance is permanently consumed even after success/failure/uncertainty; no implicit retry/refund/reset.',
    'Only the local owned SSH client is stopped/verified here. Remote server-side session termination after connection loss remains unknown.',
    'Transfer is separate from diagnostic format; a complete file does not prove collection continuity, whole-job coverage or a cause.']


def dependency(state,report):
    folder=fs.safe(artifacts.artifact_folder(state,report['artifact_id']));fs.inventory(folder)
    return dict(id=report['artifact_id'],report_digest=fs.digest(report),receipt_digest=fs.digest(fs.read(folder/'receipt.json',8192)))


def prepare(state,output,**arguments):
    settings=remote_budget.normalize(**arguments)
    doc=investigations.load(state,settings['investigation_id'],revision=settings['revision'])
    folder=investigations.revision_folder(state,settings['investigation_id'],settings['revision'])
    known={}
    for source in settings['sources']:
        _,metadata=input_files.read(source['connection']['known_hosts_file'],65536)
        known[source['id']]=metadata['sha256']
    result=dict(schema_version=1,profile=PLAN,settings=settings,known_hosts_sha256=known,network_started=False,max_parallel_connections=1,
        investigation=dict(id=settings['investigation_id'],revision=settings['revision'],report_digest=fs.digest(doc),receipt_digest=fs.digest(fs.read(folder/'receipt.json',8192))),
        limitations=LIMITATIONS,requires_ai_interpretation=True)
    return artifacts.save_artifact(output,'remote_plan',settings,[],result)


def read_plan(state,identifier):
    fs.inventory(fs.safe(artifacts.artifact_folder(state,identifier)))
    report=artifacts.load_artifact(state,identifier);result=report.get('result')
    if (report.get('kind')!='remote_plan' or report.get('sources')!=[] or type(result) is not dict
        or result.get('profile')!=PLAN or result.get('schema_version')!=1):raise InputError('verified remote transfer plan required')
    settings=remote_budget.normalize(**result['settings'])
    if settings!=result['settings'] or set(result.get('known_hosts_sha256',{}))!={s['id'] for s in settings['sources']}:raise InputError('invalid saved remote settings/trust binding')
    return report


def read_catalogue(state,identifier,plan_id,source_id):
    fs.inventory(fs.safe(artifacts.artifact_folder(state,identifier)))
    report=artifacts.load_artifact(state,identifier);result=report.get('result')
    if (report.get('kind')!='remote_catalog' or report.get('sources')!=[] or type(result) is not dict
        or result.get('profile')!=CATALOG or result.get('transfer_status')!='completed'
        or result.get('plan',{}).get('id')!=plan_id or result.get('source_id')!=source_id):raise InputError('complete matching remote metadata catalogue required')
    return report


def managed_run(output,operation,investigation_id):
    folder=Path(output).parent;plan=fs.plan(folder)
    if plan['request']['operation']!=operation or fs.safe(Path(plan['state_dir'])/'operations'/folder.name)!=fs.safe(folder):raise InputError('remote connection requires its exact managed operation plan')
    context=plan['request'].get('context')
    if context is not None and context['investigation_id']!=investigation_id:raise InputError('remote source plan belongs to another investigation context')
    return folder.name


def _selected(plan,source_id):
    selected=next((s for s in plan['result']['settings']['sources'] if s['id']==source_id),None)
    if selected is None:raise InputError('source outside selected remote plan')
    return selected


def _trust(output,plan,source):
    raw,metadata=input_files.read(source['connection']['known_hosts_file'],65536,keep=True)
    if metadata['sha256']!=plan['result']['known_hosts_sha256'][source['id']]:raise InputError('known_hosts changed since the explicit transfer plan; review trust separately')
    folder=fs.private(Path(output)/'remote-trust'/uuid.uuid4().hex);path=folder/'known_hosts'
    with path.open('xb') as stream:stream.write(raw)
    return dict(source['connection'],known_hosts_file=str(path))


def _session(state,output,plan,source,operation,protocol_bytes,retained_bytes,timeout_seconds,stop,work):
    plan_tag=dependency(state,plan)
    settings=_trust(output,plan,source);run_id=managed_run(output,operation,plan['result']['settings']['investigation_id'])
    with remote_budget.reserve(state,plan['result']['settings'],source['id'],run_id,protocol_bytes,retained_bytes) as charge:
        started=fs.stamp();client=Session(ssh_command(settings),max_bytes=protocol_bytes,timeout=timeout_seconds,should_stop=stop)
        error=None;value=None
        try:
            with client:value=work(client)
        except (OSError,ValueError) as exc:error=str(exc)[:2048]
        # Raw diagnostic output is private work, never a promoted journal source.
        error_folder=fs.private(Path(output)/'remote-diagnostics'/run_id)
        with (error_folder/'stderr.bin').open('xb') as stream:stream.write(bytes(client.stderr))
        if client.reason and error is None:error='SFTP session stopped: '+client.reason
        status='cancelled' if client.reason=='cancelled' else 'incomplete' if error else 'completed'
        return value,dict(source_id=source['id'],plan=plan_tag,charge=charge,transfer_status=status,error=error,
            transport=dict(profile='sftp-v3-over-openssh',host=source['connection']['host'],port=source['connection']['port'],node=source['connection']['node'],
                original_root=source['connection']['root'],known_hosts_sha256=plan['result']['known_hosts_sha256'][source['id']],
                acquisition_started=started,acquisition_ended=fs.stamp(),atomic_snapshot=False,local_client_closed=client.closed,remote_session_stop_verified=False),
            transfer_metrics=client.metrics(),limitations=LIMITATIONS,requires_ai_interpretation=True)


def inspect(state,output,*,plan_id,source_id,protocol_bytes=1024**2,timeout_seconds=30,limits=None,stop=None):
    plan=read_plan(state,plan_id);source=_selected(plan,source_id);limits=remote_sources.bounds(limits or {})
    value,result=_session(state,output,plan,source,'remote.inspect',protocol_bytes,0,timeout_seconds,stop,
        lambda client:remote_sources.inspect_tree(client,source['connection']['root'],**limits))
    result.update(schema_version=1,profile=CATALOG,listing_complete=False,truncated=False,members=[],collection_coverage='unknown')
    if value is not None and result['transfer_status']=='completed':result.update(value)
    return artifacts.save_artifact(output,'remote_catalog',dict(plan_id=plan_id,source_id=source_id,protocol_bytes=protocol_bytes,timeout_seconds=timeout_seconds,limits=limits),[],result)


def capture(state,output,*,plan_id,source_id,catalog_id,members,protocol_bytes=64*1024**2,max_bytes=16*1024**2,timeout_seconds=60,stop=None):
    plan=read_plan(state,plan_id);source=_selected(plan,source_id);catalogue=read_catalogue(state,catalog_id,plan_id,source_id)
    catalogue_tag=dependency(state,catalogue)
    if catalogue['result']['plan']!=dependency(state,plan):raise InputError('remote plan changed since catalogue')
    if type(members) is not list or not 1<=len(members)<=32 or len(set(members))!=len(members):raise InputError('select1..32 unique remote catalogue member IDs')
    found={m['id']:m for m in catalogue['result']['members']};selection=[]
    for identifier in members:
        member=found.get(identifier)
        if member is None or not member.get('importable'):raise InputError('selected remote member is unavailable or exceeds preview limits')
        selection.append(member)
    total=sum(m['bytes'] for m in selection)
    if type(max_bytes) is not int or not 1<=max_bytes<=64*1024**2 or total>max_bytes:raise InputError('selected remote files exceed approved retained byte budget')
    value,result=_session(state,output,plan,source,'remote.capture',protocol_bytes,total,timeout_seconds,stop,
        lambda client:remote_sources.capture_files(client,source['connection']['root'],selection,output))
    result.update(schema_version=1,profile='sftp-v3-capture-v1',catalogue=catalogue_tag,capture_complete=False,members=[],roots=[],file_count=0,expanded_bytes=0,collection_coverage='unknown')
    sources=[]
    if value is not None and result['transfer_status']=='completed':
        connection=source['connection'];uri='sftp://'+connection['host']+':'+str(connection['port'])+connection['root']
        result.update(capture_complete=True,roots=[dict(kind='sftp',path=uri)],file_count=len(value),expanded_bytes=total)
        for number,member in enumerate(value,1):
            raw=read_snapshot(member['path'])
            if len(raw)!=member['bytes'] or hashlib.sha256(raw).hexdigest()!=member['sha256']:raise InputError('owned remote capture changed before artifact seal')
            sources.append((uri.rstrip('/')+'/'+member['relative_path'],raw))
            result['members'].append(dict(id=member['member_id'],root=0,relative_path=member['relative_path'],source_id='s'+str(number),
                bytes=member['bytes'],sha256=member['sha256'],importable=True,capture={k:v for k,v in member.items() if k!='path'}))
    return artifacts.save_artifact(output,'remote_capture',dict(plan_id=plan_id,source_id=source_id,catalog_id=catalog_id,members=members,protocol_bytes=protocol_bytes,max_bytes=max_bytes,timeout_seconds=timeout_seconds),sources,result)
