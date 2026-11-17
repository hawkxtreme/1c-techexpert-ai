"""Explicit offline logcfg proposals and conditional rollback, never node writes."""
import difflib
import hashlib
import ntpath
from pathlib import Path
import posixpath
import re
import stat
import uuid
from xml.sax.saxutils import quoteattr

from . import artifacts, operation_state as fs
from .inputs import InputError, read_snapshot
from .logcfg_xml import NS, MAX_BYTES, XmlIssue, inspect, insert, remove_owned

PROFILE='logcfg-text-8.3.27.1989-v1'
EVENTS=('CALL','SCALL','SDBL','DBV8DBENG','DBMSSQL','DBPOSTGRS','PROC','SESN','CONN','EXCP','TLOCK','TTIMEOUT','TDEADLOCK')
REFERENCES=['https://1c-dn.com/library/tutorials/1c_enterprise_administrator_guide_file_mode_8_3_27/']
LIMITATIONS=[
    'Offline proposal only: target paths, process account, active configuration selection and write rights are caller-reported, not probed.',
    'XML syntax and a finite reviewed added-block profile do not validate every existing rule or prove live platform acceptance/event arrival.',
    'Duration and byte limits require an administrator or separately authorized controller; this XML does not stop collection automatically.',
    'Existing rules remain unchanged and may have additional load, privacy and retention effects. Collection cannot recover past events.',
    'Size rotation/plain text can use short local timestamps: retain source node, platform version, utc_offset and acquisition/window evidence separately.']


def _text(value,limit=2048):
    if type(value) is not str or not 1<=len(value)<=limit or any(ord(c)<32 for c in value):raise InputError('invalid bounded logcfg text')
    return value


def _remote_path(value,os,*,config=False):
    value=_text(value)
    path=ntpath if os=='windows' else posixpath
    if (not path.isabs(value) or '..' in re.split(r'[/\\]',value) or '%' in value or '$' in value
        or os=='windows' and (not ntpath.splitdrive(value)[0] or any(c in value for c in '*?<>|"'))
        or config and path.basename(value)!= 'logcfg.xml'):
        raise InputError('logcfg requires an explicit absolute target path; configuration file must be logcfg.xml')
    if os=='windows':
        from .input_files import name_parts
        tail=ntpath.splitdrive(value)[1]
        for part in re.split(r'[/\\]',tail):
            if part:name_parts(part)
    return value


def normalize(**arguments):
    result=dict(arguments)
    absent=result.setdefault('current_absent',False);current=result.get('current_file')
    if type(absent) is not bool or absent==bool(current):raise InputError('select a supplied current_file OR explicit current_absent')
    if current:result['current_file']=str(Path(_text(current)).absolute())
    else:result.pop('current_file',None)
    for key in ('node','purpose'):_text(result.get(key),256 if key=='node' else 2048)
    if result.get('os') not in ('windows','linux') or result.get('mode') not in ('file','server'):raise InputError('unsupported logcfg node OS or infobase mode')
    if result.get('process') not in ('client','terminal','web','rphost','rmngr','ragent'):raise InputError('unsupported process role')
    if result['mode']=='file' and result['process'] in ('rphost','rmngr','ragent'):raise InputError('file infobase has no required cluster server process')
    if result.get('platform_version')!='8.3.27.1989':raise InputError('unsupported logcfg preparation profile/version')
    for field in ('config_path','log_location'):result[field]=_remote_path(result.get(field),result['os'],config=field=='config_path')
    if _path_key(result['config_path'],result['os'])==_path_key(result['log_location'],result['os']):raise InputError('log location must be a separate directory')
    events=result.get('events')
    if type(events) is not list or not 1<=len(events)<=len(EVENTS) or any(type(e) is not str or e not in EVENTS for e in events) or len(set(events))!=len(events):raise InputError('select unique supported event names')
    result['events']=sorted(events)
    for field,low,high,default in [('history_hours',1,168,1),('duration_seconds',1,604800,300),('max_bytes',16384,1024**3,16*1024**2)]:
        value=result.setdefault(field,default)
        if type(value) is not int or not low<=value<=high:raise InputError('logcfg plan limit outside supported range')
    if result['history_hours']*3600<result['duration_seconds']:raise InputError('retention must cover this finite observation plan; choose explicit sufficient history_hours')
    return result


def _path_key(value,os):
    return ntpath.normcase(ntpath.normpath(value)) if os=='windows' else posixpath.normpath(value)


def _read(path):
    try:
        info=Path(path).lstat()
        if not stat.S_ISREG(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise InputError('logcfg supplied copy must be a regular unlinked file')
        return read_snapshot(path,MAX_BYTES)
    except PermissionError as exc:raise InputError('logcfg supplied copy requires read access; provide an authorized local copy') from exc
    except OSError as exc:raise InputError('cannot read supplied logcfg copy; missing input is not proof of absence on the node') from exc


def _diff(before,after):
    lines=difflib.unified_diff(before.decode('utf-8-sig',errors='replace').splitlines(keepends=True),
        after.decode('utf-8-sig',errors='replace').splitlines(keepends=True),fromfile='supplied',tofile='proposed')
    return ''.join(line if line.endswith('\n') else line+'\n\\ No newline at end of file\n' for line in lines).encode('utf-8')


def _save(state,kind,args,sources,result,names):
    result.update(requires_ai_interpretation=True,limitations=list(LIMITATIONS),references=REFERENCES)
    return artifacts.save_artifact(state,kind,args,sources,result,source_names=names)


def prepare(state,**arguments):
    args=normalize(**arguments)
    raw=b'' if args['current_absent'] else _read(args['current_file'])
    sources=[(args.get('current_file','caller reported absent'),raw)];names=['original-logcfg.xml']
    target={key:args[key] for key in ('node','os','mode','process','platform_version','config_path','log_location')}
    target['basis']='caller_reported'
    result=dict(profile=PROFILE,status='needs_review',target=target,current_absent=args['current_absent'],
        validation=dict(xml='unknown',added_profile='not_checked',existing_rules='opaque_preserved',application='not_applied',event_arrival='unknown'),
        collection_plan=dict(purpose=args['purpose'],events=args['events'],duration_seconds=args['duration_seconds'],max_bytes=args['max_bytes'],
            scope='all matching events from every process using this configuration',process_or_infobase_filter_generated=False,
            history_hours=args['history_hours'],limits_enforced_by_xml=False,retention_note='history is retention in hours, not collection duration or a byte cap; this finite profile requires retention at least its planned duration without claiming complete capture',
            load_estimate='unknown_until_representative_measurement',start='only after reviewed application',
            stop='administrator stops at earliest of duration, byte budget, incident completion or error; preserve collected files'),
        access=dict(principal='actual user or service account of the selected process',
            required=['administrator access to selected configuration file','process read access to configuration','process write access to selected log directory']),
        verification=['Compare current node file with original SHA256/absence immediately before any application; stop on divergence.',
            'Administrator saves a backup and applies only this reviewed proposal to the confirmed process configuration path.',
            'Allow configuration reload, reproduce an approved small test action and inspect new events/time/version/node and directory growth.',
            'No matching test event means collection remains unverified: check active path, process identity, rights and filters; do not claim absence of cause.',
            'Stop collection within the plan, then request logcfg.rollback_plan using a fresh copy of the current file. No automatic overwrite of later edits.'])
    document_raw=raw or (f'<?xml version="1.0" encoding="UTF-8"?>\n<config xmlns="{NS}">\n</config>\n'.encode() if args['current_absent'] else raw)
    try:
        document=inspect(document_raw)
        result['validation']['xml']='well_formed'
        logs=[n for n in document['nodes'] if n['depth']==1 and n['name']==NS+'}log']
        result['existing_log_count']=len(logs)
        if any(_path_key(n['attrs'].get('location',''),args['os'])==_path_key(args['log_location'],args['os']) for n in logs):raise XmlIssue('destination_already_configured')
        change_id=uuid.uuid4().hex;newline='\r\n' if b'\r\n' in document_raw else '\n'
        rows=['<!-- techexpert:begin '+change_id+' -->',f'  <log xmlns="{NS}" location={quoteattr(args["log_location"])} history="{args["history_hours"]}" format="text" placement="plain" rotation="size" rotationsize="1">']
        rows += [f'    <event><eq property="name" value="{event}"/></event>' for event in args['events']]
        rows += ['    <property name="all"/>','  </log>','<!-- techexpert:end '+change_id+' -->']
        text=newline+newline.join(rows)+newline
        proposed=insert(document_raw,document,text.encode('utf-8'));inspect(proposed)
        result.update(status='ready',change_id=change_id,inserted_text=text,original_sha256=hashlib.sha256(raw).hexdigest(),proposal_sha256=hashlib.sha256(proposed).hexdigest())
        result['validation']['added_profile']='reviewed_static_profile_not_live_certification'
        sources.extend([('prepared proposal',proposed),('reviewable difference',_diff(raw,proposed))]);names.extend(['logcfg.xml','change.diff'])
    except XmlIssue as exc:result['reason']=str(exc)
    return _save(state,'logcfg_proposal',args,sources,result,names)


def _proposal(state,identifier):
    folder=fs.safe(artifacts.artifact_folder(state,identifier));fs.inventory(folder)
    report=artifacts.load_artifact(state,identifier)
    if report['kind']!='logcfg_proposal' or report['result'].get('profile')!=PROFILE or report['result'].get('status')!='ready':raise InputError('ready logcfg proposal required')
    result=report['result']
    raw=[read_snapshot(artifacts.source_path(folder,s),MAX_BYTES) for s in report['sources'][:2]]
    if len(raw)!=2 or hashlib.sha256(raw[0]).hexdigest()!=result.get('original_sha256') or hashlib.sha256(raw[1]).hexdigest()!=result.get('proposal_sha256'):raise InputError('logcfg proposal source integrity mismatch')
    return report,raw,dict(id=identifier,report_digest=fs.digest(report),receipt_digest=fs.digest(fs.read(folder/'receipt.json',8192)))


def rollback_plan(state,*,proposal_id,current_file,output_state=None):
    proposal,(original,proposed),parent=_proposal(state,proposal_id)
    raw=_read(current_file);result=dict(profile=PROFILE,status='needs_review',action='none',parent=parent,target=proposal['result']['target'],validation=dict(application='not_applied'))
    sources=[(str(Path(current_file).absolute()),raw)];names=['current-logcfg.xml']
    try:
        if raw==original and not proposal['result']['current_absent']:result.update(status='no_change',rollback_basis='exact_original')
        else:
            document=inspect(raw)
            if raw==proposed:
                restored=original;basis='exact_proposal'
            else:
                restored=remove_owned(raw,document,proposal['result']['change_id'],proposal['result']['inserted_text'].encode('utf-8'))
                inspect(restored);basis='unchanged_owned_block'
            remove=raw==proposed and proposal['result']['current_absent']
            result.update(status='ready',action='remove_file' if remove else 'replace_file',rollback_basis=basis,
                expected_current_sha256=hashlib.sha256(raw).hexdigest(),restored_sha256=None if remove else hashlib.sha256(restored).hexdigest(),
                instruction='Administrator compares the exact current SHA256 before the reviewed rollback; divergence requires a new plan. Keep the collected logs. This operation has applied nothing.')
            if not remove:sources.append(('prepared rollback',restored));names.append('logcfg.xml')
            sources.append(('rollback difference',_diff(raw,b'' if remove else restored)));names.append('change.diff')
    except XmlIssue as exc:result['reason']=str(exc)
    return _save(state if output_state is None else output_state,'logcfg_rollback',dict(proposal_id=proposal_id,current_file=str(Path(current_file).absolute())),sources,result,names)
