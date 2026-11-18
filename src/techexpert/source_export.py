"""Reviewed export of an editable main configuration from a private file-IB copy.

Planning never starts 1C. Execution cannot pass the original IB to Designer.
Export provenance does not establish correspondence to a running DB configuration.
"""
from datetime import datetime,timezone
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import time
import uuid
import xml.etree.ElementTree as ET

from . import windows_native as native
from .artifacts import encoded,save_artifact,load_artifact,artifact_folder
from .inputs import InputError,json_value,read_snapshot
from .source_code import snapshot_source
from .storage import write_json

VERSION='8.3.27.1989'
FLOOR=10*1024**3
MIB=1024**2
GIB=1024**3
REQUEST_KEYS={'schema_version','platform_executable','platform_version','database_path','database_closed','database_mode',
    'configuration','output_directory','timeout_seconds','max_copy_bytes','max_output_bytes','max_files'}


def _sha(data):return hashlib.sha256(data).hexdigest()
def _stamp():return datetime.now(timezone.utc).isoformat()
def _identity(path):return native.file_identity(Path(path))


def _local(value):
    if not isinstance(value,str) or not value or len(value)>2048 or any(ord(x)<32 for x in value):raise InputError('local path requires bounded text')
    if value.replace('\\','/').startswith('//') or value.startswith(('\\\\?\\','\\\\.\\')):raise InputError('UNC and device paths are not supported for source export')
    path=Path(value)
    if not path.is_absolute() or '..' in path.parts:raise InputError('source export requires absolute local paths without parent traversal')
    for part in path.parts[1:]:
        if ':' in part or any(x in part for x in '*?"<>|') or re.fullmatch(r'(?i)(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?',part):raise InputError('invalid local path component')
    for component in (path,*path.parents):
        try:info=component.lstat()
        except FileNotFoundError:continue
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise InputError('source export paths must not traverse links or reparse points')
    return path.resolve()


def _nearest(path):
    for parent in (path,*path.parents):
        if parent.exists():return parent
    raise InputError('no accessible local volume for source export')


def _overlap(first,second):return first==second or first.is_relative_to(second) or second.is_relative_to(first)


def _binary(path):
    path=_local(str(path))
    if path.name.casefold()!='1cv8.exe' or not path.is_file():raise InputError('select an installed 1cv8.exe, not a starter or script')
    before=_identity(path);version=native.file_version(path);data=read_snapshot(path,64*MIB)
    if version!=VERSION:raise InputError('detected platform version is not supported by this export profile')
    if _identity(path)!=before:raise InputError('platform changed during inspection')
    return dict(path=str(path),version=version,sha256=_sha(data),identity=before)


def _default_binary():
    for key in ('ProgramFiles','ProgramFiles(x86)'):
        if os.environ.get(key):
            candidate=Path(os.environ[key])/'1cv8'/VERSION/'bin/1cv8.exe'
            if candidate.is_file():return str(candidate)
    raise InputError('compatible installed Windows platform not found; specify its local executable or use existing XML/BSL')


def _request(value):
    if not isinstance(value,dict) or set(value)-REQUEST_KEYS or type(value.get('schema_version')) is not int or value.get('schema_version')!=1:raise InputError('invalid source export request properties')
    if value.get('database_mode')!='file' or value.get('configuration')!='main':raise InputError('this profile exports only the editable main configuration of a file IB')
    if value.get('database_closed') is not True:raise InputError('close the selected file IB or provide a closed test copy before export')
    if value.get('platform_version')!=VERSION:raise InputError('source export requires the verified platform version '+VERSION)
    result=dict(value)
    for key,default,low,high in (('timeout_seconds',120,1,600),('max_copy_bytes',GIB,1,8*GIB),('max_output_bytes',64*MIB,1024,64*MIB),('max_files',20000,1,20000)):
        number=value.get(key,default)
        if type(number) is not int or not low<=number<=high:raise InputError('invalid source export limit '+key)
        result[key]=number
    result['database_path']=str(_local(value.get('database_path')))
    result['platform_executable']=str(_local(value.get('platform_executable') or _default_binary()))
    return result


def _folder(state,plan_id):
    if not isinstance(plan_id,str) or not re.fullmatch('[a-f0-9]{32}',plan_id):raise InputError('invalid source export plan identifier')
    return Path(state)/'source-exports'/plan_id


def _argv(plan):
    capture=Path(plan['capture_directory'])
    return [plan['platform']['path'],'DESIGNER','/F',plan['working_directory'],'/DumpConfigToFiles',plan['output_directory'],
        '-Format','Hierarchical','/DisableStartupDialogs','/DisableStartupMessages','/DisableSplash',
        '/Out',str(capture/'designer.log'),'/DumpResult',str(capture/'result.txt')]


def _space(work,output,copy_bytes,output_bytes):
    work_parent=_nearest(work);output_parent=_nearest(output)
    same=work_parent.stat().st_dev==output_parent.stat().st_dev
    required=FLOOR+copy_bytes+4*MIB+(output_bytes if same else 0)
    if shutil.disk_usage(work_parent).free<required or (not same and shutil.disk_usage(output_parent).free<FLOOR+output_bytes):raise InputError('not enough free space for private copy, export and 10 GiB floor')


def prepare(state_dir,request):
    request=_request(request);state=_local(str(Path(state_dir).absolute()));database=_local(request['database_path'])
    source=database/'1Cv8.1CD';_local(str(source))
    if not database.is_dir() or not source.is_file():raise InputError('selected file IB requires a regular 1Cv8.1CD')
    identity=_identity(source)
    if identity['bytes']>request['max_copy_bytes']:raise InputError('source IB exceeds planned copy limit; provide a smaller closed test copy or ready XML/BSL')
    platform=_binary(request['platform_executable']);plan_id=uuid.uuid4().hex;folder=_folder(state,plan_id)
    output=_local(request['output_directory']) if request.get('output_directory') else folder/'source'
    if output.suffix.lower() in ('.zip','.7z','.rar','.cf','.cfe') or output.exists():raise InputError('export requires a new directory, not an archive or existing output')
    if request.get('output_directory') and not output.parent.is_dir():raise InputError('explicit output parent must already exist')
    if folder.is_relative_to(output):raise InputError('output directory must not contain the private operation folder')
    if _overlap(folder,database) or _overlap(output,database) or _overlap(folder,Path(platform['path']).parent) or _overlap(output,Path(platform['path']).parent):raise InputError('private export paths must stay outside original IB and platform directories')
    _space(folder,output,identity['bytes'],request['max_output_bytes'])
    request['output_directory']=str(output)
    plan=dict(schema_version=1,plan_id=plan_id,created_at=_stamp(),profile='windows-file-designer-8.3.27.1989-v1',request=request,
        platform=platform,source_file=str(source),source_identity=identity,working_directory=str(folder/'work-ib'),
        capture_directory=str(folder/'capture'),output_directory=str(output),execution_started=False,requires_explicit_run=True,
        configuration_scope='editable_main_configuration',working_version_match='unknown',extensions_included=False,
        permissions='1C authorization and configuration access are not verified until a successful native export',
        retention='Private working IB copy, diagnostics and exported sources remain until explicit user removal or selected retention policy',
        limitations=['Original IB is opened only for a bounded shared-read copy; Designer receives only the private copy.',
            'Main editable configuration may differ from the database configuration and historical incident version.',
            'Extensions, server IBs, other platform versions and Linux native execution require separate verified profiles.',
            'Budgets monitor owned paths and processes; the native platform can also write its usual service logs. This is not an OS sandbox.'])
    plan['argv']=_argv(plan)
    from .operation_state import writer
    folder.parent.mkdir(parents=True,exist_ok=True)
    with writer(folder.parent):
        if _identity(source)!=identity:raise InputError('source file changed during export planning')
        folder.mkdir(exist_ok=False)
        plan['private_storage_access']=native.protect_directory(folder)
        data=encoded(plan,128*1024);(folder/'plan.json').write_bytes(data)
        write_json(folder/'plan-receipt.json',dict(schema_version=1,plan_sha256=_sha(data)))
    return dict(plan,plan_sha256=_sha(data))


def _load(state_dir,plan_id):
    folder=_folder(state_dir,plan_id);data=read_snapshot(folder/'plan.json',128*1024)
    receipt=json_value(read_snapshot(folder/'plan-receipt.json',8192).decode('utf-8'),reject_duplicates=True)
    if type(receipt) is not dict or _sha(data)!=receipt.get('plan_sha256'):raise InputError('source export plan integrity mismatch')
    plan=json_value(data.decode('utf-8'),reject_duplicates=True)
    if type(plan) is not dict or plan.get('schema_version')!=1 or plan.get('plan_id')!=plan_id or plan.get('argv')!=_argv(plan):raise InputError('unsupported source export plan')
    return folder,plan,_sha(data)


def _inventory(root,max_files,max_bytes):
    stack=[(Path(root),0)];files=0;total=0;entries_seen=0
    while stack:
        folder,depth=stack.pop();info=folder.lstat()
        if depth>64 or stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise InputError('owned export tree contains a link or exceeds depth limit')
        with os.scandir(folder) as entries:
            for entry in entries:
                entries_seen+=1
                if entries_seen>max_files*4+1024:raise InputError('owned export tree exceeds entry budget')
                info=entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise InputError('owned export tree contains a link')
                if stat.S_ISDIR(info.st_mode):stack.append((Path(entry.path),depth+1))
                elif stat.S_ISREG(info.st_mode):files+=1;total+=info.st_size
                else:raise InputError('owned export tree contains a nonregular file')
                if files>max_files or total>max_bytes:raise InputError('owned export file/byte budget exceeded')
    return dict(files=files,bytes=total)


def _result_code(path):
    data=read_snapshot(path,512)
    for encoding in ('utf-8-sig','utf-16','cp1251'):
        try:value=data.decode(encoding).strip()
        except UnicodeError:continue
        if re.fullmatch('-?[0-9]{1,6}',value):return int(value)
    raise InputError('platform result is absent or not a supported integer result')


def _configuration(output):
    data=read_snapshot(output/'Configuration.xml',MIB)
    try:text=data.decode('utf-8-sig')
    except UnicodeError as exc:raise InputError('this exported XML profile requires UTF-8') from exc
    if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():raise InputError('exported XML entities/DTD are not accepted')
    try:root=ET.fromstring(text)
    except ET.ParseError as exc:raise InputError('exported Configuration.xml is invalid') from exc
    configuration=root if root.tag.split('}')[-1]=='Configuration' else root.find('.//{*}Configuration')
    if configuration is None:raise InputError('export lacks main configuration metadata')
    def property_value(key):
        node=configuration.find('{*}Properties/{*}'+key)
        return node.text[:256] if node is not None and node.text else None
    if not property_value('Name'):raise InputError('exported configuration name is absent')
    return dict(name=property_value('Name'),version=property_value('Version'),uuid=configuration.get('uuid'),configuration_xml_sha256=_sha(data))


def _report_result(state_dir,folder,plan,plan_sha,result):
    sources=[('execution-summary.json',encoded(result,65536))]
    if result.get('native',{}).get('tree_finished'):
        for name in ('stdout.bin','stderr.bin','designer.log','result.txt'):
            path=Path(plan['capture_directory'])/name
            if path.is_file() and path.stat().st_size<=MIB:sources.append((name,read_snapshot(path,MIB)))
    artifact=save_artifact(state_dir,'source_export',dict(plan_id=plan['plan_id'],plan_sha256=plan_sha),sources,result)
    receipt=dict(schema_version=1,plan_sha256=plan_sha,artifact_id=artifact['artifact_id'],artifact_report_sha256=_sha(read_snapshot(artifact_folder(state_dir,artifact['artifact_id'])/'report.json')))
    write_json(folder/'execution.json',receipt)
    return status(state_dir,plan['plan_id'])


def status(state_dir,plan_id):
    folder,plan,digest=_load(state_dir,plan_id);receipt_path=folder/'execution.json'
    if not receipt_path.exists():
        return dict(plan_id=plan_id,plan_sha256=digest,status='running_or_interrupted' if (folder/'started.json').exists() else 'planned',
            execution_started=(folder/'started.json').exists(),requires_explicit_run=True)
    receipt=json_value(read_snapshot(receipt_path,8192).decode('utf-8'),reject_duplicates=True)
    report=load_artifact(state_dir,receipt['artifact_id'])
    if receipt.get('plan_sha256')!=digest or receipt.get('artifact_report_sha256')!=_sha(read_snapshot(artifact_folder(state_dir,receipt['artifact_id'])/'report.json')):raise InputError('source export execution integrity mismatch')
    result=report['result']
    if result.get('source_artifact_id'):
        load_artifact(state_dir,result['source_artifact_id'])
        if _sha(read_snapshot(artifact_folder(state_dir,result['source_artifact_id'])/'report.json'))!=result['source_artifact_report_sha256']:raise InputError('linked source snapshot changed')
    response=dict(result,plan_id=plan_id,plan_sha256=digest,artifact_id=receipt['artifact_id'],artifact_sources=report['sources'])
    from .export_retention import status as cleanup_status
    removed=cleanup_status(state_dir,plan_id)
    if removed is not None:response['work_copy_cleanup']=removed
    return response


def execute(state_dir,plan_id,*,expected_sha256):
    folder,plan,digest=_load(state_dir,plan_id)
    if expected_sha256!=digest:raise InputError('source export plan changed; review the current plan')
    if (folder/'execution.json').exists():return status(state_dir,plan_id)
    lock=folder/'run.lock'
    try:
        with lock.open('x',encoding='ascii') as stream:stream.write(str(os.getpid()))
    except FileExistsError as exc:raise InputError('source export is running or interrupted; inspect status before a new attempt') from exc
    try:
        if (folder/'started.json').exists():raise InputError('previous source export outcome is unknown; inspect its files before preparing a new plan')
        write_json(folder/'started.json',dict(started_at=_stamp(),plan_sha256=digest))
        result=dict(status='failed_preflight',started_at=_stamp(),finished_at=None,source_artifact_id=None,source_artifact_report_sha256=None,
            configuration_scope=plan['configuration_scope'],working_version_match='unknown',extensions_included=False,
            output_directory=plan['output_directory'],private_working_copy=plan['working_directory'],native={},copy=None,
            limitations=plan['limitations'],retention=plan['retention'],reason=None)
        request=plan['request'];working=Path(plan['working_directory']);output=Path(plan['output_directory']);capture=Path(plan['capture_directory'])
        deadline=time.monotonic()+request['timeout_seconds']
        try:
            if _binary(plan['platform']['path'])!=plan['platform']:raise InputError('platform changed since source export plan')
            if _identity(_local(plan['source_file']))!=plan['source_identity']:raise InputError('source file changed since source export plan')
            for path in (folder,working,capture,output):_local(str(path))
            if working.exists() or capture.exists() or output.exists():raise InputError('source export destination already exists; prepare a new plan')
            _space(folder,output,plan['source_identity']['bytes'],request['max_output_bytes'])
            working.mkdir();capture.mkdir();output.mkdir();native.protect_directory(output)
            result['copy']=native.copy_locked(Path(plan['source_file']),working/'1Cv8.1CD',max_bytes=request['max_copy_bytes'],
                deadline=deadline,space_floor=FLOOR+4*MIB)
            if result['copy']['source_identity']!=plan['source_identity']:raise InputError('source identity changed before locked capture')
            if _binary(plan['platform']['path'])!=plan['platform']:raise InputError('platform changed before native export')
            def guard():
                _inventory(folder,request['max_files']+32,result['copy']['bytes']+request['max_output_bytes']+4*MIB)
                _inventory(output,request['max_files'],request['max_output_bytes'])
                if shutil.disk_usage(folder).free<FLOOR or shutil.disk_usage(output).free<FLOOR:raise InputError('native export stopped at free space floor')
            guard();remaining=deadline-time.monotonic()
            if remaining<=0:raise InputError('source export timeout during preparation')
            result['status']='failed_export'
            result['native']=native.run(plan['argv'],cwd=capture,guard=guard,timeout=remaining)
            if result['native'].get('stop_reason')=='cancelled':result['status']='cancelled'
            if result['native']['status']!='completed' or result['native']['exit_code']!=0 or not result['native']['tree_finished']:raise InputError('native export did not complete successfully; inspect retained diagnostics without automatic retry')
            guard();result['platform_result']=_result_code(capture/'result.txt')
            if result['platform_result']!=0:raise InputError('native platform returned an unsuccessful result')
            result['configuration']=_configuration(output);result['export_inventory']=_inventory(output,request['max_files'],request['max_output_bytes'])
            result['status']='exported_not_indexed'
            source=snapshot_source(state_dir,output)
            result['source_artifact_id']=source['artifact_id']
            result['source_artifact_report_sha256']=_sha(read_snapshot(artifact_folder(state_dir,source['artifact_id'])/'report.json'))
            result['status']='completed'
        except (OSError,ValueError) as exc:result['reason']=str(exc)[:1024]
        except KeyboardInterrupt:result.update(status='cancelled',reason='cancelled during source preparation')
        result['finished_at']=_stamp()
        return _report_result(state_dir,folder,plan,digest,result)
    finally:lock.unlink()
