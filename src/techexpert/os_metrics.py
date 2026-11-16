"""OS observation plans, explicit local/SSH/WinRM execution and offline import."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from .artifacts import save_artifact
from .inputs import InputError,read_snapshot,json_value
from .os_probe import plan,collect,summarize
from .processes import run_bounded

PROBE=Path(__file__).with_name('os_probe.py')


def validate_request(value):
    allowed={'transport','host','port','duration_seconds','interval_seconds','max_bytes','node','role','python','use_ssl','identity_file','known_hosts_file'}
    if not isinstance(value,dict) or set(value)-allowed:raise InputError('unsupported collector request field; credentials are not accepted here')
    settings=plan(value.get('duration_seconds',300),value.get('interval_seconds',1),value.get('max_bytes',8388608))
    transport=value.get('transport','local');host=value.get('host','');role=value.get('role','onec')
    if transport not in ('local','ssh','winrm'):raise InputError('transport must be local, SSH or WinRM')
    if role not in ('onec','sql','storage','client','terminal','web','other'):raise InputError('invalid collector role')
    node=value.get('node')
    if node is not None and (not isinstance(node,str) or not 1<=len(node)<=256 or any(ord(c)<32 for c in node)):raise InputError('invalid node label')
    if transport=='ssh':
        if not isinstance(host,str) or not re.fullmatch(r'(?:[A-Za-z_][A-Za-z0-9_.-]{0,63}@)?(?:[A-Za-z0-9][A-Za-z0-9_.-]{0,252}|\[[a-fA-F0-9:]+\])',host):raise InputError('invalid SSH destination')
    elif transport=='winrm':
        if not isinstance(host,str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,252}',host):raise InputError('invalid WinRM hostname')
    elif host:raise InputError('local collection does not accept a remote host')
    use_ssl=value.get('use_ssl',False)
    if type(use_ssl) is not bool:raise InputError('use_ssl must be boolean')
    port=value.get('port',22 if transport=='ssh' else 5986 if use_ssl else 5985)
    if type(port) is not int or not 1<=port<=65535:raise InputError('invalid collector port')
    python=value.get('python','python3' if transport=='ssh' else 'python')
    if not isinstance(python,str) or not re.fullmatch(r'(?:/[A-Za-z0-9_.-]+)*/?python(?:3(?:\.[0-9]{1,2})?)?',python):
        raise InputError('collector Python must be python/python3 or an absolute Unix path ending with it')
    refs={}
    for key in ('identity_file','known_hosts_file'):
        if key in value:
            path=value[key]
            if transport!='ssh' or not isinstance(path,str) or not 1<=len(path)<=2048 or any(ord(c)<32 or c=='"' for c in path):
                raise InputError('invalid SSH file reference')
            refs[key]=path
    return dict(transport=transport,host=host,port=port,role=role,node=node,python=python,use_ssl=use_ssl,**settings,**refs)


def ssh_command(request):
    r=validate_request(request)
    if r['transport']!='ssh':raise InputError('SSH request required')
    # All remote-shell tokens are constants or validated finite numbers/path.
    command=f"{r['python']} - --duration {r['duration_seconds']:g} --interval {r['interval_seconds']:g} --role {r['role']} --max-bytes {r['max_bytes']}"
    options=[]
    if 'identity_file' in r:options+=['-i',r['identity_file'],'-o','IdentitiesOnly=yes']
    if 'known_hosts_file' in r:options+=['-o','UserKnownHostsFile="'+r['known_hosts_file']+'"']
    return ['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10',*options,
            '-p',str(r['port']),r['host'],command]


def winrm_script(request):
    r=validate_request(request)
    if r['transport']!='winrm':raise InputError('WinRM request required')
    source=base64.b64encode(PROBE.read_bytes()).decode('ascii')
    ssl=' -UseSSL' if r['use_ssl'] else ''
    return f"""$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$OutputEncoding=[Console]::OutputEncoding
$source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{source}'))
$options=New-PSSessionOption -OpenTimeout 10000 -OperationTimeout {int((r['duration_seconds']+30)*1000)}
Invoke-Command -ComputerName '{r['host']}' -Port {r['port']} -Authentication Negotiate{ssl} -SessionOption $options -ScriptBlock {{
    param($code,$duration,$interval,$role,$byteLimit)
    $ErrorActionPreference='Stop'
    $OutputEncoding=New-Object System.Text.UTF8Encoding($false)
    $code | & {r['python']} - --duration $duration --interval $interval --role $role --max-bytes $byteLimit
    if($LASTEXITCODE -ne 0){{throw 'Remote collector failed'}}
}} -ArgumentList $source,{r['duration_seconds']:g},{r['interval_seconds']:g},'{r['role']}',{r['max_bytes']}
"""


def import_os(state_dir,path):
    data=read_snapshot(path)
    document=json_value(data.decode('utf-8-sig'),reject_duplicates=True)
    result=summarize(document)
    return save_artifact(state_dir,'os_metrics',dict(import_path=str(Path(path).resolve())),
                         [(str(Path(path).resolve()),data)],result)


def collect_os(state_dir,request,*,should_stop=None):
    request=validate_request(request)
    transport=request['transport']
    if transport=='local':
        document=collect(request['duration_seconds'],request['interval_seconds'],node=request['node'],
                         role=request['role'],max_bytes=request['max_bytes'],should_stop=should_stop)
        data=json.dumps(document,ensure_ascii=False,allow_nan=False).encode('utf-8')
    else:
        timeout=request['duration_seconds']+30
        if transport=='ssh':
            code,data,_=run_bounded(ssh_command(request),timeout=timeout,max_bytes=request['max_bytes'],input_data=PROBE.read_bytes())
        else:
            if os.name!='nt':raise InputError('WinRM launcher currently requires Windows PowerShell 5.1 on the local Windows machine')
            powershell=Path(os.environ.get('SystemRoot','C:/Windows'))/'System32/WindowsPowerShell/v1.0/powershell.exe'
            with tempfile.TemporaryDirectory(prefix='techexpert-winrm-') as temporary:
                script=Path(temporary)/'collect.ps1';script.write_text(winrm_script(request),encoding='utf-8-sig')
                code,data,_=run_bounded([str(powershell),'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(script)],
                                        timeout=timeout,max_bytes=request['max_bytes'])
        if code:raise InputError('Remote collection failed; verify existing access and Python. Services/security settings were not changed. Remote completion is unknown after a connection failure.')
        document=json_value(data.decode('utf-8-sig'),reject_duplicates=True)
        if document.get('role')!=request['role'] or document.get('plan')!=plan(request['duration_seconds'],request['interval_seconds'],request['max_bytes']):
            raise InputError('remote collector plan does not match requested limits')
    result=summarize(document)
    if request['node']:result['requested_node_label']=request['node']
    return save_artifact(state_dir,'os_metrics',dict(**request,probe_sha256=hashlib.sha256(PROBE.read_bytes()).hexdigest()),
                         [('os-metrics.json',data)],result)
