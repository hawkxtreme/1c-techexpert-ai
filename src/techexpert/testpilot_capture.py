"""Finite use of an external Testpilot environment against an existing local client."""
from contextlib import ExitStack
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import re

from . import operation_state
from .artifacts import save_artifact
from .client_endpoint import BUILD,inspect_endpoint
from .client_episode import MAX_TRACE_BYTES,TESTPILOT_VERSION,decode,summarize
from .inputs import InputError
from .processes import CommandStopped,run_bounded


_LOCAL_LIST=re.compile(r'e1cib/list/(?:Документ|Справочник|РегистрСведений|Document|Catalog|InformationRegister)\.[^\W\d]\w{0,99}')
_FORM_COMPONENT=re.compile(r'[^\W\d]\w{0,99}')
_SYSTEM_ENV={'SYSTEMROOT','WINDIR','PATH','COMSPEC','PATHEXT','APPDATA','LOCALAPPDATA',
             'USERPROFILE','USERNAME','COMPUTERNAME','TEMP','TMP'}


def normalize(value):
    if type(value) is not dict or not {'endpoint','python'}<=set(value)<={
            'endpoint','python','database_mode','navigation'}:
        raise InputError('explicit Testpilot environment and endpoint required')
    endpoint=value['endpoint']
    if type(endpoint) is not dict or set(endpoint)!={'port','pid','lifetime'}:
        raise InputError('exact TestClient port, PID and lifetime required')
    if type(endpoint['port']) is not int or not 1<=endpoint['port']<=65535:
        raise InputError('invalid TestClient port')
    if type(endpoint['pid']) is not int or not 1<=endpoint['pid']<=2**32-1:
        raise InputError('invalid TestClient PID')
    if type(endpoint['lifetime']) is not str or not re.fullmatch(r'[1-9][0-9]{0,19}',endpoint['lifetime']):
        raise InputError('invalid Windows process creation identity')
    executable=value['python']
    if type(executable) is not str or not 1<=len(executable)<=2048 or any(ord(ch)<32 for ch in executable):
        raise InputError('explicit absolute Python executable of the external Testpilot environment required')
    path=Path(executable)
    if (not path.is_absolute() or path.anchor.startswith(('\\\\','//')) or '..' in path.parts
        or path.name.casefold() not in ('python.exe','python3.exe')):
        raise InputError('explicit local Python executable of the external Testpilot environment required')
    mode=value.get('database_mode','unknown')
    if mode not in ('file','server','unknown'):
        raise InputError('unsupported reported client database mode')
    result=dict(endpoint=dict(endpoint),python=str(path),database_mode=mode)
    if 'navigation' in value:
        navigation=value['navigation']
        if type(navigation) is not dict or set(navigation)!={'link','ready_form'}:
            raise InputError('exact list link and ready form required')
        link=navigation['link'];form=navigation['ready_form']
        if type(link) is not str or not _LOCAL_LIST.fullmatch(link) or type(form) is not str:
            raise InputError('only a single local infobase list link can be used here')
        prefix=link.removeprefix('e1cib/list/')+'.'
        if not form.startswith(prefix) or not _FORM_COMPONENT.fullmatch(form[len(prefix):]):
            raise InputError('ready form must be an exact form of the selected metadata object')
        result['navigation']=dict(navigation)
    return result


def _now():
    return datetime.now(timezone.utc).isoformat()


def _matched_frame(data,*,completed,settings):
    """Accept only complete framed projections. Stop tails cannot assert a final result."""
    if not data or len(data)>MAX_TRACE_BYTES:
        return None
    lines=data.split(b'\n')
    if len(lines)>3 or (completed and lines[-1]):
        raise InputError('invalid Testpilot worker framing')
    frames=[decode(line) for line in lines[:-1]]
    if any(type(f) is not dict or set(f)!={'stage','episode'} for f in frames):
        raise InputError('invalid Testpilot worker frame')
    stages=[f['stage'] for f in frames]
    if stages not in ([],['pending'],['result'],['pending','result']):
        raise InputError('invalid Testpilot worker stage sequence')
    navigation=settings.get('navigation')
    accepted={}
    previous=None
    for frame in frames:
        summary=summarize(frame['episode'],basis='approved_live_capture')
        session=summary['session']
        if (summary['origin']!='testpilot' or session and
            (not session['id'] or session['client_type']!='thin' or session['platform_build']!=BUILD
             or session['database_mode']!=settings['database_mode'])):
            raise InputError('Testpilot observation session does not match selection')
        stage=frame['stage']
        action=summary['action']
        if action and (not navigation or not session or not summary['before']
                       or action['label']!=navigation['link'] or action['ready_criterion']!=navigation['ready_form']):
            raise InputError('Testpilot observation action does not match approval')
        if stage=='pending':
            if not action or action['status']!='outcome_unknown' or summary['after']:
                raise InputError('invalid pending Testpilot action')
            previous=summary
        elif bool(action)!=bool(previous) or previous and (
            previous['session']!=session or previous['before']!=summary['before']
            or previous['timestamps']['started_at']!=summary['timestamps']['started_at']
            or previous['action']['started_at']!=action['started_at']):
            raise InputError('Testpilot action or session changed between frames')
        accepted[stage]=frame['episode']
    return accepted.get('result' if completed else 'pending')


def _capture(request,should_stop):
    endpoint=request['endpoint']
    try:
        if inspect_endpoint(endpoint['port'])!=endpoint:
            raise InputError('selected TestClient process changed')
    except (OSError,ValueError):
        return None,'endpoint_unavailable_or_changed',False,False
    script=str(Path(__file__).with_name('testpilot_worker.py'))
    env={k:v for k,v in os.environ.items() if k.upper() in _SYSTEM_ENV}
    env.update(TC1C_LOGGING='false',TC1C_SCREENSHOTS='false',TC1C_CODE_EXECUTION='false',TC1C_QUERY_EXECUTION='false')
    options={k:v for k,v in request.items() if k!='python'}
    cancelled=False
    try:
        code,data,_=run_bounded([request['python'],'-I','-B','-X','utf8',script],
            input_data=json.dumps(options,ensure_ascii=False).encode('utf-8'),
            env=env,max_bytes=MAX_TRACE_BYTES,timeout=36,should_stop=should_stop)
        reason='driver_failed' if code else None
    except CommandStopped as exc:
        cancelled=exc.reason=='cancelled'
        if not exc.process_started:
            return None,exc.reason,False,cancelled
        code,data,reason=1,exc.stdout,exc.reason
    except OSError:
        return None,'driver_unavailable',False,False
    except ValueError:
        return None,'driver_capture_unverified',True,False
    try:
        if inspect_endpoint(endpoint['port'])!=endpoint:
            raise InputError('endpoint changed after Testpilot capture')
        packet=_matched_frame(data,completed=code==0,settings=request)
    except (OSError,ValueError,RecursionError):
        return None,'endpoint_or_worker_result_unverified',True,cancelled
    if not packet and reason is None:
        reason='worker_result_missing'
    return packet,reason,True,cancelled


def observe(state_dir,*,endpoint,python,database_mode='unknown',navigation=None,should_stop=None,lock_state=None):
    request=normalize(dict(endpoint=endpoint,python=python,database_mode=database_mode,
                           **({'navigation':navigation} if navigation is not None else {})))
    start=_now()
    with ExitStack() as lock:
        try:
            directory=operation_state.private(Path(lock_state or state_dir)/'testpilot-endpoints'/str(endpoint['port']))
            lock.enter_context(operation_state.writer(directory))
        except (OSError,ValueError):
            packet,reason,started,cancelled=None,'testclient_endpoint_busy_or_unavailable',False,False
        else:
            packet,reason,started,cancelled=_capture(request,should_stop)
    if packet is None:
        packet=dict(schema_version=1,origin='testpilot',driver_version=TESTPILOT_VERSION,started_at=start,finished_at=_now(),
                    session=None,before=None,after=None,action=None,issues=[reason or 'worker_result_missing'])
    elif reason and reason not in packet['issues']:
        packet=dict(packet,issues=[*packet['issues'][:15],reason])
    result=summarize(packet,basis='approved_live_capture')
    possible=bool(navigation and started and (packet['action'] or reason))
    result.update(connection_scope=dict(host='127.0.0.1',**endpoint),action_may_have_run=possible,
                  testpilot_connection_observed=packet['session'] is not None)
    if cancelled:
        result['status']='cancelled'
    result['limitations'].append('The selected listener, process lifetime and established loopback peer are checked. A stopped driver does not stop the external 1C client.')
    retained=json.dumps(packet,ensure_ascii=False,allow_nan=False).encode('utf-8')
    return save_artifact(state_dir,'client_ui',request,[('client-episode.json',retained)],result)
