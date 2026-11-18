"""Private client observations with explicit clock and evidence boundaries."""
from datetime import datetime,timezone,timedelta
import math
import re
from pathlib import Path

from .artifacts import save_artifact
from .inputs import InputError,json_value,read_snapshot


MAX_TRACE_BYTES=512*1024
MAX_INTERVAL=timedelta(days=1)
MAX_NS=86400*10**9
TESTPILOT_VERSION='1.9.2'
_STAMP=re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])')


def _exact(value,fields):
    if type(value) is not dict or set(value)!=set(fields.split()):
        raise InputError('invalid client episode fields')


def _text(value,maximum,*,nullable=False):
    if value is None and nullable:
        return None
    if (type(value) is not str or not value.strip() or len(value)>maximum
        or any(ord(ch)<32 or ord(ch)==127 or 0xd800<=ord(ch)<=0xdfff for ch in value)):
        raise InputError('invalid bounded client text')
    return value


def _instant(value):
    if type(value) is not str or not _STAMP.fullmatch(value) or value.endswith('-00:00'):
        raise InputError('client timestamps require a known time zone')
    try:
        return datetime.fromisoformat(value.replace('Z','+00:00')).astimezone(timezone.utc)
    except (ValueError,OverflowError):
        raise InputError('invalid client timestamp') from None


def _ns(value):
    if value is not None and (type(value) is not int or not 0<=value<=MAX_NS):
        raise InputError('invalid client monotonic interval')
    return value


def _counters(value):
    if value is None:
        return None
    if type(value) is not dict or len(value)>32:
        raise InputError('invalid client counter set')
    for name,item in value.items():
        _text(name,120)
        if type(item) not in (int,float) or not 0<=item<=2**63-1 or not math.isfinite(item):
            raise InputError('invalid cumulative client counter')
    return dict(value)


def _snapshot(value,start,finish):
    if value is None:
        return None
    _exact(value,'at form_name caption counters')
    at=_instant(value['at'])
    if not start<=at<=finish:
        raise InputError('client observation outside episode time bounds')
    return dict(at=at.isoformat(),form_name=_text(value['form_name'],300,nullable=True),
                caption=_text(value['caption'],500,nullable=True),counters=_counters(value['counters']))


def _action(value,origin,start,finish,before,after):
    if value is None:
        return None
    _exact(value,'label started_at status returned_ns ready_criterion ready')
    label=_text(value['label'],500)
    action_start=_instant(value['started_at'])
    if not start<=action_start<=finish or (before and _instant(before['at'])>action_start) or (after and _instant(after['at'])<action_start):
        raise InputError('client action does not follow the recorded baseline')
    status=value['status']
    allowed=('reported','outcome_unknown') if origin=='manual' else ('returned_ok','returned_error','outcome_unknown')
    if status not in allowed:
        raise InputError('unknown client action status')
    returned=_ns(value['returned_ns'])
    if (returned is None)!=(status not in ('returned_ok','returned_error')):
        raise InputError('client tool response needs an observed round-trip interval')
    criterion=_text(value['ready_criterion'],300)
    ready=value['ready']
    if ready is not None:
        _exact(ready,'at elapsed_ns form_name')
        ready_at=_instant(ready['at'])
        if not action_start<=ready_at<=finish or (after and ready_at>_instant(after['at'])):
            raise InputError('client readiness precedes the action or exceeds the observed window')
        elapsed=_ns(ready['elapsed_ns'])
        form=_text(ready['form_name'],300,nullable=True)
        if origin=='manual':
            if status!='reported' or elapsed is not None:
                raise InputError('manual readiness uses reported wall clock markers')
        elif status!='returned_ok' or elapsed is None or elapsed<returned or form!=criterion or not after or after['form_name']!=form:
            raise InputError('client readiness requires the exact observed form after a returned action')
        ready=dict(at=ready_at.isoformat(),elapsed_ns=elapsed,form_name=form)
    return dict(label=label,started_at=action_start.isoformat(),status=status,returned_ns=returned,ready_criterion=criterion,ready=ready)


def summarize(document,*,basis):
    if basis not in ('provided_trace','approved_live_capture'):
        raise InputError('unsupported client evidence basis')
    _exact(document,'schema_version origin driver_version started_at finished_at session before after action issues')
    origin=document['origin']
    if type(document['schema_version']) is not int or document['schema_version']!=1 or origin not in ('manual','testpilot'):
        raise InputError('unsupported client evidence profile')
    if document['driver_version']!=(TESTPILOT_VERSION if origin=='testpilot' else None):
        raise InputError('unsupported client source version')
    start=_instant(document['started_at'])
    finish=_instant(document['finished_at'])
    if not timedelta(0)<=finish-start<=MAX_INTERVAL:
        raise InputError('client episode must fit in one day')
    before=_snapshot(document['before'],start,finish)
    after=_snapshot(document['after'],start,finish)
    if before and after and _instant(before['at'])>_instant(after['at']):
        raise InputError('client snapshots are out of order')
    action=_action(document['action'],origin,start,finish,before,after)
    session=document['session']
    if session is not None:
        _exact(session,'id platform_build client_type database_mode')
        for key in ('client_type','database_mode'):
            options=('thin','thick','web','unknown') if key=='client_type' else ('file','server','unknown')
            if session[key] not in options:
                raise InputError('invalid client session context')
        session=dict(session,id=_text(session['id'],120,nullable=True),
                     platform_build=_text(session['platform_build'],32,nullable=True))
    if origin=='testpilot' and (before or after) and (not session or not session['id'] or not session['platform_build']):
        raise InputError('client snapshots require a recorded Testpilot session')
    issues=document['issues']
    if (type(issues) is not list or len(issues)>16
        or any(type(item) is not str or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}',item) for item in issues)
        or len(set(issues))!=len(issues)):
        raise InputError('invalid client observation status codes')
    earlier=before['counters'] or {} if before else {}
    later=after['counters'] or {} if after else {}
    indicators=[]
    for counter in sorted(earlier.keys()|later.keys()):
        a,b=earlier.get(counter),later.get(counter)
        if a is None or b is None:
            state='missing_snapshot_or_counter';delta=None
        elif b<a:
            state='decreased_or_reset';delta=None
        else:
            state='observed_nonnegative_difference';delta=b-a
        indicators.append(dict(counter=counter,before=a,after=b,delta=delta,status=state,unit=None))
    ready=action['ready'] if action else None
    ready_basis=None
    durations=dict(tool_response=None,observed_ready=None,reported_wall_clock=None,application_write=None,refresh=None)
    if action and action['returned_ns'] is not None:
        durations['tool_response']=action['returned_ns']/1e9
    if ready:
        if origin=='manual':
            ready_basis='operator_reported_marker'
            durations['reported_wall_clock']=(_instant(ready['at'])-_instant(action['started_at'])).total_seconds()
        else:
            ready_basis='matched_form_read' if basis=='approved_live_capture' else 'provided_form_read'
            durations['observed_ready']=ready['elapsed_ns']/1e9
    status='partial' if issues or (action and not ready) else 'observed'
    if not (before or after or action):
        status='unavailable'
    return dict(status=status,profile='client-episode-v1',origin=origin,driver_version=document['driver_version'],
        session=session,session_identity_basis=basis,before=before,after=after,action=action,ready_basis=ready_basis,
        timestamps=dict(started_at=start.isoformat(),finished_at=finish.isoformat()),
        durations_seconds=durations,cumulative_indicators=indicators,issues=list(issues),cause=None,
        requires_ai_interpretation=True,limitations=[
            'Form readiness applies only to the stated predicate. Tool elapsed time includes response and observation overhead.',
            'Client identity and timings do not link this session to a specific infobase, background job or SQL request.',
            'Counters cover the session window, including observation traffic and other activity. Units and resets within the window are unverified.',
            'An unavailable snapshot or a partial action is not a zero-duration or failed application operation.',
            'The active form does not enumerate the full set of previously opened windows or application handlers.'])


def decode(data):
    if type(data) is not bytes or not 1<=len(data)<=MAX_TRACE_BYTES:
        raise InputError('client episode exceeds byte limit or is empty')
    try:
        return json_value(data.decode('utf-8-sig'),reject_duplicates=True)
    except (ValueError,RecursionError):
        raise InputError('client episode requires bounded UTF-8 JSON') from None


def import_episode(state_dir,path):
    path=Path(path)
    data=read_snapshot(path,MAX_TRACE_BYTES)
    result=summarize(decode(data),basis='provided_trace')
    return save_artifact(state_dir,'client_ui',dict(path=str(path.absolute()),origin=result['origin']),
                         [('client-episode.json',data)],result)
