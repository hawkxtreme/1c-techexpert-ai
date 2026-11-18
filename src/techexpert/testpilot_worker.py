"""Internal subprocess projection using the separately installed vendor Python API."""
from datetime import datetime,timezone
from importlib import metadata
import json
import os
from pathlib import Path
import re
import sys
import time

if __name__=='__main__':
    # Isolated Python does not add this shipped script's checkout to sys.path.
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from src.techexpert.client_endpoint import BUILD,verify_connection


DRIVER='1.9.2'
READY_READS=4


def stamp():
    return datetime.now(timezone.utc).isoformat()


def emit(stage,episode):
    data=(json.dumps(dict(stage=stage,episode=episode),ensure_ascii=False,allow_nan=False)+'\n').encode('utf-8')
    if len(data)>128*1024:
        raise ValueError('worker projection exceeds line budget')
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def _text(value,maximum):
    if (type(value) is str and value.strip() and len(value)<=maximum and
        not any(ord(ch)<32 or ord(ch)==127 or 0xd800<=ord(ch)<=0xdfff for ch in value)):
        return value
    return None


def attached(client,episode,options):
    endpoint=options['endpoint']
    port=endpoint['port']
    connection=client.call('connect',host='127.0.0.1',port=port,version=BUILD,check=False)
    session=client.connection_id
    if (not _text(session,120) or type(connection) is not dict or connection.get('ok') is not True
        or connection.get('connection_id')!=session):
        episode['issues'].append('testclient_connection_unavailable')
        return
    try:
        verify_connection(endpoint,os.getpid())
    except (OSError,ValueError):
        episode['issues'].append('testclient_connection_owner_unverified')
        return
    episode['session']=dict(id=session,platform_build=BUILD,client_type='thin',database_mode=options['database_mode'])

    def read(name,**params):
        reply=client.call(name,check=False,**params)
        if type(reply) is not dict or reply.get('connection_id')!=session or client.connection_id!=session:
            return None
        return reply

    def counters():
        reply=read('get_performance',clear=False)
        if not reply or reply.get('ok') is not True or reply.get('cleared') is not False:
            episode['issues'].append('client_counters_unavailable')
            return None
        value=reply.get('indicators')
        if (type(value) is not dict or len(value)>32 or
            any(not _text(k,120) or type(v) not in (int,float) or not 0<=v<=2**63-1 for k,v in value.items())):
            episode['issues'].append('client_counters_unavailable')
            return None
        return value

    baseline=read('get_active_window')
    if baseline and baseline.get('platform_version') not in (None,BUILD):
        episode['session']=None
        episode['issues'].append('testclient_platform_mismatch')
        return
    if not baseline or baseline.get('ok') is not True:
        episode['issues'].append('active_window_unavailable')
        baseline={}
    indicators=counters()
    episode['before']=dict(at=stamp(),form_name=_text(baseline.get('form_name'),300),
                          caption=_text(baseline.get('title'),500),counters=indicators)
    navigation=options.get('navigation')
    if not navigation:
        return
    if not baseline:
        episode['issues'].append('navigation_baseline_missing')
        return
    link=navigation['link']
    criterion=navigation['ready_form']
    # This internal entry point accepts only a metadata list link, even when
    # invoked by hand. Database changes and arbitrary commands are not exposed.
    match=re.fullmatch(r'e1cib/list/(?:Документ|Справочник|РегистрСведений|Document|Catalog|InformationRegister)\.[^\W\d]\w{0,99}',link)
    prefix=link.removeprefix('e1cib/list/')+'.'
    if not match or not criterion.startswith(prefix) or not re.fullmatch(r'[^\W\d]\w{0,99}',criterion[len(prefix):]):
        episode['issues'].append('navigation_selection_invalid')
        return
    try:
        verify_connection(endpoint,os.getpid())
    except (OSError,ValueError):
        episode['issues'].append('testclient_connection_owner_unverified')
        return
    begin=time.perf_counter_ns()
    episode['action']=dict(label=link,started_at=stamp(),status='outcome_unknown',returned_ns=None,
                           ready_criterion=criterion,ready=None)
    episode['finished_at']=stamp()
    emit('pending',episode)
    action=read('execute_command',command=link)
    returned=time.perf_counter_ns()-begin
    if action is None:
        episode['issues'].append('navigation_outcome_unknown')
        return
    if action.get('ok') is not True:
        episode['action'].update(status='returned_error',returned_ns=returned)
        episode['issues'].append('navigation_returned_error')
        return
    episode['action'].update(status='returned_ok',returned_ns=returned)
    form={}
    for attempt in range(READY_READS):
        response=read('get_context',result_mode='full',include_tables=False,include_commands=False,visible_only=True)
        data=response.get('form') if response and response.get('ok') is True else None
        if type(data) is dict:
            form=data
            if form.get('form_name')==criterion:
                episode['action']['ready']=dict(at=stamp(),elapsed_ns=time.perf_counter_ns()-begin,form_name=criterion)
                break
        if attempt+1<READY_READS:
            time.sleep(.20)
    if episode['action']['ready'] is None:
        episode['issues'].append('ready_form_not_observed')
    indicators=counters()
    episode['after']=dict(at=stamp(),form_name=_text(form.get('form_name'),300),
                         caption=_text(form.get('title'),500),counters=indicators)


def main():
    episode=dict(schema_version=1,origin='testpilot',driver_version=DRIVER,started_at=stamp(),finished_at=None,
                 session=None,before=None,after=None,action=None,issues=[])
    try:
        options=json.loads(sys.stdin.buffer.read(4097))
        if metadata.version('1c-testpilot')!=DRIVER:
            episode['issues'].append('testpilot_version_unsupported')
        else:
            from testpilot import Client
            with Client() as client:
                attached(client,episode,options)
    except (metadata.PackageNotFoundError,ImportError):
        episode['issues'].append('testpilot_dependency_unavailable')
    except Exception:
        # Driver errors can carry UI text and private paths.
        episode['issues'].append('testpilot_worker_did_not_finish_cleanly')
    episode['finished_at']=stamp()
    episode['issues']=list(dict.fromkeys(episode['issues']))
    emit('result',episode)


if __name__=='__main__':
    main()
