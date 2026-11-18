"""Observation approval and run reservations for the existing OS sampler."""
from datetime import datetime, timezone
from hashlib import sha256
import os
from pathlib import Path
import re

from . import operation_state as fs, reader_scope
from .inputs import InputError
from .os_metrics import PROBE, validate_request


FORMAT = 1
ROOT = 'os-observations'
MAX_DOCUMENT = 256 * 1024
MAX_REQUEST = 16 * 1024
MAX_APPROVALS = 16
MAX_RUNS = 32
ACTION = 'os-observation'
OPERATION = 'os.observation'
TERMINAL = {'succeeded', 'partial', 'invalid_input', 'failed', 'cancelled', 'interrupted'}
REMOTE_TERMINAL = {'completed': 'succeeded', 'byte_limit': 'partial', 'cancelled': 'cancelled'}
SHA256 = re.compile('[a-f0-9]{64}')
ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError)
QUOTAS = ('max_runs', 'max_seconds', 'max_bytes', 'min_gap_seconds')
RESERVATION_FIELDS = {'run_id', 'approval_sha256', 'source_id', 'duration_seconds',
                      'interval_seconds', 'max_bytes', 'reserved_at'}


def now():
    return datetime.now(timezone.utc)


def argument_schema():
    from . import capabilities as cap
    integer = lambda low, high: dict(type='integer', minimum=low, maximum=high)
    return cap.obj(dict(
        mode=cap.string(7, enum=['preview', 'approve', 'status']),
        context=cap.obj(dict(investigation_id=cap.CASE,expected_revision=integer(1,1000)),
                        ('investigation_id','expected_revision')),
        base_id=cap.string(80), source_ids=dict(type='array', items=cap.string(80), minItems=1, maxItems=8),
        max_runs=integer(1,MAX_RUNS),max_seconds=integer(1,7*86400),
        max_bytes=integer(16384,64*1024**2),min_gap_seconds=integer(0,86400),
        proposal_sha256=cap.SHA256),('mode','context'))


def binding_schema():
    from . import capabilities as cap
    return cap.obj(dict(approval_sha256=cap.SHA256,source_id=cap.string(80)),('approval_sha256','source_id'))


def sampler_arguments(value):
    from . import capabilities as cap
    return cap.validate(value,cap.obj(dict(
        duration_seconds=dict(type='number',minimum=1,maximum=1800),
        interval_seconds=dict(type='number',minimum=1,maximum=60),
        max_bytes=dict(type='integer',minimum=16384,maximum=8*1024**2))))


def normalize(value):
    from . import capabilities as cap
    request = cap.validate(value,argument_schema())
    mode = request['mode']
    common = {'mode','context'}
    selected = {'base_id','source_ids','max_runs','max_seconds','max_bytes'}
    allowed = common if mode=='status' else common|selected|{'min_gap_seconds'}
    if mode=='approve':
        allowed=allowed|{'proposal_sha256'}
        selected=selected|{'proposal_sha256'}
    if set(request)-allowed or (mode!='status' and selected-request.keys()):
        raise InputError('invalid observation plan properties')
    if mode!='status':
        if len(request['source_ids'])!=len(set(request['source_ids'])):
            raise InputError('select each observation source only once')
        request['source_ids'].sort()
        request.setdefault('min_gap_seconds',0)
    return request


def _date(value):
    date=datetime.fromisoformat(value)
    if date.utcoffset() is None or value.endswith('-00:00'):
        raise InputError('observation window requires an explicit time zone')
    return date.astimezone(timezone.utc)


def _window(doc, sources):
    plan=doc.get('observation_plan') or {}
    if plan.get('status') in (None,'cancelled') or not plan.get('start') or not plan.get('end'):
        raise InputError('save an active observation plan with an explicit window')
    if set(sources)-set(plan['sources']):
        raise InputError('selected OS source is outside the saved observation plan')
    start,end=_date(plan['start']),_date(plan['end'])
    if not start<end or (end-start).total_seconds()!=plan['duration_seconds']:
        raise InputError('invalid saved observation window')
    return start,end


def _doc(state, context):
    from . import context_policy,investigations
    identifier=context['investigation_id']
    if investigations._read_head(state,identifier)['revision']!=context['expected_revision']:
        raise InputError('investigation revision changed; reload before observation')
    return context_policy.selected_investigation(state,identifier,context['expected_revision'])


def _collector(settings):
    request=validate_request(settings)
    for key in ('known_hosts_file','identity_file'):
        if key in request:
            request[key]=str(Path(request[key]).absolute())
    return {key:value for key,value in request.items() if value is not None}


def _proposal(doc, request):
    from .profile_resources import effective_profile
    from .profiles import validate_profile

    if not doc.get('profile_snapshot') or not doc.get('profile_sha256'):
        raise InputError('select an environment profile before approving an OS observation')
    profile=effective_profile(validate_profile(doc['profile_snapshot']))
    base=request['base_id']
    if not any(row['id']==base for row in profile['bases']):
        raise InputError('unknown selected base')
    start,end=_window(doc,request['source_ids'])
    observed=doc['observation_plan']
    if request['max_seconds']>observed['duration_seconds'] or request['max_bytes']>observed['max_bytes']:
        raise InputError('requested collection budget exceeds the saved observation plan')
    sources={source['id']:source for source in profile['sources']}
    targets=[]
    for identifier in request['source_ids']:
        source=sources.get(identifier) or {}
        if source.get('type')!='os' or base not in source['base_ids']:
            raise InputError('OS source is not configured for the selected base')
        settings=dict(source['settings'],node=identifier)
        settings['host']=source['host'] if settings['transport']!='local' else ''
        settings['duration_seconds']=min(settings['duration_seconds'],request['max_seconds'])
        settings['max_bytes']=min(settings['max_bytes'],request['max_bytes'])
        targets.append(dict(source_id=identifier,collector=_collector(settings)))
    domain=None
    if any(row['collector']['transport']=='local' for row in targets):
        domain=reader_scope.observe()
        if domain['status']!='observed':
            raise InputError('local observation cannot verify its execution domain')
    return dict(schema_version=FORMAT,investigation_id=doc['investigation_id'],profile_sha256=doc['profile_sha256'],
                base_id=base,window=dict(start=start.isoformat(),end=end.isoformat()),targets=targets,
                budgets={key:request[key] for key in QUOTAS},probe_sha256=sha256(PROBE.read_bytes()).hexdigest(),
                local_execution_domain=domain,delivery='direct_managed_os_summary')


def _folder(state, identifier):
    return fs.safe(Path(state)/ROOT/identifier)


def read_ledger(state, identifier, *, read=fs.read):
    directory=_folder(state,identifier)
    if not directory.exists():
        return None
    try:
        receipt=read(directory/'ledger.json',MAX_DOCUMENT)
        value=receipt['value']
        if (set(receipt)!={'value','sha256'} or fs.digest(value)!=receipt['sha256']
            or set(value)!={'schema_version','active','approvals'} or type(value['schema_version']) is not int
            or value['schema_version']!=FORMAT or type(value['approvals']) is not dict
            or not 1<=len(value['approvals'])<=MAX_APPROVALS or value['active'] not in value['approvals']):
            raise InputError('invalid observation ledger')
        runs=set()
        for digest,entry in value['approvals'].items():
            plan=entry['plan'];charges=entry['reservations'];quota=plan['budgets']
            if (type(digest) is not str or not SHA256.fullmatch(digest) or fs.digest(plan)!=digest
                or set(entry)!={'plan','reservations'} or plan['investigation_id']!=identifier
                or plan['schema_version']!=FORMAT or type(charges) is not list
                or not 0<=len(charges)<=quota['max_runs']<=MAX_RUNS):
                raise InputError('invalid observation approval')
            targets={row['source_id']:row['collector'] for row in plan['targets']}
            for charge in charges:
                rid=charge['run_id'];target=targets[charge['source_id']]
                if (set(charge)!=RESERVATION_FIELDS or charge['approval_sha256']!=digest
                    or not SHA256.fullmatch(rid) or rid in runs
                    or type(charge['duration_seconds']) not in (int,float)
                    or type(charge['interval_seconds']) not in (int,float)
                    or type(charge['max_bytes']) is not int
                    or not target['interval_seconds']<=charge['interval_seconds']<=min(60,charge['duration_seconds'])
                    or not charge['duration_seconds']<=target['duration_seconds']
                    or not 16384<=charge['max_bytes']<=target['max_bytes']):
                    raise InputError('invalid observation reservation')
                _date(charge['reserved_at'])
                runs.add(rid)
            if (sum(row['duration_seconds'] for row in charges)>quota['max_seconds']
                or sum(row['max_bytes'] for row in charges)>quota['max_bytes']):
                raise InputError('observation reservations exceed saved budget')
        return value
    except ERRORS as exc:
        raise InputError('saved observation budget is unknown; preserve the previous collection state') from exc


def _save(state, identifier, value):
    document=dict(value=value,sha256=fs.digest(value))
    if len(fs.encode(document))>MAX_DOCUMENT:
        raise InputError('saved observation budget exceeds its bound')
    fs.write(fs.private(_folder(state,identifier))/'ledger.json',document)


def _stop(directory, transport):
    status=fs.read(directory/'status.json',64*1024)
    if (status['run_id']!=directory.name or status.get('status') not in TERMINAL
        or status.get('stop_verified') is not True):
        return 'unverified'
    if status['child'] is None and not fs.safe(directory/'start-permit.json').exists():
        return 'not_started_verified'
    if transport=='local':
        return 'local_stop_verified'
    report=fs.read(directory/'output.json')
    if (fs.read(directory/'output-receipt.json',8192)['sha256']!=fs.digest(report)
        or report['run_id']!=directory.name or report['status']!=status['status']
        or report['stop_verified'] is not True):
        return 'unverified'
    outcome=report['data']['result']['collection_status']
    return f'remote_reported_{outcome}' if REMOTE_TERMINAL.get(outcome)==report['status'] else 'unverified'


def _completion(state, charge, transport):
    try:
        directory=fs.folder(state,charge['run_id'])
        plan=fs.plan(directory)
        if (plan['os_observation']['reservation']!=charge
            or plan['os_observation']['collector']['transport']!=transport):
            return 'unverified'
        return _stop(directory,transport)
    except ERRORS:
        return 'unverified'


def _prior(state, ledger):
    for entry in ledger['approvals'].values():
        kinds={target['source_id']:target['collector']['transport'] for target in entry['plan']['targets']}
        for reservation in entry['reservations']:
            yield reservation,_completion(state,reservation,kinds[reservation['source_id']])


def _require_completion(state, ledger):
    if any(status=='unverified' for _,status in _prior(state,ledger)):
        raise InputError('previous collection completion is unverified; inspect its saved run before repeating')


def _verify_saved_runs(state, identifier, ledger, *, require_one_offs_stopped=False):
    """A missing or rolled-back ledger cannot hide a committed observation run."""
    from .investigation_retention import iter_saved_plans

    approvals=ledger['approvals'].values() if ledger else ()
    recorded={row['run_id']:row for entry in approvals for row in entry['reservations']}
    for directory,plan in iter_saved_plans(state):
        context=plan.get('context') or {}
        request=plan['request']
        if context.get('investigation_id')!=identifier or request['operation']!='os.collect':
            continue
        if 'observation' in request:
            binding=plan.get('os_observation') or {}
            if directory.name not in recorded or recorded[directory.name]!=binding.get('reservation'):
                raise InputError('saved observation reservation is missing or inconsistent; preserve the previous collection state')
        elif require_one_offs_stopped:
            try:
                stopped=_stop(directory,request['arguments']['transport'])
            except ERRORS:
                stopped='unverified'
            if stopped=='unverified':
                raise InputError('previous collection completion is unverified; inspect its saved run before approval')


def _room(entry, plan=None):
    quota=entry['plan']['budgets'];reservations=entry['reservations']
    seconds=quota['max_seconds'] if plan is None else min(quota['max_seconds'],plan['duration_seconds'])
    size=quota['max_bytes'] if plan is None else min(quota['max_bytes'],plan['max_bytes'])
    return dict(remaining_runs=quota['max_runs']-len(reservations),
                remaining_seconds=max(0,seconds-sum(row['duration_seconds'] for row in reservations)),
                remaining_bytes=max(0,size-sum(row['max_bytes'] for row in reservations)))


def _show(plan):
    targets=[dict(source_id=row['source_id'],
                  **{k:row['collector'][k] for k in ('transport','host','port','role','duration_seconds','interval_seconds','max_bytes')})
             for row in plan['targets']]
    return dict(base_id=plan['base_id'],window=plan['window'],budgets=plan['budgets'],
                targets=targets,delivery=plan['delivery'],probe_sha256=plan['probe_sha256'],
                local_execution_domain=plan['local_execution_domain'])


def _effective_window(doc, plan, sources):
    start,end=_window(doc,sources)
    return max(start,_date(plan['window']['start'])),min(end,_date(plan['window']['end']))


def _availability(doc, plan):
    try:
        start,end=_effective_window(doc,plan,[])
    except InputError:
        return dict(window_status='inactive',eligible_source_ids=[])
    if (doc['profile_sha256']!=plan['profile_sha256'] or start>=end
        or sha256(PROBE.read_bytes()).hexdigest()!=plan['probe_sha256']):
        return dict(window_status='inactive',eligible_source_ids=[])
    current=now()
    eligible=[row['source_id'] for row in plan['targets'] if row['source_id'] in doc['observation_plan']['sources']]
    return dict(window_status='waiting' if current<start else 'expired' if current>=end else 'open',
                effective_window=dict(start=start.isoformat(),end=end.isoformat()),eligible_source_ids=eligible)


def control(state, value):
    from .investigation_retention import writer
    request=normalize(value);context=request['context'];identifier=context['investigation_id']
    mode=request['mode']
    if mode=='preview':
        plan=_proposal(_doc(state,context),request)
        data=dict(_show(plan),stage='proposed',proposal_sha256=fs.digest(plan))
    elif mode=='status':
        doc=_doc(state,context)
        ledger=read_ledger(state,identifier)
        _verify_saved_runs(state,identifier,ledger)
        data=dict(stage='unapproved')
        if ledger:
            active=ledger['active'];entry=ledger['approvals'][active]
            runs=sorted((dict(row,completion=status) for row,status in _prior(state,ledger)),
                        key=lambda row:(row['reserved_at'],row['run_id']))
            data=dict(_show(entry['plan']),stage='approved',approval_sha256=active,approval_basis='harness_reported',
                      **_room(entry,doc['observation_plan']),**_availability(doc,entry['plan']),
                      completion_unverified=sum(row['completion']=='unverified' for row in runs),
                      recent_runs=runs[-16:])
    else:
        with writer(state,identifier):
            plan=_proposal(_doc(state,context),request);digest=fs.digest(plan)
            if digest!=request['proposal_sha256']:
                raise InputError('observation proposal changed; review its exact digest before approval')
            ledger=read_ledger(state,identifier)
            existing=ledger is not None and digest in ledger['approvals']
            _verify_saved_runs(state,identifier,ledger,require_one_offs_stopped=not existing)
            if not existing:
                ledger=ledger or dict(schema_version=FORMAT,active=digest,approvals={})
                if len(ledger['approvals'])>=MAX_APPROVALS:
                    raise InputError('saved observation approval limit reached')
                _require_completion(state,ledger)
                if now()>=_date(plan['window']['end']):
                    raise InputError('observation window already expired')
                ledger['active']=digest
                ledger['approvals'][digest]=dict(plan=plan,reservations=[])
                _save(state,identifier,ledger)
            data=dict(_show(plan),stage='approved' if ledger['active']==digest else 'superseded',
                      approval_sha256=digest,approval_basis='harness_reported',replayed=existing,**_room(ledger['approvals'][digest]))
    return dict(status='succeeded',operation=OPERATION,data=data)


def prepare_run(state, request, context, run_id):
    """The caller holds the investigation writer through operation plan admission."""
    if request['operation']!='os.collect' or context is None:
        return None,None
    identifier=context['investigation_id'];ledger=read_ledger(state,identifier)
    selection=request.get('observation')
    if selection is None:
        if ledger is not None:
            raise InputError('use the approved observation for investigation-bound collection')
        _verify_saved_runs(state,identifier,None)
        return None,None
    digest=selection['approval_sha256'];source=selection['source_id']
    if ledger is None or ledger['active']!=digest:
        raise InputError('active observation approval is unavailable')
    entry=ledger['approvals'][digest];plan=entry['plan']
    target=next((row['collector'] for row in plan['targets'] if row['source_id']==source),None)
    if target is None:
        raise InputError('collector source is outside the approved observation')
    doc=_doc(state,request['context'])
    if doc['profile_sha256']!=plan['profile_sha256'] or sha256(PROBE.read_bytes()).hexdigest()!=plan['probe_sha256']:
        raise InputError('observation profile or collector changed; review a new proposal')
    start,end=_effective_window(doc,plan,[source])
    settings=_collector(dict(target,**request['arguments']))
    if (settings['duration_seconds']>target['duration_seconds'] or settings['interval_seconds']<target['interval_seconds']
        or settings['max_bytes']>target['max_bytes']):
        raise InputError('collector exceeds per-run observation limits')
    if settings['transport']=='local' and reader_scope.observe()!=plan['local_execution_domain']:
        raise InputError('saved observation belongs to a different local execution domain')
    if settings['transport']=='winrm' and os.name!='nt':
        raise InputError('the WinRM launcher requires Windows')
    _verify_saved_runs(state,identifier,ledger)
    _require_completion(state,ledger)
    current=now()
    if not _fits(settings,start,end,current):
        raise InputError('collector does not fit the approved observation window')
    reservations=entry['reservations']
    if reservations and (current-_date(reservations[-1]['reserved_at'])).total_seconds()<plan['budgets']['min_gap_seconds']:
        raise InputError('minimum observation interval between launches has not elapsed')
    room=_room(entry,doc['observation_plan'])
    if room['remaining_runs']<1 or room['remaining_seconds']<settings['duration_seconds'] or room['remaining_bytes']<settings['max_bytes']:
        raise InputError('approved observation budget is exhausted')
    charge=dict(run_id=run_id,approval_sha256=digest,source_id=source,duration_seconds=settings['duration_seconds'],
                interval_seconds=settings['interval_seconds'],max_bytes=settings['max_bytes'],reserved_at=current.isoformat())
    reservations.append(charge)
    return dict(reservation=charge,collector=settings,starts_at=start.isoformat(),expires_at=end.isoformat()),ledger


def commit_reservation(state, context, ledger):
    _save(state,context['investigation_id'],ledger)


def time_left(binding):
    return (_date(binding['expires_at'])-now()).total_seconds()


def _fits(settings,start,end,current):
    allowance=30 if settings['transport']!='local' else 0
    return start<=current and (end-current).total_seconds()>=settings['duration_seconds']+allowance


def execution_arguments(request, plan, run_id):
    binding=plan.get('os_observation')
    if 'observation' not in request:
        if binding is not None:
            raise InputError('unexpected observation reservation')
        return request['arguments']
    charge=binding['reservation']
    expected={key:charge[key] for key in ('approval_sha256','source_id')}
    if request['operation']!='os.collect' or request['observation']!=expected or charge['run_id']!=run_id:
        raise InputError('observation reservation does not match the worker')
    settings=binding['collector']
    if not _fits(settings,_date(binding['starts_at']),_date(binding['expires_at']),now()):
        raise InputError('collector does not fit the approved observation window at start')
    return settings
