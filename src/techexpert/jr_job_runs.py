"""Relate recorded background-job boundaries inside a retained native JR session."""
from collections import Counter
from datetime import datetime
import re

from . import context_coverage, context_fields as fields, investigation_progress, native_jr
from . import operation_state as fs
from .analysis import parse_time
from .inputs import InputError


VIEW = 'jr-job-runs'
READER_CAPABILITY = 10
SESSION_START = '_$Session$_.Start'
SESSION_FINISH = '_$Session$_.Finish'
JOB_START = '_$Job$_.Start'
JOB_FINISH = ('_$Job$_.Finish', '_$Job$_.Succeed')
SESSION_EVENTS = (SESSION_START, SESSION_FINISH)
EVENTS = (*SESSION_EVENTS, JOB_START, *JOB_FINISH)
PART_NAME = re.compile(r'[0-9]{14}\.lgp', re.IGNORECASE)
POSITIVE = re.compile(r'[1-9][0-9]{0,19}')
JOB_PREFIX = '_$Job$_.'


def _event(row, sqlite):
    name = row.get('event')
    if type(name) is not str:
        return None
    if sqlite and len(name)>=2 and name[0]==name[-1]=='"':
        name=name[1:-1]
    if name in EVENTS:
        return name
    return 'other_job_marker' if name.startswith(JOB_PREFIX) else None


def _scope(row, sqlite):
    if row.get('computer') is None:
        return None
    application = row.get('application')
    if application!='BackgroundJob' and not (sqlite and application=='"BackgroundJob"'):
        return None
    if sqlite:
        codes = row['row_values']
        identity = codes['computerCode'],codes['appCode'],row.get('session')
    else:
        identity = row['computer_index'],row['application_index'],row.get('session')
    if any(value is None or not POSITIVE.fullmatch(str(value)) for value in identity):
        return None
    return tuple(map(str,identity))


def _label(row, sqlite):
    if sqlite:
        values = row['row_values']
        value = values['data'] if values['dataType']==ord('S') else None
    else:
        data = row['data']
        value = data[1] if len(data)==2 and data[0]=='S' else None
    return value if type(value) is str and 1<=len(value)<=256 and value.strip() else None


def _epochs(markers):
    opened = None
    jobs = []
    for name,row in markers:
        if name==SESSION_START:
            if jobs:
                yield opened,None,jobs
            opened,jobs = row,[]
        elif name==SESSION_FINISH:
            if jobs:
                yield opened,row,jobs
            opened,jobs = None,[]
        else:
            jobs.append((name,row))
    if jobs:
        yield opened,None,jobs


def _only(row, name, reason, opened=None, closed=None):
    if name==JOB_START:
        return reason,opened,closed,row,None,None
    if name in JOB_FINISH:
        return reason,opened,closed,None,row,None
    return reason,opened,closed,None,None,row


def _times(rows):
    values = [row.get('timestamp') or row.get('local_time') for row in rows]
    return [datetime.fromisoformat(value) for value in values] if all(values) else None


def _pair_status(opened, closed, start, finish, sqlite, duplicate_sources):
    members = {row['source'] for row in (opened,start,finish,closed)}
    if members & duplicate_sources:
        return 'duplicate_part_bytes'
    if not sqlite and len(members)!=1:
        return 'different_parts'
    connection = start.get('connection')
    if (type(connection) is not str or not POSITIVE.fullmatch(connection)
            or finish.get('connection')!=connection
            or any(row.get('connection') not in (None,'0',connection) for row in (opened,closed))):
        return 'connection_unverified'
    label = _label(start,sqlite)
    if label is None or _label(finish,sqlite)!=label:
        return 'job_label_unverified'
    return 'paired_markers'


def _jobs(opened, closed, markers, sqlite, parse_status, duplicate_sources):
    reason = None
    if opened is None or closed is None:
        reason = 'session_boundary_missing'
    elif parse_status!='parsed':
        reason = 'journal_parse_partial'
    else:
        ordered_times = _times([opened,*(row for _,row in markers),closed])
        if not ordered_times:
            reason = 'time_unknown'
        elif any(first>second for first,second in zip(ordered_times,ordered_times[1:])):
            reason = 'clock_order_uncertain'
        elif any((name!=JOB_START if index%2==0 else name not in JOB_FINISH)
                 for index,(name,_) in enumerate(markers)):
            reason = 'unpaired_marker' if len(markers)==1 else 'ambiguous_markers'
    if reason is not None:
        for name,row in markers:
            yield _only(row,name,reason,opened,closed)
        return
    for (_,start),(_,finish) in zip(markers[::2],markers[1::2]):
        status = _pair_status(opened,closed,start,finish,sqlite,duplicate_sources)
        yield status,opened,closed,start,finish,None
    if len(markers)%2:
        yield _only(markers[-1][1],JOB_START,'unpaired_marker',opened,closed)


def _series(result, source_hashes):
    sqlite = result['profile']==native_jr.lgd.PROFILE
    rows = result['records']
    ordered_parts = not sqlite and all(PART_NAME.fullmatch(row['file']) for row in rows)
    if ordered_parts:
        rows = sorted(rows,key=lambda row:(row['file'].casefold(),row['byte_start']))
    counts = Counter(source_hashes.values())
    duplicates = {key for key,value in source_hashes.items() if counts[value]>1}
    candidates, scopes = [],{}
    for row in rows:
        name = _event(row,sqlite)
        if name is None:
            continue
        identity = _scope(row,sqlite)
        if identity is not None:
            member = None if sqlite or ordered_parts else row['source']
            scopes.setdefault((member,*identity),[]).append((name,row))
        elif name not in SESSION_EVENTS:
            candidates.append(_only(row,name,'session_scope_unverified'))
    for markers in scopes.values():
        for opened,closed,jobs in _epochs(markers):
            candidates.extend(_jobs(opened,closed,jobs,sqlite,result['status'],duplicates))
    order = {row['id']:index for index,row in enumerate(rows)}
    candidates.sort(key=lambda candidate:order[(candidate[3] or candidate[4] or candidate[5])['id']])
    return candidates,sqlite


def _boundary(row, sources, sqlite):
    if row is None:
        return None
    proof = fields.proof(row)
    proof.update(source_sha256=sources[row['source']], sha256=row['sha256'])
    return dict(event=_event(row,sqlite),timestamp=fields.timestamp(row.get('timestamp')),
                recorded_local_time=fields.timestamp(row.get('local_time')),
                precision_seconds=row['precision_seconds'],evidence=proof)


def _summary(candidate, sources, sqlite, artifact, aliases):
    status,opened,closed,start,finish,other = candidate
    selected = start or finish or other
    label = _label(selected,sqlite)
    elapsed = None
    if status=='paired_markers':
        begin,end = _times((start,finish))
        elapsed = (end-begin).total_seconds()
    epoch = aliases('jr_session',fs.digest([artifact,opened['id']])) if opened is not None else None
    return dict(status=status,session_instance=epoch,job_label=aliases('jr_job',label),
                pairing_basis='observed_session_bounds_connection_and_job_label' if elapsed is not None else None,
                session_start=_boundary(opened,sources,sqlite),session_finish=_boundary(closed,sources,sqlite),
                start=_boundary(start,sources,sqlite),finish=_boundary(finish,sources,sqlite),
                other_marker=_boundary(other,sources,sqlite),recorded_wall_seconds=elapsed,execution_outcome='unknown')


def _window_match(candidate, bounds):
    status,_,_,start,finish,other = candidate
    times = [parse_time(row['timestamp']) for row in (start,finish,other) if row is not None and row.get('timestamp')]
    if not times:
        return None
    left,right = bounds
    if any(left<=stamp<right for stamp in times):
        return True
    return status=='paired_markers' and len(times)==2 and times[0]<right and times[1]>=left


def view(state, doc, attachment, args, aliases):
    from .operations import _guard_dependency_paths

    artifact = attachment['target_id']
    record = args.get('record')
    window = args.get('window')
    if window is None and record is None:
        window = investigation_progress._occurrence_window(doc.get('occurrence') or {})
        if window is None:
            raise context_coverage.WindowRequired('select a job marker or a recorded time window')
    _guard_dependency_paths(state,'artifacts',artifact)
    report = context_coverage._pinned_report(state,attachment)
    _,result = native_jr._parse_saved(state,report)
    source_hashes = {row['id']:row['sha256'] for row in report['sources']}
    series,sqlite = _series(result,source_hashes)
    untimed = 0
    if record is not None:
        matched = [item for item in series if any(row is not None and row['id']==record for row in item[3:])]
        if not matched:
            raise InputError('select a retained native job marker')
        count = len(matched)
    else:
        bounds = parse_time(window['start']),parse_time(window['end'])
        matched = []
        for candidate in series:
            present = _window_match(candidate,bounds)
            if present is None:
                untimed+=1
            elif present:
                matched.append(candidate)
        count = None if series and untimed==len(series) else len(matched)
    if context_coverage._pinned_report(state,attachment)!=report:
        raise InputError('saved JR changed during job inspection')
    offset,limit = args.get('offset',0),args.get('limit',8)
    rows = [_summary(item,source_hashes,sqlite,artifact,aliases) for item in matched[offset:offset+limit]]
    return dict(window=window,selection_basis='record' if record is not None else 'recorded_boundaries_or_paired_interval',
                relevant_boundaries_can_fall_outside_window=window is not None,records=rows,
                offset=offset,matched_count=count,next_offset=offset+len(rows) if offset+len(rows)<len(matched) else None,
                clock_alignment='not_verified',can_establish_absence=False,
                duration_basis='difference_of_recorded_job_marker_times',job_execution_time_established=False,
                coverage=dict(profile=result['profile'],parse_status=result['status'],parsed_records=result['event_count'],
                              job_candidates=len(series),untimed_candidates=untimed,
                              time_basis='native_utc' if sqlite else 'declared_fixed_offset' if result['utc_offset'] else 'local_time_only',
                              original_window_complete=None))
