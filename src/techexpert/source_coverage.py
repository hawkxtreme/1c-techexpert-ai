"""Bounded TJ suitability observations; never certifies complete collection."""
from collections import Counter,defaultdict
from itertools import islice
import hashlib
from pathlib import Path
import re
import stat

from . import __version__
from .analysis import parse_time
from .inputs import InputError,load_manifest,read_snapshot,MAX_FILE_BYTES,MAX_TOTAL_BYTES,MAX_EVENTS,MAX_RECORD_BYTES
from .native_tj import parse_tj

EVENT=re.compile(r'[A-Za-z_][A-Za-z0-9_.:-]{0,63}\Z')

def _window(value):
    if value is None:return None
    if not isinstance(value,dict) or set(value)!={'start','end'}:raise InputError('window requires exactly start and end')
    dates=[]
    for key in ('start','end'):
        text=value[key]
        if not isinstance(text,str) or 'T' not in text or text.endswith('-00:00'):raise InputError('window requires explicit known ISO time zones')
        try:dates.append(parse_time(text))
        except (ValueError,TypeError,OverflowError) as exc:raise InputError('invalid incident window timestamp') from exc
    if dates[1]<=dates[0]:raise InputError('window end must follow start')
    return dict(start=dates[0].isoformat(),end=dates[1].isoformat())

def _names(values,*,events=False,limit=16):
    if not isinstance(values,(list,tuple)) or len(values)>limit:raise InputError('too many requested event/field names')
    if any(not isinstance(v,str) or not 1<=len(v)<=128 or any(ord(c)<32 or c.isspace() for c in v)
           or (events and not EVENT.fullmatch(v)) for v in values):raise InputError('invalid event/field name')
    if len(set(values))!=len(values):raise InputError('duplicate event/field name')
    return list(values)

def validate_request(*,window=None,required_events=(),required_fields=()):
    return dict(window=_window(window),required_events=_names(required_events,events=True),required_fields=_names(required_fields))

def validate_collection(value):
    if value is None:return dict(status='unknown')
    if not isinstance(value,dict) or set(value)-{'events','filters','window'}:raise InputError('unsupported collection declaration')
    result=dict(status='user_declared_not_verified')
    if 'events' in value:result['events']=_names(value['events'],events=True,limit=64)
    if 'filters' in value:
        if not isinstance(value['filters'],str) or len(value['filters'])>2048:raise InputError('invalid collection filters')
        result['filters']=value['filters']
    if 'window' in value:result['window']=_window(value['window'])
    return result

def _counts(names,limit=100):
    counts=Counter();omitted=0
    for name in names:
        if not isinstance(name,str) or len(name)>128:omitted+=1;continue
        if name in counts or len(counts)<256:counts[name]+=1
        else:omitted+=1
    return dict(observed_counts=dict(counts.most_common(limit)),names_truncated=len(counts)>limit or omitted>0,
                occurrences_not_enumerated=omitted)

def _period(records,window):
    dates=[parse_time(record['timestamp_utc']) for record in records]
    first=min(dates) if dates else None;last=max(dates) if dates else None
    selected=list(records)
    intersects=None
    if window:
        start,end=parse_time(window['start']),parse_time(window['end'])
        selected=[record for record,stamp in zip(records,dates) if start<=stamp<end]
        intersects=bool(first is not None and last>=start and first<end)
    status=('no_parseable_timestamps' if not dates else 'not_requested' if not window else
            'observed_timestamps_in_window' if selected else 'no_recorded_timestamps_in_window')
    return dict(status=status,first_recorded_timestamp_utc=first.isoformat() if first else None,
        last_recorded_timestamp_utc=last.isoformat() if last else None,
        first_evidence=records[dates.index(first)]['evidence'] if first else None,
        last_evidence=records[dates.index(last)]['evidence'] if last else None,
        observed_span_seconds=(last-first).total_seconds() if first else None,
        records_in_window=len(selected) if window else None,span_intersects_window=intersects,
        comparison_basis='declared_clock_numeric_only',boundaries='half_open',
        operation_duration_not_used=True),selected

def summarize_bundle(bundle,*,window=None,required_events=(),required_fields=()):
    request=validate_request(window=bundle['manifest'].get('incident_window') if window is None else window,
                             required_events=required_events,required_fields=required_fields)
    sources={source['id']:source for source in bundle['sources']}
    records=defaultdict(list)
    for record in bundle['native_events']:records[record['evidence']['source']].append(record)
    attempts=bundle.get('source_attempts') or [dict(id=s['id'],availability='captured',path=s.get('path'),format=s['format']) for s in bundle['sources']]
    results=[]
    for attempt in attempts:
        source=sources.get(attempt['id']);native=attempt.get('format')=='1c-tj-text-v1'
        result=dict(attempt,assessment='not_assessed_by_tj_check' if not native else 'insufficient_data',
                    continuity='unknown',clock_alignment='not_verified')
        if not source or attempt['availability']!='captured':results.append(result);continue
        result.update(sha256=source['sha256'],bytes=source['size'],parse_status=source.get('parse_status','unknown'))
        if not native:results.append(result);continue
        observed=records[attempt['id']]
        period,selected=_period(observed,request['window'])
        issues=[issue for issue in bundle['limitations'] if issue.get('source')==attempt['id']]
        safe_issues=[{key:issue[key] for key in ('code','line','end_line','byte_start','byte_end','count','counts_by_code') if key in issue} for issue in issues[:20]]
        result.update(record_count=len(observed),profile=source.get('profile'),period=period,
            identity=dict(status='not_established_by_coverage',declared_context=source.get('declared_context',{}),
                context_basis='user_declared_not_verified',note='Use independent job_correlation evidence for a bounded run link.'),
            collection=source.get('collection',dict(status='unknown')),
            events=_counts(r['event'] for r in observed),
            fields=_counts(key for r in observed for key in set(r['properties'])|set(r.get('ambiguous_properties',{}))),
            issues=safe_issues,issues_truncated=len(issues)>20 or any(i.get('code')=='additional_limitations' for i in issues),
            snapshot_verified=source.get('snapshot_verified',False))
        event_checks={}
        declaration=result['collection'].get('events')
        declaration_window=result['collection'].get('window')
        _,declared_records=_period(observed,declaration_window)
        declaration_applies=(not declaration_window or bool(request['window'] and
            parse_time(request['window']['start'])>=parse_time(declaration_window['start']) and
            parse_time(request['window']['end'])<=parse_time(declaration_window['end'])))
        for event in request['required_events']:
            count=sum(r['event']==event for r in selected)
            any_count=sum(r['event']==event for r in observed)
            declared_count=sum(r['event']==event for r in declared_records)
            status=('declaration_conflicts_with_observed' if declaration is not None and event not in declaration and declared_count else
                'observed_in_requested_scope' if count else 'not_collected_declared' if declaration_applies and declaration is not None and event not in declaration
                else 'not_observed_collection_unknown')
            event_checks[event]=dict(status=status,observed_records=count,observed_any_time=any_count,
                declaration_window_applies_to_request=declaration_applies,
                evidence_preview=list(islice((r['evidence'] for r in selected if r['event']==event),3)),
                collection_verified=False,absence_proven=False)
        candidates=[r for r in selected if not request['required_events'] or r['event'] in request['required_events']]
        field_checks={}
        for field in request['required_fields']:
            ambiguous=sum(field in r.get('ambiguous_properties',{}) for r in candidates)
            usable=sum(field in r['properties'] and field not in r.get('ambiguous_properties',{}) and bool(r['properties'][field].strip()) for r in candidates)
            empty=sum(field in r['properties'] and field not in r.get('ambiguous_properties',{}) and not r['properties'][field].strip() for r in candidates)
            field_checks[field]=dict(status='observed_unambiguous' if usable else 'only_ambiguous_or_empty' if ambiguous or empty else 'not_observed',
                considered_records=len(candidates),usable_records=usable,ambiguous_records=ambiguous,empty_records=empty,
                event_scope=request['required_events'] or 'all_observed_events',absence_proven=False,
                evidence_preview=list(islice((r['evidence'] for r in candidates if field in r['properties'] and field not in r.get('ambiguous_properties',{}) and r['properties'][field].strip()),3)))
        result['requirements']=dict(events=event_checks,fields=field_checks)
        result['assessment']='observations_available' if selected else 'insufficient_data'
        if selected and source.get('parse_status')!='parsed':result['assessment']='partial_observations'
        results.append(result)
    usable=[s for s in results if s['assessment'] in ('observations_available','partial_observations')]
    status=('no_usable_tj_records_in_scope' if not usable else 'partial_observations' if
        any(s['assessment']=='partial_observations' or s['availability'] not in ('captured','duplicate_source') for s in results) else 'observations_available')
    return dict(schema_version=1,status=status,scope='SC01_native_TJ_only',request=request,sources=results,
        record_selection='all_parsed_records_in_each_explicit_file; not_a_job_identity_filter',
        can_establish_absence=False,requires_ai_interpretation=True,
        limitations=['First/last recorded timestamps and a span intersection do not prove collection completeness.',
            'A declared time zone does not establish clock alignment; comparisons are numeric only.',
            'Missing events/fields do not prove absence of a cause; filters and collector continuity are not verified.',
            'No database/node/process identity or whole-job boundary is inferred by this coverage check.'])

def inspect_manifest(path,*,window=None,required_events=(),required_fields=()):
    validate_request(window=window,required_events=required_events,required_fields=required_fields)
    bundle=load_manifest(path,tolerant_sources=True)
    result=summarize_bundle(bundle,window=window,required_events=required_events,required_fields=required_fields)
    result.update(manifest_sha256=bundle['manifest_sha256'],capture='temporary_read_only_not_saved',
                  state_created=False,source_connections_changed=False)
    return result

def _case_member(folder,name):
    current=folder;paths=[folder.parent,folder]
    for part in name.split('/'):
        current=current/part;paths.append(current)
    for path in paths:
        metadata=path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata,'st_file_attributes',0)&0x400:
            raise InputError('linked saved case member rejected')
        if path==paths[-1] and not stat.S_ISREG(metadata.st_mode):raise InputError('saved case member is not a regular file')
    return current

def inspect_case(state_dir,case_id,*,window=None,required_events=(),required_fields=()):
    validate_request(window=window,required_events=required_events,required_fields=required_fields)
    from .storage import load_case,case_folder
    from .inputs import json_value
    folder=case_folder(state_dir,case_id)
    for name in ('report.json','receipt.json','manifest.json'):_case_member(folder,name)
    report,digest=load_case(state_dir,case_id,with_digest=True)
    manifest=json_value(read_snapshot(_case_member(folder,'manifest.json'),1024*1024).decode('utf-8-sig'),reject_duplicates=True)
    metadata=report.get('sources')
    if not isinstance(metadata,list) or len(metadata)>32:raise InputError('invalid saved source count')
    sources=[];records=[];issues=[];total=0;verified=[];seen_ids=set();records_seen=0
    for saved in metadata:
        source=dict(saved);source_id=source.get('id')
        if not isinstance(source_id,str) or not re.fullmatch(r's(?:[1-9]|[12][0-9]|3[0-2])',source_id):raise InputError('invalid saved source identifier')
        if source_id in seen_ids:raise InputError('duplicate saved source identifier')
        seen_ids.add(source_id)
        collection=source.get('collection')
        if collection is None or collection=={'status':'unknown'}:source['collection']=dict(status='unknown')
        elif isinstance(collection,dict) and collection.get('status')=='user_declared_not_verified':
            source['collection']=validate_collection({k:v for k,v in collection.items() if k!='status'})
        else:raise InputError('invalid saved collection declaration')
        if source.get('format')=='1c-tj-text-v1':
            data=read_snapshot(_case_member(folder,'sources/'+source_id+'.bin'),min(MAX_FILE_BYTES,MAX_TOTAL_BYTES-total));total+=len(data)
            if len(data)!=source.get('size') or hashlib.sha256(data).hexdigest()!=source.get('sha256'):raise InputError('saved TJ snapshot integrity mismatch')
            budget=source.get('record_budget',0)
            if type(budget) is not int or not 0<=budget<=MAX_EVENTS:raise InputError('invalid saved record budget')
            try:
                parsed=parse_tj(data,source['profile'],max_records=min(budget,MAX_EVENTS-records_seen),max_record_bytes=MAX_RECORD_BYTES)
                records_seen+=parsed['records_seen']
                source['parse_status']=parsed['status']
                for record in parsed['records']:
                    record['evidence']=dict(source=source_id,id=source_id+':'+str(record['line']),sha256=source['sha256'],
                        **{k:record[k] for k in ('line','end_line','byte_start','byte_end')})
                    records.append(record)
                issues.extend(dict(issue,source=source_id) for issue in parsed['limitations'])
                if 'record_budget' not in source:issues.append(dict(code='original_record_budget_unknown',source=source_id))
            except (ValueError,KeyError):
                source['parse_status']='unsupported_saved_profile'
                issues.append(dict(code='unsupported_saved_profile',source=source_id))
            source['snapshot_verified']=True;verified.append(source_id)
        sources.append(source)
    attempts=report.get('source_acquisition')
    if attempts is None:
        captured={s['id']:s for s in sources};attempts=[]
        for number,spec in enumerate(manifest['sources'],1):
            source_id='s'+str(number)
            attempts.append(dict(id=source_id,format=spec.get('format'),path=spec.get('path'),
                availability='captured' if source_id in captured else 'unavailable_unknown_reason'))
    if (not isinstance(attempts,list) or len(attempts)>32 or any(not isinstance(a,dict) or not isinstance(a.get('id'),str)
        or not re.fullmatch(r's(?:[1-9]|[12][0-9]|3[0-2])',a['id']) or not isinstance(a.get('availability'),str) for a in attempts)):
        raise InputError('invalid saved acquisition records')
    bundle=dict(manifest=manifest,sources=sources,native_events=records,limitations=issues,source_attempts=attempts)
    result=summarize_bundle(bundle,window=window,required_events=required_events,required_fields=required_fields)
    result.update(case_id=case_id,case_report_sha256=digest,derived_by_product_version=__version__,
        persisted_coverage_available='source_coverage' in report,native_snapshot_integrity_verified=bool(verified),
        snapshot_sources_verified=verified,original_report_changed=False,original_paths_read=False)
    return result
