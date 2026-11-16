"""Explicit APDEX calculations over normalized measurements, not a BSP adapter."""
from datetime import datetime,timezone
import math


def instant(value):
    if not isinstance(value,str) or len(value)>80:raise ValueError('bounded timestamp with timezone required')
    parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
    if parsed.tzinfo is None:raise ValueError('timestamp must include timezone')
    return parsed.astimezone(timezone.utc)


def number(value,name,positive=False):
    if type(value) not in (int,float) or not math.isfinite(value) or value<0 or (positive and not value):
        raise ValueError(name+' must be a finite '+('positive' if positive else 'nonnegative')+' number')
    return value


def calculate(records,target_seconds,*,operation=None,start=None,end=None):
    target=number(target_seconds,'target_seconds',True)
    if target>365*86400:raise ValueError('target_seconds exceeds one year')
    if not isinstance(records,list) or len(records)>100000:raise ValueError('at most100000 measurements required')
    lower=instant(start) if start is not None else None
    upper=instant(end) if end is not None else None
    if lower is not None and upper is not None and lower>=upper:raise ValueError('start must precede end')
    operations=set();seen=set();valid=[]
    for row in records:
        if not isinstance(row,dict):raise ValueError('measurement must be an object')
        identity=row.get('id');op=row.get('operation')
        if any(not isinstance(v,str) or not 1<=len(v)<=256 or any(ord(c)<32 for c in v) for v in (identity,op)):
            raise ValueError('measurement id and operation must be bounded nonempty text')
        key=(op,identity)
        if key in seen:raise ValueError('duplicate measurement identity')
        seen.add(key);operations.add(op)
        timestamp=instant(row.get('started_at'))
        if type(row.get('success')) is not bool:raise ValueError('measurement success must be boolean')
        duration=row.get('duration_seconds')
        if duration is not None:number(duration,'duration_seconds')
        valid.append((row,timestamp,duration))
    if operation is None:
        if len(operations)>1:raise ValueError('select one operation before calculating APDEX')
        operation=next(iter(operations),None)
    elif not isinstance(operation,str) or not 1<=len(operation)<=256:raise ValueError('invalid operation')
    counts=dict(satisfied=0,tolerating=0,frustrated=0,unknown=0)
    selected=[]
    for row,timestamp,duration in valid:
        if row['operation']!=operation or (lower is not None and timestamp<lower) or (upper is not None and timestamp>=upper):continue
        selected.append(row['id'])
        if not row['success']:counts['frustrated']+=1
        elif duration is None:counts['unknown']+=1
        elif duration<=target:counts['satisfied']+=1
        elif duration<=4*target:counts['tolerating']+=1
        else:counts['frustrated']+=1
    total=len(selected)
    return dict(schema_version=1,profile='apdex-measurements-v1',operation=operation,
        target_seconds=target,tolerating_limit_seconds=4*target,unit='seconds',
        window=dict(start=start,end=end,bounds='start_inclusive_end_exclusive'),
        total=total,excluded=len(records)-total,**counts,
        score=(counts['satisfied']+.5*counts['tolerating'])/total if total and not counts['unknown'] else None,
        status='known' if total and not counts['unknown'] else 'empty' if not total else 'incomplete',
        source_record_ids=selected[:200],source_record_ids_truncated=total>200,
        limitations=['Normalized measurements only; native BSP export compatibility not established.',
                     'APDEX describes this operation, target and window; it does not establish a cause.'])
