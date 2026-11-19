"""Explicit APDEX calculations over normalized measurements, not a BSP adapter."""
from datetime import datetime,timezone
import math

from .inputs import InputError


def instant(value):
    if not isinstance(value,str) or len(value)>80:raise ValueError('bounded timestamp with timezone required')
    parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
    if parsed.tzinfo is None:raise ValueError('timestamp must include timezone')
    return parsed.astimezone(timezone.utc)


def number(value,name,positive=False):
    if type(value) not in (int,float) or type(value) is float and not math.isfinite(value) or value<0 or (positive and not value):
        raise ValueError(name+' must be a finite '+('positive' if positive else 'nonnegative')+' number')
    return value


def validate_target_selection(target_seconds, inventory_only):
    if inventory_only:
        if target_seconds is not None:
            raise InputError('APDEX inventory does not accept a target')
    elif target_seconds is None:
        raise InputError('select an explicit APDEX target or inventory_only')
    else:
        number(target_seconds, 'target_seconds', True)


def validated_records(records):
    """Validate retained normalized operation rows without inventing a target."""
    if not isinstance(records,list) or len(records)>100000:raise ValueError('at most100000 measurements required')
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
    return valid, operations


def measurement_category(success, duration, target_seconds):
    if not success:
        return 'frustrated'
    if duration is None:
        return 'unknown'
    if duration<=target_seconds:
        return 'satisfied'
    return 'tolerating' if duration<=4*target_seconds else 'frustrated'


def _selection(records, operation, start, end, *, require_one):
    lower=instant(start) if start is not None else None
    upper=instant(end) if end is not None else None
    if lower is not None and upper is not None and lower>=upper:raise ValueError('start must precede end')
    valid, operations = validated_records(records)
    if operation is None and require_one:
        if len(operations)>1:raise ValueError('select one operation before calculating APDEX')
        operation=next(iter(operations),None)
    elif operation is not None and (not isinstance(operation,str) or not 1<=len(operation)<=256):
        raise ValueError('invalid operation')
    selected = ((row, duration) for row, timestamp, duration in valid
                if (operation is None or row['operation'] == operation)
                and (lower is None or timestamp >= lower) and (upper is None or timestamp < upper))
    return operation, selected


def inventory(records, *, operation=None, start=None, end=None):
    operation, selected = _selection(records, operation, start, end, require_one=False)
    operations = set()
    total = 0
    for row, _ in selected:
        operations.add(row['operation'])
        total += 1
    return dict(schema_version=1, profile='apdex-measurements-v1', operation=operation, operation_count=len(operations),
        target_seconds=None, unit='seconds', window=dict(start=start, end=end, bounds='start_inclusive_end_exclusive'),
        total=total, excluded=len(records) - total, score=None, status='inventory' if total else 'empty',
        limitations=['Inventory of normalized measurements. A target is required to calculate APDEX.'])


def calculate(records,target_seconds,*,operation=None,start=None,end=None):
    target=number(target_seconds,'target_seconds',True)
    if target>365*86400:raise ValueError('target_seconds exceeds one year')
    operation, selection = _selection(records, operation, start, end, require_one=True)
    counts=dict(satisfied=0,tolerating=0,frustrated=0,unknown=0)
    selected=[]
    for row, duration in selection:
        selected.append(row['id'])
        counts[measurement_category(row['success'],duration,target)]+=1
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
