"""SC-01 calculations. Normalized milestones are never inferred from TJ calls."""
from datetime import datetime, timezone

SCOPE_KEYS = ('database', 'node', 'process', 'epoch', 'run')


def parse_time(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError('timestamp must be a bounded ISO8601 string')
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError('explicit timezone required')
    return dt.astimezone(timezone.utc)


def union_seconds(intervals):
    merged = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return sum((end - start).total_seconds() for start, end in merged)


def analyze_events(events, selection):
    if not isinstance(selection, dict) or any(not isinstance(selection.get(k), str) or not selection[k] for k in SCOPE_KEYS):
        raise ValueError('selection requires database, node, process, epoch and run')
    issues, selected, timeline, invalid_milestones = [], [], [], set()
    for index, item in enumerate(events):
        scope = item.get('scope')
        if not isinstance(scope, dict) or any(scope.get(k) != selection[k] for k in SCOPE_KEYS):
            continue
        ref = item.get('evidence', {}).get('id', f'event-{index + 1}')
        try:
            stamp = parse_time(item.get('timestamp'))
        except (ValueError, TypeError, OverflowError):
            issues.append(dict(code='invalid_time', evidence=[ref]))
            if item.get('kind') in ('queued', 'started', 'finished'):
                invalid_milestones.add(item['kind'])
            continue
        selected.append((item, stamp, ref))
        timeline.append(dict(kind=item.get('kind'), timestamp=item['timestamp'], evidence=ref))
    milestones = {}
    for kind in ('queued', 'started', 'finished'):
        candidates = [(time, ref) for item, time, ref in selected if item.get('kind') == kind]
        if len(candidates) == 1 and kind not in invalid_milestones:
            milestones[kind] = candidates[0]
        else:
            milestones[kind] = None
            issues.append(dict(code='ambiguous_milestone' if candidates else 'missing_milestone',
                               milestone=kind, evidence=[x[1] for x in candidates]))
    durations, metrics = {}, []
    for name, left, right in [('queue', 'queued', 'started'), ('execution', 'started', 'finished'), ('total', 'queued', 'finished')]:
        first, last = milestones[left], milestones[right]
        value, refs = None, []
        if first and last:
            refs = [first[1], last[1]]
            if last[0] >= first[0]:
                value = (last[0] - first[0]).total_seconds()
            else:
                issues.append(dict(code='contradictory_time', metric=name, evidence=refs))
        durations[name] = value
        metrics.append(dict(name=name, value=value, unit='seconds', evidence=refs,
                            status='known' if value is not None else 'unknown'))
    waits, wait_refs = [], []
    for item, start, ref in selected:
        if item.get('kind') != 'wait':
            continue
        try:
            end = parse_time(item.get('end'))
            if end < start:
                raise ValueError('negative wait')
        except (ValueError, TypeError, OverflowError):
            issues.append(dict(code='invalid_wait', evidence=[ref]))
            continue
        if durations['execution'] is not None:
            start, end = max(start, milestones['started'][0]), min(end, milestones['finished'][0])
        if end > start:
            waits.append((start, end))
            wait_refs.append(ref)
    wait_seconds = union_seconds(waits) if waits else None
    if wait_seconds is not None:
        metrics.append(dict(name='observed_wait_union', value=wait_seconds, unit='seconds', evidence=wait_refs, status='known'))
    if not selected:
        issues.append(dict(code='no_matching_events', evidence=[]))
    # A measured wait is an observation, not proof of the root cause of a regression.
    return dict(scenario='SC-01', selection=selection, durations_seconds=durations, metrics=metrics,
                wait_seconds=wait_seconds,
                wait_fraction_of_execution=(wait_seconds / durations['execution']
                                            if wait_seconds is not None and durations['execution'] else None),
                selected_event_count=len(selected), ignored_event_count=len(events)-len(selected),
                timeline=sorted(timeline, key=lambda x: parse_time(x['timestamp'])), limitations=issues,
                cause_state='insufficient_data', requires_ai_interpretation=True,
                next_steps=['Проверить принадлежность и покрытие источников.',
                            'Сопоставить с нормальным запуском при наличии измерений.',
                            'Проверить гипотезу задержки по дополнительным свидетельствам.'])
