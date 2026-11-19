"""Bounded incident-window projections of retained OS counter captures."""
from hashlib import sha256
import re

from . import artifacts, context_coverage, context_fields as fields, investigation_progress, operation_state as fs
from .analysis import parse_time
from .inputs import InputError, json_value, read_snapshot
from .os_probe import summarize


VIEW = 'os-window'
READER_CAPABILITY = 7
GROUPS = ('disk', 'cpu', 'memory', 'network')
COUNTERS = {
    'disk.avg_queue': 'requests', 'disk.inflight': 'requests',
    'disk.read_latency': 'seconds', 'disk.write_latency': 'seconds',
    'disk.read_iops': 'operations/second', 'disk.write_iops': 'operations/second',
    'disk.read_bytes_per_second': 'bytes/second', 'disk.write_bytes_per_second': 'bytes/second',
    'cpu.busy_percent': 'percent', 'memory.available': 'bytes',
    'network.rx_bytes_per_second': 'bytes/second', 'network.tx_bytes_per_second': 'bytes/second',
}
POINT_COUNTERS = ('disk.inflight', 'memory.available')


def _time(value):
    if type(value) is str and fields.DATE.fullmatch(value) and not value.endswith('-00:00'):
        try:
            return parse_time(value)
        except (ValueError, OverflowError):
            pass
    return None


def _select(rows, window):
    start, end = (parse_time(window[key]) for key in ('start','end'))
    first = last = previous = last_recorded = None
    previous_elapsed = 0
    selected = []
    untimed = reversals = contained = 0
    largest_gap = None
    for index, row in enumerate(rows):
        stamp = _time(row.get('timestamp'))
        elapsed = row['elapsed_seconds']
        if stamp is None:
            untimed += 1
        else:
            first = stamp if first is None else min(first,stamp)
            last = stamp if last is None else max(last,stamp)
            if last_recorded is not None and last_recorded >= stamp:
                reversals += 1
            last_recorded = stamp
            if start <= stamp < end:
                spacing = None
                if previous is not None and start <= previous < stamp:
                    spacing = elapsed - previous_elapsed
                    gap = (stamp-previous).total_seconds()
                    largest_gap = gap if largest_gap is None else max(gap,largest_gap)
                    contained += 1
                selected.append((index,stamp,spacing))
        previous, previous_elapsed = stamp, elapsed
    status = 'observed_samples_in_window' if selected else 'no_recorded_samples_in_window' if first is not None else 'timestamps_unavailable'
    coverage = dict(status=status, samples_in_window=len(selected), contained_intervals=contained,
        untimed_samples=untimed, clock_order_issues=reversals, largest_recorded_gap_seconds=largest_gap,
        observed_range=[stamp.isoformat() if stamp is not None else None for stamp in (first,last)],
        continuity='unknown')
    return selected, coverage


def _counter_key(item, group):
    device = item.get('device') if group == 'disk' else None
    if type(device) is not str or not re.fullmatch(r'[0-9]{1,12}:[0-9]{1,12}',device):
        device = None
    partition = item.get('partition') if group == 'disk' else None
    return group,item['instance'],device,partition if type(partition) is bool else None


def _summaries(rows, selected, artifact_id, group_filter, aliases, *, estimate_totals):
    devices = {}
    for index, stamp, spacing in selected:
        for metric_index,item in enumerate(rows[index]['metrics']):
            name, unit = item['metric'],item['unit']
            if COUNTERS.get(name) != unit:
                continue
            group = name.split('.',1)[0]
            if group_filter is not None and group != group_filter:
                continue
            group_key = _counter_key(item,group)
            metrics = devices.setdefault(group_key,{})
            entry = metrics.setdefault(name, dict(known=[], unavailable=0, boundary=0))
            if spacing is None and name not in POINT_COUNTERS:
                entry['boundary'] += 1
                continue
            value = fields.number(item.get('value'))
            if value is None or item.get('status') != 'known':
                entry['unavailable'] += 1
            else:
                entry['known'].append((value,index,metric_index,stamp,spacing))

    records = []
    for key, metrics in devices.items():
        group, _, _, partition = key
        identity = aliases('os_'+group, fs.digest(dict(artifact=artifact_id,object=key)))
        counters = {}
        for name, entry in metrics.items():
            values = entry['known']
            maximum = max(values,key=lambda item: item[0]) if values else None
            unit = COUNTERS[name]
            stats = dict(unit=unit, known_samples=len(values), unavailable_samples=entry['unavailable'],
                excluded_boundary_samples=entry['boundary'],
                missing_object_samples=len(selected)-len(values)-entry['unavailable']-entry['boundary'],
                minimum=min(item[0] for item in values) if values else None,
                maximum=maximum[0] if maximum else None,
                sample_mean=sum(item[0] for item in values)/len(values) if values else None)
            if maximum:
                stats['maximum_sample'] = dict(pointer=f'/samples/{maximum[1]}/metrics/{maximum[2]}',
                                               timestamp=maximum[3].isoformat())
            if unit.endswith('/second'):
                stats['estimated_total_unit'] = unit.removesuffix('/second')
                stats['estimated_total'] = sum(item[0]*item[4] for item in values) if values and estimate_totals else None
                stats['estimated_interval_seconds'] = sum(item[4] for item in values) if values and estimate_totals else None
            counters[name] = stats
        records.append(dict(group=group, instance=identity, reported_partition=partition, metrics=counters))
    return sorted(records,key=lambda record:(GROUPS.index(record['group']),record['instance']))


def view(state, doc, attachment, args, aliases):
    window = args.get('window') or investigation_progress._occurrence_window(doc.get('occurrence') or {})
    if window is None:
        raise context_coverage.WindowRequired('OS samples require the incident time window')
    from .operations import _guard_dependency_paths
    artifact_id = attachment['target_id']
    _guard_dependency_paths(state,'artifacts',artifact_id)
    report = context_coverage._pinned_report(state,attachment)
    if report.get('kind') != 'os_metrics' or len(report['sources']) != 1:
        raise InputError('select a retained OS metrics capture')
    source, = report['sources']
    path = artifacts.source_path(artifacts.artifact_folder(state,artifact_id),source,kind='os_metrics')
    raw = read_snapshot(path,source['bytes'])
    if len(raw) != source['bytes'] or sha256(raw).hexdigest() != source['sha256']:
        raise InputError('saved OS metric bytes differ from the capture')
    capture = json_value(raw.decode('utf-8-sig'),reject_duplicates=True)
    try:
        summary = summarize(capture)
    except AttributeError as exc:
        raise InputError('invalid saved OS metric samples') from exc
    rows = capture['samples']
    selected, coverage = _select(rows,window)
    group = args.get('metric_group')
    records = _summaries(rows,selected,artifact_id,group,aliases,estimate_totals=not coverage['clock_order_issues'])
    if context_coverage._pinned_report(state,attachment) != report:
        raise InputError('saved OS report changed during verification')
    offset, limit = args.get('offset',0),args.get('limit',8)
    page = records[offset:offset+limit]
    coverage.update(capture_samples=len(rows),plan_step_seconds=summary['plan']['interval_seconds'],
                    capture_status=fields.enum(summary['collection_status'],('completed','cancelled','timeout','byte_limit')))
    return dict(window=window,window_basis='explicit_window' if 'window' in args else 'saved_occurrence',
        time_basis='recorded_sample_timestamps',interval_selection='adjacent_sample_timestamps_wholly_in_half_open_window',
        clock_alignment='not_verified',can_establish_absence=False,node=aliases('os_node',summary['node']),
        role=fields.enum(summary['role'],('onec','sql','storage','client','terminal','web','other')),
        scope=fields.enum(summary['scope'],('windows_host','linux_kernel_and_current_network_namespace','host')),
        container=capture.get('container') if type(capture.get('container')) is bool else None,
        coverage=coverage,source=dict(id=source['id'],sha256=source['sha256'],byte_start=0,byte_end=source['bytes']),
        metric_group=group, records=page, offset=offset, total_objects=len(records),
        next_offset=offset+len(page) if offset+len(page)<len(records) else None,
        counter_estimates='observed_rate_times_monotonic_sample_spacing',attribution='not_established')
