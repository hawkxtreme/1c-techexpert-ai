"""Read-only descriptions of explicit retained observations, never a normality verdict."""
from collections import Counter
import hashlib
from pathlib import Path
import re
import zlib

from . import operation_state as fs, retained_resources as retained
from .apdex import instant, validated_records
from .inputs import InputError, MAX_TOTAL_BYTES, json_value, open_verified_snapshot
from .sample_statistics import MAX_VALUES, describe_values, duration

KINDS = dict(case='cases', artifact='artifacts')
CONTEXT = ('platform_version', 'workload', 'launch_conditions', 'selection_basis')


def _text(value, maximum):
    return type(value) is str and 1 <= len(value) <= maximum and not any(ord(c) < 32 for c in value)


def _object(value):
    return value if type(value) is dict else {}


def normalize(inputs, operation, *, window=None, context=None, reported_normal_seconds=None, offset=0, limit=20):
    if type(inputs) is not list or not 1 <= len(inputs) <= 16:
        raise InputError('sample requires1..16 explicit retained resources')
    refs = []
    for value in inputs:
        if (type(value) is not dict or set(value) != {'kind', 'id'} or type(value['kind']) is not str
            or value['kind'] not in KINDS or type(value['id']) is not str or not re.fullmatch('[a-f0-9]{32}', value['id'])):
            raise InputError('invalid retained sample reference')
        if value in refs:
            raise InputError('the same retained resource cannot be selected twice')
        refs.append(dict(value))
    if not _text(operation, 256):
        raise InputError('one bounded operation label is required')
    context = {} if context is None else context
    if type(context) is not dict or set(context) - set(CONTEXT) or any(not _text(value, 2048) for value in context.values()):
        raise InputError('invalid reported sample context')
    if reported_normal_seconds is not None and not duration(reported_normal_seconds):
        raise InputError('reported normal must be a finite nonnegative duration up to one year')
    if type(offset) is not int or not 0 <= offset <= MAX_VALUES or type(limit) is not int or not 1 <= limit <= 200:
        raise InputError('invalid bounded sample page')
    if window is not None:
        if type(window) is not dict or set(window) != {'start', 'end'}:
            raise InputError('sample window requires start and end')
        try:
            ordered = instant(window['start']) < instant(window['end'])
        except (ValueError, TypeError, OverflowError) as exc:
            raise InputError('sample window requires bounded timestamps with explicit timezone') from exc
        if not ordered:
            raise InputError('sample window start must precede end')
    return dict(inputs=refs, operation=operation, window=dict(window) if window else None, context=dict(context),
                reported_normal_seconds=reported_normal_seconds, offset=offset, limit=limit)


def _load(state, ref, remaining, plans):
    from . import artifacts, storage
    folder = fs.safe(state / KINDS[ref['kind']] / ref['id'])
    fs.inventory(folder)
    receipt = fs.read(folder / 'receipt.json', 8192)
    preview = fs.read(folder / 'report.json', storage.MAX_REPORT_BYTES)
    if type(preview) is not dict or type(preview.get('sources')) is not list or len(preview['sources']) > 32:
        raise InputError('invalid retained sample source metadata')
    sources = [retained.selected(preview, dict(ref, source_id=s.get('id'))) for s in preview['sources'] if type(s) is dict]
    if len(sources) != len(preview['sources']):
        raise InputError('invalid retained sample source metadata')
    size = sum(s['size'] for s in sources)
    if size > remaining:
        raise InputError('sample retained sources exceed64MiB work limit')
    report = storage.verified_case(state, ref['id']) if ref['kind'] == 'case' else artifacts.load_artifact(state, ref['id'])
    if fs.digest(report) != fs.digest(preview):
        raise InputError('retained sample report changed during loading')
    context_digest, receipt_digest = retained.context(folder, ref['kind'])
    if receipt_digest != fs.digest(receipt):
        raise InputError('retained sample receipt changed during loading')
    if ref['kind'] == 'artifact' and (report.get('kind') != 'apdex' or len(sources) != 1
        or _object(report.get('result')).get('profile') != 'apdex-measurements-v1'):
        raise InputError('sample artifacts require retained normalized APDEX measurements')
    dependencies = [dict(kind=KINDS[ref['kind']], id=ref['id'], report_digest=fs.digest(report), receipt_digest=receipt_digest)]
    metadata = []
    payload = None
    for source in sources:
        source_ref = dict(ref, source_id=source['id'])
        binding = retained.binding(report, source_ref, source)
        crc = 0
        chunks = []
        path=folder/'sources'/(source['id']+'.bin') if ref['kind']=='case' else artifacts.source_path(folder,source)
        with open_verified_snapshot(fs.safe(path),
                source['sha256'], expected_size=source['size']) as stream:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                crc = zlib.crc32(chunk, crc)
                if ref['kind'] == 'artifact':
                    chunks.append(chunk)
        if ref['kind'] == 'artifact':
            payload = b''.join(chunks)
        if binding:
            from .input_intake import read_plan
            if binding['id'] not in plans:
                parent = fs.safe(state / 'artifacts' / binding['id'])
                fs.inventory(parent)
                parent_receipt = fs.digest(fs.read(parent / 'receipt.json', 8192))
                plan = read_plan(state, binding['id'])
                if parent_receipt != fs.digest(fs.read(parent / 'receipt.json', 8192)):
                    raise InputError('sample parent changed during loading')
                plans[binding['id']] = dict(report=plan, receipt_digest=parent_receipt)
            cached = plans[binding['id']]
            plan = cached['report']
            retained.check_plan(plan, binding, source, crc)
            if cached['receipt_digest'] != fs.digest(fs.read(state / 'artifacts' / binding['id'] / 'receipt.json', 8192)):
                raise InputError('sample parent changed during binding validation')
            dependency = dict(kind='artifacts', id=binding['id'], report_digest=fs.digest(plan),
                receipt_digest=cached['receipt_digest'])
            if dependency not in dependencies:
                dependencies.append(dependency)
        metadata.append(dict(source_id=source['id'], sha256=source['sha256'], bytes=source['size'], crc32=crc, binding=binding))
    profiles = [s.get('profile', {}).get('platform_version') for s in sources if type(s.get('profile')) is dict]
    versions = sorted({value for value in profiles if _text(value, 64)})
    summary = dict(ref, report_digest=fs.digest(report), receipt_digest=receipt_digest, context_digest=context_digest,
        sources=metadata, declared_platform_versions=versions, product_version=report.get('product_version'),
        operation_binding='normalized_row_operation' if ref['kind'] == 'artifact' else 'caller_reported_not_verified')
    baseline = report.get('baseline', {})
    if ref['kind'] == 'case' and type(baseline) is dict and duration(baseline.get('reported_seconds')):
        summary['reported_normal'] = dict(seconds=baseline['reported_seconds'], status='user_reported_not_measured')
    return dict(ref=ref, report=report, summary=summary, payload=payload, size=size, dependencies=dependencies)


def _case_row(state, resource):
    from .storage import read_evidence
    report = resource['report']
    rows = report.get('metrics', [])
    metrics = [row for row in rows if type(row) is dict and row.get('name') == 'execution'] if type(rows) is list else []
    metric = metrics[0] if len(metrics) == 1 else {}
    value = metric.get('value') if metric.get('unit') == 'seconds' and metric.get('status') == 'known' else None
    reason = None
    if value != _object(report.get('durations_seconds')).get('execution'):
        value, reason = None, 'conflicting_execution_metric'
    refs = metric.get('evidence', [])
    evidence = []
    if type(refs) is list and 1 <= len(refs) <= 32:
        for ref in refs:
            identity = ref.get('id') if type(ref) is dict else ref
            if type(identity) is not str:
                raise InputError('invalid execution measurement evidence')
            item = read_evidence(state, resource['ref']['id'], identity)
            source_id = identity.split(':')[0]
            source = next((s for s in resource['summary']['sources'] if s['source_id'] == source_id), None)
            if source is None or item['sha256'] != source['sha256'] or type(ref) is dict and ref.get('sha256') != source['sha256']:
                raise InputError('execution evidence disagrees with retained sample source')
            evidence.append(dict(source_id=source_id, evidence_id=identity, sha256=source['sha256'],
                byte_start=item.get('byte_start', 0), byte_end=item.get('byte_end', source['bytes']),
                range_scope='parsed_record' if 'byte_start' in item else 'whole_source_with_checked_line', line=item['line']))
    if not evidence:
        value, reason = None, 'missing_measurement_evidence'
    timeline = report.get('timeline')
    starts = [row.get('timestamp') for row in timeline if type(row) is dict and row.get('kind') == 'started'] if type(timeline) is list else []
    stamp = starts[0] if len(starts) == 1 and type(starts[0]) is str else None
    life = _object(report.get('job_correlation')).get('job_lifecycle', {})
    outcome = 'unknown'
    if type(life) is dict and life.get('status') == 'established':
        if life.get('state') == 'completed':
            outcome = 'success'
        elif life.get('state') in ('failed', 'cancelled'):
            outcome = 'failed'
    return dict(resource['ref'], observation_id=resource['ref']['id'], operation_binding='caller_reported_not_verified',
        started_at=stamp, value_seconds=value, outcome=outcome, outcome_basis='platform_job_state_not_business_correctness',
        precision_seconds=metric.get('precision_seconds') if duration(metric.get('precision_seconds')) else None,
        measurement_basis=metric.get('basis') if _text(metric.get('basis'), 128) else 'normalized_execution_milestones',
        evidence=evidence, reason=reason)


def _duplicates(resources, case_rows):
    groups = {}
    excluded = {}
    for index, resource in enumerate(resources):
        sources = resource['summary']['sources']
        if not sources or any(s['binding'] is None for s in sources):
            continue
        material = tuple(sorted({(s['binding']['id'], s['binding']['report_digest'], s['binding']['member_id']) for s in sources}))
        key = (resource['ref']['kind'], material)
        if resource['ref']['kind'] == 'case':
            key += (resource['summary']['context_digest'],)
        groups.setdefault(key, []).append(index)
    for group in groups.values():
        if len(group) < 2:
            continue
        fingerprints = set()
        for index in group:
            row = case_rows.get(index)
            if row is not None:
                value = {key: row[key] for key in ('started_at', 'value_seconds', 'outcome', 'precision_seconds', 'measurement_basis', 'reason')}
                sources = {source['source_id']: source for source in resources[index]['summary']['sources']}
                evidence = []
                for record in row['evidence']:
                    token = {key: item for key, item in record.items() if key not in ('source_id', 'evidence_id')}
                    token['catalogue_member'] = sources[record['source_id']]['binding']
                    evidence.append(token)
                value['evidence'] = sorted(evidence, key=fs.encode)
                value['producer'] = resources[index]['summary']['product_version']
                fingerprints.add(fs.digest(value))
        if len(fingerprints) > 1:
            excluded.update({index: 'conflicting_input_interpretation' for index in group})
        else:
            excluded.update({index: 'duplicate_input_view' for index in group[1:]})
    return excluded


def describe(state, inputs, operation, **options):
    args = normalize(inputs, operation, **options)
    state = Path(state)
    resources, plans, dependencies = [], {}, []
    remaining = MAX_TOTAL_BYTES
    for ref in args['inputs']:
        resource = _load(state, ref, remaining, plans)
        remaining -= resource['size']
        resources.append(resource)
        for dependency in resource['dependencies']:
            if dependency not in dependencies:
                dependencies.append(dependency)
    case_rows = {i: _case_row(state, resource) for i, resource in enumerate(resources) if resource['ref']['kind'] == 'case'}
    duplicate_inputs = _duplicates(resources, case_rows)
    lower = instant(args['window']['start']) if args['window'] else None
    upper = instant(args['window']['end']) if args['window'] else None
    values, records, exclusions = [], [], Counter()
    counts = Counter(inspected=0, selected=0, included=0, missing_duration=0, unknown_outcome=0)
    first = last = None
    missing_start = 0
    fingerprint = hashlib.sha256()
    for index, resource in enumerate(resources):
        if resource['ref']['kind'] == 'case':
            observations = [case_rows[index]]
        else:
            raw = json_value(resource['payload'].decode('utf-8-sig'), reject_duplicates=True)
            if type(raw) is not list or counts['inspected'] + len(raw) > MAX_VALUES:
                raise InputError('sample exceeds100000 inspected observations')
            valid, _ = validated_records(raw)
            source = resource['summary']['sources'][0]
            observations = (dict(resource['ref'], observation_id=row['id'], row_index=n, operation=row['operation'],
                operation_binding='normalized_row_operation', started_at=row['started_at'], value_seconds=value,
                outcome='success' if row['success'] else 'failed', outcome_basis='normalized_success_flag',
                precision_seconds=None, measurement_basis='normalized_duration_seconds', reason=None,
                evidence=[dict(source_id='s1', sha256=source['sha256'], byte_start=0, byte_end=source['bytes'],
                    range_scope='whole_json_array_with_checked_row', row_index=n)]) for n, (row, _, value) in enumerate(valid, 1))
        for row in observations:
            counts['inspected'] += 1
            if counts['inspected'] > MAX_VALUES:
                raise InputError('sample exceeds100000 inspected observations')
            try:
                stamp = instant(row['started_at'])
            except (ValueError, TypeError, OverflowError):
                stamp = None
            reason = ('other_operation' if row.get('operation', operation) != operation else
                'unknown_operation_start' if lower is not None and stamp is None else
                'outside_window' if stamp is not None and (lower is not None and stamp < lower or upper is not None and stamp >= upper) else None)
            selected = reason is None
            if selected:
                counts['selected'] += 1
                if index not in duplicate_inputs:
                    if stamp is None:
                        missing_start += 1
                    else:
                        first = min(first, stamp) if first is not None else stamp
                        last = max(last, stamp) if last is not None else stamp
                reason = duplicate_inputs.get(index)
                if reason is None and row['outcome'] == 'failed':
                    reason = 'unsuccessful_completion'
                if reason is None and row['value_seconds'] is not None and not duration(row['value_seconds']):
                    reason = 'duration_outside_supported_range'
            if reason:
                exclusions[reason] += 1
                status = 'excluded'
            else:
                values.append(row['value_seconds'])
                if row['outcome'] == 'unknown':
                    counts['unknown_outcome'] += 1
                if row['value_seconds'] is None:
                    status = 'missing_duration'
                    counts['missing_duration'] += 1
                    reason = row['reason'] or 'unknown_duration'
                else:
                    status = 'included'
                    counts['included'] += 1
            row.update(index=counts['inspected'], status=status, reason=reason, normalized_start_utc=stamp.isoformat() if stamp else None)
            if row['value_seconds'] is not None and not duration(row['value_seconds']):
                row.update(value_seconds=None, original_value_in_retained_source=True)
            fingerprint.update(fs.encode(row))
            if args['offset'] < counts['inspected'] <= args['offset'] + args['limit']:
                records.append(row)
    statistics = describe_values(values)
    following = args['offset'] + len(records)
    return dict(schema_version=1, profile='retained-sample-v1', operation=operation, metric='execution_duration', unit='seconds',
        descriptor=dict(operation=dict(value=operation, origin='caller_reported_except_normalized_row_filter'),
            context=dict(values=args['context'], origin='caller_reported_not_verified'),
            reported_normal=dict(seconds=args['reported_normal_seconds'], status='not_provided' if args['reported_normal_seconds'] is None else 'user_reported_not_measured')),
        selection=dict(window=args['window'], window_rule='operation_start_in_half_open_window_whole_duration',
            failures='counted_and_excluded_from_completed_duration_distribution', unknown_durations='counted_not_zero',
            duplicates='same_verified_catalogue_view_only; conflicting_interpretations_excluded; equal_payload_not_merged', outlier_removal='none'),
        inputs=[resource['summary'] for resource in resources], dependencies=dependencies, counts=dict(counts),
        statistics=statistics, exclusions=dict(exclusions), records=records, matched_count=counts['inspected'],
        next_offset=following if following < counts['inspected'] else None,
        period=dict(first_started_utc=first.isoformat() if first else None, last_started_utc=last.isoformat() if last else None,
            missing_start_count=missing_start, basis='selected_operation_starts_not_capture_or_report_creation_time', clock_alignment='not_verified'),
        selection_sha256=fingerprint.hexdigest(), normal_established=False, independent_runs=None, requires_ai_interpretation=True,
        limitations=['Descriptive observed rows only. Their count does not prove independent runs, normality, representative sampling, comparable conditions, database ownership or a cause.',
            'Reported operation/context/normal and source profile versions remain declarations. A source integrity receipt is not authentication.',
            'Existing case execution metrics or normalized duration fields are used; raw CALL/SCALL durations are never substituted for a whole operation.',
            'Platform completion is separate from business correctness. Normalized success is supplied data. Unknown outcomes remain visible.',
            'Period means observed operation starts; capture continuity, historical completeness and clock alignment remain unknown.'])


def pin(state, arguments, data, add, references):
    expected = []
    summaries = data.get('inputs')
    if type(summaries) is not list or len(summaries) != len(arguments['inputs']):
        raise InputError('sample retained inputs disagree with request')
    for ref, summary in zip(arguments['inputs'], summaries):
        if any(summary.get(key) != value for key, value in ref.items()):
            raise InputError('sample retained resource identity mismatch')
        report = add(KINDS[ref['kind']], ref['id'])
        folder = state / KINDS[ref['kind']] / ref['id']
        context_digest, receipt_digest = retained.context(folder, ref['kind'])
        if (summary.get('report_digest') != fs.digest(report) or summary.get('receipt_digest') != receipt_digest
            or summary.get('context_digest') != context_digest):
            raise InputError('sample input changed before presentation')
        dependency = dict(kind=KINDS[ref['kind']], id=ref['id'], report_digest=fs.digest(report), receipt_digest=receipt_digest)
        if dependency not in expected:
            expected.append(dependency)
        metadata = summary.get('sources')
        if type(metadata) is not list or len(metadata) != len(report.get('sources', [])):
            raise InputError('sample source bindings are incomplete')
        for source, checked in zip(report['sources'], metadata):
            source_ref = dict(ref, source_id=source['id'])
            selected = retained.selected(report, source_ref)
            binding = retained.binding(report, source_ref, selected)
            if (checked.get('source_id') != source['id'] or checked.get('sha256') != selected['sha256']
                or checked.get('bytes') != selected['size'] or checked.get('binding') != binding
                or type(checked.get('crc32')) is not int or not 0 <= checked['crc32'] < 2**32):
                raise InputError('sample source binding disagrees with retained evidence')
            if binding:
                plan = add('artifacts', binding['id'])
                retained.check_plan(plan, binding, selected, checked['crc32'])
                dependency = dict(kind='artifacts', id=binding['id'], report_digest=fs.digest(plan),
                    receipt_digest=fs.digest(fs.read(state / 'artifacts' / binding['id'] / 'receipt.json', 8192)))
                if dependency not in expected:
                    expected.append(dependency)
    if data.get('dependencies') != expected or expected != references:
        raise InputError('sample dependencies disagree with retained inputs')
