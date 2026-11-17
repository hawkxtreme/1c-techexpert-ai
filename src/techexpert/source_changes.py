"""Verified retained-byte relations, separate from file history and event identity."""
import ntpath
import posixpath
import re
import zlib
import hashlib

from .inputs import InputError, MAX_FILE_BYTES, MAX_RECORD_BYTES, open_verified_snapshot, read_snapshot, json_value
from . import operation_state as fs
from .native_tj_stream import summarize_frames

KINDS = dict(case='cases', artifact='artifacts')


def reference(value):
    if (type(value) is not dict or set(value) != {'kind', 'id', 'source_id'}
        or type(value['kind']) is not str or value['kind'] not in KINDS or type(value['id']) is not str or not re.fullmatch('[a-f0-9]{32}', value['id'])
        or type(value['source_id']) is not str or not re.fullmatch(r's(?:[1-9]|[12][0-9]|3[0-2])', value['source_id'])):
        raise InputError('invalid saved source reference')
    return dict(value)


def _selected(report, ref):
    sources = report.get('sources')
    if (type(sources) is not list or len(sources) > 32
        or any(type(s) is not dict or type(s.get('id')) is not str or not re.fullmatch(r's(?:[1-9]|[12][0-9]|3[0-2])', s['id']) for s in sources)
        or len({s['id'] for s in sources}) != len(sources)):
        raise InputError('invalid saved source list')
    selected = next((item for item in sources if item.get('id') == ref['source_id']), None)
    if selected is None:
        raise InputError('selected source is unavailable in the saved resource')
    size = selected.get('size' if ref['kind'] == 'case' else 'bytes')
    if type(size) is not int or not 0 <= size <= MAX_FILE_BYTES or not re.fullmatch('[a-f0-9]{64}', str(selected.get('sha256', ''))):
        raise InputError('invalid saved source bounds')
    return dict(selected, size=size)


def _binding(report, ref, source):
    result = report if ref['kind'] == 'case' else report.get('result')
    intake = result.get('input_intake') if type(result) is dict else None
    if intake is None:
        return None
    if (type(intake) is not dict or not re.fullmatch('[a-f0-9]{32}', str(intake.get('artifact_id', '')))
        or not re.fullmatch('[a-f0-9]{64}', str(intake.get('plan_report_digest', '')))
        or type(intake.get('selected')) is not list or not 1 <= len(intake['selected']) <= 32):
        raise InputError('invalid saved input catalogue binding')
    selected = [capture for index, capture in enumerate(intake['selected'], 1)
                if type(capture) is dict and capture.get('source_id', 's' + str(index)) == ref['source_id']]
    if len(selected) != 1:
        raise InputError('ambiguous saved input catalogue source')
    capture = selected[0]
    if (capture.get('sha256') != source['sha256'] or capture.get('bytes') != source['size']
        or capture.get('input_origin') != source.get('input_origin')
        or not re.fullmatch(r'm[1-9][0-9]{0,2}', str(capture.get('member_id', '')))):
        raise InputError('saved source disagrees with its input catalogue capture')
    return dict(id=intake['artifact_id'], report_digest=intake['plan_report_digest'], member_id=capture['member_id'])


def _check_plan(plan, binding, source, crc=None):
    from .input_intake import selected_members
    if (plan.get('kind') != 'input_catalog' or plan.get('sources') != []
        or fs.digest(plan) != binding['report_digest']):
        raise InputError('source input catalogue integrity mismatch')
    member = selected_members(plan, [binding['member_id']])[0]
    root = plan['result']['roots'][member['root']]
    origin = dict(kind=root['kind'], path=root['path'], member=member['relative_path'] if root['kind'] != 'file' else None, member_id=member['id'])
    if source.get('input_origin') != origin:
        raise InputError('saved source origin disagrees with catalogue member')
    if member['bytes'] != source['size'] or member.get('sha256', source['sha256']) != source['sha256']:
        raise InputError('source bytes disagree with catalogue member')
    if crc is not None and 'crc32' in member and member['crc32'] != crc:
        raise InputError('source CRC disagrees with catalogue member')


def _context(folder, kind):
    receipt = fs.read(folder/'receipt.json', 8192)
    name = 'manifest' if kind == 'case' else 'request'
    raw = read_snapshot(fs.safe(folder/(name+'.json')), 1024**2)
    if hashlib.sha256(raw).hexdigest() != receipt.get(name+'_sha256'):
        raise InputError('source interpretation context integrity mismatch')
    request = json_value(raw.decode('utf-8-sig'), reject_duplicates=True)
    if kind == 'case':
        if type(request) is not dict:
            raise InputError('invalid saved case context')
        context = {key: request.get(key) for key in ('schema', 'scenario', 'selection', 'correlation_profile', 'workload_profile', 'incident_window')}
    else:
        # Import staging paths differ between captures; actual parameters such
        # as APDEX target, version, time and filters remain interpretation.
        context = {key: value for key, value in request.items() if key not in ('path', 'measurements', 'input_plan', 'members')} if type(request) is dict else request
    return fs.digest(context), fs.digest(receipt)


def _load(state, ref):
    from . import storage, artifacts
    folder = fs.safe(state / KINDS[ref['kind']] / ref['id'])
    fs.inventory(folder)
    report = storage.verified_case(state, ref['id']) if ref['kind'] == 'case' else artifacts.load_artifact(state, ref['id'])
    source = _selected(report, ref)
    binding = _binding(report, ref, source)
    context_digest, receipt_digest = _context(folder, ref['kind'])
    dependencies = [dict(kind=KINDS[ref['kind']], id=ref['id'], report_digest=fs.digest(report), receipt_digest=receipt_digest)]
    plan = None
    if binding:
        from .input_intake import read_plan
        fs.inventory(fs.safe(state / 'artifacts' / binding['id']))
        plan = read_plan(state, binding['id'])
        _check_plan(plan, binding, source)
        dependencies.append(dict(kind='artifacts', id=binding['id'], report_digest=fs.digest(plan),
                                 receipt_digest=fs.digest(fs.read(state/'artifacts'/binding['id']/'receipt.json', 8192))))
    return dict(ref=ref, report=report, source=source, path=folder/'sources'/(ref['source_id']+'.bin'),
                binding=binding, plan=plan, dependencies=dependencies, context_digest=context_digest, receipt_digest=receipt_digest)


def _read(stream, count):
    parts = []
    while count:
        data = stream.read(count)
        if not data:
            raise InputError('retained source became shorter while comparing')
        parts.append(data)
        count -= len(data)
    return b''.join(parts)


def _bytes(left, right):
    sources = [item['source'] for item in (left, right)]
    with open_verified_snapshot(left['path'], sources[0]['sha256'], expected_size=sources[0]['size']) as first, \
         open_verified_snapshot(right['path'], sources[1]['sha256'], expected_size=sources[1]['size']) as second:
        remaining = [s['size'] for s in sources]
        common = 0
        changed = False
        crcs = [0, 0]
        while max(remaining):
            chunks = [_read(stream, min(65536, remaining[index])) for index, stream in enumerate((first, second))]
            for index, block in enumerate(chunks):
                remaining[index] -= len(block)
                crcs[index] = zlib.crc32(block, crcs[index])
            overlap = min(map(len, chunks))
            if not changed:
                a, b = chunks
                if a[:overlap] == b[:overlap]:
                    common += overlap
                else:
                    common += next(index for index in range(overlap) if a[index] != b[index])
                    changed = True
                if len(a) != len(b):
                    changed = True
    return common, crcs


def _framing(item, point=None):
    source = item['source']
    if source.get('format') != '1c-tj-text-v1':
        return dict(status='not_applicable')
    from .native_tj import validate_profile
    try:
        validate_profile(source['profile'], source['path'])
    except (KeyError, ValueError, TypeError) as exc:
        raise InputError('unsupported saved TJ framing profile') from exc
    with open_verified_snapshot(item['path'], source['sha256'], expected_size=source['size']) as stream:
        result = summarize_frames(stream, size=source['size'], max_record_bytes=MAX_RECORD_BYTES, point=point)
    return dict(result, status='framed' if result['complete_scan'] else 'partial')


def _capture(source):
    acquisition = source.get('acquisition')
    if not isinstance(acquisition, dict) or acquisition.get('method') != 'tj-prefix-v1':
        return None
    if (type(acquisition.get('byte_start')) is not int or acquisition['byte_start'] != 0
        or type(acquisition.get('byte_end')) is not int or acquisition['byte_end'] != source['size'] or acquisition.get('sha256') != source['sha256']):
        raise InputError('invalid saved prefix acquisition bounds')
    identity = acquisition.get('file_identity')
    if type(identity) is not dict or not {'device', 'inode'} <= identity.keys() or any(type(v) is not str or not 1 <= len(v) <= 64 for v in identity.values()):
        raise InputError('invalid saved prefix file identity')
    scope = acquisition.get('reader_scope')
    if (type(scope) is not dict or scope.get('profile') != 'local-reader-domain-v1' or scope.get('status') != 'observed'
        or scope.get('platform') not in ('windows', 'linux') or not re.fullmatch('[a-f0-9]{64}', str(scope.get('id', '')))):
        return None
    return acquisition


def _ordered(one, two):
    values = [item.get(field) for item in (one, two) for field in ('started_monotonic_ns', 'finished_monotonic_ns')]
    return (all(type(v) is str and re.fullmatch('[0-9]{1,32}', v) for v in values)
            and int(values[0]) <= int(values[1]) <= int(values[2]) <= int(values[3]))


def _observation(left, right, byte_relation, duplicate):
    one, two = [_capture(item['source']) for item in (left, right)]
    relation = duplicate or 'unknown_origin'
    same_reader = same_identity = same_path = None
    ordered = False
    if not duplicate and one and two:
        same_reader = one['reader_scope'] == two['reader_scope']
        if not same_reader:
            relation = 'different_reader_domains'
        else:
            same_identity = one['file_identity'] == two['file_identity']
            paths = [item['source'].get('path') for item in (left, right)]
            # Case-sensitive Windows directories exist. Case-only differences
            # remain distinct lexical paths; never infer replacement by folding.
            normalize = ntpath.normpath if one['reader_scope']['platform'] == 'windows' else posixpath.normpath
            same_path = all(type(p) is str for p in paths) and normalize(paths[0]) == normalize(paths[1])
            ordered = _ordered(one, two)
            relation = ('order_unknown' if not ordered else 'same_observed_identity_different_path' if same_identity and not same_path else
                'distinct_observed_files' if not same_identity and not same_path else 'path_replaced' if not same_identity else
                {'identical': 'same_observed_prefix', 'extended_prefix': 'prefix_extended', 'shortened_prefix': 'prefix_shortened', 'changed': 'prefix_rewritten'}[byte_relation])
    return dict(relation=relation, same_reader=same_reader, same_observed_identity=same_identity, same_observed_path=same_path,
                capture_order='ordered' if ordered else 'unknown_or_not_ordered', lifetime_continuity='not_proven', rotation_proven=False,
                clock_alignment='not_verified')


def compare(state, before, after):
    from pathlib import Path
    refs = [reference(value) for value in (before, after)]
    left, right = [_load(Path(state), ref) for ref in refs]
    common, crcs = _bytes(left, right)
    sizes = [item['source']['size'] for item in (left, right)]
    byte_relation = ('identical' if common == sizes[0] == sizes[1] else 'extended_prefix' if common == sizes[0] else
                     'shortened_prefix' if common == sizes[1] else 'changed')
    for item, crc in zip((left, right), crcs):
        if item['binding']:
            _check_plan(item['plan'], item['binding'], item['source'], crc)
    same_bytes = byte_relation == 'identical'
    duplicate = ('same_retained_source' if before == after else 'same_catalogue_member'
                 if same_bytes and left['binding'] and left['binding'] == right['binding'] else None)
    fields = ('format', 'profile', 'declared_context', 'collection', 'record_budget')
    changes = [field for field in fields if left['source'].get(field) != right['source'].get(field)]
    if left['context_digest'] != right['context_digest']:
        changes.append('context')
    if left['report'].get('product_version') != right['report'].get('product_version'):
        changes.append('producer_version')
    observation = _observation(left, right, byte_relation, duplicate)
    first_frames = _framing(left)
    tail = first_frames.get('incomplete_tail')
    point = tail['byte_start'] if tail and tail['byte_start'] < sizes[1] else None
    second_frames = _framing(right, point)
    transition = dict(status='not_applicable' if not tail else 'unknown', valid_event=None)
    if tail and common == sizes[0] and not changes and observation['relation'] == 'prefix_extended':
        frame = second_frames.get('point_frame')
        if frame and frame['byte_start'] == tail['byte_start']:
            transition.update(status='frame_completed' if frame['terminated'] else 'still_incomplete', after_frame=frame)
    suggested = dict(byte_start=0, byte_end=sizes[1], basis='full_current_source')
    if duplicate and not changes:
        suggested = None
    elif observation['relation'] == 'prefix_extended' and not changes and first_frames.get('complete_scan'):
        suggested['byte_start'] = first_frames['terminated_prefix_bytes']
        suggested['basis'] = 'verified_common_prefix_include_old_incomplete_frame'
    dependencies = []
    summaries = []
    for item, crc in zip((left, right), crcs):
        for dependency in item['dependencies']:
            if dependency not in dependencies:
                dependencies.append(dependency)
        summaries.append(dict(item['ref'], report_digest=fs.digest(item['report']), sha256=item['source']['sha256'],
                              bytes=item['source']['size'], crc32=crc, context_digest=item['context_digest'], receipt_digest=item['receipt_digest']))
    return dict(schema_version=1, before=summaries[0], after=summaries[1], dependencies=dependencies,
        byte_relation=byte_relation, common_prefix_bytes=common, observation=observation,
        input_duplicate=dict(duplicate=True if duplicate else None, basis=duplicate or 'not_established'),
        interpretation=dict(same=not changes, changed_fields=changes),
        framing=dict(before=first_frames, after=second_frames, tail_transition=transition), suggested_after_range=suggested,
        counts=dict(unique_input_bytes_after=0 if duplicate else None, events_deduplicated=False), requires_ai_interpretation=True,
        limitations=['Byte equality and a scoped observed file ID do not prove uninterrupted history, absence of ABA, source-node or infobase ownership.',
            'Replacement at a path or another path for an ID does not prove a rotation mechanism.',
            'Reading suggestions never merge events, rewrite old evidence or establish a cause, collection completeness or absence of an incident.',
            'Tail completion concerns quote-aware framing only; accepted-event validity is not checked by this comparison.'])


def pin(state, arguments, data, add, references):
    """Recheck every derived dependency against the exact first-output snapshot."""
    expected = []
    for side in ('before', 'after'):
        ref = reference(arguments[side])
        report = add(KINDS[ref['kind']], ref['id'])
        summary = data.get(side, {})
        if any(summary.get(key) != value for key, value in ref.items()) or summary.get('report_digest') != fs.digest(report):
            raise InputError('source comparison input changed before presentation')
        source = _selected(report, ref)
        if summary.get('sha256') != source['sha256'] or summary.get('bytes') != source['size']:
            raise InputError('source comparison bytes disagree with saved resource')
        if type(summary.get('crc32')) is not int or not 0 <= summary['crc32'] < 2**32:
            raise InputError('source comparison requires a checked byte CRC')
        context_digest, receipt_digest = _context(state/KINDS[ref['kind']]/ref['id'], ref['kind'])
        if summary.get('context_digest') != context_digest or summary.get('receipt_digest') != receipt_digest:
            raise InputError('source comparison context changed before presentation')
        dependency = dict(kind=KINDS[ref['kind']], id=ref['id'], report_digest=fs.digest(report), receipt_digest=receipt_digest)
        if dependency not in expected:
            expected.append(dependency)
        binding = _binding(report, ref, source)
        if binding:
            plan = add('artifacts', binding['id'])
            _check_plan(plan, binding, source, summary.get('crc32'))
            dependency = dict(kind='artifacts', id=binding['id'], report_digest=fs.digest(plan),
                              receipt_digest=fs.digest(fs.read(state/'artifacts'/binding['id']/'receipt.json', 8192)))
            if dependency not in expected:
                expected.append(dependency)
    if data.get('dependencies') != expected or expected != references:
        raise InputError('source comparison dependency list disagrees with selected resources')
