"""Shared retained-source bounds, catalogue origin and interpretation receipts."""
import hashlib
import re

from .inputs import InputError, MAX_FILE_BYTES, read_snapshot, json_value
from . import operation_state as fs


def selected(report, ref):
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


def binding(report, ref, source):
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


def check_plan(plan, binding, source, crc=None):
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


def context(folder, kind):
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
        context = {key: value for key, value in request.items() if key not in ('path', 'import_path', 'measurements', 'input_plan', 'members')} if type(request) is dict else request
    return fs.digest(context), fs.digest(receipt)
