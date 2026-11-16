"""Private case snapshots, deliberately separate from original inputs."""
import hashlib
import io
import itertools
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .analysis import analyze_events
from .inputs import InputError, load_manifest, read_snapshot, json_value
from .native_tj import parse_tj
from .observations import summarize_native, preview_record

ROOT = Path(__file__).resolve().parents[2]
MAX_REPORT_BYTES = 16 * 1024 * 1024


def default_state_dir():
    if os.name == 'nt':
        return Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData/Local')) / '1c-techexpert-ai'
    return Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local/state')) / '1c-techexpert-ai'


def write_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def knowledge_revision():
    digest = hashlib.sha256()
    for path in sorted((ROOT / 'knowledge').rglob('*.md')):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def investigate(manifest_path, state_dir):
    bundle = load_manifest(manifest_path)
    result = analyze_events(bundle['events'], bundle['manifest']['selection'])
    native_sources = [s for s in bundle['sources'] if s['format'] == '1c-tj-text-v1']
    formats = {s['format'] for s in bundle['manifest']['sources']}
    contract = next(iter(formats)) if len(formats) == 1 else 'mixed-v1'
    if '1c-tj-text-v1' in formats:
        result['native_observations'] = summarize_native(bundle['native_events'])
        result['limitations'].append(dict(code='native_job_link_unproven',
            detail='Native event durations do not establish queue, execution or whole-job boundaries.'))
        result['next_steps'].insert(0, 'Сопоставить записи ТЖ с конкретным запуском по независимым идентификаторам; '
                                   'CALL/SCALL и совпадение времени не доказывают границы задания.')
    result['limitations'] = bundle['limitations'] + result['limitations']
    if len(result['limitations']) > 500:
        omitted = len(result['limitations']) - 500
        result['limitations'] = result['limitations'][:500] + [dict(code='additional_limitations', count=omitted)]
    result.update(schema_version=1, product_version=__version__, knowledge_revision=knowledge_revision(),
                  created_at=datetime.now(timezone.utc).isoformat(), origin=bundle['manifest']['origin'],
                  input_contract=contract, native_1c_compatibility_verified=False,
                  native_compatibility_scope='text_parser_only_not_sc01_end_to_end' if native_sources else 'not_checked',
                  symptom=bundle['manifest'].get('symptom', ''),
                  baseline=dict(reported_seconds=bundle['manifest'].get('reported_normal_seconds'),
                                status='user_reported_not_measured'),
                  sources=[{k: v for k, v in source.items() if k != 'data'} for source in bundle['sources']])
    if len(result['timeline']) > 200:
        result['timeline'] = result['timeline'][:200]
        result['limitations'].append(dict(code='timeline_preview_limited', limit=200))
    result['case_id'] = uuid.uuid4().hex
    if len((json.dumps(result,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode('utf-8')) > MAX_REPORT_BYTES:
        raise InputError('report exceeds the resumable case size limit; narrow the input')
    folder = Path(state_dir) / 'cases' / result['case_id']
    (folder / 'sources').mkdir(parents=True, exist_ok=False)
    if os.name != 'nt':
        folder.chmod(0o700)
    (folder / 'manifest.json').write_bytes(bundle['manifest_data'])
    for source in bundle['sources']:
        (folder / 'sources' / f"{source['id']}.bin").write_bytes(source['data'])
    write_json(folder / 'report.json', result)
    receipt = dict(schema_version=1, report_sha256=hashlib.sha256((folder / 'report.json').read_bytes()).hexdigest(),
                   manifest_sha256=bundle['manifest_sha256'])
    # The receipt is written last: incomplete captures are not resumable cases.
    write_json(folder / 'receipt.json', receipt)
    return result


def case_folder(state_dir, case_id):
    if not re.fullmatch(r'[a-f0-9]{32}', case_id):
        raise InputError('invalid case identifier')
    return Path(state_dir) / 'cases' / case_id


def load_case(state_dir, case_id):
    folder = case_folder(state_dir, case_id)
    try:
        report_data = read_snapshot(folder / 'report.json', MAX_REPORT_BYTES)
        receipt = json_value(read_snapshot(folder / 'receipt.json', 8192).decode('utf-8'))
        if hashlib.sha256(report_data).hexdigest() != receipt['report_sha256']:
            raise InputError('saved report integrity mismatch')
        if hashlib.sha256(read_snapshot(folder / 'manifest.json', 1024*1024)).hexdigest() != receipt['manifest_sha256']:
            raise InputError('saved manifest integrity mismatch')
        report = json_value(report_data.decode('utf-8'))
        if report.get('schema_version') != 1 or report.get('case_id') != case_id:
            raise InputError('unsupported saved case schema')
        return report
    except (OSError, KeyError, ValueError, TypeError) as exc:
        raise InputError(f'Cannot resume case: {exc}') from exc


def read_evidence(state_dir, case_id, evidence_id):
    match = re.fullmatch(r'(s[1-9][0-9]*):([1-9][0-9]*)', evidence_id)
    if not match:
        raise InputError('evidence id must be source:line, for example s1:2')
    report = load_case(state_dir, case_id)
    source = next((s for s in report['sources'] if s['id'] == match[1]), None)
    if source is None:
        raise InputError('unknown evidence source')
    data = read_snapshot(case_folder(state_dir, case_id) / 'sources' / (match[1] + '.bin'))
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise InputError('evidence snapshot integrity mismatch')
    number = int(match[2])
    if source['format'] == '1c-tj-text-v1':
        parsed = parse_tj(data, source['profile'], max_records=source['record_budget'])
        record = next((r for r in parsed['records'] if r['line'] == number), None)
        if record is None:
            raise InputError('evidence id is not the start of a parsed native record')
        text = data[record['byte_start']:record['byte_end']].decode('utf-8-sig').rstrip('\r\n')
        return dict(case_id=case_id, evidence_id=evidence_id, sha256=source['sha256'],
                    **{k: record[k] for k in ('line','end_line','byte_start','byte_end')},
                    integrity_verified=True, untrusted_source_content=True,
                    text=text[:4096], truncated=len(text)>4096)
    line = next(itertools.islice(io.BytesIO(data), number-1, number), None)
    if line is None:
        raise InputError('evidence line does not exist')
    text = line.decode('utf-8-sig' if number == 1 else 'utf-8', errors='replace').rstrip('\r\n')
    return dict(case_id=case_id, evidence_id=evidence_id, sha256=source['sha256'], line=number,
                integrity_verified=True, untrusted_source_content=True, text=text[:4096], truncated=len(text)>4096)


def list_native_events(state_dir, case_id, *, source_id=None, event=None, properties=None, offset=0, limit=20):
    """Page exact native matches in source/record order, never imply run membership."""
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise InputError('events requires offset>=0 and limit between 1 and 100')
    properties = {} if properties is None else properties
    if (not isinstance(properties, dict) or len(properties)>16 or
            any(not isinstance(k,str) or not 1<=len(k)<=128 or not isinstance(v,str) or len(v)>2048
                for k,v in properties.items())):
        raise InputError('at most 16 bounded property filters are supported')
    if event is not None and (not isinstance(event,str) or not 1<=len(event)<=64):
        raise InputError('invalid event name')
    report = load_case(state_dir, case_id)
    sources = [s for s in report['sources'] if s['format']=='1c-tj-text-v1']
    if source_id is not None:
        sources = [s for s in sources if s['id']==source_id]
        if not sources:
            raise InputError('unknown native evidence source')
    matched, page, statuses = 0, [], []
    for source in sources:
        data = read_snapshot(case_folder(state_dir,case_id)/'sources'/(source['id']+'.bin'))
        if hashlib.sha256(data).hexdigest()!=source['sha256']:
            raise InputError('evidence snapshot integrity mismatch')
        parsed = parse_tj(data,source['profile'],max_records=source['record_budget'])
        statuses.append(dict(source=source['id'],status=parsed['status']))
        for record in parsed['records']:
            if event is not None and record['event']!=event:
                continue
            if any(record['properties'].get(k)!=v for k,v in properties.items()):
                continue
            if offset<=matched<offset+limit:
                record['evidence']=dict(id=f"{source['id']}:{record['line']}", source=source['id'],
                    sha256=source['sha256'], **{k:record[k] for k in ('line','end_line','byte_start','byte_end')})
                page.append(preview_record(record))
            matched+=1
    return dict(case_id=case_id,matched_count=matched,offset=offset,limit=limit,
                next_offset=offset+limit if offset+limit<matched else None,records=page,
                source_statuses=statuses,integrity_verified=True,untrusted_source_content=True,
                job_correlation='not_established',selection_basis='exact_properties_only_not_job_identity')
