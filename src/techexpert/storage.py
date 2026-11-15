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
    result['limitations'] = bundle['limitations'] + result['limitations']
    if len(result['limitations']) > 500:
        omitted = len(result['limitations']) - 500
        result['limitations'] = result['limitations'][:500] + [dict(code='additional_limitations', count=omitted)]
    result.update(schema_version=1, product_version=__version__, knowledge_revision=knowledge_revision(),
                  created_at=datetime.now(timezone.utc).isoformat(), origin=bundle['manifest']['origin'],
                  input_contract='normalized-events-v1', native_1c_compatibility_verified=False,
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
    line = next(itertools.islice(io.BytesIO(data), number-1, number), None)
    if line is None:
        raise InputError('evidence line does not exist')
    text = line.decode('utf-8-sig' if number == 1 else 'utf-8', errors='replace').rstrip('\r\n')
    return dict(case_id=case_id, evidence_id=evidence_id, sha256=source['sha256'], line=number,
                integrity_verified=True, untrusted_source_content=True, text=text[:4096], truncated=len(text)>4096)
