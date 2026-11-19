"""Seal a released SC-01 trial's answer and check its structured evidence."""

from pathlib import PurePosixPath
import re
import stat

from scripts import sc01_trial as trial
from scripts.sc01_kit import verification_schema
from src.techexpert import context_policy, investigations, operation_state as fs, storage
from src.techexpert.comparison import compare_reports
from src.techexpert.context_disclosure import verify_case_summary
from src.techexpert.inputs import InputError, json_value, read_snapshot
from src.techexpert.operations import _guard_dependency_paths

RESULT = 'verification-result.json'
MAX_ANSWER = 1024 * 1024
MAX_RESULT = 4 * MAX_ANSWER
SAVED_ID = re.compile('[a-f0-9]{32}')
UNKNOWN = dict(effect='inconclusive', business_result='not_verified', goal='unknown', recurrence='unknown')


def _file(path):
    path = fs.safe(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise InputError('verification requires an ordinary snapshot file')
    return path


def _answer(raw):
    answer = json_value(raw.decode('utf-8-sig'), reject_duplicates=True)
    schema = verification_schema()
    properties = schema['properties']
    if type(answer) is not dict or not set(schema['required']) <= answer.keys() or answer.keys() - properties.keys():
        raise InputError('invalid verification answer schema')
    for name, rule in properties.items():
        if 'enum' in rule and answer[name] not in rule['enum']:
            raise InputError(f'invalid verification answer {name}')
    if not trial._answer_text(answer['summary']) or (
            answer.get('mechanism') is not None and not trial._answer_text(answer['mechanism'])):
        raise InputError('invalid verification answer text')
    for name in ('limitations', 'next_steps'):
        values = answer.get(name, [])
        if type(values) is not list or len(values) > 32 or any(not trial._answer_text(value) for value in values):
            raise InputError(f'invalid verification answer {name}')
    refs = answer['evidence']
    if type(refs) is not list or len(refs) > 32 or any(not trial._evidence_reference(ref, comparison=True) for ref in refs):
        raise InputError('invalid verification answer evidence')
    comparison_id = answer['comparison_id']
    if comparison_id is not None and (not isinstance(comparison_id, str) or not SAVED_ID.fullmatch(comparison_id)):
        raise InputError('invalid verification comparison identity')
    return answer


def _member_json(root, name, inventory):
    raw = read_snapshot(trial._relative(root, name), MAX_ANSWER)
    if trial.digest(raw) != inventory.get(name):
        raise InputError('released or prepared trial member changed')
    return json_value(raw.decode('utf-8'), reject_duplicates=True)


def _manifest_identity(root, name, inventory):
    manifest = _member_json(root, name, inventory)
    parent = PurePosixPath(name).parent
    sources = tuple((source['format'], inventory[(parent / source['path']).as_posix()])
                    for source in manifest['sources'])
    return inventory[name], sources


def _inputs(workspace, prepared, released):
    diagnosis = prepared['diagnosis_inventory']
    initial = _member_json(workspace, 'intake.json', diagnosis)['cases']
    verification = workspace / 'verification'
    inventory = released['inventory']
    intake = _member_json(verification, 'intake.json', inventory)
    phases = {}
    for group in ('before', 'after'):
        names = intake[group]
        if (type(names) is not list or len(names) != prepared['pair_count']
                or any(not isinstance(name, str) or not name.startswith('verification/') for name in names)):
            raise InputError('invalid released pair inventory')
        phases[group] = [_manifest_identity(verification, name.removeprefix('verification/'), inventory)
                         for name in names]
    allowed = {_manifest_identity(workspace, name, diagnosis) for name in initial}
    allowed.update(phases['before'] + phases['after'])
    return phases, allowed


def _verified_case(state, case_id, allowed):
    _guard_dependency_paths(state, 'cases', case_id)
    folder = storage.case_folder(state, case_id)
    report, report_sha = storage.load_case(state, case_id, with_digest=True)
    manifest_sha = trial.digest(read_snapshot(folder / 'manifest.json', MAX_ANSWER))
    sources = report['sources']
    identity = manifest_sha, tuple((source['format'], source['sha256']) for source in sources)
    if identity not in allowed or any(source['id'] != f's{index}' for index, source in enumerate(sources, 1)):
        raise InputError('case does not match a complete released or prepared trial input')
    _, checked_sha = storage.verified_case(state, case_id, with_digest=True)
    if checked_sha != report_sha:
        raise InputError('case report changed during verification')
    return report, report_sha, identity


def _comparison(state, comparison_id, phases, case):
    base = storage.comparison_folder(state, comparison_id)
    for name in ('report.json', 'report.md', 'receipt.json'):
        _file(base / name)
    report, report_sha = storage.read_comparison_record(state, comparison_id)
    groups = {}
    inputs = {}
    for group, expected in phases.items():
        ids = report[group + '_case_ids']
        if type(ids) is not list or len(ids) != len(expected):
            raise InputError('comparison must contain every released pair in order')
        if any(not isinstance(case_id, str) or not SAVED_ID.fullmatch(case_id) for case_id in ids):
            raise InputError('invalid released pair case identity')
        runs = [case(case_id) for case_id in ids]
        if [identity for _, _, identity in runs] != expected:
            raise InputError('comparison differs from the released pair order or inputs')
        groups[group] = [item for item, _, _ in runs]
        inputs[group] = [dict(case_id=item['case_id'], sha256=sha) for item, sha, _ in runs]
    references = inputs['before'] + inputs['after']
    if report['input_reports'] != references or len({ref['case_id'] for ref in references}) != len(references):
        raise InputError('comparison input reports differ from the verified released pairs')

    calculated = compare_reports(groups['before'], groups['after'])
    fields = ('comparison_profile', 'before_count', 'after_count', 'pairs', 'performance', 'result_correctness')
    if any(report[field] != calculated[field] for field in fields):
        raise InputError('saved comparison facts differ from the verified input reports')
    performance = calculated['performance']
    return report, dict(id=comparison_id, report_sha256=report_sha, **inputs,
                        pair_count=len(inputs['before']), performance_status=performance['status'],
                        before_median_seconds=performance['before_median_seconds'],
                        after_median_seconds=performance['after_median_seconds'],
                        business_result=calculated['result_correctness']['status'])


def _comparison_citation(state, case_id, identifier, report, proof, views):
    if report is None:
        raise InputError('comparison evidence requires a verified saved comparison')
    comparison_id = proof['id']
    if case_id in ('comparison', comparison_id) and identifier == comparison_id:
        return dict(comparison_report_sha256=proof['report_sha256'])
    if case_id == comparison_id:
        # A historical reply may name a comparison attachment from a cited revision.
        binding = ('comparison', comparison_id, investigations._digest(report))
        for investigation_id, revision in sorted(views):
            pinned = context_policy.selected_investigation(state, investigation_id, revision)
            for attachment in pinned['attachments']:
                if (attachment['id'] == identifier
                        and (attachment['kind'], attachment['target_id'], attachment['report_sha256']) == binding):
                    return dict(comparison_report_sha256=proof['report_sha256'],
                                investigation_id=investigation_id, investigation_revision=revision,
                                attachment=identifier)
    raise InputError('comparison citation does not identify the verified saved comparison')


def _citations(state, answer, case, comparison_report, comparison_proof):
    result = []
    pending = []
    views = set()
    for ref in answer['evidence']:
        case_id, identifier = ref['case_id'], ref['id']
        entry = dict(case_id=case_id, id=identifier)
        result.append(entry)
        if case_id in ('comparison', answer['comparison_id']):
            pending.append(entry)
            continue
        report, sha, _ = case(case_id)
        if identifier.startswith('view:'):
            proof = verify_case_summary(state, identifier, report)
            views.add((proof['investigation_id'], proof['investigation_revision']))
        else:
            record = storage.read_evidence(state, case_id, identifier)
            proof = {key: record[key] for key in ('sha256', 'line', 'byte_start', 'byte_end') if key in record}
        entry.update(case_report_sha256=sha, proof=proof)
    for entry in pending:
        entry['proof'] = _comparison_citation(state, entry['case_id'], entry['id'], comparison_report,
                                               comparison_proof, views)
    return result


def _claims(answer, comparison):
    observed = dict(UNKNOWN)
    if comparison is not None:
        if comparison['performance_status'] == 'improved':
            observed['effect'] = 'improved'
        observed['business_result'] = comparison['business_result']
    claims = {}
    for name, unknown in UNKNOWN.items():
        reported = answer[name]
        if reported == observed[name]:
            check = 'matches'
        elif reported == unknown:
            check = 'not_asserted'
        elif observed[name] == unknown:
            check = 'unsupported'
        else:
            check = 'contradicted'
        claims[name] = dict(reported=reported, observed=observed[name], check=check)
    return claims


def _result(output, prepared, released, raw):
    answer = _answer(raw)
    workspace = output / 'diagnosis'
    phases, allowed = _inputs(workspace, prepared, released)
    state = workspace / 'state'
    cases = {}

    def case(case_id):
        if case_id not in cases:
            cases[case_id] = _verified_case(state, case_id, allowed)
        return cases[case_id]

    report = comparison = None
    if answer['comparison_id'] is not None:
        report, comparison = _comparison(state, answer['comparison_id'], phases, case)
    citations = _citations(state, answer, case, report, comparison)
    claims = _claims(answer, comparison)
    checks = {claim['check'] for claim in claims.values()}
    if 'contradicted' in checks:
        status = 'contradictions'
    elif checks != {'matches'} or comparison is None or answer['status'] != 'completed':
        status = 'incomplete'
    else:
        status = 'consistent'
    return dict(schema_version=1, answer_utf8=raw.decode('utf-8'), answer_sha256=trial.digest(raw),
                preparation_sha256=fs.digest(prepared), release_sha256=fs.digest(released),
                frozen_diagnosis_sha256=released['frozen_diagnosis_sha256'], answer_status=answer['status'],
                cause_state=answer['cause_state'], comparison=comparison, citations=citations,
                claims=claims, structured_check=status, requires_independent_quality_review=True)


def finalize(output, response=None):
    output = fs.safe(output)
    with fs.writer(output):
        prepared = trial.verify_prepared(output)
        stage = trial._release_status(output)
        if stage['release_status'] != 'released':
            raise InputError('release the verification inputs before sealing an answer')
        path = fs.safe(output / RESULT)
        replayed = path.exists()
        if replayed:
            saved = fs.read(_file(path), MAX_RESULT)
            if (type(saved) is not dict or set(saved) != {'result', 'sha256'}
                    or fs.digest(saved['result']) != saved['sha256']):
                raise InputError('saved verification result integrity mismatch')
            raw = saved['result']['answer_utf8'].encode('utf-8')
            if len(raw) > MAX_ANSWER:
                raise InputError('saved verification answer exceeds the byte limit')
        else:
            response = response if response is not None else output / 'diagnosis/verification/answer.json'
            raw = read_snapshot(_file(response), MAX_ANSWER)
        result = _result(output, prepared, stage['release'], raw)
        receipt = dict(result=result, sha256=fs.digest(result))
        if replayed:
            if receipt != saved:
                raise InputError('saved verification proof no longer matches retained evidence')
        else:
            fs.write(path, receipt)
    return dict(status='verification_recorded', replayed=replayed, result_path=str(path), receipt_sha256=receipt['sha256'],
                answer_status=result['answer_status'], structured_check=result['structured_check'],
                claims=result['claims'], requires_independent_quality_review=True)
