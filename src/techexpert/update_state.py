"""Bounded observations of saved formats and local operation completion."""
import os
from pathlib import Path
import re
import stat

from . import check_history, context_excerpt, context_intake, context_program, fix_verification, investigation_progress, investigation_task, native_jr_sqlite, operation_state as fs, operations, os_observation, report_references
from . import apdex_preparation
from .context_disclosure import APDEX_VIEW, VIEW_READER_CAPABILITIES
from .inputs import InputError, json_value, read_snapshot
from . import logcfg_observation, native_tj


FORMATS = dict(profiles=[1,2], cases=[1], artifacts=[1,2], comparisons=[1],
    investigations=[1,2], **{'custom-templates':[1], 'operations':[1], 'kernel-calls':[1]})
STATE_CONTRACT = dict(schema_version=1, family='techexpert-local-state', schemas=FORMATS)
_ID = re.compile(r'[a-f0-9]{32}')
_RUN = re.compile(r'[a-f0-9]{64}')
_REVISION = re.compile(r'[0-9]{6}')
_TEMPLATE = re.compile(r'USR-[a-z0-9][a-z0-9-]{0,47}')
_ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError)


def supports(metadata, observed, *, case_retirement_schemas=(), report_retirement_schemas=(),
             tj_reference_schemas=(), tj_json_schemas=(), context_disclosure_schemas=(), context_intake_schemas=(),
             context_program_schemas=(), report_reference_schemas=(), investigation_progress_schemas=(),
             check_history_schemas=(), investigation_task_schemas=(), os_observation_schemas=(), jr_lgd_schemas=(),
             fix_verification_schemas=(), apdex_preparation_schemas=()):
    contract = metadata['state_contract']
    if contract is None and metadata['version'] in ('0.34.0','0.35.0'):
        contract = STATE_CONTRACT
    if (type(contract) is not dict or set(contract) != set(STATE_CONTRACT)
        or type(contract['schema_version']) is not int or contract['schema_version'] != 1
        or contract['family'] != STATE_CONTRACT['family'] or type(contract['schemas']) is not dict):
        return False
    declared = contract['schemas']
    if set(declared) != set(FORMATS) or type(metadata['knowledge_schema']) is not int or metadata['knowledge_schema'] not in (1,2):
        return False
    for name, versions in declared.items():
        if (type(versions) is not list or not versions or any(type(item) is not int or item not in FORMATS[name] for item in versions)
            or not set(observed[name]) <= set(versions)):
            return False
    return (set(observed.get('case-source-retirements', ())) <= set(case_retirement_schemas)
            and set(observed.get('investigation-report-retirements', ())) <= set(report_retirement_schemas)
            and set(observed.get('report-references', ())) <= set(report_reference_schemas)
            and set(observed.get('investigation-progress', ())) <= set(investigation_progress_schemas)
            and set(observed.get('check-history', ())) <= set(check_history_schemas)
            and set(observed.get('investigation-task', ())) <= set(investigation_task_schemas)
            and set(observed.get('os-observation', ())) <= set(os_observation_schemas)
            and set(observed.get('jr-lgd', ())) <= set(jr_lgd_schemas)
            and set(observed.get('fix-verification', ())) <= set(fix_verification_schemas)
            and set(observed.get('apdex-preparation', ())) <= set(apdex_preparation_schemas)
            and set(observed.get('tj-reference-windows', ())) <= set(tj_reference_schemas)
            and set(observed.get('tj-json', ())) <= set(tj_json_schemas)
            and set(observed.get('context-disclosure', ())) <= set(context_disclosure_schemas)
            and set(observed.get('context-intake', ())) <= set(context_intake_schemas)
            and set(observed.get('context-program', ())) <= set(context_program_schemas))


def _exists(path):
    try:
        fs.safe(path).lstat()
    except FileNotFoundError:
        return False
    return True


def inspect_state(state):
    """Inspect saved metadata and markers. Operation originals are never opened."""
    state = fs.safe(state)
    schemas = {name:set() for name in FORMATS}
    schemas['case-source-retirements'] = set()
    schemas['investigation-report-retirements'] = set()
    schemas['report-references'] = set()
    schemas['investigation-progress'] = set()
    schemas['check-history'] = set()
    schemas['investigation-task'] = set()
    schemas['os-observation'] = set()
    schemas['jr-lgd'] = set()
    schemas['fix-verification'] = set()
    schemas['apdex-preparation'] = set()
    schemas['tj-reference-windows'] = set()
    schemas['tj-json'] = set()
    schemas['context-disclosure'] = set()
    schemas['context-intake'] = set()
    schemas['context-program'] = set()
    problems = []
    remaining_bytes = 64*1024**2
    remaining_entries = 8192

    def children(path, *, optional=True):
        nonlocal remaining_entries
        try:
            stream = os.scandir(fs.safe(path))
        except FileNotFoundError:
            if optional:
                return []
            raise
        with stream:
            found = []
            for item in stream:
                remaining_entries -= 1
                if remaining_entries < 0:
                    raise InputError('bounded state inventory exhausted')
                info = item.stat(follow_symlinks=False)
                if getattr(info,'st_file_attributes',0)&0x400 or not (
                        stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    raise InputError('linked or special saved resource')
                found.append(Path(item.path))
        return sorted(found)

    def document(path, limit=16*1024**2):
        nonlocal remaining_bytes
        data = read_snapshot(fs.safe(path),min(remaining_bytes,limit),share_delete=True)
        remaining_bytes -= len(data)
        value = json_value(data.decode('utf-8'),reject_duplicates=True)
        if type(value) is not dict:
            raise InputError('saved metadata must be an object')
        return value

    def schema(kind, value):
        version = value.get('schema_version')
        if type(version) is not int or not 1<=version<=2**31-1:
            raise InputError('missing saved state schema')
        schemas[kind].add(version)

    def pending(kind, folder, current):
        owners = (current.get('owner'), current.get('child'))
        live = any(fs.inspect_process(info)['state']=='running' for info in owners if type(info) is dict)
        problems.append(dict(kind=kind, id=folder.name, status='active' if live else 'stop_unverified'))

    def managed(root, kind, pattern):
        for folder in children(root):
            if not pattern.fullmatch(folder.name):
                raise InputError('unexpected managed operation entry')
            try:
                current = document(folder/'status.json')
                schema(kind,current)
                if kind=='operations':
                    if current.get('run_id')!=folder.name:
                        raise InputError('operation status identity mismatch')
                    plan = document(folder/'plan.json')
                    fs.checked_plan(folder,plan,document(folder/'plan-receipt.json'))
                    if plan['request'].get('operation') == context_program.OPERATION:
                        schema('context-program',plan)
                    else:
                        schema(kind,plan)
                    if 'check_binding' in plan:
                        binding = check_history.saved_binding(plan)
                        if binding is not None:
                            schemas['check-history'].add(binding['schema_version'])
                    if 'observation' in plan['request']:
                        schemas['os-observation'].add(os_observation.FORMAT)
                    if 'presentation' in plan['request']:
                        if not context_intake.protects(plan['request']):
                            raise InputError('unknown retained operation presentation')
                        schemas['context-intake'].add(context_intake.reader_capability(plan['request']))
                    output = _exists(folder/'output.json')
                    receipt = _exists(folder/'output-receipt.json')
                    status = current.get('status')
                    if (status not in operations.TERMINAL or current.get('stop_verified') is not True or output!=receipt
                        or status in ('succeeded','partial') and not output):
                        pending(kind,folder,current)
                else:
                    if current.get('call_id')!=folder.name:
                        raise InputError('kernel status identity mismatch')
                    plan = document(folder/'plan.json')
                    schema(kind,plan)
                    if current.get('status')!='finished':
                        pending(kind,folder,current)
                        continue
                    claim = document(folder/'call-receipt.json')
                    value = claim.get('value')
                    digest = fs.digest(plan)
                    if (document(folder/'plan-receipt.json').get('sha256')!=digest
                        or type(claim.get('schema_version')) is not int or claim['schema_version']!=1
                        or type(value) is not dict or claim.get('sha256')!=fs.digest(value)
                        or value.get('call_id')!=folder.name or value.get('plan_sha256')!=digest
                        or value.get('controller',{}).get('tree_finished') is not True):
                        raise InputError('controller completion unverified')
                    if plan.get('action') == 'context-read' and value.get('response', {}).get('exit_code') == 0:
                        selection = json_value(plan['arguments']['selection'], reject_duplicates=True)
                        capability = VIEW_READER_CAPABILITIES.get(selection['kind'])
                        if capability is not None:
                            schemas['context-disclosure'].add(capability)
            except _ERRORS:
                problems.append(dict(kind=kind,id=folder.name,status='state_unavailable_or_incomplete'))

    def marker(path, kind):
        if _exists(path):
            problems.append(dict(kind=kind,status='writer_or_interruption'))

    try:
        profiles = state/'profiles'
        marker(profiles/'write.lock','profiles')
        for path in children(profiles):
            if path.name=='current.json' or re.fullmatch(r'[0-9]+\.json',path.name):
                schema('profiles',document(path))

        from .tj_reference import saved_reference_formats
        for kind in ('cases','artifacts','comparisons','investigations','custom-templates'):
            for folder in children(state/kind):
                if kind=='custom-templates' and folder.name=='writer.lock':
                    continue
                pattern = _TEMPLATE if kind=='custom-templates' else _ID
                if not pattern.fullmatch(folder.name):
                    raise InputError('unexpected saved resource entry')
                if kind in ('investigations','custom-templates'):
                    marker(folder/'write.lock',kind)
                    revisions = children(folder/'revisions',optional=False)
                    if not revisions or any(not _REVISION.fullmatch(path.name) for path in revisions):
                        raise InputError('revision history is incomplete')
                    for path in revisions:
                        report = document(path/'report.json')
                        schema(kind,report)
                        if kind == 'investigations':
                            version = report_references.observed_format(report)
                            if version is not None:
                                schemas['report-references'].add(version)
                            if 'stage_decision' in report:
                                schemas['investigation-progress'].add(investigation_progress.FORMAT)
                            if 'source_gaps' in report or (report.get('observation_plan') or {}).get('status')=='evidence_unavailable':
                                from .occurrence_resume import READER_CAPABILITY, gaps
                                gaps(report)
                                schemas['investigation-progress'].add(READER_CAPABILITY)
                            if investigation_task.saved(report):
                                schemas['investigation-task'].add(report['task_notes']['schema_version'])
                else:
                    report = document(folder/'report.json')
                    schema(kind,report)
                    if kind == 'cases':
                        schemas['tj-reference-windows'].update(saved_reference_formats(report))
                        sources = [*report.get('sources', []), *report.get('source_acquisition', [])]
                        if any(source.get('format') == native_tj.JSON_FORMAT for source in sources):
                            schemas['tj-json'].add(native_tj.JSON_READER)
                    if (kind == 'artifacts' and report.get('kind') == logcfg_observation.KIND
                            and report['result']['observation']['timestamp_profile'] == native_tj.JSON_ISO):
                        schemas['tj-json'].add(native_tj.JSON_READER)
                    if (kind == 'artifacts' and report.get('kind') == logcfg_observation.KIND
                            and 'process_search' in report['result']):
                        search = report['result']['process_search']
                        schemas['context-intake'].add(logcfg_observation.FILE_LOOKUP_CAPABILITY if 'file_binding' in search else 9)
                    if (kind=='artifacts' and report.get('kind')=='native-jr'
                            and report['result'].get('profile')==native_jr_sqlite.PROFILE):
                        schemas['jr-lgd'].add(native_jr_sqlite.READER_FORMAT)
                    if kind=='artifacts' and report.get('kind')==fix_verification.KIND:
                        schemas['fix-verification'].add(fix_verification.READER_FORMAT)
                    if kind == 'artifacts' and (report.get('kind') == apdex_preparation.KIND
                        or report.get('kind') == 'apdex' and report['result'].get('target_seconds') is None):
                        schemas['apdex-preparation'].add(apdex_preparation.READER_FORMAT)
                    if kind == 'artifacts' and report.get('kind') == context_excerpt.KIND:
                        schemas['context-disclosure'].add(context_excerpt.READER_CAPABILITY)
                        if fs.writer_active(folder):
                            problems.append(dict(kind='context-excerpt', id=folder.name, status='active'))

        exports = state / 'source-exports'
        if fs.writer_active(exports):
            problems.append(dict(kind='source-exports', status='active'))
        for folder in children(exports):
            if folder.name == 'writer.lock':
                continue
            marker(folder/'run.lock','source-exports')
            if _exists(folder/'started.json') and not _exists(folder/'execution.json'):
                problems.append(dict(kind='source-exports',id=folder.name,status='stop_unverified'))
        retention = state / 'retention'
        if fs.writer_active(retention):
            problems.append(dict(kind='retention', status='active'))
        from .case_retention import status as retirement_status
        for folder in children(retention / 'case-sources'):
            if not _ID.fullmatch(folder.name):
                raise InputError('unexpected case source registry entry')
            if fs.writer_active(folder):
                problems.append(dict(kind='case-sources', id=folder.name, status='active'))
            for entry in children(folder):
                if entry.name == 'writer.lock':
                    continue
                receipt = retirement_status(state, folder.name, entry.name, read=document)
                if receipt is None:
                    continue
                schema('case-source-retirements', receipt)
                if receipt['status'] == 'outcome_unverified':
                    problems.append(dict(kind='case-sources', id=folder.name, source_id=entry.name,
                                         status='retirement_outcome_unverified'))
        from .investigation_retention import status as report_status
        for folder in children(retention / 'reports'):
            if not _ID.fullmatch(folder.name):
                raise InputError('unexpected report retention entry')
            if fs.writer_active(folder):
                problems.append(dict(kind='reports', id=folder.name, status='active'))
            receipt = report_status(state, folder.name, read=document)
            if receipt is not None:
                schema('investigation-report-retirements', receipt)
                if receipt['status'] == 'cleanup_pending':
                    problems.append(dict(kind='reports', id=folder.name, status='cleanup_pending'))
        from .context_policy import stored_policy
        for folder in children(state / 'context-disclosure' / 'policies'):
            if not _RUN.fullmatch(folder.name):
                raise InputError('unexpected context disclosure policy entry')
            if fs.writer_active(folder):
                problems.append(dict(kind='context-disclosure', status='active'))
            policy = stored_policy(folder, folder.name, read=document)
            if policy is not None:
                schema('context-disclosure', policy)
                if 'apdex' in policy['categories']:
                    schemas['context-disclosure'].add(VIEW_READER_CAPABILITIES[APDEX_VIEW])
        marker(state/'incident-drafts/write.lock','incident-drafts')
        for folder in children(state/'incident-drafts'):
            if _ID.fullmatch(folder.name):
                marker(folder/'write.lock','incident-drafts')
        for path in children(state/'incident-private'):
            if path.suffix=='.lock':
                marker(path,'incident-private')
        for folder in children(state/os_observation.ROOT):
            if not _ID.fullmatch(folder.name):
                raise InputError('unexpected observation registry entry')
            ledger=os_observation.read_ledger(state,folder.name,read=document)
            schema('os-observation',ledger)
        managed(state/'operations','operations',_RUN)
        managed(state/'kernel-calls','kernel-calls',_ID)
    except _ERRORS:
        problems.append(dict(kind='saved_state',status='state_unavailable_or_incomplete'))
    return dict(activity='active' if any(item['status']=='active' for item in problems)
        else 'unresolved' if problems else 'idle_observed', schemata={name:sorted(values) for name,values in schemas.items()},
        problem_count=len(problems), problems=problems[:32],
        metadata_complete=not any(item['status']=='state_unavailable_or_incomplete' for item in problems),
        managed_activity_only=True, admission_locked=False)
