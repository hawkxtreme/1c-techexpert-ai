"""Passive investigation status from committed revisions and context-bound runs."""
from datetime import datetime, timezone
import stat

from . import operation_state as fs
from .inputs import InputError


FORMAT = 1
DECISIONS = {
    'sufficient_answer': ('completed', 'completed', 'Ответ по задаче сохранён.'),
    'checks_exhausted': ('partial', 'completed_with_limits', 'Доступные полезные проверки завершены.'),
    'budget_limit': ('partial', 'completed_with_limits', 'Этап завершён по установленному лимиту.'),
    'episode_needed': ('partial', 'needs_episode', 'Нужно выбрать эпизод расследования.'),
    'data_needed': ('partial', 'needs_data', 'Для продолжения нужны данные или доступ.'),
    'cancelled': ('cancelled', 'stopped', 'Агент сообщил об отмене этапа.'),
    'error': ('error', 'error', 'Агент зафиксировал ошибку этапа.'),
}
ACTIVE = {'starting', 'running', 'finalizing'}
MAX_CHECKS = 20
MAX_RESULT_METADATA = 32 * 1024**2
NO_TIMESTAMP = datetime.min.replace(tzinfo=timezone.utc)
ERRORS = (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError)
STOP_CODES = {'timeout', 'output_limit', 'owned_disk_limit', 'kernel_timeout', 'cancelled',
              'kernel_memory_limit', 'worker_failed_before_sealed_result', 'context_intake_incomplete'}


def validate_decision(doc):
    from .investigations import _object, _text

    if 'stage_decision' not in doc:
        return
    decision = _object(doc['stage_decision'], ('reason', 'detail'), ('reason', 'detail'))
    reason = _text(decision['reason'], 64)
    _text(decision['detail'], 2048)
    if reason not in DECISIONS or DECISIONS[reason][0] != doc['execution_status']:
        raise InputError('investigation stage reason disagrees with the execution status')
    if doc.get('workflow_stage') == 'awaiting_occurrence':
        raise InputError('awaiting occurrence already has a saved continuation reason')
    if reason == 'sufficient_answer' and doc['assessment'] is None:
        raise InputError('a completed answer requires a saved assessment')


def _instant(value):
    if type(value) is not str or len(value) > 64:
        raise InputError('invalid recorded timestamp')
    value = datetime.fromisoformat(value)
    if value.utcoffset() is None:
        raise InputError('recorded timestamp must include a time zone')
    return value


def _occurrence_window(occurrence):
    from .source_coverage import validate_request

    start, end = occurrence.get('started_at'), occurrence.get('ended_at')
    if start is None or end is None:
        return None
    try:
        return validate_request(window=dict(start=start, end=end))['window']
    except InputError:
        # Older reports may have a point event or a time representation that
        # cannot be used as the exact bounds of a retained evidence query.
        return None


def _record(folder, operation, revision):
    from .operations import TERMINAL

    row = dict(run_id=folder.name, operation=operation, revision=revision, state='unverified',
               local_stop_verified=False, cancellation_requested=False, last_recorded_at=None)
    try:
        current = fs.read(folder/'status.json', 64*1024)
        state = current['status']
        if (current['run_id'] != folder.name or type(current['schema_version']) is not int
                or current['schema_version'] != 1 or state not in TERMINAL | {'preparing','starting','running','stopping'}):
            return row
        records = [current['heartbeat_at']]
        if current.get('finished_at') is not None:
            records.append(current['finished_at'])
        try:
            request = fs.read(folder/'cancel.json', 8192)
        except FileNotFoundError:
            request = None
        if request is not None:
            records.append(request['requested_at'])
            row['cancellation_requested'] = True
        row['last_recorded_at'] = max(records, key=_instant)
        reason = current.get('stop_reason')
        row['stop_reason'] = reason if type(reason) is str and reason in STOP_CODES else None
        row['local_stop_verified'] = current.get('stop_verified') is True
        if state in TERMINAL and row['local_stop_verified']:
            row['state'] = state
        elif state == 'stopping' or row['cancellation_requested']:
            row['state'] = 'stop_requested'
        elif fs.inspect_process(current['owner'])['state'] == 'running':
            if state in ('preparing','starting'):
                row['state'] = 'starting'
            elif state == 'running':
                if row['local_stop_verified']:
                    row['state'] = 'finalizing'
                elif fs.inspect_process(current.get('child'))['state'] == 'running':
                    row['state'] = 'running'
    except ERRORS:
        row.update(state='unverified', local_stop_verified=False)
    return row


def _case_volume(state, result, remaining):
    from .operations import _snapshot_folder

    try:
        case, = [item for item in result['snapshots'] if item['kind'] == 'cases']
        folder = _snapshot_folder(state, 'cases', case['id'])
        path = fs.safe(folder/'report.json')
        info = path.lstat()
        size = info.st_size
        if not stat.S_ISREG(info.st_mode) or not 0 < size <= remaining:
            return None, remaining
        remaining -= size
        report = fs.read(path, size)
        if fs.digest(report) != case['report_digest'] or report['case_id'] != case['id']:
            return None, remaining
        sizes = [source['size'] for source in report['sources']]
        if all(type(value) is int and value >= 0 for value in sizes):
            return sum(sizes), remaining
    except ERRORS:
        return None, remaining
    return None, remaining


def _result_metadata(state, row, remaining):
    row.update(result_receipt='not_observed', saved_result_bytes=None, captured_input_bytes=None)
    if row['state'] not in ('succeeded','partial','failed','cancelled','invalid_input','interrupted'):
        return remaining
    try:
        folder = fs.folder(state, row['run_id'])
        receipt = fs.read(folder/'output-receipt.json', 8192)
        path = fs.safe(folder/'output.json')
        info = path.lstat()
        digest = receipt['sha256']
        if (not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= fs.MAX_DOCUMENT or type(digest) is not str
                or len(digest) != 64 or any(ch not in '0123456789abcdef' for ch in digest)):
            raise InputError('result receipt is unavailable')
        row.update(result_receipt='recorded', saved_result_bytes=info.st_size)
        if row['operation'] == 'case.analyze' and row['state'] in ('succeeded','partial') and info.st_size <= remaining:
            remaining -= info.st_size
            result = fs.read(path, info.st_size)
            if (fs.digest(result) != digest or result['run_id'] != row['run_id'] or result['operation'] != row['operation']
                    or result['status'] != row['state'] or result['stop_verified'] is not True):
                raise InputError('result manifest identity mismatch')
            row['result_receipt'] = 'checked'
            if result['snapshots']:
                row['captured_input_bytes'], remaining = _case_volume(state, result, remaining)
    except ERRORS:
        if row['state'] in ('succeeded','partial') or row['result_receipt'] != 'not_observed':
            row.update(result_receipt='unverified', saved_result_bytes=None, captured_input_bytes=None)
    return remaining


def _operations(state, identifier, revisions):
    from .capabilities import ROUTES
    from .investigation_retention import iter_saved_plans

    rows = []
    complete = True
    try:
        for folder, plan in iter_saved_plans(state):
            context = plan.get('context') or {}
            reported = plan['request'].get('context') or {}
            if identifier not in (context.get('investigation_id'),reported.get('investigation_id')):
                continue
            number = context.get('expected_revision')
            operation = plan['request']['operation']
            if (type(number) is not int or revisions.get(number) != (context['report_sha256'], context['profile_sha256'])
                    or context.get('investigation_id') != identifier
                    or reported != dict(investigation_id=identifier, expected_revision=number) or operation not in ROUTES):
                complete = False
                continue
            rows.append(_record(folder, operation, number))
    except ERRORS:
        complete = False
    return rows, complete


def _phase(doc, rows, complete):
    states = {row['state'] for row in rows}
    if 'stop_requested' in states:
        return 'stop_requested', 'operation_stop_requested', 'tool_registry', 'Остановка проверки запрошена.'
    if states & ACTIVE:
        return 'checking', 'operation_active', 'observed_local_process', 'Есть действующая проверка.'
    if not complete or 'unverified' in states:
        return 'needs_data', 'operation_status_unverified', 'tool_registry', 'Нужно подтвердить состояние проверок.'
    if doc.get('workflow_stage') == 'awaiting_occurrence':
        return 'needs_data', 'awaiting_occurrence', 'saved_report', 'Ожидается сообщение о повторении события.'
    decision = doc.get('stage_decision')
    if decision is not None:
        reason = decision['reason']
        _, state, message = DECISIONS[reason]
        return state, reason, 'harness_reported', message
    execution = doc['execution_status']
    if execution in ('completed','cancelled','error'):
        state = {'completed':'completed','cancelled':'stopped','error':'error'}[execution]
        return state, None, 'harness_reported', 'Сохранён итог этапа. Причина остановки не записана.'
    return 'awaiting_agent', None, 'saved_report', 'Этап можно продолжить в текущем чате.'


def view(state, investigation_id):
    from . import context_policy, investigations, occurrence_resume

    state = fs.safe(state)
    head = investigations._read_head(state, investigation_id)
    chain = context_policy.verified_revisions(state, investigation_id, head['revision'])
    doc = next(chain)
    revisions = {doc['revision']: (fs.digest(doc), doc['profile_sha256'])}
    for previous in chain:
        revisions[previous['revision']] = fs.digest(previous), previous['profile_sha256']
    validate_decision(doc)
    stage = doc.get('workflow_stage','initial_analysis')
    collection = (doc.get('observation_plan') or {}).get('collection_state','unknown')
    occurrence = doc.get('occurrence') or {}
    occurrence_status = occurrence.get('status')
    if (stage not in investigations.STAGES or collection not in investigations.COLLECTION_STATES
            or occurrence_status not in (None,'reported_not_verified','evidenced_by_harness')
            or doc['execution_status'] not in investigations.EXECUTIONS or doc['cause_state'] not in investigations.CAUSES):
        raise InputError('unsupported saved investigation status')
    rows, complete = _operations(state, investigation_id, revisions)
    recorded = [doc['created_at'], *(row['last_recorded_at'] for row in rows if row['last_recorded_at'])]
    last = max(recorded, key=_instant)
    rows.sort(key=lambda row: (row['state'] in ACTIVE | {'stop_requested','unverified'},
                               _instant(row['last_recorded_at']) if row['last_recorded_at'] else NO_TIMESTAMP,
                               row['run_id']), reverse=True)
    recent = rows[:MAX_CHECKS]
    remaining = MAX_RESULT_METADATA
    for row in recent:
        remaining = _result_metadata(state, row, remaining)
    phase, reason, basis, message = _phase(doc, rows, complete)
    if investigations._read_head(state, investigation_id) != head:
        raise InputError('investigation changed during the observation; repeat the status read')
    unknown = not complete or any(row['state'] in ('unverified','stop_requested') for row in rows)
    return dict(schema_version=FORMAT, investigation_id=investigation_id, revision=doc['revision'],
                workflow_stage=stage, state=phase, reason=reason,
                basis=basis, message=message, saved_execution_status=doc['execution_status'],
                saved_stage_reason=(doc.get('stage_decision') or {}).get('reason'), cause_state=doc['cause_state'],
                operation_inventory='complete' if complete else 'incomplete',
                active_checks=None if unknown else sum(row['state'] in ACTIVE for row in rows),
                recent_checks=recent, more_checks=len(rows)>len(recent), last_recorded_at=last, observed_at=fs.stamp(),
                collection_state=collection, occurrence_status=occurrence_status,
                occurrence_window=_occurrence_window(occurrence),
                source_gaps=occurrence_resume.public_gaps(doc),
                available_facts=dict(saved=len(doc['facts']), with_tool_measurement=sum('measurement' in row for row in doc['facts']),
                                     evidence_references=len(doc['evidence'])),
                scope='context-bound local operations and saved report metadata',
                collection_observation='saved_plan_only', bytes_scope='saved result file size and source lengths recorded at capture',
                collector_stop_verified=None, evidence_content_revalidated=False)
