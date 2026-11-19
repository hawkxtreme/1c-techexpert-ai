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
from .analysis import analyze_events,parse_time
from .inputs import InputError, load_manifest, read_snapshot, json_value, WHOLE_JSON_FORMATS,open_verified_snapshot
from .native_tj import FORMATS as TJ_FORMATS, JSON_FORMAT as TJ_JSON, iter_tj
from .observations import summarize_native, preview_record, native_report, with_evidence
from .job_correlation import correlate_job, record_matches_link
from .order_load import analyze_order_load
from .comparison import compare_reports

ROOT = Path(__file__).resolve().parents[2]
MAX_REPORT_BYTES = 16 * 1024 * 1024


def default_state_dir():
    if os.name == 'nt':
        return Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData/Local')) / '1c-techexpert-ai'
    return Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local/state')) / '1c-techexpert-ai'


def write_json(path, value, *, replacer=None, compact=False):
    path = Path(path)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=None if compact else 2,
                      separators=(',',':') if compact else None, allow_nan=False)
            if not compact:stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        (os.replace if replacer is None else replacer)(temporary,path)
    finally:
        if temporary.exists():
            temporary.unlink()


def knowledge_revision():
    from .knowledge import load_library
    return load_library()['legacy_digest']


def job_report(bundle):
    """Project verified lifecycle observations without inventing normalized events."""
    selection = bundle['manifest']['selection']
    correlation = correlate_job(bundle['lifecycle_documents'], bundle['native_events'], selection)
    life, link = correlation['job_lifecycle'], correlation['native_link']
    if link['status']=='established':
        # An unreadable session switch could invalidate ownership of later
        # records. Only located errors wholly outside the session are harmless.
        start, finish = link['session']['evidence']
        def only_retained_ambiguity(issue):
            return (issue['code']=='ambiguous_property' or
                    (issue['code']=='additional_limitations' and type(issue.get('count')) is int and issue['count']>0
                     and issue.get('counts_by_code')=={'ambiguous_property':issue['count']}))
        gaps = [issue for issue in bundle['limitations']
                if issue.get('source')==link['identity']['source'] and not only_retained_ambiguity(issue)
                and (issue.get('byte_start', -1)<finish['byte_end']
                     and issue.get('byte_end', finish['byte_end'])>start['byte_start'])]
        if gaps:
            link.update(status='not_established', identity={}, body={}, session={}, linked_evidence=[],
                        linked_count=0, linked_evidence_truncated=False)
            link['limitations'].append(dict(code='unparsed_session_window',
                detail='Unparsed bytes or omitted parser details prevent proving uninterrupted session ownership.'))
            correlation['status']='not_established'
    execution = life.get('execution_seconds') if life['status']=='established' else None
    durations = dict(queue=None, execution=execution, total=None)
    metrics = [dict(name=name, value=value, unit='seconds', status='known' if value is not None else 'unknown',
                    evidence=life.get('evidence', []) if value is not None else [])
               for name, value in durations.items()]
    if execution is not None:
        metrics[1].update(precision_seconds=life['precision_seconds'],
                          bounds_seconds=life['execution_bounds_seconds'], basis='platform_begin_end_seconds')
    timeline = []
    if life['status']=='established':
        for kind, field in (('started','begin_utc'), ('finished','end_utc')):
            if life.get(field):
                timeline.append(dict(kind=kind, timestamp=life[field], evidence=life.get('evidence', []),
                                     precision_seconds=life['precision_seconds']))
    return dict(scenario='SC-01', selection=selection, durations_seconds=durations, metrics=metrics,
                job_correlation=correlation, timeline=timeline, wait_seconds=None, wait_fraction_of_execution=None,
                selected_event_count=link.get('linked_count', 0),
                ignored_event_count=len(bundle['native_events'])-link.get('linked_count', 0),
                limitations=life.get('limitations', [])+link.get('limitations', []),
                cause_state='insufficient_data', requires_ai_interpretation=True,
                next_steps=['Проверить доказательства границ задания и ограниченной привязки записей ТЖ.',
                            'Сопоставить с измеренным нормальным запуском загрузки заказов.',
                            'Проверить причины задержки по дополнительным свидетельствам; очередь пока неизвестна.'])


def investigate(manifest_path, state_dir, *, intake=None, reference_sha256=None, reference_state=None,
                prefix_review=None, should_stop=None, logcfg_observation=None, time_correction=None):
    bundle = load_manifest(manifest_path, reference_sha256=reference_sha256,
                           reference_state=state_dir if reference_state is None else reference_state,
                           prefix_review=prefix_review, should_stop=should_stop,
                           retained=time_correction['input'] if time_correction is not None else None)
    if intake is not None:
        selected=intake['selected']
        if len(selected)!=len(bundle['sources']):raise InputError('selected input capture is incomplete')
        for number,(source,capture) in enumerate(zip(bundle['sources'],selected),1):
            if (source['id']!=f's{number}' or source['path']!=capture['path']
                or source['size']!=capture['bytes'] or source['sha256']!=capture['sha256']):raise InputError('selected input capture integrity mismatch')
            origin=capture['input_origin'];source['input_origin']=dict(origin)
            source['path']=(origin['path']+'!/'+origin['member'] if origin['kind']=='zip'
                else origin['path'].rstrip('/')+'/'+origin['member'] if origin['kind'] in ('directory','sftp') else origin['path'])
            bundle['source_attempts'][number-1]['path']=source['path']
    has_correlation = bundle['manifest'].get('correlation_profile') == '1c-file-job-markers-v1'
    generic=bundle['manifest']['schema']==2
    result = native_report() if generic else job_report(bundle) if has_correlation else analyze_events(bundle['events'], bundle['manifest']['selection'])
    from .source_coverage import summarize_bundle
    result['source_coverage']=summarize_bundle(bundle)
    result['source_acquisition']=bundle['source_attempts']
    if intake is not None:result['input_intake']=intake
    if reference_sha256 is not None:result['reference_plan_sha256']=reference_sha256
    if logcfg_observation is not None:
        result['logcfg_observation'] = logcfg_observation
    if bundle['manifest'].get('workload_profile')=='sc01-order-load-v1':
        result['order_load']=analyze_order_load(bundle,result)
    native_sources = [s for s in bundle['sources'] if s['format'] in TJ_FORMATS]
    formats = {s['format'] for s in bundle['manifest']['sources']}
    contract = next(iter(formats)) if len(formats) == 1 else 'mixed-v1'
    if formats.intersection(TJ_FORMATS):
        result['native_observations'] = summarize_native(bundle['native_events'])
        if has_correlation:
            result['native_observations']['job_correlation'] = 'see_job_correlation_for_bounded_subset'
        elif not generic:
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
                  native_compatibility_scope=('controlled_file_job_markers_8.3.27.1989_only_not_sc01_regression'
                    if has_correlation else 'supported_TJ_observation_profiles_only_no_runtime_ownership' if TJ_JSON in formats
                    else 'supported_TJ_text_profile_only_no_runtime_ownership' if generic
                    else 'text_parser_only_not_sc01_end_to_end' if native_sources else 'not_checked'),
                  symptom=bundle['manifest'].get('symptom', ''),
                  baseline=dict(reported_seconds=bundle['manifest'].get('reported_normal_seconds'),
                                status='user_reported_not_measured'),
                  sources=[{k: v for k, v in source.items() if k != 'data'} for source in bundle['sources']])
    if time_correction is not None:
        from .tj_time_correction import summarize
        result['time_correction'] = summarize(time_correction, result)
        original_review = time_correction['original'].get('reference_plan_sha256')
        if original_review is not None:
            result['reference_plan_sha256'] = original_review
    if len(result['timeline']) > 200:
        result['timeline'] = result['timeline'][:200]
        result['limitations'].append(dict(code='timeline_preview_limited', limit=200))
    result['case_id'] = uuid.uuid4().hex
    if len((json.dumps(result,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode('utf-8')) > MAX_REPORT_BYTES:
        raise InputError('report exceeds the resumable case size limit; narrow the input')
    folder = Path(state_dir) / 'cases' / result['case_id']
    if reference_sha256 is not None or time_correction is not None:
        from .operation_state import private, safe
        if should_stop and should_stop():
            raise InputError('TJ observation stopped before saving the case')
        folder = safe(folder)
        folder.mkdir(parents=True, exist_ok=False)
        private(folder)
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


def case_source_path(state_dir, case_id, source_id):
    from .case_retention import require_available
    require_available(state_dir, case_id, source_id)
    return case_folder(state_dir, case_id) / 'sources' / (source_id + '.bin')


def load_case(state_dir, case_id, *, with_digest=False):
    folder = case_folder(state_dir, case_id)
    try:
        report_data = read_snapshot(folder / 'report.json', MAX_REPORT_BYTES)
        receipt = json_value(read_snapshot(folder / 'receipt.json', 8192).decode('utf-8'))
        if hashlib.sha256(report_data).hexdigest() != receipt['report_sha256']:
            raise InputError('saved report integrity mismatch')
        if hashlib.sha256(read_snapshot(folder / 'manifest.json', 1024*1024)).hexdigest() != receipt['manifest_sha256']:
            raise InputError('saved manifest integrity mismatch')
        report = json_value(report_data.decode('utf-8'))
        if type(report) is not dict or report.get('schema_version') != 1 or report.get('case_id') != case_id:
            raise InputError('unsupported saved case schema')
        from .tj_reference import has_saved_reference
        has_saved_reference(report)
        return (report, hashlib.sha256(report_data).hexdigest()) if with_digest else report
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
    if source['format'] in TJ_FORMATS:
        found=None
        with open_verified_snapshot(case_source_path(state_dir,case_id,match[1]),source['sha256'],expected_size=source.get('size')) as stream:
            scan=iter_tj(stream,source['profile'],max_records=source['record_budget'])
            for record in scan:
                if record['line']==int(match[2]):found=(record,scan.raw_record)
        if found is None:raise InputError('evidence id is not the start of a parsed native record')
        record,raw=found;text=raw.decode('utf-8-sig').rstrip('\r\n')
        proof = dict(case_id=case_id,evidence_id=evidence_id,sha256=source['sha256'],**{k:record[k] for k in ('line','end_line','byte_start','byte_end')},integrity_verified=True,untrusted_source_content=True,text=text[:4096],truncated=len(text)>4096)
        if 'reference_capture' in source:
            from .tj_reference import original_location
            proof['original_location'] = original_location(source, record)
        return proof
    data = read_snapshot(case_source_path(state_dir, case_id, match[1]))
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise InputError('evidence snapshot integrity mismatch')
    number = int(match[2])
    if source['format'] in WHOLE_JSON_FORMATS:
        if number != 1:
            raise InputError('runtime evidence id must refer to the whole document at line 1')
        text = data.decode('utf-8-sig', errors='replace')
        return dict(case_id=case_id, evidence_id=evidence_id, sha256=source['sha256'],
                    line=1, end_line=max(1,len(data.splitlines())), byte_start=0, byte_end=len(data),
                    integrity_verified=True, untrusted_source_content=True,
                    text=text[:4096], truncated=len(text)>4096)
    line = next(itertools.islice(io.BytesIO(data), number-1, number), None)
    if line is None:
        raise InputError('evidence line does not exist')
    text = line.decode('utf-8-sig' if number == 1 else 'utf-8', errors='replace').rstrip('\r\n')
    return dict(case_id=case_id, evidence_id=evidence_id, sha256=source['sha256'], line=number,
                integrity_verified=True, untrusted_source_content=True, text=text[:4096], truncated=len(text)>4096)


def list_native_events(state_dir, case_id, *, source_id=None, event=None, properties=None, offset=0, limit=20,
                       linked_run=False,window=None,index_memory_bytes=None):
    """Page exact native matches; only an explicit proven link permits run membership."""
    from .case_event_index import page as indexed_page
    from .case_retention import require_available
    from .source_coverage import validate_request
    window=validate_request(window=window)['window']
    bounds=(parse_time(window['start']),parse_time(window['end'])) if window else None
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise InputError('events requires offset>=0 and limit between 1 and 100')
    properties = {} if properties is None else properties
    if (not isinstance(properties, dict) or len(properties)>16 or
            any(not isinstance(k,str) or not 1<=len(k)<=128 or not isinstance(v,str) or len(v)>2048
                for k,v in properties.items())):
        raise InputError('at most 16 bounded property filters are supported')
    if event is not None and (not isinstance(event,str) or not 1<=len(event)<=64):
        raise InputError('invalid event name')
    report, digest = load_case(state_dir, case_id, with_digest=True)
    link = report.get('job_correlation', {}).get('native_link', {})
    verified_sources = []
    if linked_run:
        for source in report['sources']:
            if source['format']=='1c-job-runtime-v1':
                if not re.fullmatch(r's[1-9][0-9]*',source['id']):raise InputError('invalid saved evidence source')
                with open_verified_snapshot(case_source_path(state_dir,case_id,source['id']),source['sha256'],expected_size=source.get('size')):pass
                verified_sources.append(source['id'])
    sources = [s for s in report['sources'] if s['format'] in TJ_FORMATS]
    if source_id is not None:
        sources = [s for s in sources if s['id']==source_id]
        if not sources:
            raise InputError('unknown native evidence source')
    matched, page, statuses = 0, [], []
    for source in sources:
        if not re.fullmatch(r's[1-9][0-9]*',source['id']):raise InputError('invalid saved evidence source')
        raw = case_source_path(state_dir, case_id, source['id'])
        verified_sources.append(source['id'])
        indexed = indexed_page(state_dir, case_id, digest, source, raw, event=event, properties=properties,
                               bounds=bounds, linked_run=linked_run, offset=max(0, offset-matched),
                               limit=limit-len(page), memory_bytes=index_memory_bytes)
        if indexed is not None:
            count, rows, status = indexed
            matched += count
            page.extend(rows)
            statuses.append(dict(source=source['id'], status=status))
            continue
        with open_verified_snapshot(raw,source['sha256'],expected_size=source.get('size')) as stream:
            scan=iter_tj(stream,source['profile'],max_records=source['record_budget'])
            for record in scan:
                with_evidence(record, source)
                if bounds and not bounds[0]<=parse_time(record['timestamp_utc'])<bounds[1]:continue
                if linked_run and not record_matches_link(record,link):continue
                if event is not None and record['event']!=event:continue
                if any(record['properties'].get(k)!=v for k,v in properties.items()):continue
                if offset<=matched<offset+limit:page.append(preview_record(record))
                matched+=1
            statuses.append(dict(source=source['id'],status=scan.summary['status']))
    for identifier in verified_sources:
        require_available(state_dir, case_id, identifier)
    result=dict(case_id=case_id,matched_count=matched,offset=offset,limit=limit,
                next_offset=offset+limit if offset+limit<matched else None,records=page,
                source_statuses=statuses,integrity_verified=True,untrusted_source_content=True,
                job_correlation=link.get('status','not_established') if linked_run else 'not_established',
                selection_basis='verified_marker_window_only_not_full_job' if linked_run else 'exact_properties_only_not_job_identity')
    if window:result.update(window=window,time_selection_basis='recorded_timestamp_half_open_not_operation_overlap',clock_alignment='not_verified')
    if any('reference_capture' in source for source in sources):
        from .tj_reference import view
        result['reference_windows'] = [view(source) for source in sources if 'reference_capture' in source]
    return result


def verified_case(state_dir, case_id, *, with_digest=False):
    report,digest=load_case(state_dir,case_id,with_digest=True)
    for source in report['sources']:
        if not re.fullmatch(r's[1-9][0-9]*',source['id']):
            raise InputError('invalid saved evidence source')
        with open_verified_snapshot(case_source_path(state_dir,case_id,source['id']),source['sha256'],expected_size=source.get('size')):pass
    return (report,digest) if with_digest else report


def comparison_folder(state_dir, comparison_id):
    if not re.fullmatch(r'[a-f0-9]{32}',comparison_id):
        raise InputError('invalid comparison identifier')
    return Path(state_dir)/'comparisons'/comparison_id


def comparison_markdown(report):
    lines=['# SC-01: проверка исправления','',
        f"Сравнение: `{report['comparison_id']}`. Итог: **{report['status']}**.",
        f"Скорость: **{report['performance']['status']}**. Данные: **{report['result_correctness']['status']}**.",'',
        f"Происхождение входов: {report.get('provenance',{}).get('overall','unknown')}. Область проверки: {report.get('verification_scope','unknown')}.",
        'Происхождение declared provided само по себе не удостоверяет подлинность. Причину интерпретирует агент; название варианта не доказывает её.',
        'Секундные границы учитываются отдельно от замеров тела и сервиса. Очередь не измерена.','',
        '| Пара | До, случай | После, случай | Выполнение до, с | После, с | Границы не пересекаются |',
        '| --- | --- | --- | --- | --- | --- |']
    for pair in report['pairs']:
        lines.append(f"| {pair['index']} | {pair['before_case_id']} | {pair['after_case_id']} | "
                     f"{pair['before_seconds']} | {pair['after_seconds']} | {pair['strictly_faster_with_precision']} |")
    lines+=['',f"HTTP-запросы до: {report['external_calls']['before_counts']}; после: {report['external_calls']['after_counts']}.",
            '', 'Полные границы, контроль результата, хэши, ограничения и ссылки на свидетельства — в report.json.',
            'Продолжение: `comparison ID`; исходный случай: `show CASE_ID`; доказательство: `evidence CASE_ID SOURCE:LINE`.','']
    return '\n'.join(lines)


def compare_cases(state_dir, before_ids, after_ids, *, output_state_dir=None):
    if any(not isinstance(ids,list) or not 1<=len(ids)<=20 for ids in (before_ids,after_ids)):
        raise InputError('compare requires 1..20 case ids in each group')
    before_inputs=[verified_case(state_dir,case_id,with_digest=True) for case_id in before_ids]
    after_inputs=[verified_case(state_dir,case_id,with_digest=True) for case_id in after_ids]
    before=[item[0] for item in before_inputs]
    after=[item[0] for item in after_inputs]
    report=compare_reports(before,after)
    report.update(comparison_id=uuid.uuid4().hex,product_version=__version__,
                  created_at=datetime.now(timezone.utc).isoformat(),before_case_ids=before_ids,after_case_ids=after_ids)
    report['input_reports']=[dict(case_id=item['case_id'],sha256=digest) for item,digest in before_inputs+after_inputs]
    if len(json.dumps(report,ensure_ascii=False,allow_nan=False).encode('utf-8'))>MAX_REPORT_BYTES:
        raise InputError('comparison report exceeds size limit')
    from .case_retention import case_writers
    folder = comparison_folder(state_dir if output_state_dir is None else output_state_dir, report['comparison_id'])
    with case_writers(state_dir, before_ids + after_ids):
        folder.mkdir(parents=True, exist_ok=False)
        write_json(folder / 'report.json', report)
        (folder / 'report.md').write_text(comparison_markdown(report), encoding='utf-8', newline='\n')
        write_json(folder / 'receipt.json', dict(schema_version=1,
            report_sha256=hashlib.sha256((folder / 'report.json').read_bytes()).hexdigest(),
            markdown_sha256=hashlib.sha256((folder / 'report.md').read_bytes()).hexdigest()))
    return report


def read_comparison_record(state_dir, comparison_id):
    """Check the saved comparison receipt independently of its input cases."""
    folder=comparison_folder(state_dir,comparison_id)
    receipt=json_value(read_snapshot(folder/'receipt.json',8192).decode('utf-8'))
    if type(receipt) is not dict:raise InputError('invalid saved comparison receipt')
    data=read_snapshot(folder/'report.json',MAX_REPORT_BYTES)
    if (hashlib.sha256(data).hexdigest()!=receipt['report_sha256'] or
            hashlib.sha256(read_snapshot(folder/'report.md',MAX_REPORT_BYTES)).hexdigest()!=receipt['markdown_sha256']):
        raise InputError('saved comparison integrity mismatch')
    report=json_value(data.decode('utf-8'))
    if type(report) is not dict or report.get('schema_version')!=1 or report.get('comparison_id')!=comparison_id:
        raise InputError('unsupported saved comparison')
    return report,receipt['report_sha256']


def load_comparison(state_dir, comparison_id, *, input_state_dir=None):
    report,_=read_comparison_record(state_dir,comparison_id)
    for item in report['input_reports']:
        _,digest=verified_case(state_dir if input_state_dir is None else input_state_dir,item['case_id'],with_digest=True)
        if digest!=item['sha256']:
            raise InputError('comparison input report integrity mismatch')
    return report
