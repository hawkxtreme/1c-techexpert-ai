"""Bounded SC-01 before/after measurements, independent of AI interpretation.

The caller must load saved reports and check their snapshot integrity. This
module checks the comparison contract again; labels such as baseline/cached
and an earlier AI conclusion never determine measured success. Platform dates,
body observations and service timings remain separate measurements.
"""
import math
import ntpath
import re
import statistics
import uuid

from .sample_statistics import describe_values


MAX_CASES = 20
MIN_PAIRS = 5
SCOPE = 'controlled_windows_file_8.3.27.1989'
PLATFORM = '8.3.27.1989'
SIGNATURE_FIELDS = ('input_sha256', 'catalog_sha256', 'catalog_revision',
                    'row_count', 'service_delay_ms', 'database_seed_sha256',
                    'observed_computer_name', 'service_module_sha256')


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _text(value, maximum=256):
    return isinstance(value, str) and 0 < len(value) <= maximum


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _integer(value, minimum=0, maximum=86400):
    return type(value) is int and minimum <= value <= maximum


def _number(value, maximum=86400000):
    return (type(value) is int and 0 <= value <= maximum or
            type(value) is float and math.isfinite(value) and 0 <= value <= maximum)


def _evidence(value, case_id):
    """Copy bounded locators rather than arbitrary nested report contents."""
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        return None
    records = []
    for item in value:
        if not isinstance(item, dict) or not _text(item.get('id'),64):
            return None
        match = re.fullmatch(r'(s[1-9][0-9]*):([1-9][0-9]*)', item['id'])
        if not match or item.get('source') != match[1] or not _digest(item.get('sha256')):
            return None
        clean = {key:item[key] for key in ('id', 'source', 'sha256')}
        for key in ('line', 'end_line', 'byte_start', 'byte_end'):
            if key in item:
                if not _integer(item[key], 0 if key.startswith('byte_') else 1, 64*1024*1024):
                    return None
                clean[key] = item[key]
        records.append(clean)
    return dict(case_id=case_id, records=records)


def _case(value, group, index):
    issues = []
    report = _mapping(value)
    case_id = report.get('case_id')
    if not isinstance(case_id, str) or re.fullmatch(r'[0-9a-f]{32}', case_id) is None:
        issues.append('invalid_case_id')
        case_id = None
    if report.get('scenario') != 'SC-01':
        issues.append('unsupported_scenario')
    order = _mapping(report.get('order_load'))
    if order.get('status') != 'observed' or order.get('scope') != SCOPE:
        issues.append('unverified_order_load_profile')
    signature = _mapping(order.get('workload_signature'))
    computer_name = signature.get('observed_computer_name')
    if (not all(_digest(signature.get(key)) for key in
                ('input_sha256','catalog_sha256','database_seed_sha256','service_module_sha256')) or
            not _text(signature.get('catalog_revision')) or not _integer(signature.get('row_count'),1,1000) or
            not _integer(signature.get('service_delay_ms'),0,100) or not _text(computer_name,255) or
            not computer_name.strip() or any(c in computer_name for c in '\r\n\x00')):
        issues.append('incomplete_workload_signature')
        signature_key = None
    else:
        signature_key = tuple(computer_name.casefold() if key=='observed_computer_name' else signature[key]
                              for key in SIGNATURE_FIELDS)
    signature_evidence = _evidence(signature.get('evidence'), case_id)
    if signature_evidence is None:
        issues.append('missing_workload_evidence')
    correlation = _mapping(report.get('job_correlation'))
    life = _mapping(correlation.get('job_lifecycle'))
    link = _mapping(correlation.get('native_link'))
    identity = _mapping(link.get('identity'))
    if life.get('status') != 'established' or life.get('state') != 'completed':
        issues.append('job_not_confirmed_completed')
    job = life.get('job_uuid')
    try:
        parsed = uuid.UUID(job) if isinstance(job,str) and len(job)==36 else None
        if parsed is None or not parsed.int:
            raise ValueError('invalid UUID')
        job = str(parsed)
    except ValueError:
        issues.append('invalid_job_uuid')
        job = None
    if link.get('status') != 'established' or identity.get('process_label') != '1cv8':
        issues.append('unverified_native_job_link')
    if identity.get('job_uuid') is not None and identity['job_uuid'] != job:
        issues.append('conflicting_native_job_uuid')
    database = identity.get('database_file')
    if not _text(database,4096) or not ntpath.splitdrive(database)[0] or not ntpath.isabs(database):
        issues.append('unknown_file_database')
        database = None
    else:
        database = ntpath.normcase(ntpath.normpath(database))
    sources = report.get('sources')
    if not isinstance(sources,list) or not 1 <= len(sources) <= 32:
        issues.append('missing_platform_profile')
    else:
        profiles = [_mapping(s.get('profile')) for s in sources if isinstance(s,dict) and
                    s.get('format') in ('1c-tj-text-v1','1c-job-runtime-v1')]
        if not profiles or any(profile.get('platform_version') != PLATFORM for profile in profiles):
            issues.append('unsupported_platform_profile')
    seconds, bounds = life.get('execution_seconds'), life.get('execution_bounds_seconds')
    if (not _integer(seconds) or type(life.get('precision_seconds')) is not int or life['precision_seconds'] != 1 or
            not isinstance(bounds,list) or len(bounds)!=2 or not all(_integer(x) for x in bounds) or
            bounds != [max(0, seconds-1), seconds+1]):
        issues.append('invalid_platform_measurement')
        seconds, bounds = None, None
    execution_evidence = _evidence(life.get('evidence'), case_id)
    if execution_evidence is None:
        issues.append('missing_execution_evidence')
    result = _mapping(order.get('result_validation'))
    result_evidence = _evidence(result.get('evidence'), case_id)
    count = signature.get('row_count')
    counts_valid = (_integer(count,1,1000) and all(type(result.get(k)) is int and result[k]==count
                   for k in ('expected_count','actual_count','written_count')))
    if not counts_valid:
        issues.append('different_or_unknown_completed_work')
    expected, actual = result.get('expected_sha256'), result.get('actual_sha256')
    if result_evidence is None or not _digest(expected) or not _digest(actual):
        result_status = 'not_verified'
    elif (result.get('status') == 'mismatch' or expected != actual or
          (_integer(result.get('mismatch_count'),0,1000) and result['mismatch_count']>0)):
        result_status = 'mismatch'
    elif (result.get('status') == 'matches_expected' and counts_valid and
          type(result.get('mismatch_count')) is int and result['mismatch_count']==0):
        result_status = 'matches_expected'
    else:
        result_status = 'not_verified'
    external = _mapping(order.get('external_calls'))
    external_evidence = _evidence(external.get('evidence'), case_id)
    call_count = external.get('count')
    if (external.get('status') != 'verified' or not _integer(call_count,0,10000) or external_evidence is None or
            not _integer(external.get('unique_skus'),0,1000) or external['unique_skus']>call_count or
            not _integer(external.get('repeated_lookups'),0,10000) or
            external['repeated_lookups'] != call_count-external['unique_skus']):
        call_count = None
    duration = order.get('load_duration_ms')
    load_evidence = _evidence(order.get('load_duration_evidence'), case_id)
    if not _number(duration) or load_evidence is None:
        duration = None
    declared_origin = report.get('origin')
    origin = declared_origin if declared_origin in ('provided','synthetic') else 'unknown'
    return dict(case_id=case_id, group=group, index=index, job_uuid=job, issues=issues, origin=origin,
        signature=signature_key, database=database, seconds=seconds, bounds=bounds,
        execution_evidence=execution_evidence, signature_evidence=signature_evidence,
        result_status=result_status, result_evidence=result_evidence,
        expected_digest=expected if _digest(expected) else None,
        actual_digest=actual if _digest(actual) else None,
        call_count=call_count, external_evidence=external_evidence,
        load_duration_ms=duration, load_evidence=load_evidence)


def _median(values):
    return statistics.median(values) if values and all(x is not None for x in values) else None


def _origin(cases):
    origins = {case['origin'] for case in cases}
    if not origins or 'unknown' in origins:
        return 'unknown'
    return next(iter(origins)) if len(origins)==1 else 'mixed'


def compare_reports(before, after):
    """Compare all explicitly supplied pairs without discarding bad or slow runs."""
    if (not isinstance(before,list) or not isinstance(after,list) or
            len(before)>MAX_CASES or len(after)>MAX_CASES):
        raise ValueError('before and after must each contain at most 20 saved reports')
    left = [_case(report,'before',i+1) for i,report in enumerate(before)]
    right = [_case(report,'after',i+1) for i,report in enumerate(after)]
    cases = left+right
    limitations = [dict(code=code,group=case['group'],index=case['index'],case_id=case['case_id'])
                   for case in cases for code in case['issues']]
    comparable = bool(cases) and not limitations
    signatures = {case['signature'] for case in cases if case['signature'] is not None}
    databases = {case['database'] for case in cases if case['database'] is not None}
    if len(signatures)!=1 or len(databases)!=1:
        comparable=False
        limitations.append(dict(code='different_or_unknown_comparison_conditions'))
    expected = {case['expected_digest'] for case in cases if case['expected_digest'] is not None}
    if len(expected)!=1:
        comparable=False
        limitations.append(dict(code='different_or_unknown_expected_result'))
    for key in ('case_id','job_uuid'):
        values=[case[key] for case in cases if case[key] is not None]
        if len(values)!=len(set(values)):
            comparable=False
            limitations.append(dict(code='duplicate_'+key))
    enough = len(left)==len(right) and len(left)>=MIN_PAIRS
    if not enough:
        limitations.append(dict(code='insufficient_repeats', required_pairs=MIN_PAIRS,
                                before_count=len(left),after_count=len(right)))
    if len(left)!=len(right):
        comparable=False
        limitations.append(dict(code='unpaired_runs'))
    pairs=[]
    for i in range(max(len(left),len(right))):
        one = left[i] if i<len(left) else None
        two = right[i] if i<len(right) else None
        faster = (one['bounds'][0]>two['bounds'][1]
                  if one and two and one['bounds'] is not None and two['bounds'] is not None else None)
        pairs.append(dict(index=i+1,before_case_id=one['case_id'] if one else None,
            after_case_id=two['case_id'] if two else None,
            before_seconds=one['seconds'] if one else None,after_seconds=two['seconds'] if two else None,
            before_bounds_seconds=one['bounds'] if one else None,after_bounds_seconds=two['bounds'] if two else None,
            strictly_faster_with_precision=faster,
            before_execution_evidence=one['execution_evidence'] if one else None,
            after_execution_evidence=two['execution_evidence'] if two else None))
    before_median=_median([case['seconds'] for case in left])
    after_median=_median([case['seconds'] for case in right])
    before_lower=_median([case['bounds'][0] if case['bounds'] is not None else None for case in left])
    after_upper=_median([case['bounds'][1] if case['bounds'] is not None else None for case in right])
    reduction=(1-after_upper/before_lower if before_lower is not None and before_lower>0 and after_upper is not None else None)
    improvement=(comparable and enough and all(pair['strictly_faster_with_precision'] is True for pair in pairs)
                 and reduction is not None and reduction>=.5)
    performance=dict(status='improved' if improvement else 'inconclusive' if comparable else 'not_comparable',
        metric='platform_job_execution_seconds',precision_seconds=1,
        before_median_seconds=before_median,after_median_seconds=after_median,
        before_lower_median_seconds=before_lower,after_upper_median_seconds=after_upper,
        conservative_reduction_fraction=reduction,
        before_distribution=describe_values([case['seconds'] for case in left]),
        after_distribution=describe_values([case['seconds'] for case in right]),
        reported_speedup_ratio=(before_median/after_median if before_median is not None and after_median else None),
        interpretation='Measured execution only; correctness and causal interpretation are separate.')
    statuses=[case['result_status'] for case in cases]
    result_status=('mismatch' if 'mismatch' in statuses else 'matches_expected'
                   if statuses and all(status=='matches_expected' for status in statuses) and len(expected)==1 else 'not_verified')
    result_correctness=dict(status=result_status,
        cases=[dict(case_id=case['case_id'],group=case['group'],index=case['index'],status=case['result_status'],
                    expected_sha256=case['expected_digest'],actual_sha256=case['actual_digest'],
                    evidence=case['result_evidence']) for case in cases])
    calls_verified=bool(cases) and all(case['call_count'] is not None for case in cases)
    external=dict(status='verified' if calls_verified else 'not_verified',
        before_counts=[case['call_count'] for case in left],
        after_counts=[case['call_count'] for case in right],
        before_median_count=_median([case['call_count'] for case in left]),
        after_median_count=_median([case['call_count'] for case in right]),
        evidence=[case['external_evidence'] for case in cases if case['external_evidence'] is not None],
        interpretation='Request counts are observations; neither fewer calls nor their labels prove cause.')
    provenance = dict(before=_origin(left),after=_origin(right),overall=_origin(cases),
        case_origins=[dict(case_id=case['case_id'],group=case['group'],index=case['index'],origin=case['origin'])
                      for case in cases],origin_authenticity_verified=False,
        interpretation='Declared source origin is preserved; comparison does not authenticate a real experiment.')
    verification_scope = ('synthetic_calculations_only' if provenance['overall']=='synthetic' else
                          'provided_evidence_only' if provenance['overall']=='provided' else
                          'mixed_or_unknown_evidence_only')
    return dict(schema_version=1,scenario='SC-01',comparison_profile='sc01-order-load-v1',
        status='verified' if improvement and result_status=='matches_expected' and calls_verified else 'not_verified',
        before_count=len(left),after_count=len(right),required_pairs=MIN_PAIRS,
        criteria=dict(all_pairs_strictly_faster_with_second_precision=True,
                      conservative_median_reduction_at_least=.5,results_must_match_expected=True,
                      includes_all_supplied_runs=True,variants_do_not_determine_success=True),
        comparability=dict(status='comparable' if comparable else 'not_comparable',
            signature_fields=list(SIGNATURE_FIELDS),scope=SCOPE,platform_version=PLATFORM,
            host_identity_basis='matching_observed_runtime_hostname_not_physical_node_identity',
            evidence=[case['signature_evidence'] for case in cases if case['signature_evidence'] is not None]),
        provenance=provenance,verification_scope=verification_scope,
        performance=performance,result_correctness=result_correctness,external_calls=external,pairs=pairs,
        load_observations=dict(before_median_ms=_median([case['load_duration_ms'] for case in left]),
            after_median_ms=_median([case['load_duration_ms'] for case in right]),
            evidence=[case['load_evidence'] for case in cases if case['load_evidence'] is not None],
            interpretation='Separate runtime load observations, not substituted for platform execution bounds.'),
        limitations=limitations,cause=None,requires_ai_interpretation=True)
