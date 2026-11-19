"""Allowlisted evidence fields for a retained investigation's model-facing view."""
from datetime import datetime
from hashlib import sha256
import hmac
import math
import re


TJ_NAMES = ('CALL', 'SCALL', 'EXCP', 'TLOCK', 'TTIMEOUT', 'TDEADLOCK', 'SDBL', 'DBMSSQL',
            'DBPOSTGRS', 'DBV8DBEng', 'CONN', 'PROC', 'SESN', 'CLSTR', 'LOCK', 'QERR', 'EXCPCNTX')
TJ_ALIASES = {
    'user': ('Usr', 'UserName'),
    'client_node': ('ClientComputerName', 't:computerName'),
    'server_node': ('ServerComputerName',),
    'base': ('IB', 'DataBase'),
    'session': ('SessionID', 't:sessionID'),
    'connection': ('t:connectID',),
    'component': ('IName',),
    'operation': ('Method', 'Func'),
    'application': ('AppID', 'Appl'),
}
SOURCE_FORMATS = ('1c-tj-text-v1', 'normalized-events-v1', '1c-job-runtime-v1',
                  'sc01-http-service-v1', 'sc01-run-capture-v1')
PARSE_STATES = ('empty', 'not_parsed', 'invalid', 'partial', 'parsed', 'complete', 'skipped')
RECORD_ID = re.compile(r's[1-9][0-9]{0,2}:r?[1-9][0-9]{0,8}')
SQLITE_ROW_ID = re.compile(r'[1-9][0-9]{0,18}')
SOURCE_ID = re.compile(r's[1-9][0-9]{0,2}')
ATTACHMENT_ID = re.compile(r'A-[A-Za-z0-9-]{1,60}')
DATE = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'
                  r'(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})?')


def enum(value, choices, default='unknown'):
    return value if type(value) is str and value in choices else default


def number(value):
    if type(value) in (int, float) and -10**18 <= value <= 10**18 and math.isfinite(value):
        return value
    return None


def measurements(value, keys):
    return {key: number(value.get(key)) for key in keys}


def identifier(value, pattern):
    return value if type(value) is str and pattern.fullmatch(value) else None


def timestamp(value):
    if type(value) is not str or len(value) > 35 or not DATE.fullmatch(value):
        return None
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).isoformat()
    except ValueError:
        return None


class Aliases:
    def __init__(self, key, investigation_id):
        self.key = hmac.digest(bytes.fromhex(key), investigation_id.encode('ascii'), sha256)

    def __call__(self, category, value):
        if type(value) is not str or not value or len(value) > 512:
            return None
        digest = hmac.digest(self.key, (category + '\0' + value).encode('utf-8'), sha256)
        return f'{category}-{digest.hex()[:24]}'


def proof(value):
    result = dict(
        id=identifier(value.get('id', value.get('evidence_id')), RECORD_ID),
        **measurements(value, ('line', 'end_line', 'byte_start', 'byte_end')))
    if 'original_location' in value:
        result['original_location'] = measurements(value['original_location'],
                                                    ('line', 'end_line', 'byte_start', 'byte_end'))
    if value.get('evidence_kind')=='sqlite_row_projection':
        result.update(evidence_kind='sqlite_row_projection', sqlite_row_id=identifier(value.get('sqlite_row_id'),SQLITE_ROW_ID))
    return result


def tj_event(record, aliases):
    event = record.get('event')
    properties = record.get('properties', {})
    ambiguous = record.get('ambiguous_property_names', [])
    identities = {}
    # A cut preview could contain identical partial values for distinct subjects.
    if not record.get('properties_truncated'):
        for kind, names in TJ_ALIASES.items():
            possible = {properties[name] for name in names if name in properties}
            if len(possible) == 1 and all(name not in ambiguous for name in names):
                alias = aliases(kind, possible.pop())
                if alias:
                    identities[kind] = alias
    return dict(event=enum(event, TJ_NAMES, None) or aliases('event', event),
                timestamp_utc=timestamp(record.get('timestamp_utc')),
                **measurements(record, ('duration_us', 'depth')), aliases=identities,
                evidence=proof(record['evidence']))


def jr_event(record, aliases):
    # Journal computer and session identifiers have no established equivalence to
    # the native TJ's client/server roles or to a particular session lifetime.
    identities = {}
    for key in ('user', 'computer', 'application', 'connection', 'session', 'metadata'):
        if key not in record.get('truncated_fields', ()):
            kind = f'jr_{key}'
            alias = aliases(kind, record.get(key))
            if alias:
                identities[key] = alias
    return dict(event=aliases('jr_event', record.get('event'))
                if 'event' not in record.get('truncated_fields', ()) else None,
                timestamp=timestamp(record.get('timestamp')), local_time=timestamp(record.get('local_time')),
                precision_seconds=number(record.get('precision_seconds')),
                severity=enum(record.get('severity'), ('I', 'E', 'W', 'N')),
                transaction_state=enum(record.get('transaction_state'), ('N', 'U', 'R', 'C')),
                aliases=identities, evidence=proof(record))


def case_summary(report):
    correlation = report.get('job_correlation', {})
    link = correlation.get('native_link', {})
    measurements_by_run = report.get('order_load', {})
    calls = measurements_by_run.get('external_calls', {})
    data = measurements_by_run.get('result_validation', {})
    result = dict(
        origin=enum(report.get('origin'), ('provided', 'synthetic')),
        durations_seconds=measurements(report.get('durations_seconds', {}), ('queue', 'execution', 'total')),
        job_correlation=enum(correlation.get('status'), ('established', 'not_established')),
        timestamp_scope='observed_records_partial_coverage_possible',
        linked_count=number(link.get('linked_count')),
        linked_evidence=[value for record in link.get('linked_evidence', [])[:5]
                         if (value := identifier(record.get('id'), RECORD_ID))],
        native_event_count=number(report.get('native_observations', {}).get('event_count')),
        sources=[dict(id=identifier(item.get('id'), SOURCE_ID),
                      format=enum(item.get('format'), SOURCE_FORMATS),
                      parsed_event_count=number(item.get('parsed_event_count')),
                      parse_status=enum(item.get('parse_status'), PARSE_STATES))
                 for item in report['sources']],
        requires_ai_interpretation=True)
    if measurements_by_run:
        verified = calls.get('status') == 'verified'
        result.update(external_calls=dict(status='verified' if verified else 'not_verified',
                      **measurements(calls if verified else {}, ('count', 'unique_skus',
                                   'repeated_lookups', 'server_elapsed_seconds', 'client_elapsed_seconds'))),
                      result_validation=dict(status=enum(data.get('status'),
                          ('matches_expected', 'mismatch', 'not_verified')),
                          **measurements(data, ('expected_count', 'actual_count', 'mismatch_count'))))
    return result


def comparison_summary(report):
    performance = report['performance']
    calls = report['external_calls']
    provenance = report.get('provenance', {})
    return dict(
        comparison_status=enum(report.get('status'), ('verified', 'not_verified')),
        verification_scope=enum(report.get('verification_scope'),
            ('synthetic_calculations_only', 'provided_evidence_only', 'mixed_or_unknown_evidence_only')),
        provenance=dict(overall=enum(provenance.get('overall'), ('synthetic', 'provided', 'mixed')),
                        origin_authenticity_verified=False),
        comparability=enum(report['comparability'].get('status'), ('comparable', 'not_comparable')),
        performance=dict(status=enum(performance.get('status'), ('improved', 'inconclusive', 'not_comparable')),
                         **measurements(performance, ('before_median_seconds', 'after_median_seconds',
                                                      'conservative_reduction_fraction', 'precision_seconds'))),
        result_correctness=enum(report['result_correctness'].get('status'),
                                ('matches_expected', 'mismatch', 'not_verified')),
        external_calls=dict(status=enum(calls.get('status'), ('verified', 'not_verified')),
                            **measurements(calls, ('before_median_count', 'after_median_count'))),
        **measurements(report, ('before_count', 'after_count', 'required_pairs')),
        pairs=[dict(**measurements(item, ('index', 'before_seconds', 'after_seconds')),
                    strictly_faster_with_precision=(item['strictly_faster_with_precision']
                        if type(item.get('strictly_faster_with_precision')) is bool else None))
               for item in report['pairs']],
        requires_ai_interpretation=True)


def _verification_sample(sample):
    if sample is None:
        return None
    counts = measurements(sample['counts'], ('selected', 'failed', 'unknown_outcome', 'unknown_duration',
        'met', 'breaches', 'uncertain_bounds', 'chronology_conflicts', 'unplaced', 'duplicate_observations'))
    apdex = sample['apdex']
    return dict(profile=enum(sample.get('profile'), ('normalized_apdex_rows', 'saved_case_execution',
                                                    'controlled_case_comparison')),
                value=number(sample['value']), counts=counts,
                durations_seconds=measurements(sample['statistics'], ('median', 'minimum', 'maximum')),
                apdex=measurements(apdex, ('satisfied', 'tolerating', 'frustrated', 'unknown'))
                if apdex is not None else None)


def fix_summary(result):
    application, comparability, effect, goal, recurrence = (
        result[key] for key in ('application', 'comparability', 'effect', 'goal', 'recurrence'))
    direction = ('better', 'no_confirmed_change', 'worse')
    criterion = goal['criterion']
    return dict(
        status=enum(result['status'], ('evaluated', 'awaiting_measurements')),
        application=dict(status=enum(application['status'], ('proposed', 'reported', 'evidenced')),
                         basis=enum(application['basis'], ('caller_declaration', 'harness_linked_evidence'))),
        comparability=dict(status=enum(comparability['status'], ('comparable', 'not_comparable')),
                           basis=enum(comparability['basis'], ('runtime_conditions_not_verified',
                                                              'sealed_controlled_comparison'))),
        effect=dict(status=enum(effect['status'], direction), observed_direction=enum(effect['observed_direction'], direction),
                    basis=enum(effect['basis'], ('nominal_supplied_samples', 'controlled_paired_duration_bounds')),
                    required_pairs=number(effect.get('required_pairs'))),
        goal=dict(status=enum(goal['status'], ('reached', 'not_reached')),
                  criterion=dict(kind=enum(criterion['kind'], ('duration', 'apdex')),
                                 **measurements(criterion, ('value', 'target_seconds'))),
                  **measurements(goal, ('minimum_observations',))),
        recurrence=dict(status=enum(recurrence['status'], ('observed',)), window_selected=recurrence['window'] is not None,
                        **measurements(recurrence, ('threshold_seconds', 'breaches', 'unknown_duration')),
                        complete_coverage=None),
        before=_verification_sample(result['before']), after=_verification_sample(result['after']),
        result_correctness=enum(result['result_correctness'], ('matches_expected', 'mismatch', 'not_verified')),
        verification_scope=enum(result['verification_scope'], ('selected_reported_measurements', 'retained_comparison',
            'synthetic_calculations_only', 'provided_evidence_only', 'mixed_or_unknown_evidence_only')),
        requires_ai_interpretation=True)
