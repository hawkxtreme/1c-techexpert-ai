"""APDEX over saved operation attempts with checked execution evidence."""
from collections import Counter

from . import operation_state as fs
from .apdex import instant, measurement_category
from .sample_statistics import duration


SAMPLE_PROFILE = 'saved_case_execution'


def _lifecycle(report):
    correlation = report.get('job_correlation')
    life = correlation.get('job_lifecycle') if isinstance(correlation, dict) else None
    return life if isinstance(life, dict) else {}


def execution_bounds(row, report):
    value = row['value_seconds']
    if value is None or not duration(value):
        return None
    if row['kind'] == 'artifact':
        return value, value
    life = _lifecycle(report)
    candidate = life.get('execution_bounds_seconds')
    if (life.get('status') == 'established' and life.get('execution_seconds') == value and type(candidate) is list
            and len(candidate) == 2 and all(duration(number) for number in candidate) and candidate[0] <= value <= candidate[1]):
        return tuple(candidate)
    return None


def _attempt(row, life):
    if (row['measurement_basis'] != 'platform_begin_end_seconds' or not row['evidence']
            or life.get('status') != 'established' or not isinstance(life.get('job_uuid'), str)):
        return None
    try:
        start, end, operation_start = map(instant, (life.get('begin_utc'), life.get('end_utc'), row['started_at']))
    except (ValueError, OverflowError):
        return None
    if start != operation_start or (end - start).total_seconds() != row['value_seconds']:
        return None
    return fs.digest([life['job_uuid'].lower(), start.isoformat(), end.isoformat()])


def evidence_keys(observations):
    return {(row['attempt_sha256'], record['sha256'], record['byte_start'], record['byte_end'])
            for row in observations if row['attempt_sha256'] is not None for record in row['records']}


class CaseSample:
    def __init__(self, target):
        self.target = target
        self.counts = Counter(selected=0, failed=0, unknown_duration=0, unknown_outcome=0,
                              uncertain_bounds=0, unplaced=0, duplicate_observations=0, conflicting_inputs=0)
        self.categories = Counter(satisfied=0, tolerating=0, frustrated=0, unknown=0)
        self.observations = []
        self.seen = set()

    def observe(self, row, report):
        reason = row['reason']
        if reason in ('other_operation', 'outside_window', 'duplicate_input_view'):
            return
        if reason == 'unknown_operation_start':
            self.counts['unplaced'] += 1
            return
        if reason == 'conflicting_input_interpretation':
            self.counts['conflicting_inputs'] += 1
            return
        life = _lifecycle(report)
        attempt = _attempt(row, life)
        bounds = execution_bounds(row, report) if attempt is not None else None
        outcome = row['outcome'] if attempt else 'unknown'
        record = dict(case_id=row['id'], attempt_sha256=attempt, records=row['evidence'], outcome=outcome,
                      duration_seconds=row['value_seconds'] if attempt else None, bounds_seconds=list(bounds) if bounds else None,
                      precision_seconds=row['precision_seconds'] if attempt else None)
        keys = evidence_keys([record])
        repeated = bool(keys & self.seen)
        self.seen.update(keys)
        self.counts['selected'] += 1
        self.counts['failed'] += outcome == 'failed'
        self.counts['unknown_outcome'] += outcome == 'unknown'
        self.counts['unknown_duration'] += bounds is None
        self.counts['duplicate_observations'] += repeated
        category = None
        if self.target is not None:
            category = 'unknown'
            if not repeated and outcome == 'failed':
                category = 'frustrated'
            elif not repeated and outcome == 'success' and bounds is not None:
                lower, upper = (measurement_category(True, value, self.target) for value in bounds)
                if lower == upper:
                    category = lower
                else:
                    self.counts['uncertain_bounds'] += 1
            self.categories[category] += 1
        self.observations.append(dict(record, category=category))

    def summary(self):
        counts = self.counts
        disqualifiers = ('unknown_duration', 'unknown_outcome', 'uncertain_bounds', 'unplaced',
                         'duplicate_observations', 'conflicting_inputs')
        incomplete = any(counts[name] for name in disqualifiers)
        n = counts['selected']
        score = None
        if self.target is not None and n and not incomplete:
            score = (self.categories['satisfied'] + .5 * self.categories['tolerating']) / n
        return dict(profile=SAMPLE_PROFILE, status='incomplete' if incomplete else 'observed' if n else 'no_rows',
                    **counts, score_at_target=score, apdex=dict(self.categories) if self.target is not None else None,
                    execution_evidence=self.observations)
