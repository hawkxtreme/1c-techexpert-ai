"""Bounded descriptive durations; no baseline, independence or population verdict."""
import math
from statistics import median

MAX_VALUES = 100000
MAX_SECONDS = 365 * 86400


def duration(value):
    return (type(value) in (int, float) and (type(value) is int or math.isfinite(value))
            and 0 <= value <= MAX_SECONDS)


def describe_values(values):
    if type(values) is not list or len(values) > MAX_VALUES:
        raise ValueError('at most100000 duration values required')
    if any(value is not None and not duration(value) for value in values):
        raise ValueError('durations must be finite nonnegative numbers up to one year, or unknown')
    ordered = sorted(value for value in values if value is not None)
    count = len(ordered)
    center = median(ordered) if count else None

    def percentile(percent):
        if not count:
            return None
        position = (count - 1) * percent / 100
        lower = int(position)
        upper = min(lower + 1, count - 1)
        return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)

    percentiles = {str(p): percentile(p) for p in (25, 50, 75, 90, 95)}
    missing = len(values) - count
    return dict(supplied_count=len(values), count=count, missing_count=missing,
        status='empty' if not values else 'unknown' if not count else 'partial' if missing else 'known',
        median=center, minimum=ordered[0] if count else None, maximum=ordered[-1] if count else None,
        range=ordered[-1] - ordered[0] if count else None,
        median_absolute_deviation=median([abs(value - center) for value in ordered]) if count else None,
        interquartile_range=percentiles['75'] - percentiles['25'] if count else None,
        percentiles=dict(values=percentiles, sample_size=count, method='linear_between_ordered_positions_(n-1)*p'),
        outlier_removal='none', population_inference=False)
