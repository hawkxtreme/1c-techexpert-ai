"""Bounded native observations; no cross-source joins or job lifecycle inference."""
from collections import Counter
from heapq import nlargest


def preview_record(record):
    # A source is untrusted and a single SQL/Context property can be very large.
    result = {key: record[key] for key in ('event', 'raw_time', 'timestamp', 'timestamp_utc',
              'duration_us', 'depth', 'evidence') if key in record}
    if 'start_timestamp_utc' in record:
        result['start_timestamp_utc'] = record['start_timestamp_utc']
    properties, used = {}, 0
    for key, value in record['properties'].items():
        if len(key) > 128 or len(properties) >= 24 or used >= 4096:
            break
        text = value[:min(512, 4096-used)]
        properties[key] = text
        used += len(text)
    result['properties'] = properties
    result['properties_truncated'] = properties != record['properties']
    result['untrusted_source_content'] = True
    return result


def summarize_native(records):
    counts = Counter(record['event'] for record in records)
    stamps = [r['timestamp_utc'] for r in records]
    return dict(event_count=len(records), by_event=dict(counts.most_common(100)),
                event_names_omitted=max(0, len(counts)-100),
                first_timestamp_utc=min(stamps) if stamps else None,
                last_timestamp_utc=max(stamps) if stamps else None,
                coverage='observed_records_only_continuity_and_filters_unknown',
                clock_alignment='not_verified', time_basis='source_declared_not_independently_verified',
                job_correlation='not_established', aggregation='no_duration_sum_or_cross_source_join',
                records_preview=[preview_record(r) for r in records[:20]],
                preview_limited=len(records)>20,
                longest_events=[preview_record(r) for r in nlargest(10, records, key=lambda r:r['duration_us'])])
