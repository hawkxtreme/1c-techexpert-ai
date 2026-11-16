"""Bounded text TJ observations for one explicitly declared platform profile.

Text grammar: 1C 8.3.27 Administrator Guide, section 3.24.3.4.
UTF-8 and single-hour context for minute timestamps are adapter constraints,
not universal platform claims. Physical placement does not choose timestamp
grammar. A header timestamp is not universally confirmed to mean event finish;
therefore no operation-start or background-job milestones are inferred here.
"""

import os
import re
from datetime import datetime, timedelta, timezone


FORMAT = '1c-tj-text-v1'
PLATFORM_VERSION = '8.3.27.1989'
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 100_000
MAX_RECORD_BYTES = 16 * 1024 * 1024
BOM = b'\xef\xbb\xbf'
OFFSET = re.compile(r'([+-])([0-9]{2}):([0-9]{2})\Z')
HOUR = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:00(?::00(?:\.0{1,6})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z')
HEAD_TAIL = r'-(?P<duration>[0-9]{1,20}),(?P<event>[A-Za-z_][A-Za-z0-9_.:-]{0,63}),(?P<depth>[0-9]{1,10})(?P<separator>,|$)'
HEADERS = {
    'minute': re.compile(r'(?P<time>[0-9]{2}:[0-9]{2}\.[0-9]{6})' + HEAD_TAIL),
    'iso': re.compile(r'(?P<time>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6})' + HEAD_TAIL),
}


def _offset(value):
    if not isinstance(value, str) or not (match := OFFSET.fullmatch(value)):
        raise ValueError('utc_offset must explicitly use +HH:MM or -HH:MM')
    hours, minutes = int(match[2]), int(match[3])
    if hours > 23 or minutes > 59 or value == '-00:00':
        raise ValueError('utc_offset is outside the supported explicit-offset profile')
    seconds = (hours * 60 + minutes) * 60 * (1 if match[1] == '+' else -1)
    return timezone(timedelta(seconds=seconds))


def validate_profile(spec, path):
    """Validate declarations, without reading the path or guessing clock context."""
    if not isinstance(spec, dict):
        raise ValueError('native TJ profile must be an object')
    for field, expected in (('format', FORMAT), ('platform_version', PLATFORM_VERSION), ('encoding', 'utf-8')):
        if spec.get(field) != expected:
            raise ValueError(f'{field} must be explicitly {expected}')
    placement = spec.get('placement')
    if not isinstance(placement, str) or placement not in ('folders', 'plain'):
        raise ValueError('placement must be folders or plain')
    timestamp_format = spec.get('timestamp_format')
    if not isinstance(timestamp_format, str) or timestamp_format not in HEADERS:
        raise ValueError('timestamp_format must be explicitly minute or iso, independently of placement')
    result = {key: spec[key] for key in ('format', 'platform_version', 'encoding', 'placement', 'timestamp_format')}
    result.update(duration_unit='microseconds', start_time_inference='disabled_pending_event_semantics',
                  timestamp_rule='recorded_time_only; no operation-finish or job-boundary inference',
                  encoding_rule='strict_utf8; optional_initial_bom_only', clock_verification='not_verified')
    if timestamp_format == 'minute':
        if type(spec.get('rotation_hours')) is not int or spec['rotation_hours'] != 1:
            raise ValueError('minute timestamps require explicitly declared rotation_hours=1')
        value = spec.get('file_hour')
        if not isinstance(value, str) or not HOUR.fullmatch(value):
            raise ValueError('file_hour must be an exact ISO hour with an explicit UTC offset')
        try:
            hour = datetime.fromisoformat(value)
            _offset('+00:00' if value.endswith('Z') else value[-6:])
        except ValueError as error:
            raise ValueError('file_hour must be a valid exact hour and explicit offset') from error
        if hour.minute or hour.second or hour.microsecond or hour.tzinfo is None:
            raise ValueError('file_hour must identify one exact offset-aware hour')
        try:
            name = os.fspath(path).replace('\\', '/').rsplit('/', 1)[-1]
        except (TypeError, AttributeError) as error:
            raise ValueError('path must be a file path') from error
        filename_hour = re.fullmatch(r'(?:.+_[0-9]+_)?(?P<hour>[0-9]{8})\.log', name, re.IGNORECASE)
        if filename_hour and filename_hour['hour'] != hour.strftime('%y%m%d%H'):
            raise ValueError('YYMMDDHH in the log filename disagrees with the explicitly declared file_hour')
        result.update(file_hour=hour.isoformat(), rotation_hours=1, time_basis='user_declared_hour_and_offset')
    else:
        _offset(spec.get('utc_offset'))
        result.update(utc_offset=spec['utc_offset'], time_basis='recorded_date_and_user_declared_offset')
    return result


def _frames(data, offset, stop):
    """Yield byte ranges; a newline inside a quoted name/value is never a header.

    Quote recognition is limited to token starts. In particular O'Brien and
    Windows backslashes do not change state. The same scan continues through
    oversized records, so apparent headers inside an open quote stay data.
    """
    start, start_line, line = offset, 1, 1
    position, prefix_commas = offset, 0
    section, token_start, quote = 'prefix', True, None
    while position < stop:
        char = data[position]
        if quote is not None:
            if char == quote:
                if position + 1 < stop and data[position + 1] == quote:
                    position += 2
                    continue
                quote = None
            elif char == 10:
                line += 1
        elif char == 10:
            yield start, position + 1, start_line, line, True, False
            start, start_line = position + 1, line + 1
            line += 1
            section, token_start, quote, prefix_commas = 'prefix', True, None, 0
        elif token_start and char in (34, 39):
            quote, token_start = char, False
        elif section == 'prefix':
            if char == 44:
                prefix_commas += 1
                token_start = True
                if prefix_commas == 3:
                    section = 'name'
            else:
                token_start = False
        elif section == 'name':
            if char == 61:
                section, token_start = 'value', True
            elif char == 44:
                token_start = True
            else:
                token_start = False
        elif char == 44:
            section, token_start = 'name', True
        else:
            token_start = False
        position += 1
    if start < stop:
        yield start, stop, start_line, line, False, quote is not None


def _token(text, position, delimiter):
    if position >= len(text):
        return '', position
    if text[position] in ('"', "'"):
        quote = text[position]
        position += 1
        parts = []
        while position < len(text):
            char = text[position]
            if char == quote:
                if position + 1 < len(text) and text[position + 1] == quote:
                    parts.append(quote)
                    position += 2
                    continue
                return ''.join(parts), position + 1
            parts.append(char)
            position += 1
        raise ValueError('unclosed quoted property token')
    start = position
    while position < len(text) and text[position] != delimiter:
        if text[position] in '\r\n' or (delimiter == '=' and text[position] == ','):
            raise ValueError('property delimiter or quoting is invalid')
        position += 1
    return text[start:position], position


def _properties(text, position):
    properties, ambiguous = {}, {}
    while position < len(text):
        name, position = _token(text, position, '=')
        if not name or position >= len(text) or text[position] != '=':
            raise ValueError('property name must be followed by equals')
        value, position = _token(text, position + 1, ',')
        if name in ambiguous:
            ambiguous[name].append(value)
        elif name in properties:
            ambiguous[name] = [properties.pop(name), value]
        else:
            properties[name] = value
        if position == len(text):
            return properties, ambiguous
        if text[position] != ',':
            raise ValueError('quoted value must end at a property boundary')
        position += 1
        if position == len(text):
            raise ValueError('trailing property separator')
    return properties, ambiguous


def _record(text, profile):
    header = HEADERS[profile['timestamp_format']].match(text)
    if not header:
        raise ValueError('record header does not match the declared text profile')
    raw_time = header['time']
    if profile['timestamp_format'] == 'minute':
        timestamp = datetime.fromisoformat(profile['file_hour']).replace(
            minute=int(raw_time[:2]), second=int(raw_time[3:5]), microsecond=int(raw_time[6:]))
    else:
        timestamp = datetime.fromisoformat(raw_time).replace(tzinfo=_offset(profile['utc_offset']))
    if header['separator'] == ',' and header.end() == len(text):
        raise ValueError('missing property after separator')
    properties, ambiguous = _properties(text, header.end())
    return dict(raw_time=raw_time, event=header['event'], duration_us=int(header['duration']),
                depth=int(header['depth']), properties=properties, ambiguous_properties=ambiguous,
                timestamp=timestamp.isoformat(timespec='microseconds'),
                timestamp_utc=timestamp.astimezone(timezone.utc).isoformat(timespec='microseconds'),
                start_timestamp_utc=None)


def parse_tj(data, profile, max_records=100000, max_record_bytes=262144):
    """Return observations and bounded limitations, preserving source byte ranges.

    Evidence byte_end includes a record's LF/CRLF terminator and is exclusive.
    Unterminated tails are conservatively withheld, even when syntactically
    plausible. No full-data decoding or unbounded record buffering is used.
    """
    if not isinstance(data, bytes):
        raise ValueError('TJ input must be immutable bytes')
    if type(max_records) is not int or not 0 <= max_records <= MAX_RECORDS:
        raise ValueError('max_records must be an integer from 0 through 100000')
    if type(max_record_bytes) is not int or not 1 <= max_record_bytes <= MAX_RECORD_BYTES:
        raise ValueError('max_record_bytes must be an integer from 1 through 16777216')
    profile = validate_profile(profile, '')
    records, limitations = [], []
    omitted, records_seen = 0, 0

    def limited(code, message, **location):
        nonlocal omitted
        if len(limitations) < 199:
            limitations.append(dict(code=code, message=message, **location))
        else:
            omitted += 1

    start = 3 if data.startswith(BOM) else 0
    stop = min(len(data), MAX_INPUT_BYTES)
    cursor = start
    frames = _frames(data, start, stop)
    while records_seen < max_records:
        try:
            begin, end, first_line, last_line, terminated, open_quote = next(frames)
        except StopIteration:
            break
        cursor = end
        records_seen += 1
        location = dict(line=first_line, end_line=last_line, byte_start=begin, byte_end=end)
        if end - begin > max_record_bytes:
            limited('record_too_large', 'Record exceeded the byte limit and was not decoded.', **location)
            if open_quote:
                limited('ambiguous_record_boundary', 'An open quote prevents safe recovery before the end of input.', **location)
            continue
        raw = data[begin:end]
        try:
            text = raw.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            limited('invalid_utf8', 'Record does not satisfy the declared strict UTF-8 profile.', **location)
            continue
        if '\ufeff' in text:
            limited('unexpected_bom', 'A BOM is only accepted at byte zero of the file.', **location)
            continue
        if not terminated:
            limited('ambiguous_record_boundary' if open_quote else 'truncated_record',
                    'Final record is incomplete or lacks a terminating newline; it was not accepted.', **location)
            continue
        text = text[:-2] if text.endswith('\r\n') else text[:-1]
        try:
            record = _record(text, profile)
        except (ValueError, OverflowError):
            limited('invalid_record', 'Record header, time or property grammar is invalid.', **location)
            continue
        record.update(location)
        if record['ambiguous_properties']:
            limited('ambiguous_property', 'Repeated properties retained separately; no value selected.', **location)
        records.append(record)
    if cursor < stop:
        limited('record_limit', 'Record-attempt budget reached; remaining bytes were not parsed.', byte_start=cursor)
    if len(data) > MAX_INPUT_BYTES:
        limited('input_byte_limit', 'Input exceeds the 16 MiB adapter scan limit.', byte_start=stop)
    if omitted:
        limitations.append(dict(code='additional_limitations', count=omitted,
                                message='Additional limitation details were omitted.'))
    if len(data) == start:
        status = 'empty'
    elif records_seen == 0:
        status = 'not_parsed'
    elif not records:
        status = 'invalid'
    else:
        status = 'partial' if limitations else 'parsed'
    return dict(records=records, limitations=limitations, records_seen=records_seen, status=status)
