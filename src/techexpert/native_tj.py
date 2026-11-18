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
MAX_REFERENCE_SCAN_BYTES = 256 * 1024 * 1024
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


class _TJScan:
    def __init__(self,stream,profile,max_records,max_record_bytes,chunk_size,max_input_bytes):
        from .native_tj_stream import Frames,MAX_CHUNK_BYTES
        if type(max_records) is not int or not 0<=max_records<=MAX_RECORDS:raise ValueError('max_records must be an integer from 0 through 100000')
        if type(max_record_bytes) is not int or not 1<=max_record_bytes<=MAX_RECORD_BYTES:raise ValueError('max_record_bytes must be an integer from 1 through 16777216')
        if type(chunk_size) is not int or not 1<=chunk_size<=MAX_CHUNK_BYTES:raise ValueError('chunk_size must be an integer from 1 through 65536')
        if type(max_input_bytes) is not int or not 1<=max_input_bytes<=MAX_REFERENCE_SCAN_BYTES:raise ValueError('TJ scan byte limit is outside supported bounds')
        if not callable(getattr(stream,'read',None)):raise ValueError('TJ input requires a binary stream')
        self.profile=validate_profile(profile,'');self.max_records=max_records;self.max_record_bytes=max_record_bytes
        self.frames=Frames(stream,chunk_size=chunk_size,max_input_bytes=max_input_bytes,max_record_bytes=max_record_bytes)
        self.records_seen=0;self.accepted=0;self.limitations=[];self.omitted=0;self.omitted_by_code={}
        self.raw_record=None;self._summary=None;self._iterator=self._scan()

    def __iter__(self):return self
    def __next__(self):return next(self._iterator)

    @property
    def summary(self):
        if self._summary is None:raise ValueError('TJ scan has not completed')
        return self._summary

    def limited(self,code,message,**location):
        if len(self.limitations)<199:self.limitations.append(dict(code=code,message=message,**location))
        else:self.omitted+=1;self.omitted_by_code[code]=self.omitted_by_code.get(code,0)+1

    def _scan(self):
        self.frames.initialize();cursor=self.frames.start;frames=iter(self.frames)
        try:
            while self.records_seen<self.max_records:
                try:frame=next(frames)
                except StopIteration:break
                cursor=frame['byte_end'];self.records_seen+=1;self.raw_record=None
                location={key:frame[key] for key in ('line','end_line','byte_start','byte_end')}
                if frame['raw'] is None:
                    self.limited('record_too_large','Record exceeded the byte limit and was not decoded.',**location)
                    if frame['open_quote']:self.limited('ambiguous_record_boundary','An open quote prevents safe recovery before the end of input.',**location)
                    continue
                try:text=frame['raw'].decode('utf-8',errors='strict')
                except UnicodeDecodeError:
                    self.limited('invalid_utf8','Record does not satisfy the declared strict UTF-8 profile.',**location);continue
                if '\ufeff' in text:
                    self.limited('unexpected_bom','A BOM is only accepted at byte zero of the file.',**location);continue
                if not frame['terminated']:
                    self.limited('ambiguous_record_boundary' if frame['open_quote'] else 'truncated_record','Final record is incomplete or lacks a terminating newline; it was not accepted.',**location);continue
                text=text[:-2] if text.endswith('\r\n') else text[:-1]
                try:record=_record(text,self.profile)
                except (ValueError,OverflowError):
                    self.limited('invalid_record','Record header, time or property grammar is invalid.',**location);continue
                record.update(location)
                if record['ambiguous_properties']:self.limited('ambiguous_property','Repeated properties retained separately; no value selected.',**location)
                self.accepted+=1;self.raw_record=frame['raw'];yield record
        finally:frames.close()
        self.frames.finish();self.raw_record=None
        if cursor<self.frames.scan_size:self.limited('record_limit','Record-attempt budget reached; remaining bytes were not parsed.',byte_start=cursor)
        if self.frames.seen>self.frames.limit:self.limited('input_byte_limit','Input exceeds the adapter scan byte limit.',byte_start=self.frames.limit)
        if self.omitted:self.limitations.append(dict(code='additional_limitations',count=self.omitted,counts_by_code=self.omitted_by_code,message='Additional limitation details were omitted.'))
        status=('empty' if self.frames.seen==self.frames.start else 'not_parsed' if not self.records_seen else 'invalid' if not self.accepted else 'partial' if self.limitations else 'parsed')
        self._summary=dict(limitations=self.limitations,records_seen=self.records_seen,status=status)


def iter_tj(stream,profile,max_records=100000,max_record_bytes=262144,*,chunk_size=65536,max_input_bytes=None):
    """Yield bounded native observations; summary is final only after exhaustion.

    The caller owns the binary stream and source integrity verification. A scan
    reads at most the explicit input budget plus one lookahead byte. Raw
    evidence for the current accepted record is available as raw_record.
    """
    limit = MAX_INPUT_BYTES if max_input_bytes is None else max_input_bytes
    return _TJScan(stream,profile,max_records,max_record_bytes,chunk_size,limit)


def parse_tj(data,profile,max_records=100000,max_record_bytes=262144):
    """Compatibility collector over the same incremental strict UTF-8 parser."""
    import io
    if not isinstance(data,bytes):raise ValueError('TJ input must be immutable bytes')
    scan=iter_tj(io.BytesIO(data),profile,max_records,max_record_bytes)
    return dict(records=list(scan),**scan.summary)
