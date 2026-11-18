"""A disposable SQLite index over one verified saved text TJ snapshot."""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
from time import monotonic
import uuid

try:
    import sqlite3
except ImportError:
    sqlite3 = None

from . import __version__, input_files, operation_state as fs, retained_resources, storage
from .analysis import parse_time
from .case_retention import SnapshotRetirement, case_writers
from .inputs import InputError, json_value, open_verified_snapshot
from .job_correlation import record_matches_link
from .native_tj import FORMAT, MAX_RECORDS, iter_tj
from .observations import preview_record, with_evidence
from .profiles import profile_writer, require_unconfigured_path

MAX_DATABASE_BYTES = 64 * 1024**2
MAX_HEADER_BYTES = 8192
MAGIC = b'TECHEXPERT-TJ-INDEX-1\n'
MAX_BYTES = MAX_DATABASE_BYTES + MAX_HEADER_BYTES + len(MAGIC) + 4
_TIME_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_SOURCE = re.compile(r's(?:[1-9]|[12][0-9]|3[0-2])')
_CACHE_ERRORS = (OSError, ValueError, KeyError, TypeError, OverflowError, RecursionError, MemoryError)
if sqlite3 is not None:
    _CACHE_ERRORS += (sqlite3.Error,)


def path_for(state, case_id, source_id):
    storage.case_folder(state, case_id)
    if not isinstance(source_id, str) or _SOURCE.fullmatch(source_id) is None:
        raise InputError('invalid native case source identifier')
    return fs.safe(Path(state) / 'case-indexes' / case_id / source_id / 'events.index')


def _supported():
    return sqlite3 is not None and all(hasattr(sqlite3.Connection, name) for name in ('serialize', 'deserialize'))


def _connection(seconds):
    deadline = monotonic() + seconds
    con = sqlite3.connect(':memory:')
    con.set_progress_handler(lambda: int(monotonic() > deadline), 2048)
    return con, deadline


def _read(state, case_id, source_id):
    folder = storage.case_folder(state, case_id)
    for name in ('report.json', 'receipt.json', 'manifest.json'):
        fs.safe(folder / name)
    report, digest = storage.load_case(state, case_id, with_digest=True)
    source = retained_resources.selected(report, dict(kind='case', source_id=source_id))
    if source['format'] != FORMAT:
        raise InputError('event index requires a saved native text TJ source')
    return report, digest, source


def _binding(case_id, report_digest, source):
    return dict(case_id=case_id, report_sha256=report_digest, source_id=source['id'],
                source_sha256=source['sha256'], source_bytes=source.get('size'), product_version=__version__)


def _timestamp(value):
    stamp = value - _TIME_EPOCH
    return (stamp.days * 86400 + stamp.seconds) * 10**6 + stamp.microseconds


def _encode(record, database):
    header = fs.encode(dict(record=record, sha256=fs.digest(record)))
    if len(header) > MAX_HEADER_BYTES or not 0 < len(database) <= MAX_DATABASE_BYTES:
        raise InputError('event index exceeds its storage limit')
    return MAGIC + len(header).to_bytes(4, 'big') + header + database


def _decode(data):
    height = len(MAGIC)
    if not data.startswith(MAGIC) or len(data) < height + 4:
        raise InputError('unsupported case index format')
    size = int.from_bytes(data[height:height + 4], 'big')
    limit = height + 4 + size
    if not 0 < size <= MAX_HEADER_BYTES or not limit < len(data) <= limit + MAX_DATABASE_BYTES:
        raise InputError('invalid case index byte bounds')
    sealed = json_value(data[height + 4:limit].decode('utf-8'), reject_duplicates=True)
    record = sealed.get('record') if type(sealed) is dict else None
    database = data[limit:]
    if (type(record) is not dict or sealed.get('sha256') != fs.digest(record)
            or type(record.get('schema_version')) is not int or record['schema_version'] != 1
            or type(record.get('generation')) is not str or not re.fullmatch('[a-f0-9]{32}', record['generation'])
            or type(record.get('record_count')) is not int or not 0 <= record['record_count'] <= MAX_RECORDS
            or record.get('parse_status') not in ('empty', 'not_parsed', 'invalid', 'partial', 'parsed')
            or record.get('database_bytes') != len(database)
            or record.get('database_sha256') != hashlib.sha256(database).hexdigest()):
        raise InputError('case index integrity mismatch')
    return record, database


def _cached(path, binding, max_bytes=MAX_BYTES):
    try:
        data, _ = input_files.read(path, max_bytes, keep=True)
        record, database = _decode(data)
        if record['binding'] == binding:
            return record, database
    except _CACHE_ERRORS:
        pass
    return None


def _materialize(path, source, link):
    connection, deadline = _connection(30)
    with closing(connection), connection:
        page_limit = MAX_DATABASE_BYTES // 4096
        connection.execute('pragma page_size=4096')
        connection.execute(f'pragma max_page_count={page_limit}')
        connection.execute('pragma temp_store=memory')
        connection.execute('create table events(seq integer primary key, event text, stamp integer, linked integer, preview text)')
        connection.execute('create table properties(seq integer, name text, value text, primary key(seq,name)) without rowid')
        count = 0
        with open_verified_snapshot(path, source['sha256'], expected_size=source['size']) as stream:
            scan = iter_tj(stream, source['profile'], max_records=source['record_budget'])
            for count, captured in enumerate(scan, 1):
                if monotonic() > deadline:
                    raise InputError('event index build timed out')
                record = with_evidence(captured, source)
                rendered = json.dumps(preview_record(record), ensure_ascii=False, separators=(',', ':'), allow_nan=False)
                connection.execute('insert into events values (?,?,?,?,?)', (count, record['event'],
                    _timestamp(parse_time(record['timestamp_utc'])), int(record_matches_link(record, link)), rendered))
                connection.executemany('insert into properties values (?,?,?)',
                    ((count, key, value) for key, value in record['properties'].items()
                     if 1 <= len(key) <= 128 and len(value) <= 2048))
        connection.execute('create index event_page on events(event,seq)')
        connection.execute('create index event_time on events(stamp,seq)')
        connection.commit()
        return connection.serialize(), count, scan.summary['status']


def _publish(path, data):
    if shutil.disk_usage(path.parent).free - len(data) < 10 * 1024**3:
        raise InputError('event index would cross the local free space floor')
    try:
        info = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise InputError('event index path is occupied by a linked or special file')
    staging = path.with_name('events-' + uuid.uuid4().hex + '.tmp')
    created = False
    try:
        with staging.open('xb') as stream:
            created = True
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staging, fs.safe(path))
    finally:
        if created:
            staging.unlink(missing_ok=True)


def build(state, case_id, source_id):
    if not _supported():
        raise InputError('event indexes require SQLite serialization support in this Python runtime')
    path = path_for(state, case_id, source_id)
    with case_writers(state, [case_id], require_sources=False):
        report, digest, source = _read(state, case_id, source_id)
        raw = fs.safe(storage.case_source_path(state, case_id, source_id))
        descriptor = _binding(case_id, digest, source)
        saved = _cached(path, descriptor)
        if saved is not None:
            with open_verified_snapshot(raw, source['sha256'], expected_size=source['size']):
                pass
            return dict(saved[0], status='ready', path=str(path), replayed=True)
        try:
            database, count, status = _materialize(raw, source, report.get('job_correlation', {}).get('native_link', {}))
        except (sqlite3.Error, MemoryError) as error:
            raise InputError('SQLite could not build the bounded event index') from error
        record = dict(schema_version=1, binding=descriptor, generation=uuid.uuid4().hex, created_at=fs.stamp(),
                      record_count=count, parse_status=status, database_bytes=len(database),
                      database_sha256=hashlib.sha256(database).hexdigest())
        data = _encode(record, database)
        with profile_writer(fs.safe(Path(state) / 'profiles')):
            require_unconfigured_path(state, path)
            fs.private(path.parent)
            _publish(path, data)
        return dict(record, status='ready', path=str(path), replayed=False)


def inspect(state, case_id, source_id):
    path = path_for(state, case_id, source_id)
    _, digest, source = _read(state, case_id, source_id)
    saved = _cached(path, _binding(case_id, digest, source))
    if saved is None:
        return dict(status='unavailable' if path.exists() else 'absent', path=str(path))
    try:
        raw = storage.case_source_path(state, case_id, source_id)
        source_status = 'present' if fs.safe(raw).is_file() else 'missing'
    except SnapshotRetirement:
        source_status = 'retired_or_unverified'
    return dict(saved[0], status='cached', path=str(path), source_status=source_status,
                source_integrity='not_rechecked')


def _query(database, event, properties, bounds, linked_run, offset, limit):
    connection, _ = _connection(5)
    with closing(connection):
        connection.execute('pragma trusted_schema=off')
        connection.execute('pragma temp_store=memory')
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 256 * 1024)
        connection.deserialize(database)
        connection.execute('pragma query_only=on')
        conditions, arguments = [], []
        if event is not None:
            conditions.append('event=?')
            arguments.append(event)
        if bounds is not None:
            conditions.append('stamp>=? and stamp<?')
            arguments.extend(_timestamp(value) for value in bounds)
        if linked_run:
            conditions.append('linked=1')
        for key, value in properties.items():
            conditions.append('exists (select 1 from properties where seq=e.seq and name=? and value=?)')
            arguments.extend((key, value))
        where = ' where ' + ' and '.join(conditions) if conditions else ''
        (count,) = connection.execute('select count(*) from events e' + where, arguments).fetchone()
        if not 0 <= count <= MAX_RECORDS:
            raise InputError('invalid case index result count')
        if not limit or offset >= count:
            return count, []
        rows = connection.execute('select preview from events e' + where + ' order by seq limit ? offset ?',
                                  [*arguments, limit, offset])
        return count, [json_value(body, reject_duplicates=True) for (body,) in rows]


def page(state, case_id, report_digest, source, raw, *, event, properties, bounds, linked_run, offset, limit, memory_bytes):
    """Return a verified derived page or let the unchanged parser handle it."""
    if not _supported():
        return None
    # Loading the envelope and deserializing SQLite briefly keep several copies.
    available = MAX_BYTES if memory_bytes is None else min(MAX_BYTES, (memory_bytes - 128 * 1024**2) // 6)
    if available <= 0:
        return None
    try:
        path = path_for(state, case_id, source['id'])
    except _CACHE_ERRORS:
        return None
    found = _cached(path, _binding(case_id, report_digest, source), available)
    if found is None:
        return None
    record, database = found
    try:
        count, rows = _query(database, event, properties, bounds, linked_run, offset, limit)
        if count > record['record_count'] or any(type(row) is not dict for row in rows):
            return None
    except _CACHE_ERRORS:
        return None
    with open_verified_snapshot(fs.safe(raw), source['sha256'], expected_size=source.get('size')):
        pass
    return count, rows, record['parse_status']
