"""Read the observed legacy 1C EventLog SQLite layout from sealed input bytes."""
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from time import monotonic

try:
    import sqlite3
except ImportError:
    sqlite3 = None

from .inputs import InputError, MAX_EVENTS, MAX_FILE_BYTES, MAX_RECORD_BYTES


PROFILE = '1c-jr-lgd-eventlog-v1'
READER_FORMAT = 1
SIDECARS = ('-wal', '-shm', '-journal')
SQLITE_MAGIC = b'SQLite format 3\0'
RECORD_SECONDS = 1
STORED_RESOLUTION_SECONDS = 0.0001
TIME_BASIS = 'native_utc_second_precision'
EPOCH = datetime(1, 1, 1, tzinfo=timezone.utc)
MAX_REFERENCES = 32
QUERY_SECONDS = 20

EVENT_FIELDS = ('rowID', 'severity', 'date', 'connectID', 'session', 'transactionStatus',
                'transactionDate', 'transactionID', 'userCode', 'computerCode', 'appCode', 'eventCode',
                'comment', 'metadataCodes', 'sessionDataSplitCode', 'dataType', 'data', 'dataPresentation',
                'workServerCode', 'primaryPortCode', 'secondaryPortCode')
TEXT_FIELDS = {'comment', 'metadataCodes', 'data', 'dataPresentation'}
DICTIONARIES = {'EventCodes': 'event', 'UserCodes': 'user', 'ComputerCodes': 'computer',
                'AppCodes': 'application', 'MetadataCodes': 'metadata'}
SEVERITY = {1: 'I', 2: 'W', 3: 'E', 4: 'N'}
TRANSACTION = {1: 'C', 2: 'U', 3: 'N', 4: 'R'}


def _validate_header(data):
    if len(data)<100 or len(data)>MAX_FILE_BYTES or not data.startswith(SQLITE_MAGIC):
        raise InputError('LGD requires a bounded SQLite database snapshot')
    if data[18:20]!=b'\x01\x01':
        raise InputError('LGD requires a self-contained SQLite snapshot without WAL')
    size = int.from_bytes(data[16:18], 'big')
    size = 65536 if size==1 else size
    pages = int.from_bytes(data[28:32], 'big')
    if (not 512<=size<=65536 or size & (size-1) or pages*size!=len(data)
            or data[24:28]!=data[92:96]):
        raise InputError('LGD SQLite snapshot size or header is inconsistent')


def _columns(names, text, *, key=None):
    return tuple((name, 'TEXT' if name in text else 'INTEGER', int(name==key)) for name in names)


def _verify_schema(db):
    tables = {'EventLog': _columns(EVENT_FIELDS, TEXT_FIELDS, key='rowID'),
              'EventLogMetadata': _columns(('eventLogID','metadataCode'), ())}
    for table in DICTIONARIES:
        columns = ('code','name','uuid') if table in ('UserCodes','MetadataCodes') else ('code','name')
        tables[table] = _columns(columns, ('name','uuid'), key='code')
    inventory = {name: (kind, columns, no_rowid) for schema, name, kind, columns, no_rowid, _strict
                 in db.execute('PRAGMA main.table_list') if schema=='main'}
    if any(entry[0] in ('virtual','shadow') for entry in inventory.values()):
        raise InputError('unsupported LGD schema with virtual tables')
    for table, expected in tables.items():
        if inventory.get(table)!=('table',len(expected),0):
            raise InputError('unsupported LGD schema for '+table)
        observed = [(name, kind.upper(), key, hidden) for _index,name,kind,_required,_default,key,hidden
                    in db.execute(f'PRAGMA main.table_xinfo({table})')]
        if observed!=[(name,kind,key,0) for name,kind,key in expected]:
            raise InputError('unsupported LGD schema for '+table)
    if db.execute('PRAGMA main.quick_check(1)').fetchone()!=('ok',):
        raise InputError('LGD SQLite snapshot integrity check failed')

    def authorize(action, table, column, database, caller):
        if action==sqlite3.SQLITE_SELECT and caller is None:
            return sqlite3.SQLITE_OK
        if (action==sqlite3.SQLITE_READ and database=='main' and caller is None
                and table in tables and any(column==name for name, _, _ in tables[table])):
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    db.set_authorizer(authorize)


def _rows(db, query):
    for index, row in enumerate(db.execute(query+f' LIMIT {MAX_EVENTS+1}'), 1):
        if index>MAX_EVENTS:
            raise InputError('LGD table row budget exceeded')
        yield row


def _references(db):
    dictionaries = {}
    for table, field in DICTIONARIES.items():
        dictionary = dictionaries[field] = {}
        for code, name in _rows(db, f'SELECT code,name FROM main.{table} NOT INDEXED ORDER BY code'):
            if type(code) is not int or type(name) is not str or len(name)>2048:
                raise InputError('invalid LGD reference field')
            dictionary[code] = name
    metadata = defaultdict(set)
    for event, code in _rows(db, 'SELECT eventLogID,metadataCode FROM main.EventLogMetadata NOT INDEXED'):
        if type(event) is not int or type(code) is not int:
            raise InputError('invalid LGD metadata reference')
        metadata[event].add(code)
        if len(metadata[event])>MAX_REFERENCES:
            raise InputError('LGD metadata references exceed the record limit')
    return dictionaries, metadata


def _stamp(value):
    if type(value) is not int or value<=0:
        return None
    try:
        return EPOCH + timedelta(microseconds=value*100)
    except OverflowError:
        return None


def projection_text(values):
    return json.dumps(values, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def _scan(db, filename, deadline):
    dictionaries, metadata = _references(db)
    records, counts, issues = [], Counter(), Counter()

    def lookup(kind, code):
        value = dictionaries[kind].get(code)
        if code not in (None,0) and value is None:
            issues['unresolved_'+kind+'_reference']+=1
        return value

    query = f"SELECT {','.join(EVENT_FIELDS)} FROM main.EventLog NOT INDEXED ORDER BY rowID"
    for ordinal, row in enumerate(_rows(db, query), 1):
        if monotonic()>=deadline:
            raise InputError('LGD read exceeded its processing deadline')
        values = dict(zip(EVENT_FIELDS, row, strict=True))
        if (type(values['rowID']) is not int or values['rowID']<=0
                or any(value is not None and type(value) is not (str if field in TEXT_FIELDS else int)
                       for field,value in values.items() if field!='date')
                or type(values['date']) not in (int,str,type(None))):
            raise InputError('invalid typed value in LGD event row')
        text = projection_text(values).encode('utf-8')
        if len(text)>MAX_RECORD_BYTES:
            raise InputError('LGD row projection exceeds record byte limit')
        stamp = _stamp(values['date'])
        if stamp is None:
            issues['unknown_timestamp']+=1
        refs = sorted(metadata.pop(values['rowID'], ()))
        names = [value for code in refs if (value:=lookup('metadata',code)) is not None]
        event = lookup('event',values['eventCode'])
        label = event or 'unresolved_event'
        if label in counts or len(counts)<128:
            counts[label]+=1
        else:
            issues['event_counts_over_limit']+=1
        records.append(dict(
            id=f's1:r{ordinal}', source='s1', file=filename, sqlite_row_id=str(values['rowID']),
            evidence_kind='sqlite_row_projection', byte_start=None, byte_end=None, sha256=sha256(text).hexdigest(),
            journal_id=None, source_time=values['date'], local_time=None,
            timestamp=stamp.replace(microsecond=0).isoformat() if stamp is not None else None,
            stored_timestamp_utc=stamp.isoformat() if stamp is not None else None,
            utc_offset='+00:00', precision_seconds=RECORD_SECONDS,
            severity=SEVERITY.get(values['severity']), severity_code=values['severity'],
            transaction_state=TRANSACTION.get(values['transactionStatus']), transaction_status_code=values['transactionStatus'],
            event=event, user=lookup('user',values['userCode']), computer=lookup('computer',values['computerCode']),
            application=lookup('application',values['appCode']),
            session=str(values['session']) if values['session'] is not None else None,
            connection=str(values['connectID']) if values['connectID'] is not None else None,
            metadata=names[0] if len(refs)==len(names)==1 else None, metadata_values=names,
            comment=values['comment'], row_values=values,
            database_identity=None, lifetime_epoch=None, job_identity=None,
        ))
    if metadata:
        issues['orphan_metadata_reference']+=len(metadata)
    return records, counts, issues


def parse_snapshot(data, filename):
    _validate_header(data)
    if (sqlite3 is None or not hasattr(sqlite3.Connection, 'deserialize')
            or sqlite3.sqlite_version_info<(3,37,0)):
        raise InputError('LGD reader requires Python SQLite deserialize and SQLite 3.37 or later')
    deadline = monotonic()+QUERY_SECONDS
    try:
        with closing(sqlite3.connect(':memory:')) as db:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_RECORD_BYTES)
            db.set_progress_handler(lambda: int(monotonic()>=deadline), 2048)
            db.deserialize(data)
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA query_only=ON')
            db.execute('PRAGMA temp_store=MEMORY')
            _verify_schema(db)
            records, counts, issues = _scan(db, filename, deadline)
    except (sqlite3.Error,UnicodeError) as exc:
        raise InputError('LGD SQLite snapshot could not be read within the supported profile and limits') from exc
    times = [row['timestamp'] for row in records if row['timestamp'] is not None]
    return dict(profile=PROFILE, journal_id=None, writer_version=None, utc_offset='+00:00',
                time_basis=TIME_BASIS, precision_seconds=RECORD_SECONDS,
                stored_resolution_seconds=STORED_RESOLUTION_SECONDS,
                event_count=len(records), records=records, counts=dict(counts),
                status='partial' if issues else 'parsed', issues=[dict(code=key,count=value) for key,value in sorted(issues.items())],
                observed_local_range=[None,None], observed_utc_range=[min(times,default=None),max(times,default=None)],
                database_identity=None, complete_incident_coverage=None, requires_ai_interpretation=True,
                limitations=['The SQLite schema is recognized. The original 1C writer build is unknown.',
                             'Fractional storage units do not verify clock precision. Incident windows use recorded UTC seconds.',
                             'Observed timestamps do not prove coverage, clock alignment, database membership or job identity.'])
