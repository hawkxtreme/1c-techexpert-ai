"""Local Windows observations of one process using a file base and a TJ file."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re

from . import operation_state as fs, reader_scope
from .analysis import parse_time
from .inputs import InputError


PROFILE = 'windows-tj-file-holder-v1'
REFERENCE_CAPABILITY = 3
INTAKE_CAPABILITY = 12
SHA256 = re.compile('[a-f0-9]{64}')
STATUSES = ('observed', 'base_unavailable', 'journal_holder_unavailable',
            'different_journal_holder', 'association_changed', 'reader_unavailable', 'stopped')
IDENTITY = ('process_sha256','base_file_sha256','process_started_at')


def process_key(pid, lifetime, domain):
    return fs.digest(dict(platform='windows',pid=pid,lifetime=lifetime,domain_sha256=domain))


def _creation_time(lifetime):
    # FILETIME uses 100 ns ticks since 1601-01-01. Round up to a full
    # microsecond so an earlier journal timestamp is never included by rounding.
    return (datetime(1601,1,1,tzinfo=timezone.utc)
            + timedelta(microseconds=(int(lifetime)+9)//10)).isoformat()


def observe(base_file, journal, expected, *, stop):
    from . import logcfg_discovery, profile_files, tj_reference, windows_native

    def result(status, **facts):
        return dict(status=status,at=fs.stamp(),**facts)

    if stop and stop():
        return result('stopped')
    domain = reader_scope.observe()
    if domain['status']!='observed' or domain['platform']!='windows':
        return result('reader_unavailable')
    try:
        base = profile_files.file_base_path(base_file)
        client = logcfg_discovery._file_client(base)
    except (OSError,ValueError):
        return result('base_unavailable')
    identity = (client['pid'],client['lifetime'])
    if stop and stop():
        return result('stopped')
    try:
        path = profile_files._ordinary_path(str(journal))
        current = tj_reference._path_state(path)
        if any(current[key]!=expected[key] for key in ('identity','path_chain_sha256')):
            return result('association_changed')
        holders = windows_native.file_open_processes(path)
        if holders!= (identity,):
            return result('different_journal_holder' if len(holders)==1 else 'journal_holder_unavailable')
        after = tj_reference._path_state(path)
        same_file = all(after[key]==current[key] for key in ('identity','path_chain_sha256'))
        live = fs.process_identity(identity[0])
        if (not same_file or live['state']!='running' or live['lifetime']!=identity[1]
                or domain!=reader_scope.observe() or client['identity']!=logcfg_discovery._base_file_identity(base)):
            return result('association_changed')
        created = _creation_time(identity[1])
    except (OSError,ValueError,OverflowError):
        return result('journal_holder_unavailable')
    return result('observed',process_sha256=process_key(*identity,domain['id']),
                  base_file_sha256=fs.digest(client['identity']),process_started_at=created)


def capture(base_file, before, after):
    return dict(profile=PROFILE,base_path_sha256=fs.digest(str(Path(base_file))),before=before,after=after)


def _time(value):
    if type(value) is not str or not 1<=len(value)<=60 or value.endswith('-00:00'):
        raise InputError('invalid file process observation time')
    return parse_time(value)


def status(capture_window):
    value=capture_window.get('file_process')
    if value is None:
        if 'file_process' in capture_window:
            raise InputError('invalid saved file process observation')
        return 'not_recorded'
    if (type(value) is not dict or set(value)!={'profile','base_path_sha256','before','after'}
            or value['profile']!=PROFILE or not _hash(value['base_path_sha256'])):
        raise InputError('invalid saved file process observation')
    before,after=value['before'],value['after']
    clock_order_uncertain=False
    for point in (before,after):
        if type(point) is not dict or point.get('status') not in STATUSES:
            raise InputError('invalid file process boundary')
        keys={'status','at'}
        if point['status']=='observed':
            keys.update(IDENTITY)
        if set(point)!=keys:
            raise InputError('invalid file process boundary fields')
        at=_time(point['at'])
        if point['status']=='observed':
            if not all(_hash(point[key]) for key in IDENTITY[:2]):
                raise InputError('invalid file process boundary identity')
            clock_order_uncertain |= _time(point['process_started_at'])>at
    if (clock_order_uncertain
            or not _time(capture_window['started_at'])<=_time(before['at'])<=_time(after['at'])<=_time(capture_window['finished_at'])):
        return 'clock_order_uncertain'
    if before['status']!='observed' or after['status']!='observed':
        return 'unavailable'
    if any(before[key]!=after[key] for key in IDENTITY):
        return 'different_boundaries'
    return 'same_observed_file_holder'


def _hash(value):
    return type(value) is str and SHA256.fullmatch(value)
