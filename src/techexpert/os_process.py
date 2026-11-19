"""Cumulative I/O counters for one explicitly selected local process lifetime."""
from functools import partial
from hashlib import sha256
import os
from pathlib import Path
import re
import struct

from . import operation_state as fs, os_storage, reader_scope
from .inputs import InputError


READER_CAPABILITY = 3
SCHEMA = 1
SCOPES = {'windows': 'windows_process_io_transfers', 'linux': 'linux_process_storage_accounting'}
BASES = ('explicit_pid','windows_file_holder_at_review')
STATUSES = ('observed','not_running','different_lifetime','unavailable','out_of_scope')
COUNTERS = ('read_bytes','write_bytes')
LIMIT = (1 << 64) - 1
DECIMAL = re.compile(r'[1-9][0-9]{0,19}')
LINUX_LIFETIME = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}:[0-9]{1,20}')


def reader_digest():
    native = Path(__file__).with_name('windows_native.py')
    return fs.digest([sha256(path.read_bytes()).hexdigest() for path in (Path(__file__),native)])


def validate_target(target):
    if type(target) is not dict:
        raise InputError('invalid process observation target')
    names = {'pid','lifetime','platform','domain_sha256','basis'}
    platform, basis = target.get('platform'),target.get('basis')
    lifetime_pattern = DECIMAL if platform=='windows' else LINUX_LIFETIME
    if platform=='linux':
        names.add('pid_namespace')
    if basis=='windows_file_holder_at_review':
        names.add('file_identity_sha256')
    if (set(target)!=names or not isinstance(platform,str) or platform not in SCOPES
            or type(target['pid']) is not int or not 1<=target['pid']<=0xFFFFFFFF
            or type(target['lifetime']) is not str or not lifetime_pattern.fullmatch(target['lifetime'])
            or not os_storage._hash(target['domain_sha256'])
            or (platform=='linux' and (type(target['pid_namespace']) is not str
                                       or not DECIMAL.fullmatch(target['pid_namespace'])))
            or (basis!='explicit_pid' and (basis!='windows_file_holder_at_review' or platform!='windows'
                                          or not os_storage._hash(target['file_identity_sha256'])))):
        raise InputError('invalid process observation target')
    return target


def _linux_local_proc():
    with Path('/proc/self/status').open('rb') as stream:
        status = stream.read(16385)
    # A procfs mounted for an ancestor namespace uses its PID numbering.
    return len(status)<=16384 and any(line.split()==[b'NSpid:',str(os.getpid()).encode('ascii')]
                                     for line in status.splitlines() if line.startswith(b'NSpid:'))


def select(selection, domain, file_base):
    pid = selection.get('pid')
    holder = None
    if pid is None:
        if domain['platform']!='windows' or file_base is None:
            raise InputError('select an explicit PID outside a local Windows file base')
        from . import logcfg_discovery, profile_files
        try:
            holder = logcfg_discovery._file_client(profile_files.file_base_path(file_base))
        except logcfg_discovery.DiscoveryError as exc:
            raise InputError(f'file process selection failed ({exc}); select an explicit PID') from exc
        except (OSError,ValueError) as exc:
            raise InputError('file process selection is unavailable; select an explicit PID') from exc
        pid = holder['pid']
    if domain['platform']=='linux' and (struct.calcsize('P')!=8 or not _linux_local_proc()):
        raise InputError('process I/O requires a 64-bit Linux collector with local procfs')
    identity = fs.process_identity(pid)
    if identity['state']!='running' or not identity['lifetime'] or (holder and identity['lifetime']!=holder['lifetime']):
        raise InputError('selected process lifetime is unavailable')
    target = dict(pid=pid,lifetime=identity['lifetime'],platform=domain['platform'],domain_sha256=domain['id'],
                  basis='explicit_pid')
    if domain['platform']=='linux':
        target['pid_namespace']=identity.get('pid_namespace')
    if holder:
        target.update(basis='windows_file_holder_at_review',file_identity_sha256=fs.digest(holder['identity']))
    return validate_target(target)


def _linux_status(target):
    identity = fs.process_identity(target['pid'])
    if identity.get('pid_namespace')!=target['pid_namespace']:
        return 'out_of_scope'
    if identity['state']!='running':
        # An inaccessible PID can be hidden by procfs and look like an exit.
        return 'unavailable'
    return 'observed' if identity['lifetime']==target['lifetime'] else 'different_lifetime'


def _linux_io(target):
    # Opening through the proc directory descriptor prevents PID reuse from
    # redirecting the subsequent open to the replacement process.
    flags = os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC
    descriptor = os.open('/proc/'+str(target['pid']),flags|os.O_DIRECTORY)
    try:
        status = _linux_status(target)
        if status!='observed':
            return dict(status=status)
        fd = os.open('io',flags,dir_fd=descriptor)
        with os.fdopen(fd,'rb') as stream:
            raw = stream.read(4097)
        status = _linux_status(target)
    finally:
        os.close(descriptor)
    if status!='observed':
        return dict(status=status)
    counts = {}
    for line in raw.splitlines():
        key, _, value = line.partition(b': ')
        if key in (b'read_bytes',b'write_bytes'):
            name = key.decode('ascii')
            if (name in counts or not re.fullmatch(rb'[0-9]{1,20}',value)
                    or int(value)>LIMIT or len(raw)>4096):
                return dict(status='unavailable')
            counts[name]=int(value)
    return dict(status='observed',**counts) if set(counts)==set(COUNTERS) else dict(status='unavailable')


def _sample(target, in_domain):
    try:
        if not in_domain:
            result = dict(status='out_of_scope')
        elif target['platform']=='windows':
            from .windows_native import process_io
            result = process_io(target['pid'],target['lifetime'])
        else:
            result = _linux_io(target)
    except ProcessLookupError:
        result = dict(status='not_running')
    except OSError as exc:
        result = dict(status='not_running' if getattr(exc,'winerror',None)==87
                      and target['platform']=='windows' else 'unavailable')
    return dict(result,at=fs.stamp())


def sampler(target):
    domain = reader_scope.observe()
    in_domain = domain['platform']==target['platform'] and domain['id']==target['domain_sha256']
    if in_domain and target['platform']=='linux':
        try:
            in_domain = struct.calcsize('P')==8 and _linux_local_proc()
        except OSError:
            in_domain = False
    return partial(_sample,target,in_domain)


def observation(target):
    return dict(schema_version=SCHEMA,platform=target['platform'],basis=target['basis'],
                target_sha256=fs.digest(target))


def record(capture, *, origin):
    """Validate the retained typed samples without consulting the live process."""
    if 'process_observation' not in capture:
        return None,None
    header = capture['process_observation']
    if (type(header) is not dict or set(header)!={'schema_version','platform','basis','target_sha256'}
            or type(header['schema_version']) is not int or header['schema_version']!=SCHEMA
            or not os_storage._hash(header['target_sha256'])
            or type(header['platform']) is not str or header['platform'] not in SCOPES
            or header['basis'] not in BASES
            or (header['basis']=='windows_file_holder_at_review' and header['platform']!='windows')):
        raise InputError('invalid process observation header')
    if os_storage.PLATFORMS[header['platform']]!=capture['scope']:
        raise InputError('process observation does not match the collector scope')
    samples = []
    observed = 0
    for row in capture['samples']:
        sample = row.get('process_io')
        if type(sample) is not dict or sample.get('status') not in STATUSES:
            raise InputError('invalid process observation sample')
        available = sample['status']=='observed'
        keys = {'at','status'}|set(COUNTERS) if available else {'at','status'}
        if (set(sample)!=keys or not isinstance(sample['at'],str) or len(sample['at'])>60
                or available and any(type(sample[key]) is not int or not 0<=sample[key]<=LIMIT for key in COUNTERS)):
            raise InputError('invalid process measurement fields')
        observed += available
        samples.append(sample)
    return dict(origin=origin,counter_scope=SCOPES[header['platform']],selection_basis=header['basis'],
                observed_samples=observed,unavailable_samples=len(samples)-observed),samples
