"""Read-only storage observations for an explicitly selected local file or directory."""
import os
from pathlib import Path
import re
import stat

from . import input_files, operation_state as fs, reader_scope
from .analysis import parse_time
from .inputs import InputError


SCHEMA = 1
READER_CAPABILITY = 2
SHA256 = re.compile(r'[a-f0-9]{64}')
DISK_NUMBER = re.compile(r'[0-9]{1,10}')
BLOCK_NUMBER = re.compile(r'[0-9]{1,12}:[0-9]{1,12}')
WINDOWS_INSTANCE = re.compile(r'([0-9]{1,10})(?: [A-Za-z]:)*')
PLATFORMS = {'windows': 'windows_host', 'linux': 'linux_kernel_and_current_network_namespace'}
REQUIRED = ('domain_sha256', 'path_identity_sha256', 'mapping_sha256')


def local_path(value):
    """Check a local path's syntax without opening it or resolving a drive."""
    from .profile_files import credential_address
    if (type(value) is not str or not 1 <= len(value) <= 2000 or value.startswith(('\\', '//'))
            or '://' in value or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or credential_address(value)):
        raise InputError('storage observation requires an explicit local filesystem path')
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts:
        raise InputError('storage observation requires an absolute local path without traversal')
    if os.name == 'nt':
        if not re.fullmatch(r'[A-Za-z]:', path.drive):
            raise InputError('storage observation requires an ordinary local drive')
        for part in path.parts[1:]:
            input_files.name_parts(part)
    return str(path)


def file_base_target(base):
    if base['mode'] != 'file' or not base['connection'].strip():
        return None
    from .discovery import describe_connection
    value = base['connection']
    try:
        if re.match(r'(?i)^file\s*=', value):
            selected = describe_connection(value)
            if selected['mode'] != 'file':
                return None
            value = selected['connection']
        path = Path(local_path(value))
        return local_path(str(path if path.suffix.casefold() == '.1cd' else path/'1Cv8.1CD'))
    except InputError:
        return None


def reader_digest():
    from hashlib import sha256
    return sha256(Path(__file__).read_bytes()).hexdigest()


def _windows_extents(kernel, path):
    from ctypes import (Structure, POINTER, byref, c_int64, c_size_t, c_void_p, create_unicode_buffer,
                        get_last_error, sizeof, WinError)
    from ctypes import wintypes as w

    signatures = {
        'GetVolumePathNameW':([w.LPCWSTR,w.LPWSTR,w.DWORD],w.BOOL),
        'GetVolumeNameForVolumeMountPointW':([w.LPCWSTR,w.LPWSTR,w.DWORD],w.BOOL),
        'CreateFileW':([w.LPCWSTR,w.DWORD,w.DWORD,c_void_p,w.DWORD,w.DWORD,w.HANDLE],w.HANDLE),
        'DeviceIoControl':([w.HANDLE,w.DWORD,c_void_p,w.DWORD,c_void_p,w.DWORD,POINTER(w.DWORD),c_void_p],w.BOOL),
        'CloseHandle':([w.HANDLE],w.BOOL),
    }
    for name,(arguments,result) in signatures.items():
        function=getattr(kernel,name)
        function.argtypes=arguments
        function.restype=result

    class Extent(Structure):
        _fields_ = [('disk',w.DWORD),('start',c_int64),('length',c_int64)]

    class Extents(Structure):
        _fields_ = [('count',w.DWORD),('extents',Extent*32)]

    mount, volume = create_unicode_buffer(2048),create_unicode_buffer(128)
    if not kernel.GetVolumePathNameW(str(path),mount,len(mount)):
        raise WinError(get_last_error())
    if not kernel.GetVolumeNameForVolumeMountPointW(mount.value,volume,len(volume)):
        raise WinError(get_last_error())
    if not re.fullmatch(r'\\\\\?\\Volume\{[a-fA-F0-9-]{36}\}\\',volume.value):
        raise InputError('invalid local volume name')
    handle = kernel.CreateFileW(volume.value[:-1],0,7,None,3,0,None)
    if handle in (None,c_size_t(-1).value):
        raise WinError(get_last_error())
    try:
        buffer, used = Extents(),w.DWORD()
        # IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS with metadata-only access.
        if not kernel.DeviceIoControl(handle,0x560000,None,0,byref(buffer),sizeof(buffer),byref(used),None):
            raise WinError(get_last_error())
        if not 1 <= buffer.count <= 32 or Extents.extents.offset + buffer.count*sizeof(Extent) > used.value:
            raise InputError('invalid volume extent count')
        extents = sorted((item.disk,item.start,item.length) for item in buffer.extents[:buffer.count])
        if any(start<0 or length<=0 for _,start,length in extents):
            raise InputError('invalid volume extent bounds')
    finally:
        kernel.CloseHandle(handle)
    return sorted({str(disk) for disk,_,_ in extents}),fs.digest([volume.value.casefold(),extents])


def observe(value):
    path = Path(local_path(value))
    domain = reader_scope.observe()
    platform = domain['platform']

    def unavailable(status):
        return dict(at=fs.stamp(),status=status,platform=platform)

    if domain['status'] != 'observed' or platform not in PLATFORMS:
        return unavailable('domain_unavailable')
    try:
        if platform == 'windows':
            import ctypes as c
            kernel = c.WinDLL('kernel32',use_last_error=True)
            kernel.GetDriveTypeW.argtypes = [c.c_wchar_p]
            kernel.GetDriveTypeW.restype = c.c_uint
            if kernel.GetDriveTypeW(path.anchor) != 3:
                return unavailable('not_fixed_local_volume')
        chain = input_files.chain(path)
        _,device,_,mode = chain[-1]
        if mode not in (stat.S_IFREG,stat.S_IFDIR):
            return unavailable('unsupported_path')
        if platform == 'windows':
            keys,mapping = _windows_extents(kernel,path)
        else:
            number = f'{os.major(device)}:{os.minor(device)}'
            if not Path('/sys/dev/block',number).exists():
                return unavailable('not_block_backed')
            keys,mapping = [number],fs.digest(number)
        if chain != input_files.chain(path) or domain != reader_scope.observe():
            return unavailable('changed_during_observation')
        return dict(at=fs.stamp(),status='observed',platform=platform,domain_sha256=domain['id'],
                    path_identity_sha256=fs.digest(chain),mapping_sha256=mapping,device_keys=keys)
    except (OSError, ValueError, OverflowError):
        return unavailable('unavailable')


def _hash(value):
    return type(value) is str and SHA256.fullmatch(value)


def _stamp(value):
    if type(value) is not str or value.endswith('-00:00'):
        raise ValueError('storage observation requires an explicit offset')
    return parse_time(value)


def binding(capture, *, origin):
    observation = capture.get('storage_observation')
    if observation is None:
        return None
    result = dict(status='unusable_observation',origin=origin,device_keys=[])
    try:
        if (type(observation) is not dict or type(observation.get('schema_version')) is not int
                or observation['schema_version'] != SCHEMA or not _hash(observation['selected_path_sha256'])):
            return result
        before, after = observation['before'],observation['after']
        if before['status'] != 'observed' or after['status'] != 'observed':
            status = 'unavailable'
        else:
            platform = before['platform']
            pattern = DISK_NUMBER if platform == 'windows' else BLOCK_NUMBER
            for item in (before,after):
                keys = item['device_keys']
                if (PLATFORMS.get(item['platform']) != capture['scope'] or not all(_hash(item[key]) for key in REQUIRED)
                        or type(keys) is not list or not 1 <= len(keys) <= 32
                        or any(type(key) is not str or not pattern.fullmatch(key) for key in keys)
                        or sorted(set(keys)) != keys):
                    return result
            if any(before[key]!=after[key] for key in (*REQUIRED,'platform','device_keys')):
                status = 'different_boundaries'
            else:
                start, end = _stamp(before['at']),_stamp(after['at'])
                rows = capture['samples']
                checked = rows and all(start<=_stamp(row.get('timestamp'))<=end for row in rows)
                if not checked:
                    status = 'not_bracketed'
                else:
                    return dict(result,status='same_boundary_observations',platform=platform,device_keys=before['device_keys'])
        return dict(result,status=status)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        return result


def counter_key(platform, instance, device):
    if platform == 'windows' and (match := WINDOWS_INSTANCE.fullmatch(instance)):
        return match[1]
    return device if platform == 'linux' else None
