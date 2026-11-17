"""Bounded read-only reader domain; never physical-host authentication.

Linux: https://docs.kernel.org/admin-guide/sysctl/kernel.html#random
Windows structure research (undocumented layout, unavailable means unknown):
https://geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi/system_boot_environment_information.htm
https://geoffchappellmirror.github.io/studies/windows/km/ntoskrnl/api/ex/sysinfo/timeofday.htm
BootIdentifier alone identifies a boot entry; kernel BootTime also scopes it.
"""
import hashlib
import os
from pathlib import Path
import re
import sys
import uuid

PROFILE = 'local-reader-domain-v1'


def _native():
    if os.name == 'nt':
        import ctypes as c
        query = c.WinDLL('ntdll').NtQuerySystemInformation
        query.argtypes = [c.c_uint32, c.c_void_p, c.c_uint32, c.POINTER(c.c_uint32)]
        query.restype = c.c_int32
        parts = []
        for kind, size, used in ((90, 32, 16), (3, 48, 8)):
            buffer = c.create_string_buffer(size)
            length = c.c_uint32()
            if query(kind, buffer, size, c.byref(length)) != 0 or length.value != size or not any(buffer.raw[:used]):
                raise OSError('native reader domain unavailable')
            parts.append(buffer.raw[:used])
        return b'windows-boot-entry-time\0' + b''.join(parts)
    if sys.platform.startswith('linux'):
        with Path('/proc/sys/kernel/random/boot_id').open('rb') as stream:
            boot = stream.read(129).strip()
        if not re.fullmatch(rb'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', boot):
            raise OSError('kernel boot domain unavailable')
        identities = [Path('/proc/self/ns/' + name).stat().st_ino for name in ('mnt', 'time')]
        if any(value <= 0 for value in identities):
            raise OSError('kernel namespace unavailable')
        return b'linux-boot-mount-time\0' + uuid.UUID(boot.decode('ascii')).bytes + ':'.join(map(str, identities)).encode('ascii')
    raise OSError('reader platform unavailable')


def observe():
    value = dict(profile=PROFILE, status='unknown', platform='windows' if os.name == 'nt' else 'linux' if sys.platform.startswith('linux') else 'other', id=None)
    try:
        raw = _native()
        if type(raw) is not bytes or not 16 <= len(raw) <= 256 or not any(raw):
            return value
        value.update(status='observed', id=hashlib.sha256(PROFILE.encode('ascii') + b'\0' + raw).hexdigest())
    except (OSError, ValueError, AttributeError, UnicodeError):
        pass
    return value
