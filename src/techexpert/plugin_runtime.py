"""Check the shipped stdio launcher without starting TechExpert or provisioning Python."""

import os
from pathlib import Path
import shutil

from .inputs import InputError, json_value
from .processes import CommandStopped, run_bounded


LAUNCHER = 'python3'
LAUNCH_ENV = {'PYTHON_MANAGER_AUTOMATIC_INSTALL': '0'}
MINIMUM = (3, 11)
PROBE = 'import json, sys; print(json.dumps(dict(version=sys.version_info[:3], executable=sys.executable)))'


def check():
    launcher = shutil.which(LAUNCHER)
    details = dict(command=LAUNCHER, launcher=launcher, minimum_python='.'.join(map(str, MINIMUM)),
                   scope='current_process_environment', action='enable_supported_python')
    if launcher is None:
        return dict(details, status='launcher_missing')

    try:
        code, output, _ = run_bounded([launcher, '-I', '-B', '-X', 'utf8', '-c', PROBE],
            env=dict(os.environ, **LAUNCH_ENV), timeout=5, max_bytes=4096)
    except CommandStopped as error:
        return dict(details, status='launcher_failed', reason=error.reason)
    except (InputError, OSError):
        return dict(details, status='launcher_failed', reason='execution_unverified')
    if code:
        return dict(details, status='launcher_failed', reason='nonzero_exit', launcher_exit_code=code)

    try:
        probe = json_value(output.decode('utf-8'), reject_duplicates=True)
        version, executable = probe['version'], probe['executable']
        if (type(version) is not list or len(version) != 3
                or any(type(number) is not int or not 0 <= number <= 999 for number in version)
                or type(executable) is not str or not Path(executable).is_absolute()
                or any(ord(char) < 32 for char in executable)):
            raise InputError('invalid interpreter response')
    except (KeyError, ValueError, TypeError, RecursionError):
        return dict(details, status='launcher_failed', reason='invalid_response')
    details.update(python_version='.'.join(map(str, version)), python_executable=executable)
    if tuple(version[:2]) < MINIMUM:
        return dict(details, status='unsupported_python')
    return dict(details, status='available', action=None)
