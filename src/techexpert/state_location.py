"""Select the per-user default for new sessions without changing saved investigations."""

from pathlib import Path
import stat

from . import operation_state as fs
from .inputs import InputError
from .storage import default_state_dir


MAX_SELECTION_BYTES = 8192


class StateLocationError(InputError):
    def __init__(self, reason, message):
        super().__init__(message)
        self.reason = reason

    def response(self):
        return dict(status='invalid_input', stop_reason=self.reason, message=str(self))


def _settings(default):
    return default.with_name('1c-techexpert-ai-settings') / 'state-location.json'


def _absolute(directory):
    path = Path(directory)
    text = str(path)
    text.encode('utf-8')
    if (not path.is_absolute() or '..' in path.parts or text.startswith('\\\\')
            or any(ord(char) < 32 for char in text)):
        raise InputError('Select an absolute local directory for service state.')
    return path


def _load(default):
    try:
        path = fs.safe(_settings(default))
        try:
            info = path.lstat()
        except FileNotFoundError:
            return dict(schema_version=1, revision=0, state_dir=str(default), source='platform_default')
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise InputError('invalid state location file')
        saved = fs.read(path, MAX_SELECTION_BYTES)
        if (type(saved) is not dict or set(saved) != {'schema_version', 'revision', 'state_dir'}
                or type(saved['schema_version']) is not int or saved['schema_version'] != 1
                or type(saved['revision']) is not int or saved['revision'] < 1
                or type(saved['state_dir']) is not str):
            raise InputError('invalid state location properties')
        directory = _absolute(saved['state_dir'])
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise StateLocationError('state_location_invalid',
                                 'Check the saved service state selection. Use --state-dir for the intended investigation.') from exc
    return dict(saved, state_dir=str(directory), source='selected')


def load():
    return _load(default_state_dir().absolute())


def save(directory, *, expected_revision):
    if type(expected_revision) is not int or expected_revision < 0:
        raise InputError('Read state-location and pass its revision with --expected-revision.')
    default = default_state_dir().absolute()

    def require_current():
        if _load(default)['revision'] != expected_revision:
            raise StateLocationError('state_location_changed',
                                     'Service state selection changed. Read state-location before saving.')

    # Check the displayed selection before touching its settings folder.
    require_current()
    destination = fs.safe(_absolute(directory))
    fs.require_free_space(destination)
    value = dict(schema_version=1, revision=expected_revision + 1, state_dir=str(destination))
    if len(fs.encode(value)) > MAX_SELECTION_BYTES:
        raise InputError('The selected service state path exceeds the settings size limit.')
    path = _settings(default)
    folder = fs.private(path.parent)
    with fs.writer(folder):
        require_current()
        fs.write(path, value)
    return dict(value, source='selected')
