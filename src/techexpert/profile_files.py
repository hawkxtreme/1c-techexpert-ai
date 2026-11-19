"""Bounded observations for explicitly selected local files in the setup helper."""
import os
from pathlib import Path
import re
import stat

from . import input_files, native_jr, native_tj
from .inputs import InputError


ACTION = 'profile-files'
OPERATION = 'profile.files'
MAX_REQUEST = 128 * 1024
ENTRY_LIMIT = 128
HEADER_LIMIT = 8
PREFIX_BYTES = 4096
BASE_KINDS = {'file_jr', 'file_tj'}
KINDS = {*BASE_KINDS, 'tj', 'jr', 'source'}


class _ObservationError(ValueError):
    pass


def _text(value, maximum, *, empty=False):
    return (type(value) is str and len(value) <= maximum and (empty or bool(value.strip()))
            and all(ord(character) >= 32 and ord(character) != 127 for character in value))


def credential_address(value):
    return bool(re.search(r'(?i)(?:pwd|password|token|secret|authorization)\s*[=:]', value)
                or re.search(r'://[^/]*@', value))


def normalize(request):
    if type(request) is not dict or set(request) != {'items'} or type(request['items']) is not list or len(request['items']) > 100:
        raise InputError('select up to 100 explicit local paths')
    seen = set()
    items = []
    for item in request['items']:
        if type(item) is not dict or not {'id', 'kind', 'path'} <= item.keys():
            raise InputError('invalid local source selection')
        identifier, kind, path = (item[key] for key in ('id', 'kind', 'path'))
        if not _text(identifier, 80) or identifier in seen or not _text(kind, 16) or kind not in KINDS or not _text(path, 2048):
            raise InputError('invalid local source identity or path')
        if credential_address(path):
            raise InputError('select an address without credentials')
        extras = set(item) - {'id', 'kind', 'path'}
        if kind == 'jr':
            if extras - {'platform_version', 'utc_offset'} or any(not _text(item[key], 64, empty=True) for key in extras):
                raise InputError('invalid local journal settings')
        elif kind == 'source':
            if extras - {'source_kind'} or item.get('source_kind', 'catalog') not in ('catalog', 'git'):
                raise InputError('invalid local source layout')
        elif extras:
            raise InputError('unexpected local source selection fields')
        items.append(dict(item))
        seen.add(identifier)
    return dict(items=items)


def from_bases(bases, *, kind='file_jr'):
    if kind not in BASE_KINDS or type(bases) is not list or len(bases) > 100:
        raise InputError('select file infobases in the setup helper')
    items = []
    for item in bases:
        if (type(item) is not dict or set(item) != {'id', 'mode', 'connection'}
                or item['mode'] not in ('file', 'server', 'unknown') or not _text(item['id'], 80)
                or not _text(item['connection'], 2048, empty=True)):
            raise InputError('invalid file infobase selection')
        if item['mode'] == 'file' and item['connection'].strip():
            path = item['connection'].strip() if kind == 'file_jr' else item['connection']
            items.append(dict(id=item['id'], kind=kind, path=path))
    return normalize(dict(items=items))


def from_profile(profile, *, find=None):
    from .profile_resources import effective_profile
    from .profiles import validate_profile

    current = effective_profile(validate_profile(profile))
    if find:
        return from_bases([{key: row[key] for key in ('id', 'mode', 'connection')} for row in current['bases']], kind=find)
    rows = []
    for source in current['sources']:
        kind, settings = source['type'], source['settings']
        if kind not in ('tj', 'jr', 'source') or settings.get('transport') == 'sftp':
            continue
        item = dict(id=source['id'], kind=kind, path=source['path'])
        if kind == 'jr':
            item.update({key: settings[key] for key in ('platform_version', 'utc_offset') if key in settings})
        elif kind == 'source':
            item['source_kind'] = settings.get('kind', 'catalog')
        rows.append(item)
    return normalize(dict(items=rows))


def _ordinary_path(value):
    if value.startswith(('\\', '//')) or '://' in value or re.match(r'[^/\\]+@[^/\\]+:', value):
        raise _ObservationError('separate_access_required')
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts:
        raise _ObservationError('absolute_path_required')
    if os.name == 'nt':
        import ctypes

        try:
            for part in path.parts[1:]:
                input_files.name_parts(part)
        except InputError as error:
            raise _ObservationError('unsupported_path') from error
        # Resolve the drive class before opening a path on it. This also keeps
        # mapped shares out of the local-only helper.
        if ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(path.anchor)) not in (2, 3, 6):
            raise _ObservationError('separate_access_required')
    return path


def _chain(path):
    try:
        return input_files.chain(path)
    except InputError as error:
        raise _ObservationError('linked_path') from error


def _peek(path):
    ancestry = _chain(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise _ObservationError('unsupported_path')
    signature = input_files.signature(before)
    options = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(path, options), 'rb') as stream:
        if input_files.signature(os.fstat(stream.fileno())) != signature:
            raise _ObservationError('changed_during_check')
        data = stream.read(PREFIX_BYTES)
        if input_files.signature(os.fstat(stream.fileno())) != signature:
            raise _ObservationError('changed_during_check')
    if _chain(path) != ancestry or input_files.signature(path.lstat()) != signature:
        raise _ObservationError('changed_during_check')
    return data


def _entries(directory, limit=ENTRY_LIMIT):
    ancestry = _chain(directory)
    signature = input_files.signature(directory.lstat())
    result = []
    with os.scandir(directory) as entries:
        for entry in entries:
            if len(result) == limit:
                break
            result.append(Path(entry.path))
        else:
            entry = None
    if _chain(directory) != ancestry or input_files.signature(directory.lstat()) != signature:
        raise _ObservationError('changed_during_check')
    return sorted(result, key=lambda path: (path.name.casefold(), path.name)), entry is not None


def _file_journal(base):
    if base.name.casefold() == '1cv8.1cd':
        _chain(base)
        if not stat.S_ISREG(base.lstat().st_mode):
            raise _ObservationError('infobase_file_not_found')
        base = base.parent
    items, limited = _entries(base)
    if limited:
        raise _ObservationError('scan_limit')
    files = [path for path in items if path.name.casefold() == '1cv8.1cd']
    folders = [path for path in items if path.name.casefold() == '1cv8log']
    if len(files) > 1 or len(folders) > 1:
        raise _ObservationError('journal_group_ambiguous')
    if not files:
        raise _ObservationError('infobase_file_not_found')
    _chain(files[0])
    if not stat.S_ISREG(files[0].lstat().st_mode):
        raise _ObservationError('infobase_file_not_found')
    if not folders:
        raise _ObservationError('journal_location_unknown')
    _chain(folders[0])
    if not stat.S_ISDIR(folders[0].lstat().st_mode):
        raise _ObservationError('journal_location_unknown')
    return folders[0]


def _read_header(row, path):
    result = _peek(path)
    row['headers_checked'] += 1
    return result


def _jr(path, directory, row, item):
    if directory:
        children, limited = _entries(path)
        if limited:
            raise _ObservationError('scan_limit')
        members = [child for child in children if child.name.casefold() == '1cv8.lgf' or child.suffix.casefold() in ('.lgp', '.lgd')]
    else:
        members = [path] if path.suffix.casefold() == '.lgd' else []
    row['files_observed'] = len(members)
    if not members:
        return 'journal_files_missing'
    if len({member.name.casefold() for member in members}) != len(members):
        return 'journal_group_ambiguous'
    if any(member.suffix.casefold() == '.lgd' for member in members):
        if len(members) != 1:
            return 'journal_group_ambiguous'
        journal = members[0]
        data = _read_header(row, journal)
        if not data.startswith(native_jr.lgd.SQLITE_MAGIC) or len(data) < 100:
            return 'header_unrecognized'
        row.update(format='jr_sqlite', snapshot_confirmation_required=True,
                   time_status='native_utc' if item.get('utc_offset') in (None, '', '+00:00') else 'offset_conflicts_with_utc')
        try:
            native_jr.reject_sidecars(journal)
        except InputError:
            return 'snapshot_required'
        if data[18:20] != b'\x01\x01':
            return 'snapshot_required'
        if item['kind'] == 'file_jr':
            row['candidate_path'] = str(journal)
        return 'header_seen'
    dictionary = next((child for child in members if child.name.casefold() == '1cv8.lgf'), None)
    parts = [child for child in members if child.suffix.casefold() == '.lgp']
    if dictionary is None or not parts:
        return 'journal_group_incomplete'
    matches = [native_jr.HEADER.match(_read_header(row, child)) for child in (dictionary, *parts[:HEADER_LIMIT - 1])]
    if any(match is None for match in matches):
        return 'header_unrecognized'
    if len({match[1].lower() for match in matches}) != 1:
        return 'journal_group_ambiguous'
    version = item.get('platform_version')
    offset = item.get('utc_offset')
    time_status = ('offset_unknown' if not offset else 'declared_offset'
                   if re.fullmatch(r'[+-](?:[01][0-9]|2[0-3]):[0-5][0-9]', offset) and offset != '-00:00' else 'invalid_offset')
    row.update(format='jr_sequential', sampling_limited=len(members) > HEADER_LIMIT,
        version_status=('unknown' if not version else 'declared_supported' if version == native_jr.PLATFORM else 'declared_unsupported'),
        time_status=time_status)
    if item['kind'] == 'file_jr':
        row['candidate_path'] = str(path)
    return 'select_journal_parts' if len(parts) > 31 else 'header_seen'


def _samples(root, suffixes):
    pending = [(root, 0)]
    chosen = []
    visited = 0
    limited = False
    while pending and visited < ENTRY_LIMIT and len(chosen) < HEADER_LIMIT:
        directory, depth = pending.pop(0)
        children, capped = _entries(directory, ENTRY_LIMIT - visited)
        limited |= capped
        for child in children:
            visited += 1
            if len(chosen) == HEADER_LIMIT:
                limited = True
                break
            if child.name == '.git':
                continue
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                limited = True
                continue
            if stat.S_ISREG(info.st_mode) and child.suffix.casefold() in suffixes:
                chosen.append(child)
            elif stat.S_ISDIR(info.st_mode):
                if depth < 2:
                    pending.append((child, depth + 1))
                else:
                    limited = True
    return chosen, limited or bool(pending)


def _json_header_seen(raw):
    first, newline, _ = raw.partition(b'\n')
    if not newline:
        return False
    try:
        text = first.decode('utf-8-sig')
    except UnicodeDecodeError:
        return False
    return text.lstrip().startswith('{') and native_tj.json_record_seen(text)


def _tj(path, directory, row):
    files, limited = _samples(path, {'.log', '.txt'}) if directory else ([path], False)
    row.update(files_observed=len(files), sampling_limited=limited)
    seen = set()
    recognized = 0
    for member in files:
        raw = _read_header(row, member)
        prefix = raw.decode('utf-8-sig', errors='replace')
        line = next((value for value in prefix.splitlines() if value.strip()), '')
        matches = {name for name, header in native_tj.HEADERS.items() if header.match(line)}
        if not matches and _json_header_seen(raw):
            matches.add(native_tj.JSON_ISO)
        if matches:
            seen.update(matches)
            recognized += 1
    row['recognized_headers'] = recognized
    if len(seen) == 1:
        row['format'] = 'tj_' + seen.pop()
        return 'header_seen' if recognized == len(files) else 'partial_headers'
    if seen:
        return 'mixed_tj_headers'
    return 'header_unrecognized' if files else 'scan_limit' if limited else 'no_supported_files_seen'


def _source(path, directory, row, source_kind):
    if not directory:
        return 'directory_required'
    if source_kind == 'git':
        for marker in (path / '.git', path / 'HEAD'):
            try:
                _chain(marker)
            except FileNotFoundError:
                continue
            row['format'] = 'git_layout'
            return 'repository_marker_seen'
        return 'no_supported_files_seen'
    files, limited = _samples(path, {'.xml', '.bsl'})
    row.update(files_observed=len(files), sampling_limited=limited)
    if files:
        _read_header(row, files[0])
        row['format'] = 'xml_bsl_files'
        return 'source_files_seen'
    return 'scan_limit' if limited else 'no_supported_files_seen'


def file_base_path(value):
    if re.match(r'(?i)^file\s*=', value):
        from .discovery import describe_connection

        try:
            connection = describe_connection(value)
        except InputError as error:
            raise _ObservationError('invalid_file_connection') from error
        if connection['mode'] != 'file':
            raise _ObservationError('invalid_file_connection')
        value = connection['connection']
    return _ordinary_path(value)


def _file_tj(item, row, *, stop):
    from . import logcfg_discovery, logcfg_observation, logcfg_xml

    info, snapshot = logcfg_discovery.observe_file(item['path'], stop=stop)
    if snapshot is None:
        return info['status']
    try:
        locations = logcfg_observation.declared_locations(snapshot['raw'])
    except logcfg_xml.XmlIssue:
        return 'invalid_or_unsupported_xml'
    row.update(locations, platform_version=info['platform_version'], version_status='observed_client')
    return 'logcfg_locations_found' if row['candidate_paths'] else 'logcfg_location_unknown'


def _observe(item, row, *, stop):
    kind = item['kind']
    if kind == 'file_tj':
        return _file_tj(item, row, stop=stop)
    if kind == 'file_jr':
        path = _file_journal(file_base_path(item['path']))
    else:
        path = _ordinary_path(item['path'])
    _chain(path)
    mode = path.lstat().st_mode
    directory = stat.S_ISDIR(mode)
    if not directory and not stat.S_ISREG(mode):
        return 'unsupported_path'
    if kind in ('tj', 'jr') and not directory and path.suffix.casefold() == '.zip':
        if _read_header(row, path)[:4] in (b'PK\x03\x04', b'PK\x05\x06'):
            row['format'] = 'zip'
            return 'archive_selection_required'
        return 'header_unrecognized'
    if kind in ('file_jr', 'jr'):
        return _jr(path, directory, row, item)
    if kind == 'tj':
        return _tj(path, directory, row)
    return _source(path, directory, row, item.get('source_kind', 'catalog'))


def inspect(request, *, stop=lambda: None):
    rows = []
    for item in normalize(request)['items']:
        if reason := stop():
            raise TimeoutError(reason)
        row = dict(id=item['id'], kind=item['kind'], format=None, candidate_path=None, version_status='unknown',
                   files_observed=0, headers_checked=0, sampling_limited=False, coverage_verified=False)
        try:
            row['status'] = _observe(item, row, stop=stop)
        except _ObservationError as error:
            row['status'] = str(error)
        except FileNotFoundError:
            row['status'] = 'not_found'
        except PermissionError as error:
            row['status'] = 'file_busy' if getattr(error, 'winerror', None) == 32 else 'access_denied'
        except (OSError, ValueError):
            row['status'] = 'check_unavailable'
        rows.append(row)
    scope = 'local_configuration_and_file_observation' if any(row['kind'] == 'file_tj' for row in rows) else 'local_metadata_and_sample_headers'
    return dict(items=rows, scope=scope, max_header_bytes=PREFIX_BYTES,
                collection_started=False, database_opened=False)
