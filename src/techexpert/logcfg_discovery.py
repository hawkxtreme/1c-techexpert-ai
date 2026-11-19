"""Read the first observable configuration for an explicitly selected Windows client."""

import os
from pathlib import Path

from . import input_files, logcfg_xml, native_tj, profile_files, windows_native
from . import operation_state as fs
from .inputs import InputError


BASIS = 'windows_client_search_order'
TIERS = ('version', 'user', 'shared', 'all_users')
CLIENTS = {'1cv8.exe': 'thick_client', '1cv8c.exe': 'thin_client'}
MAX_LOCATOR_BYTES = 64 * 1024


class DiscoveryError(InputError):
    pass


def _leaf(folder, name):
    path = profile_files._ordinary_path(str(folder / name))
    profile_files._chain(path)
    return path, input_files.observe(path)


def _read(path, observed, maximum):
    raw, checked = input_files.read(path, maximum, keep=True, observed=observed)
    input_files.read(path, maximum, expected=checked, observed=observed)
    return raw, checked


def _shared_folder(image, local_app_data):
    try:
        path, observed = _leaf(image.parent / 'conf', 'conf.cfg')
    except FileNotFoundError:
        checked = None
        values = []
    else:
        try:
            raw, checked = _read(path, observed, MAX_LOCATOR_BYTES)
        except FileNotFoundError as error:
            raise DiscoveryError('shared_location_unresolved') from error
        values = []
        for line in raw.decode('utf-8-sig').splitlines():
            key, separator, value = line.partition('=')
            if key.strip().casefold() == 'conflocation':
                values.append(value.strip() if separator else '')
    if values:
        if len(values) != 1 or not values[0] or '%' in values[0] or '$' in values[0]:
            raise DiscoveryError('shared_location_unresolved')
        try:
            return profile_files._ordinary_path(values[0]), checked
        except profile_files._ObservationError as error:
            raise DiscoveryError('shared_location_unresolved') from error
    installation = image.parent.parent.parent
    computer_roots = [Path(root) / '1cv8' for name in ('ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432')
                      if (root := os.environ.get(name))]
    user_roots = ([local_app_data / 'Programs' / name for name in ('1cv8', '1cv8_x86', '1cv8_x64')]
                  if local_app_data else [])
    if image.parent.parent.name == native_tj.PLATFORM_VERSION and installation in computer_roots + user_roots:
        return installation / 'conf', checked
    raise DiscoveryError('shared_location_unresolved')


def find(image, local_app_data, all_users):
    """Inspect four fixed leaf positions, resolving ConfLocation only if reached."""
    checked = []
    folders = dict(version=image.parent / 'conf',
                   user=local_app_data / '1C' / '1cv8' / 'conf' if local_app_data else None,
                   all_users=all_users / '1C' / '1cv8' / 'conf' if all_users else None)
    locator = None
    for tier in TIERS:
        try:
            if tier == 'shared':
                folder, locator = _shared_folder(image, local_app_data)
            else:
                folder = folders[tier]
            if folder is None:
                raise DiscoveryError('account_paths_unavailable')
            file, observed = _leaf(folder, 'logcfg.xml')
        except FileNotFoundError:
            checked.append(dict(tier=tier, status='not_found'))
            continue
        except PermissionError:
            status = 'access_denied'
        except DiscoveryError as error:
            status = str(error)
        except (OSError, ValueError):
            status = 'configuration_path_unavailable'
        else:
            checked.append(dict(tier=tier, status='found'))
            return dict(status='found', tier=tier, file=file, observation=observed, checked=checked, locator=locator)
        checked.append(dict(tier=tier, status=status))
        return dict(status=status, checked=checked)
    return dict(status='config_file_not_found', checked=checked)


def _client(pid):
    if os.name != 'nt':
        raise DiscoveryError('process_platform_unsupported')
    identity = fs.process_identity(pid)
    if identity['state'] == 'not_running':
        raise DiscoveryError('process_not_running')
    if identity['state'] != 'running' or not identity['lifetime']:
        raise DiscoveryError('process_identity_unavailable')
    image, same_account = windows_native.process_context(pid)
    role = CLIENTS.get(image.name.casefold())
    if role is None or image.parent.name.casefold() != 'bin':
        raise DiscoveryError('process_not_1c_client')
    if not same_account:
        raise DiscoveryError('process_account_differs')
    path = profile_files._ordinary_path(str(image))
    profile_files._chain(path)
    before = input_files.observe(path)
    version = windows_native.file_version(path)
    if input_files.observe(path) != before or fs.process_identity(pid) != identity:
        raise DiscoveryError('process_changed')
    if version != native_tj.PLATFORM_VERSION:
        raise DiscoveryError('process_version_unsupported')
    return dict(role=role, platform_version=version, image=str(path), process=identity, image_observation=before)


def observe(pid, *, stop):
    """Bind the copy to two observations of the client and the lookup."""
    info = dict(location_basis=BASIS, checked_locations=[])
    if stop():
        raise InputError('configuration inspection stopped')
    try:
        client = _client(pid)
    except DiscoveryError as error:
        return dict(info, status=str(error)), None
    except (OSError, ValueError):
        return dict(info, status='process_metadata_unavailable'), None
    info.update(platform_version=client['platform_version'], os='windows', process_role=client['role'],
                account_basis='same_current_token_user')
    home = os.environ.get('LOCALAPPDATA')
    shared = os.environ.get('ALLUSERSPROFILE')
    info['account_folder_basis'] = 'local_agent_environment'
    roots = (Path(home) if home else None, Path(shared) if shared else None)
    image = Path(client['image'])
    found = find(image, *roots)
    info['checked_locations'] = found['checked']
    if found['status'] != 'found':
        return dict(info, status=found['status']), None
    info['selected_tier'] = found['tier']
    if found['observation']['bytes'] > logcfg_xml.MAX_BYTES:
        return dict(info, status='xml_byte_limit'), None
    if stop():
        raise InputError('configuration inspection stopped')
    try:
        raw, _ = _read(found['file'], found['observation'], logcfg_xml.MAX_BYTES)
    except PermissionError:
        return dict(info, status='access_denied'), None
    except (OSError, ValueError):
        return dict(info, status='config_file_unavailable'), None
    try:
        stable = find(image, *roots) == found and _client(pid) == client
    except (OSError, ValueError):
        stable = False
    if not stable:
        return dict(info, status='configuration_search_changed'), None
    return dict(info, status='found'), dict(path=found['file'], raw=raw, process=client, locator=found['locator'])
