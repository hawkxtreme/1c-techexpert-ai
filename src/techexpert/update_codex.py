"""Confirmed installation into the selected Codex local marketplace profile."""
import os
from pathlib import Path
import shutil
import tomllib
import uuid

from . import operation_state as fs, updates
from .inputs import InputError, json_value, read_snapshot
from .processes import run_bounded
from .release_packages import PLUGIN, version_number


SUPPORTED_CODEX = 'codex-cli 0.164.0'
_ENV = {'SYSTEMROOT','WINDIR','PATH','PATHEXT','APPDATA','LOCALAPPDATA','USERPROFILE','HOME',
        'USERNAME','COMPUTERNAME','TEMP','TMP','LANG','LC_ALL'}
_FIELDS = {'release_id','expected_selection','observed_cache','observed_registration','profile','maintenance_window','activation_id'}


def _profile(state, path):
    profile = fs.safe(path)
    if not profile.is_dir():
        raise InputError('choose an existing local Codex profile directory')
    private_updates = updates._root(state)
    if profile.is_relative_to(private_updates) or private_updates.is_relative_to(profile):
        raise InputError('choose a Codex profile separate from the release store')
    return profile


def _cache(profile):
    return fs.safe(profile/'plugins/cache'/updates.MARKETPLACE/PLUGIN)


def _registered(profile):
    try:
        config = read_snapshot(fs.safe(profile/'config.toml'),1024*1024,share_delete=True)
    except FileNotFoundError:
        return False
    try:
        plugin = tomllib.loads(config.decode('utf-8')).get('plugins',{}).get(updates.SELECTOR,{})
    except (ValueError,AttributeError) as exc:
        raise InputError('local Codex registration is unverified') from exc
    return type(plugin) is dict and plugin.get('enabled') is True


def _cache_release(state, profile, choices):
    cache = _cache(profile)
    try:
        with os.scandir(cache) as rows:
            paths = []
            for row in rows:
                if paths or not row.is_dir(follow_symlinks=False):
                    raise InputError('Codex cache contains an unverified installation')
                paths.append(fs.safe(Path(row.path)))
    except FileNotFoundError:
        return None
    if not paths:
        return None
    path = paths[0]
    version_number(path.name)
    for release in dict.fromkeys(item for item in choices if item is not None):
        record = updates._staged(state,release)
        if path.name!=record['metadata']['version']:
            continue
        try:
            updates._verify_tree(path,record['files'],installed=True)
        except (OSError,ValueError):
            continue
        return release
    raise InputError('Codex cache has local changes or an unverified installation')


def plan_install(state, release_id, profile, *, maintenance_window=False):
    state = fs.safe(state)
    profile = _profile(state,profile)
    record = updates._staged(state,release_id)
    current = updates._selection_id(state)
    observed = updates._ensure_safe_point(state,record,require_idle=False)
    cached = _cache_release(state,profile,(current,release_id))
    plan = dict(schema_version=1,kind='codex_install',state=str(state),profile=str(profile),
        release_id=release_id,expected_selection=current,observed_cache=cached,maintenance_window=maintenance_window is True,
        observed_registration=_registered(profile),activation_id=uuid.uuid4().hex)
    status = 'needs_safe_point' if observed['activity']!='idle_observed' or maintenance_window is not True else 'installation_plan'
    return dict(status=status,plan=plan,plan_sha256=fs.digest(plan),activity=observed,
        codex_profile=str(profile),current_selection=current,installed_release=cached,
        **updates._presentation(state,record))


def _command(profile):
    executable = shutil.which('codex')
    if not executable:
        raise InputError('Codex CLI is unavailable')
    executable = str(Path(executable).resolve(strict=True))
    env = {key:value for key,value in os.environ.items() if key.upper() in _ENV}
    env.update(CODEX_HOME=str(profile),PYTHONDONTWRITEBYTECODE='1')

    def call(*args, plain=False):
        code, data, _ = run_bounded([executable,'--no-daemon',*map(str,args)],env=env,
            max_bytes=256*1024,timeout=25,cwd=profile)
        if code:
            raise InputError('Codex command did not complete: '+' '.join(args[:3]))
        answer = data.decode('utf-8')
        return answer.strip() if plain else json_value(answer,reject_duplicates=True)

    if call('--version',plain=True)!=SUPPORTED_CODEX:
        raise InputError('this local activation profile requires '+SUPPORTED_CODEX)
    return call


def _marketplace(command, root):
    listing = command('plugin','marketplace','list','--json')
    marketplaces = listing.get('marketplaces') if type(listing) is dict else None
    if type(marketplaces) is not list or len(marketplaces)>128 or any(type(item) is not dict for item in marketplaces):
        raise InputError('Codex marketplace listing is unverified')
    names = [item for item in marketplaces if item.get('name')==updates.MARKETPLACE]
    if len(names)>1 or names and fs.safe(names[0]['root'])!=root:
        raise InputError('selected profile uses a different managed marketplace root')
    if any(item.get('name')=='1c-techexpert-local' for item in marketplaces):
        raise InputError('this Codex profile already uses the unmanaged TechExpert marketplace')
    return bool(names)


def _verified_install(state, plan, profile, record, command):
    release_id = plan['release_id']
    root = updates._root(state)
    if (updates._selection_id(state)!=release_id or not _marketplace(command,root) or not _registered(profile)
        or _cache_release(state,profile,(release_id,))!=release_id):
        raise InputError('Codex installation outcome is unresolved; retain the interrupted activation')
    return dict(status='installed',installation_verified=True,runtime_reload_observed=False,
        installed_root=str(_cache(profile)/record['metadata']['version']),codex_profile=str(profile),
        codex_version=SUPPORTED_CODEX,**updates._presentation(state,record))


def install(state, plan, *, expected_sha256):
    updates._plan(state,plan,expected_sha256,'codex_install',_FIELDS)
    if plan['maintenance_window'] is not True:
        raise InputError('observe the installation safe point and confirm the selected Codex profile')
    profile = _profile(state,plan['profile'])
    release_id = updates._hash(plan['release_id'])
    root = updates._root(state)
    journal = fs.safe(root/'activations'/expected_sha256)
    record = updates._staged(state,release_id)
    with fs.writer(root):
        updates._space(profile)
        command = _command(profile)
        if journal.exists():
            saved = fs.read(journal/'plan.json',65536)
            if saved!=plan:
                raise InputError('activation has an incomplete or mismatched plan')
            verified = _verified_install(state,plan,profile,record,command)
            if not (journal/'result.json').exists():
                fs.write(journal/'result.json',verified)
            return dict(verified,replayed=True)

        current = updates._selection_id(state)
        if current!=plan['expected_selection']:
            raise InputError('local marketplace selection changed; review the current installation plan')
        target = _cache_release(state,profile,(current,release_id))
        if target!=plan['observed_cache']:
            raise InputError('Codex installed cache changed since review')
        registered = _registered(profile)
        if registered is not plan['observed_registration']:
            raise InputError('Codex plugin registration changed since review')
        known_marketplace = _marketplace(command,root)
        updates._ensure_safe_point(state,record,require_idle=True)
        fs.private(journal.parent)
        journal.mkdir()
        fs.write(journal/'plan.json',plan)
        manifest = root/updates.MANIFEST
        if current!=release_id:
            fs.private(manifest.parent)
            fs.write(manifest,updates._selection_manifest(release_id))
        if not known_marketplace:
            command('plugin','marketplace','add',root,'--json')
        if target!=release_id or not registered:
            reply = command('plugin','add',updates.SELECTOR,'--json')
            expected = _cache(profile)/record['metadata']['version']
            if (type(reply) is not dict or reply.get('pluginId')!=updates.SELECTOR or reply.get('version')!=record['metadata']['version']
                or fs.safe(reply['installedPath'])!=expected):
                raise InputError('Codex install reply does not match the selected package and profile')
        result = _verified_install(state,plan,profile,record,command)
        fs.write(journal/'result.json',result)
        return dict(result,replayed=False)
