"""Confirmed installation into the selected Codex local marketplace profile."""
import os
from pathlib import Path
import shutil
import tomllib
import uuid

from . import input_files, operation_state as fs, updates
from .inputs import InputError, json_value, read_snapshot
from .processes import run_bounded
from .release_packages import PLUGIN, version_number


SUPPORTED_CODEX = 'codex-cli 0.164.0'
_ENV = {'SYSTEMROOT','WINDIR','PATH','PATHEXT','APPDATA','LOCALAPPDATA','USERPROFILE','HOME',
        'USERNAME','COMPUTERNAME','TEMP','TMP','LANG','LC_ALL'}
_FIELDS = {'release_id','expected_selection','observed_cache','observed_registration','profile','maintenance_window','activation_id'}
_CACHE_FIELD = 'observed_python_cache'


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


def _cache_release(state, profile, choices, *, observe_python_cache=False):
    cache = _cache(profile)
    try:
        with os.scandir(cache) as rows:
            paths = []
            for row in rows:
                if paths or not row.is_dir(follow_symlinks=False):
                    raise InputError('Codex cache contains an unverified installation')
                paths.append(fs.safe(Path(row.path)))
    except FileNotFoundError:
        return None, []
    if not paths:
        return None, []
    path = paths[0]
    version_number(path.name)
    for release in dict.fromkeys(item for item in choices if item is not None):
        record = updates._staged(state,release)
        if path.name!=record['metadata']['version']:
            continue
        try:
            bytecode = updates._verify_tree(path,record['files'],installed=True,
                observe_python_cache=observe_python_cache)
        except (OSError,ValueError):
            continue
        return release, bytecode
    raise InputError('Codex cache has local changes or an unverified installation')


def _cache_summary(files):
    if files:
        return dict(file_count=len(files), bytes=sum(file['bytes'] for file in files), sha256=fs.digest(files))
    return None


def _save_python_cache(cache, journal, files, approved):
    manifest = dict(schema_version=1, files=files)
    updates._space(journal, approved['bytes']+len(fs.encode(manifest)))
    backup = fs.private(journal/'python-cache')
    for number, item in enumerate(files, 1):
        source = fs.safe(cache/item['path'])
        if source.lstat().st_nlink!=1:
            raise InputError('installed Python cache link count changed since review')
        identity = dict(bytes=item['bytes'],sha256=item['sha256'])
        data, _ = input_files.read(source,updates.LIMITS['max_file_bytes'],keep=True,expected=identity,
            observed=item['observed'])
        with fs.safe(backup/f'{number:04}.bin').open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    fs.write(backup/'manifest.json',manifest)


def _saved_python_cache(journal, approved):
    if approved is None:
        return None
    backup = journal/'python-cache'
    manifest_path = backup/'manifest.json'
    try:
        manifest = fs.read(manifest_path,1024*1024)
        files = manifest['files']
        if (type(manifest['schema_version']) is not int or manifest['schema_version']!=1
            or type(files) is not list or not 1<=len(files)<=updates.LIMITS['max_files']
            or _cache_summary(files)!=approved):
            raise InputError('retained file list differs from the plan')
        for number, item in enumerate(files, 1):
            input_files.read(fs.safe(backup/f'{number:04}.bin'),updates.LIMITS['max_file_bytes'],
                expected=dict(bytes=item['bytes'],sha256=item['sha256']))
    except (OSError,ValueError,KeyError,TypeError) as exc:
        raise InputError('saved Python cache is incomplete or changed') from exc
    return dict(approved, manifest_path=str(manifest_path))


def plan_install(state, release_id, profile, *, maintenance_window=False):
    state = fs.safe(state)
    profile = _profile(state,profile)
    record = updates._staged(state,release_id)
    current = updates._selection_id(state)
    observed = updates._ensure_safe_point(state,record,require_idle=False)
    cached, bytecode = _cache_release(state,profile,(current,release_id),observe_python_cache=True)
    plan = dict(schema_version=1,kind='codex_install',state=str(state),profile=str(profile),
        release_id=release_id,expected_selection=current,observed_cache=cached,maintenance_window=maintenance_window is True,
        observed_registration=_registered(profile),activation_id=uuid.uuid4().hex)
    if bytecode:
        plan[_CACHE_FIELD] = _cache_summary(bytecode)
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


def _verified_install(state, plan, profile, record, command, journal):
    release_id = plan['release_id']
    root = updates._root(state)
    retained = _saved_python_cache(journal,plan.get(_CACHE_FIELD))
    if (updates._selection_id(state)!=release_id or not _marketplace(command,root) or not _registered(profile)
        or _cache_release(state,profile,(release_id,))[0]!=release_id):
        raise InputError('Codex installation outcome is unresolved; retain the interrupted activation')
    result = dict(status='installed',installation_verified=True,runtime_reload_observed=False,
        installed_root=str(_cache(profile)/record['metadata']['version']),codex_profile=str(profile),
        codex_version=SUPPORTED_CODEX,**updates._presentation(state,record))
    if retained is not None:
        result['retained_python_cache'] = retained
    return result


def install(state, plan, *, expected_sha256):
    fields = _FIELDS | {_CACHE_FIELD} if type(plan) is dict and _CACHE_FIELD in plan else _FIELDS
    updates._plan(state,plan,expected_sha256,'codex_install',fields)
    approved = plan.get(_CACHE_FIELD)
    if _CACHE_FIELD in fields and (type(approved) is not dict or set(approved)!={'file_count','bytes','sha256'}
        or type(approved['file_count']) is not int or type(approved['bytes']) is not int):
        raise InputError('invalid Python cache observation in the update plan')
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
            verified = _verified_install(state,plan,profile,record,command,journal)
            if not (journal/'result.json').exists():
                fs.write(journal/'result.json',verified)
            return dict(verified,replayed=True)

        current = updates._selection_id(state)
        if current!=plan['expected_selection']:
            raise InputError('local marketplace selection changed; review the current installation plan')
        target, bytecode = _cache_release(state,profile,(current,release_id),observe_python_cache=True)
        if target!=plan['observed_cache'] or _cache_summary(bytecode)!=approved:
            raise InputError('Codex installed cache changed since review')
        registered = _registered(profile)
        if registered is not plan['observed_registration']:
            raise InputError('Codex plugin registration changed since review')
        known_marketplace = _marketplace(command,root)
        updates._ensure_safe_point(state,record,require_idle=True)
        fs.private(journal.parent)
        journal.mkdir()
        fs.private(journal)
        fs.write(journal/'plan.json',plan)
        if bytecode:
            installed = _cache(profile)/updates._staged(state,target)['metadata']['version']
            _save_python_cache(installed,journal,bytecode,approved)
            _saved_python_cache(journal,approved)
            if _cache_release(state,profile,(current,release_id),observe_python_cache=True)!=(target,bytecode):
                raise InputError('Codex installed cache changed during preservation')
            if _registered(profile) is not registered:
                raise InputError('Codex plugin registration changed during preservation')
            updates._ensure_safe_point(state,record,require_idle=True)
        manifest = root/updates.MANIFEST
        if current!=release_id:
            fs.private(manifest.parent)
            fs.write(manifest,updates._selection_manifest(release_id))
        if not known_marketplace:
            command('plugin','marketplace','add',root,'--json')
        if target!=release_id or not registered or bytecode:
            reply = command('plugin','add',updates.SELECTOR,'--json')
            expected = _cache(profile)/record['metadata']['version']
            if (type(reply) is not dict or reply.get('pluginId')!=updates.SELECTOR or reply.get('version')!=record['metadata']['version']
                or fs.safe(reply['installedPath'])!=expected):
                raise InputError('Codex install reply does not match the selected package and profile')
        result = _verified_install(state,plan,profile,record,command,journal)
        fs.write(journal/'result.json',result)
        return dict(result,replayed=False)
