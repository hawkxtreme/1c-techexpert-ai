"""Select bounded local journals from the exact saved investigation profile."""

from datetime import datetime
from pathlib import Path
import stat

from . import context_policy, input_files, native_jr, native_tj, profile_files, storage, tj_reference
from . import operation_state as fs
from .inputs import InputError, MAX_FILE_BYTES, MAX_TOTAL_BYTES
from .investigation_progress import _occurrence_window
from .profile_resources import effective_profile
from .source_coverage import validate_request


PREVIEW = 'source.check'
CAPTURES = {'case.analyze': 'tj', 'jr.import': 'jr'}
OPERATIONS = {PREVIEW, *CAPTURES}
REASONS = ('journal_preview_changed', 'journal_preview_incomplete', 'journal_coverage_limited')
MAX_MEMBERS = 32


class PreviewChanged(InputError):
    pass


def schema(cap, operation):
    preview = operation == PREVIEW
    fields = dict(profile_journal=cap.obj(dict(source=cap.string(4, pattern='j[1-9][0-9]{0,2}'),
                                              window=cap.WINDOW), () if preview else ('source',)))
    if not preview:
        fields['preview_sha256'] = cap.SHA256
    return cap.obj(fields, tuple(fields))


def normalize(cap, operation, arguments):
    result = cap.validate(arguments, schema(cap, operation))
    selected = result['profile_journal']
    if 'window' in selected:
        if 'source' not in selected:
            raise InputError('select a journal before giving a collection window')
        selected['window'] = validate_request(window=selected['window'])['window']
    return result


def _window(doc, explicit):
    if explicit is not None:
        return explicit, 'explicit_window'
    if doc.get('occurrence') is not None:
        return _occurrence_window(doc['occurrence']), 'saved_occurrence'
    if doc.get('workflow_stage') == 'awaiting_occurrence':
        return None, None
    episode = doc['episode']
    try:
        if any('T' not in episode[key] or episode[key].endswith('-00:00') for key in ('start', 'end')):
            return None, None
        bounds = {key: datetime.fromisoformat(episode[key]) for key in ('start', 'end')}
        declared = episode.get('utc_offset')
        for key, value in bounds.items():
            # Keep any explicit offset in the timestamp and require agreement
            # when the saved episode also provides a separate offset.
            if value.utcoffset() is None:
                bounds[key] = value.replace(tzinfo=native_tj._offset(declared))
            elif declared and value.utcoffset() != native_tj._offset(declared).utcoffset(None):
                return None, None
        return validate_request(window={key: value.isoformat() for key, value in bounds.items()})['window'], 'saved_episode'
    except (KeyError, TypeError, ValueError, OverflowError):
        return None, None


def _configuration_status(source):
    settings = source['settings']
    if settings.get('transport', 'local') != 'local':
        return 'separate_access_required'
    if not source['path']:
        return 'path_required'
    if not settings.get('platform_version'):
        return 'version_required'
    if settings['platform_version'] != native_tj.PLATFORM_VERSION:
        return 'version_unsupported'
    try:
        native_tj._offset(settings.get('utc_offset'))
    except ValueError:
        return 'offset_required'
    if source['type'] == 'tj' and settings.get('timestamp_format') not in (None, '', 'iso'):
        return 'timestamp_profile_unsupported'
    return 'configured'


def _files(root, kind, *, directory):
    if not directory:
        if kind == 'tj' and root.suffix.casefold() in ('.log', '.txt'):
            return [root]
        raise InputError('journal_layout_unsupported')
    chosen = []
    visited = 0
    pending = [(root, 0)]
    while pending:
        folder, depth = pending.pop()
        children, capped = profile_files._entries(folder, input_files.MAX_ENTRIES - visited)
        if capped:
            raise InputError('journal_scan_limit')
        visited += len(children)
        for path in children:
            name = path.name.casefold()
            relevant = (path.suffix.casefold() == '.log' if kind == 'tj' else
                        name == '1cv8.lgf' or path.suffix.casefold() in ('.lgp', '.lgd'))
            info = path.lstat()
            linked = stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400
            if relevant and not stat.S_ISDIR(info.st_mode):
                input_files.name_parts(path.name)
                if linked or not stat.S_ISREG(info.st_mode):
                    raise InputError('linked_or_special_journal')
                chosen.append(path)
                if len(chosen) > MAX_MEMBERS:
                    raise InputError('journal_scan_limit')
            elif kind == 'tj':
                if linked:
                    raise InputError('linked_or_special_journal')
                if stat.S_ISDIR(info.st_mode):
                    if depth == 2:
                        raise InputError('journal_scan_limit')
                    pending.append((path, depth + 1))
    return sorted(chosen, key=lambda p: (p.name.casefold() != '1cv8.lgf', str(p)))


INVENTORY_STATES = frozenset(('journal_layout_unsupported', 'journal_scan_limit', 'journal_inventory_changed',
                              'linked_or_special_journal', 'no_journal_files', 'journal_byte_limit'))


def _jr_inventory(files):
    if native_jr._profile([file.name for file in files]) != native_jr.PROFILE:
        raise InputError('journal_layout_unsupported')
    items = [dict(path=str(path), observation=input_files.observe(path)) for path in files]
    count = sum(item['observation']['bytes'] for item in items)
    identities = {(item['observation']['device'], item['observation']['inode']) for item in items}
    if len(identities) != len(items) or len({input_files.name_key(file.name) for file in files}) != len(files):
        raise InputError('journal_layout_unsupported')
    if count > MAX_TOTAL_BYTES or any(item['observation']['bytes'] > MAX_FILE_BYTES for item in items):
        raise InputError('journal_byte_limit')
    return items, count


def _tj_review(root, files, selection, settings, window, state, manifest_path):
    retained = min(MAX_FILE_BYTES, MAX_TOTAL_BYTES // len(files))
    nested = any(path != root and path.parent != root for path in files)
    placement = settings.get('placement') or ('folders' if nested else 'plain')
    specs = [dict(path=str(path), format=native_tj.FORMAT, platform_version=settings['platform_version'],
                  encoding='utf-8', timestamp_format='iso', placement=placement, utc_offset=settings['utc_offset'],
                  external_window=dict(window, max_retained_bytes=retained)) for path in files]
    manifest = dict(schema=2, origin='provided', sources=specs, incident_window=window)
    for spec in specs:
        native_tj.validate_profile(spec, spec['path'])
    raw = fs.encode(manifest)
    review = tj_reference.build_review(manifest_path, raw, manifest, state)
    # The generated manifest resides in a different private worker directory on
    # each attempt. File identities, declared parser settings and bytes remain bound.
    selection['tj'] = {key: value for key, value in review.items() if key != 'manifest_path'}
    return raw, review


def _plan(state, output, binding, source, public, window):
    kind = source['type']
    root = profile_files._ordinary_path(source['path'])
    profile_files._chain(root)
    mode = root.lstat().st_mode
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        raise InputError('journal_layout_unsupported')
    files = _files(root, kind, directory=stat.S_ISDIR(mode))
    if not files:
        raise InputError('no_journal_files')
    plan = dict(binding=binding, source=public['source'], kind=kind, window=window,
                window_basis=public['window_basis'], root=str(root))
    manifest_path = output / 'profile-journal-manifest.json'
    raw = review = None
    if kind == 'tj':
        if sum(file.lstat().st_size for file in files) > native_tj.MAX_REFERENCE_SCAN_BYTES:
            raise InputError('journal_byte_limit')
        raw, review = _tj_review(root, files, plan, source['settings'], window, state, manifest_path)
        public.update(capture_scope='recorded_time_window', source_bytes=review['external_bytes'],
                      expected_read_bytes=review['expected_read_bytes'], max_retained_bytes=review['max_retained_bytes'])
    else:
        plan['jr'], count = _jr_inventory(files)
        public.update(capture_scope='selected_jr_group', source_bytes=count,
                      expected_read_bytes=2 * count, max_retained_bytes=count)
    public.update(status='ready', file_count=len(files), preview_sha256=fs.digest(plan))
    return plan, manifest_path, raw, review


def _capture_jr(output, plan, settings, stop):
    sources = []
    for item in plan['jr']:
        if stop():
            raise InputError('journal capture stopped')
        path = Path(item['path'])
        observed = item['observation']
        data, checked = input_files.read(path, MAX_FILE_BYTES, keep=True, observed=observed)
        input_files.read(path, MAX_FILE_BYTES, expected=checked, observed=observed)
        sources.append((path.name, data))
    root = Path(plan['root'])
    current, _ = _jr_inventory(_files(root, 'jr', directory=True))
    if current != plan['jr']:
        raise PreviewChanged('journal group changed during capture')
    request = dict(path=plan['root'], platform_version=settings['platform_version'],
                   utc_offset=settings['utc_offset'], consistency='unknown')
    result = native_jr.parse_snapshot(sources, utc_offset=request['utc_offset'])
    return native_jr._save_snapshot(output, request, sources, result)


def execute(operation, args, state, output, binding, *, stop):
    doc = context_policy.selected_investigation(state, binding['investigation_id'], binding['expected_revision'])
    if fs.digest(doc) != binding['report_sha256'] or doc['profile_sha256'] != binding['profile_sha256']:
        raise InputError('journal profile binding changed')
    profile = effective_profile(doc['profile_snapshot']) if doc['profile_snapshot'] else {'sources': [], 'bases': []}
    journals = {f'j{number}': source for number, source in enumerate(
        (source for source in profile['sources'] if source['type'] in ('tj', 'jr')), 1)}
    selection = args['profile_journal']
    ref = selection.get('source')
    if ref is None:
        bases = {base['id']: f'b{number}' for number, base in enumerate(profile['bases'], 1)}
        return dict(journal_sources=[dict(source=key, kind=source['type'], status=_configuration_status(source),
                                         bases=[bases[base] for base in source['base_ids']])
                                     for key, source in journals.items()]), []
    source = journals.get(ref)
    status = _configuration_status(source) if source else 'source_not_configured'
    window, basis = _window(doc, selection.get('window'))
    if status == 'configured' and window is None:
        status = 'window_required'
    public = dict(source=ref, kind=source['type'] if source else None, status=status, window=window,
                  window_basis=basis, source_bytes_read=False)
    if status == 'configured':
        try:
            plan, path, raw, review = _plan(state, output, binding, source, public, window)
        except profile_files._ObservationError as error:
            public['status'] = {'separate_access_required': 'separate_access_required',
                                'absolute_path_required': 'absolute_path_required', 'linked_path': 'linked_or_special_journal',
                                'changed_during_check': 'journal_inventory_changed'}.get(str(error), 'journal_layout_unsupported')
        except (FileNotFoundError, PermissionError) as error:
            public['status'] = 'not_found' if isinstance(error, FileNotFoundError) else 'access_denied'
        except (OSError, ValueError) as error:
            reason = str(error)
            public['status'] = reason if reason in INVENTORY_STATES else 'journal_layout_unsupported'
    if operation == PREVIEW:
        return dict(journal_preview=public), []
    if (public['status'] != 'ready' or args['preview_sha256'] != public['preview_sha256']
            or CAPTURES[operation] != public['kind']):
        raise PreviewChanged('a matching preview of this configured journal and window is required')
    if stop():
        raise InputError('journal capture stopped')
    if operation == 'case.analyze':
        with path.open('xb') as stream:
            stream.write(raw)
        report = storage.investigate(path, output, reference_state=state,
                                     reference_sha256=fs.digest(review), should_stop=stop)
        return report, [dict(kind='cases', id=report['case_id'])]
    report = _capture_jr(output, plan, source['settings'], stop)
    return report, [dict(kind='artifacts', id=report['artifact_id'])]
