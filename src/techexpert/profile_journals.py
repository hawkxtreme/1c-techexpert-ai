"""Select bounded local journals from the exact saved investigation profile."""

from datetime import datetime, timedelta
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
HOURLY_MINUTE = 'hourly_minute'
FIXED_PREFIX = 'fixed_prefix'
PREFIX_PLAN = 'tj_prefix_plan'
PREFIX_FAILURES = dict(source_truncated='journal_prefix_truncated', source_replaced='journal_prefix_replaced',
                       prefix_changed='journal_prefix_changed')
REASONS = ('journal_preview_changed', 'journal_preview_incomplete', 'journal_coverage_limited',
           'journal_parse_failed', 'journal_prefix_bounded', *PREFIX_FAILURES.values())
MAX_MEMBERS = 32


class PreviewChanged(InputError):
    pass


def schema(cap, operation):
    preview = operation == PREVIEW
    selector = dict(source=cap.string(4, pattern='j[1-9][0-9]{0,2}'), window=cap.WINDOW)
    if operation != 'jr.import':
        selector['timestamp_profile'] = cap.string(16, enum=[HOURLY_MINUTE],
            description='Declare short timestamps and one-hour rotation verified for this source and window.')
        selector['read_mode'] = cap.string(16, enum=[FIXED_PREFIX],
            description='Use a fixed byte boundary per selected TJ file, allowing append-only growth.')
    fields = dict(profile_journal=cap.obj(selector, () if preview else ('source',)))
    if not preview:
        fields['preview_sha256'] = cap.SHA256
    required = tuple(fields)
    if operation == 'case.analyze':
        fields['preview_id'] = dict(cap.CASE, description='Required for fixed_prefix. Use the ID returned by source.check.')
    return cap.obj(fields, required)


def normalize(cap, operation, arguments):
    result = cap.validate(arguments, schema(cap, operation))
    selected = result['profile_journal']
    if selected and 'source' not in selected:
        raise InputError('select a journal before giving a window or timestamp profile')
    if operation == 'case.analyze' and ('preview_id' in result) != (selected.get('read_mode') == FIXED_PREFIX):
        raise InputError('fixed-prefix capture requires the retained preview ID')
    if 'window' in selected:
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


def _configuration_status(source, timestamp_profile=None):
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
    kind = source['type']
    declared = settings.get('timestamp_format')
    if timestamp_profile == HOURLY_MINUTE:
        if kind != 'tj' or declared not in (None, '', 'minute'):
            return 'timestamp_profile_conflict'
    elif kind == 'tj':
        if declared == 'minute':
            return 'hourly_rotation_required'
        if declared not in (None, '', 'iso'):
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
                if kind == 'jr' and len(chosen) > MAX_MEMBERS:
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
    'linked_or_special_journal', 'no_journal_files', 'journal_byte_limit', 'hourly_filename_required',
    'hourly_window_unsupported', 'no_hour_files_in_window'))


def _hourly_members(files, window, offset):
    zone = native_tj._offset(offset)
    try:
        start = datetime.fromisoformat(window['start']).astimezone(zone)
        last = (datetime.fromisoformat(window['end']) - timedelta(microseconds=1)).astimezone(zone)
    except (ValueError, OverflowError) as error:
        raise InputError('hourly_window_unsupported') from error
    if last.year - start.year >= 100:
        raise InputError('hourly_window_unsupported')
    first_hour = start.replace(minute=0, second=0, microsecond=0)
    chosen = {}
    for file in files:
        match = native_tj.HOUR_FILENAME.fullmatch(file.name)
        if match is None:
            raise InputError('hourly_filename_required')
        stamp = match['hour']
        yy, month, day, hour = (int(stamp[index:index + 2]) for index in range(0, 8, 2))
        year = start.year + (yy - start.year) % 100
        try:
            if year > last.year:
                # Check whether the name contains a valid date in some century.
                # A date outside the requested years supplies no absolute year.
                datetime(2000 + yy, month, day, hour)
                continue
            candidate = datetime(year, month, day, hour, tzinfo=zone)
        except ValueError as error:
            raise InputError('hourly_filename_required') from error
        if first_hour <= candidate <= last:
            chosen[file] = dict(timestamp_format='minute', file_hour=candidate.isoformat(), rotation_hours=1)
    return chosen


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


def _tj_review(root, profiles, selection, settings, window, state, manifest_path):
    retained = min(MAX_FILE_BYTES, MAX_TOTAL_BYTES // len(profiles))
    nested = any(path != root and path.parent != root for path in profiles)
    placement = settings.get('placement') or ('folders' if nested else 'plain')
    specs = [dict(path=str(path), format=native_tj.FORMAT, platform_version=settings['platform_version'],
                  encoding='utf-8', placement=placement, external_window=dict(window, max_retained_bytes=retained),
                  **profile) for path, profile in profiles.items()]
    manifest = dict(schema=2, origin='provided', sources=specs, incident_window=window)
    for spec in specs:
        native_tj.validate_profile(spec, spec['path'])
    raw = fs.encode(manifest)
    review = tj_reference.build_review(manifest_path, raw, manifest, state)
    # The generated manifest resides in a different private worker directory on
    # each attempt. File identities, declared parser settings and bytes remain bound.
    selection['tj'] = {key: value for key, value in review.items() if key != 'manifest_path'}
    return raw, review


def _plan(state, output, binding, source, public, window, selection):
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
        settings = source['settings']
        offset = settings['utc_offset']
        if selection.get('timestamp_profile') == HOURLY_MINUTE:
            profiles = _hourly_members(files, window, offset)
            public.update(timestamp_profile=HOURLY_MINUTE, files_outside_window=len(files) - len(profiles),
                          hour_basis='filename_and_requested_year_with_declared_offset')
            if not profiles:
                raise InputError('no_hour_files_in_window')
        else:
            profiles = dict.fromkeys(files, dict(timestamp_format='iso', utc_offset=offset))
        files = list(profiles)
        if len(files) > MAX_MEMBERS:
            raise InputError('journal_scan_limit')
        if sum(file.lstat().st_size for file in files) > native_tj.MAX_REFERENCE_SCAN_BYTES:
            raise InputError('journal_byte_limit')
        raw, review = _tj_review(root, profiles, plan, settings, window, state, manifest_path)
        public.update(capture_scope='recorded_time_window', source_bytes=review['external_bytes'],
                      expected_read_bytes=review['expected_read_bytes'], max_retained_bytes=review['max_retained_bytes'])
        if selection.get('read_mode') == FIXED_PREFIX:
            plan['selector'] = selection
            plan['tj']['method'] = tj_reference.PREFIX_METHOD
            public['capture_scope'] = 'reviewed_prefix_window'
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


def _save_prefix_plan(output, plan, raw, preview):
    from .artifacts import save_artifact

    result = dict(schema_version=1, plan=plan, manifest=raw.decode('utf-8'), preview=preview)
    report = save_artifact(output, PREFIX_PLAN, plan['selector'], [], result)
    return report, [dict(kind='artifacts', id=report['artifact_id'])]


def _checked_prefix_plan(report, identifier, args):
    saved = report.get('result')
    if (report.get('artifact_id') != identifier or report.get('kind') != PREFIX_PLAN or report.get('sources') != []
            or type(saved) is not dict or saved.get('schema_version') != 1 or type(saved.get('plan')) is not dict
            or type(saved.get('manifest')) is not str or type(saved.get('preview')) is not dict):
        raise PreviewChanged('a verified fixed-prefix preview is required')
    plan, preview = saved['plan'], saved['preview']
    if (plan.get('selector') != args['profile_journal'] or preview.get('status') != 'ready'
            or preview.get('capture_scope') != 'reviewed_prefix_window'
            or preview.get('source_bytes_read') is not False or preview.get('preview_sha256') != fs.digest(plan)
            or ('preview_sha256' in args and preview['preview_sha256'] != args['preview_sha256'])):
        raise PreviewChanged('fixed-prefix preview differs from the approved selection')
    return saved


def _capture_prefix(state, output, binding, source, window, args, stop):
    from .artifacts import artifact_folder, load_artifact

    identifier = args['preview_id']
    try:
        fs.inventory(fs.safe(artifact_folder(state, identifier)))
        saved = _checked_prefix_plan(load_artifact(state, identifier), identifier, args)
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        raise PreviewChanged('fixed-prefix preview is unavailable or changed') from error
    plan = saved['plan']
    if plan['binding'] != binding or plan['window'] != window or plan['root'] != str(profile_files._ordinary_path(source['path'])):
        raise PreviewChanged('fixed-prefix preview binds another investigation revision, source or window')
    if stop():
        raise InputError('journal capture stopped')
    path = output / 'profile-journal-manifest.json'
    with path.open('xb') as stream:
        stream.write(saved['manifest'].encode('utf-8'))
    return storage.investigate(path, output, reference_state=state, reference_sha256=fs.digest(plan['tj']),
        prefix_review=plan['tj'], should_stop=stop)


def pin_prefix(operation, args, data, add):
    if operation == PREVIEW:
        if data.get('kind') == PREFIX_PLAN:
            identifier = data['artifact_id']
            _checked_prefix_plan(add('artifacts', identifier), identifier, args)
        return
    identifier = args['preview_id']
    saved = _checked_prefix_plan(add('artifacts', identifier), identifier, args)
    review = saved['plan']['tj']
    if data.get('reference_plan_sha256') != fs.digest(review) or len(data['sources']) != len(review['sources']):
        raise InputError('fixed-prefix snapshot differs from the retained plan')
    for actual, planned in zip(data['sources'], review['sources']):
        capture = actual.get('reference_capture', {})
        if (actual['id'] != planned['id'] or actual['path'] != planned['path'] or capture.get('method') != tj_reference.PREFIX_METHOD
                or capture.get('original_bytes') != planned['observation']['bytes']
                or capture.get('file_identity') != planned['observation']['identity'] or capture.get('window') != planned['window']):
            raise InputError('captured TJ files differ from the reviewed prefixes')


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
    timestamp_profile = selection.get('timestamp_profile')
    status = _configuration_status(source, timestamp_profile) if source else 'source_not_configured'
    fixed_prefix = selection.get('read_mode') == FIXED_PREFIX
    if fixed_prefix and status == 'configured' and source['type'] != 'tj':
        status = 'journal_read_mode_unsupported'
    window, basis = _window(doc, selection.get('window'))
    if status == 'configured' and window is None:
        status = 'window_required'
    public = dict(source=ref, kind=source['type'] if source else None, status=status, window=window,
                  window_basis=basis, source_bytes_read=False)
    if fixed_prefix and operation == 'case.analyze':
        if status != 'configured':
            raise PreviewChanged('configured TJ selection is unavailable')
        report = _capture_prefix(state, output, binding, source, window, args, stop)
        return report, [dict(kind='cases', id=report['case_id'])]
    if status == 'configured':
        try:
            plan, path, raw, review = _plan(state, output, binding, source, public, window, selection)
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
        if fixed_prefix and public['status'] == 'ready':
            return _save_prefix_plan(output, plan, raw, public)
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


def partial_reason(operation, args, data):
    preview = data.get('journal_preview')
    if preview is not None and preview['status'] != 'ready':
        return 'journal_preview_incomplete'
    if operation != 'case.analyze':
        return None
    if args['profile_journal'].get('read_mode') == FIXED_PREFIX:
        if any(capture['unread_appended_bytes'] or capture['incomplete_tail_bytes']
               for capture in (tj_reference.prefix_summary(source) for source in data['sources'])):
            return 'journal_prefix_bounded'
    if data['source_coverage']['status'] == 'observations_available':
        return None
    if args['profile_journal'].get('timestamp_profile') == HOURLY_MINUTE:
        parse_states = {source['reference_capture']['original_parse_status'] for source in data['sources']}
        if 'invalid' in parse_states and parse_states <= {'invalid', 'empty'}:
            return 'journal_parse_failed'
    return 'journal_coverage_limited'
