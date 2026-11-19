"""Read one supplied configuration for a selected local TJ without probing other paths."""

import os
from pathlib import Path
import re

from . import artifacts, input_files, logcfg, logcfg_xml, native_tj, profile_files
from . import operation_state as fs
from .inputs import InputError


KIND = 'logcfg_observation'
HOURLY_MINUTE = 'hourly_minute'
NS = logcfg_xml.NS + '}'
EVENT_NAMES = {*logcfg.EVENTS, 'VRSREQUEST', 'VRSRESPONSE'}
OPERATORS = {NS + part for part in ('eq', 'ne', 'gt', 'ge', 'lt', 'le', 'like')}
ATTRIBUTES = {'location', 'history', 'format', 'placement', 'rotation', 'rotationperiod', 'rotationsize', 'compress'}


def _number(value):
    return int(value) if value is not None and re.fullmatch(r'[0-9]{1,8}', value) else None


def _location(value):
    if not value or value.startswith(('\\', '//')):
        return None
    try:
        return Path(logcfg._remote_path(value, 'windows' if os.name == 'nt' else 'linux'))
    except InputError:
        return None


def _matching_rule(nodes, target):
    matches, narrower, unresolved = [], False, False
    for rule in nodes:
        if rule['depth'] != 1 or rule['name'] not in (NS + 'log', NS + 'defaultlog'):
            continue
        attrs = rule['attrs']
        default = rule['name'] == NS + 'defaultlog'
        if default and (_number(attrs.get('history')) == 0 or 'location' not in attrs):
            # Implicit account-specific destinations are outside this lexical check.
            continue
        location = _location(attrs.get('location'))
        if location is None:
            unresolved = True
        elif target.is_relative_to(location):
            matches.append((rule, location))
        elif location.is_relative_to(target):
            narrower = True
    if len(matches) > 1 or matches and narrower:
        return 'ambiguous_location', None, None
    if unresolved:
        return 'unresolved_location', None, None
    if not matches:
        return 'narrower_source_required' if narrower else 'unmatched_location', None, None
    rule, location = matches[0]
    if rule['name'] != NS + 'log':
        return 'default_log_unsupported', None, None
    return 'matched', rule, location


def _settings(attrs, known_version):
    defaults = []

    def field(key, allowed, default):
        if key not in attrs and known_version:
            defaults.append(key)
            return default
        value = attrs.get(key)
        return value if value in allowed else None

    def number(key, default):
        if key not in attrs and known_version:
            defaults.append(key)
            return default
        return _number(attrs.get(key)) or None

    settings = dict(format=field('format', ('text', 'json'), 'text'),
                    placement=field('placement', ('folders', 'plain'), 'folders'),
                    rotation=field('rotation', ('period', 'size'), 'period'),
                    compression=field('compress', ('none', 'zip'), 'none'), history_hours=_number(attrs.get('history')))
    if settings['rotation'] == 'period':
        settings['rotation_hours'] = number('rotationperiod', 1)
    elif settings['rotation'] == 'size':
        settings['rotation_megabytes'] = number('rotationsize', 100)
    return settings, defaults


def _filters(nodes, rule):
    children = []
    for node in nodes:
        if not rule['open_end'] <= node['start'] < rule['close_start']:
            continue
        if node['depth'] == 2:
            children.append((node, []))
        else:
            children[-1][1].append(node)
    names, conditional = set(), set()
    branches = opaque = properties = other = 0
    all_properties = False
    for child, nested in children:
        if child['name'] == NS + 'property':
            properties += 1
            all_properties |= child['attrs'] == {'name': 'all'} and not nested
        elif child['name'] == NS + 'event':
            branches += 1
            if child['attrs'] or any(node['depth'] != 3 or node['name'] not in OPERATORS or
                                     node['attrs'].keys() != {'property', 'value'} for node in nested):
                opaque += 1
                continue
            named = {node['attrs']['value'].upper() for node in nested
                     if node['name'] == NS + 'eq' and node['attrs']['property'] == 'name'} & EVENT_NAMES
            if len(nested) == 1:
                names.update(named)
            else:
                conditional.update(named)
            if not named:
                opaque += 1
        else:
            other += 1
    events = dict(branches=branches, names=sorted(names), conditional_names=sorted(conditional - names),
                  opaque_branches=opaque, unrecognized_children=other)
    fields = dict(rules=properties, mode='all' if all_properties else 'selected' if properties else 'not_declared')
    return events, fields


def _describe(document, source, target, info):
    status, rule, location = _matching_rule(document['nodes'], target)
    info['status'] = status
    if rule is None:
        return None
    configured = source['settings']
    known_version = configured.get('platform_version') == native_tj.PLATFORM_VERSION
    settings, defaults = _settings(rule['attrs'], known_version)
    events, properties = _filters(document['nodes'], rule)
    unsupported = rule['attrs'].keys() - ATTRIBUTES
    info.update(settings=settings, defaults=defaults, events=events, properties=properties,
                unrecognized_attributes=len(unsupported))
    if not known_version:
        info['reader_status'] = 'version_unsupported' if configured.get('platform_version') else 'version_required'
        return location
    reader_settings = (settings['format'], settings['placement'], settings['rotation'],
                       settings.get('rotation_hours'), settings['compression'])
    if (not unsupported and not events['unrecognized_children']
            and reader_settings == ('text', 'folders', 'period', 1, 'none')):
        if (configured.get('placement') not in (None, '', 'folders')
                or configured.get('timestamp_format') not in (None, '', 'minute')):
            info['reader_status'] = 'logcfg_profile_conflict'
        else:
            info.update(timestamp_profile=HOURLY_MINUTE, reader_status='supported_profile')
    return location


def inspect_copy(output, binding, reference, source, supplied, *, stop):
    info = dict(source=reference, status='source_not_configured', journal_bytes_read=False,
                timestamp_profile=None, reader_status='logcfg_reader_unsupported', runtime_applicability='unverified',
                location_basis='explicit_locations_in_supplied_copy')
    if source is None:
        return dict(logcfg=info), []
    if source['type'] != 'tj' or not source['path']:
        info['status'] = 'path_required' if source['type'] == 'tj' else 'logcfg_source_unsupported'
        return dict(logcfg=info), []
    if source['settings'].get('transport', 'local') != 'local':
        info['status'] = 'separate_access_required'
        return dict(logcfg=info), []
    if stop():
        raise InputError('configuration inspection stopped')
    try:
        target = profile_files._ordinary_path(source['path'])
        path = profile_files._ordinary_path(supplied)
        observed = input_files.observe(path)
        if observed['bytes'] > logcfg_xml.MAX_BYTES:
            info['status'] = 'xml_byte_limit'
            return dict(logcfg=info), []
        raw, checked = input_files.read(path, logcfg_xml.MAX_BYTES, keep=True, observed=observed)
        input_files.read(path, logcfg_xml.MAX_BYTES, expected=checked, observed=observed)
        document = logcfg_xml.inspect(raw)
    except logcfg_xml.XmlIssue:
        info['status'] = 'invalid_or_unsupported_xml'
    except FileNotFoundError:
        info['status'] = 'config_file_not_found'
    except PermissionError:
        info['status'] = 'access_denied'
    except (OSError, ValueError):
        info['status'] = 'config_file_unavailable'
    else:
        location = _describe(document, source, target, info)
        if stop():
            raise InputError('configuration inspection stopped')
        report = artifacts.save_artifact(output, KIND, dict(path=supplied), [(str(path), raw)],
            dict(observation=info, binding=_scope(binding, reference), location=str(location) if location else None),
            source_names=['logcfg.xml'])
        return report, [dict(kind='artifacts', id=report['artifact_id'])]
    return dict(logcfg=info), []


def _scope(binding, reference):
    return dict(investigation_id=binding['investigation_id'], profile_sha256=binding['profile_sha256'], source=reference)


def dependency(report):
    return dict(id=report['artifact_id'], report_digest=fs.digest(report))


def select(state, binding, reference, identifier):
    try:
        fs.inventory(fs.safe(artifacts.artifact_folder(state, identifier)))
        report = artifacts.load_artifact(state, identifier)
        if report['kind'] != KIND or report['result']['binding'] != _scope(binding, reference):
            return 'logcfg_scope_mismatch', None, None
        info = report['result']['observation']
        if info['timestamp_profile'] != HOURLY_MINUTE:
            return info['reader_status'], None, None
        return 'configured', dependency(report), Path(report['result']['location'])
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return 'logcfg_snapshot_unavailable', None, None


def check_layout(files, location):
    for file in files:
        if (file.parent.parent != location or not re.fullmatch(r'.+_[0-9]+', file.parent.name)
                or not re.fullmatch(r'[0-9]{8}\.log', file.name, re.IGNORECASE)):
            raise InputError('logcfg_layout_conflict')
