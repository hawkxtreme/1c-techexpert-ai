"""Read the portable product package as data, without loading its code."""
import hashlib
from io import BytesIO
from pathlib import Path
import re

from . import input_files, input_zip
from .inputs import InputError, json_value
from .operation_state import safe
from .plugin_runtime import LAUNCH_ENV, LAUNCHER
from .readiness import MANIFEST, canonical, parse_inventory


PLUGIN = '1c-techexpert-ai'
FORMAT = 'src/techexpert/assets/update-format.json'
CASE_RETIREMENT_FORMAT = 'src/techexpert/assets/case-retirement-format.json'
REPORT_RETIREMENT_FORMAT = 'src/techexpert/assets/report-retirement-format.json'
REPORT_REFERENCE_FORMAT = 'src/techexpert/assets/report-reference-format.json'
INVESTIGATION_PROGRESS_FORMAT = 'src/techexpert/assets/investigation-progress-format.json'
CHECK_HISTORY_FORMAT = 'src/techexpert/assets/check-history-format.json'
INVESTIGATION_TASK_FORMAT = 'src/techexpert/assets/investigation-task-format.json'
OS_OBSERVATION_FORMAT = 'src/techexpert/assets/os-observation-format.json'
JR_LGD_FORMAT = 'src/techexpert/assets/jr-lgd-format.json'
FIX_VERIFICATION_FORMAT = 'src/techexpert/assets/fix-verification-format.json'
APDEX_PREPARATION_FORMAT = 'src/techexpert/assets/apdex-preparation-format.json'
TJ_REFERENCE_FORMAT = 'src/techexpert/assets/tj-reference-format.json'
TJ_JSON_FORMAT = 'src/techexpert/assets/tj-json-format.json'
CONTEXT_DISCLOSURE_FORMAT = 'src/techexpert/assets/context-disclosure-format.json'
CONTEXT_INTAKE_FORMAT = 'src/techexpert/assets/context-intake-format.json'
CONTEXT_PROGRAM_FORMAT = 'src/techexpert/assets/context-program-format.json'
MIB = 1024**2
ARCHIVE_LIMIT = 16*MIB
LIMITS = dict(max_depth=12, max_files=512, max_file_bytes=MIB, max_total_bytes=16*MIB)
_VERSION = re.compile(r'(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4})){2}')
_RUNTIME_VERSION = re.compile(r"""^__version__\s*=\s*(['"])([^'"\r\n]+)\1[ \t]*$""",re.MULTILINE)
_ROOT_MEMBERS = {'README.md', 'AGENTS.md', 'techexpert.py', '.codex-plugin/plugin.json',
    'plugin.json', 'mcp.json', '.mcp.json', '.agents/plugins/marketplace.json', '.agents/skills/techexpert/SKILL.md'}
_FILES = {
    'src/techexpert/': {'.py', '.json', '.html', '.md'},
    'skills/': {'.md'},
    'knowledge/': {'.md', '.json'},
    'scripts/': {'.py'},
    'evaluations/': {'.md', '.xml'},
    'examples/sc01/': {'.md', '.json', '.jsonl', '.xml', '.bsl', '.csv'},
    'tests/fixtures/': {'.json', '.txt', '.lgf', '.lgp', '.csv', '.md'},
    'infrastructure/lab/': {'.onec', '.postgres', '.md', '.yaml', '.sh', '.asc'},
}
_EXTRAS = ('evaluations/', 'examples/sc01/', 'tests/fixtures/', 'infrastructure/lab/')


def _json(data):
    value = json_value(data.decode('utf-8'), reject_duplicates=True)
    if type(value) is not dict:
        raise InputError('package metadata must be an object')
    return value


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def version_number(value):
    if type(value) is not str or not _VERSION.fullmatch(value):
        raise InputError('package version requires a stable numeric SemVer')
    return tuple(map(int, value.split('.')))


def _allowed(name, listed):
    if name in _ROOT_MEMBERS or name in (MANIFEST, 'scripts/mcp_sc01_smoke.py'):
        return True
    if name not in listed and not name.startswith(_EXTRAS):
        return False
    suffix = Path(name).suffix
    return any(name.startswith(folder) and suffix in suffixes for folder, suffixes in _FILES.items())


def _additional_schemas(contents, listed, filename, field):
    if filename not in contents:
        return []
    declared = _json(contents[filename])
    versions = declared.get(field)
    if (filename not in listed or set(declared) != {'schema_version', field}
            or type(declared['schema_version']) is not int or declared['schema_version'] != 1
            or type(versions) is not list or not versions
            or any(type(version) is not int or not 1 <= version <= 2**31-1 for version in versions)
            or len(set(versions)) != len(versions)):
        raise InputError('invalid supplemental state compatibility declaration')
    return versions


def read_package(path):
    path = safe(path)
    data, identity = input_files.read(path, ARCHIVE_LIMIT, keep=True)
    catalogue = input_zip.catalogue(BytesIO(data), LIMITS, max_entries=LIMITS['max_files'])
    members = [(item['relative_path'], item['bytes']) for item in catalogue]
    contents = dict(input_zip.members(data, LIMITS, members))
    if MANIFEST not in contents:
        raise InputError('product bundle manifest is missing')
    inventory = parse_inventory(contents[MANIFEST], expected_version=None)
    listed = inventory['members']
    if set(listed)-contents.keys() or 'README.md' not in contents:
        raise InputError('declared package member is missing')
    for name in contents:
        if not _allowed(name, listed):
            raise InputError('unsupported package member: '+name)
    for name, digest in listed.items():
        if _digest(canonical(contents[name])) != digest:
            raise InputError('package member digest mismatch: '+name)
    version = inventory['product_version']
    version_number(version)
    for name in ('plugin.json', '.codex-plugin/plugin.json'):
        values = _json(contents[name])
        if values.get('name') != PLUGIN or values.get('version') != version:
            raise InputError('plugin identity differs from the package')
    runtime = _RUNTIME_VERSION.findall(canonical(contents['src/techexpert/__init__.py']).decode('utf-8'))
    if len(runtime)!=1 or runtime[0][1]!=version:
        raise InputError('runtime version differs from the package')
    plugin = _json(contents['.codex-plugin/plugin.json'])
    if plugin.get('skills')!='./skills/' or plugin.get('mcpServers')!='./.mcp.json':
        raise InputError('unsupported local plugin entrypoint')
    local = '${PLUGIN_ROOT}'
    stdio = dict(type='stdio',command=LAUNCHER,args=['-X','utf8',local+'/techexpert.py','mcp-stdio'],cwd=local)
    portable, compatibility = (_json(contents[name]).get('mcpServers') for name in ('mcp.json','.mcp.json'))
    supported = ({'techexpert':stdio}, {'techexpert':dict(stdio, env=LAUNCH_ENV)})
    if portable != compatibility or portable not in supported:
        raise InputError('unsupported local MCP configuration')
    book = _json(contents['knowledge/index.json'])
    revision = book.get('revision')
    if type(revision) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,79}', revision):
        raise InputError('unsupported knowledge revision')
    contract = _json(contents[FORMAT]) if FORMAT in contents else None
    return dict(path=str(path), identity=identity, metadata=dict(version=version, knowledge_revision=revision,
        knowledge_schema=book.get('schema_version'), state_contract=contract), inventory=inventory, files=contents,
        hashes={name:dict(sha256=_digest(value), bytes=len(value)) for name, value in contents.items()},
        archive=data, case_retirement_schemas=_additional_schemas(contents, listed, CASE_RETIREMENT_FORMAT, 'case_source_retirements'),
        report_retirement_schemas=_additional_schemas(contents, listed, REPORT_RETIREMENT_FORMAT, 'investigation_report_retirements'),
        report_reference_schemas=_additional_schemas(contents, listed, REPORT_REFERENCE_FORMAT, 'report_references'),
        investigation_progress_schemas=_additional_schemas(contents, listed, INVESTIGATION_PROGRESS_FORMAT, 'investigation_progress'),
        check_history_schemas=_additional_schemas(contents, listed, CHECK_HISTORY_FORMAT, 'check_history'),
        investigation_task_schemas=_additional_schemas(contents, listed, INVESTIGATION_TASK_FORMAT, 'investigation_task'),
        os_observation_schemas=_additional_schemas(contents, listed, OS_OBSERVATION_FORMAT, 'os_observation'),
        jr_lgd_schemas=_additional_schemas(contents, listed, JR_LGD_FORMAT, 'jr_lgd'),
        fix_verification_schemas=_additional_schemas(contents, listed, FIX_VERIFICATION_FORMAT, 'fix_verification'),
        apdex_preparation_schemas=_additional_schemas(contents, listed, APDEX_PREPARATION_FORMAT, 'apdex_preparation'),
        tj_reference_schemas=_additional_schemas(contents, listed, TJ_REFERENCE_FORMAT, 'external_tj_windows'),
        tj_json_schemas=_additional_schemas(contents, listed, TJ_JSON_FORMAT, 'native_tj_json'),
        context_disclosure_schemas=_additional_schemas(contents, listed, CONTEXT_DISCLOSURE_FORMAT, 'context_disclosure'),
        context_intake_schemas=_additional_schemas(contents, listed, CONTEXT_INTAKE_FORMAT, 'context_intake'),
        context_program_schemas=_additional_schemas(contents, listed, CONTEXT_PROGRAM_FORMAT, 'context_program'))


def installed_inventory(root):
    root = safe(root)
    data, identity = input_files.read(root/MANIFEST,MIB,keep=True)
    inventory = parse_inventory(data,expected_version=None)
    version_number(inventory['product_version'])
    observed = {}
    changed = []
    remaining = LIMITS['max_total_bytes']
    for name, expected in inventory['members'].items():
        input_files.name_parts(name)
        if not _allowed(name, inventory['members']):
            raise InputError('unsupported installed inventory member')
        try:
            current, _ = input_files.read(root/name,min(MIB,remaining),keep=True)
            remaining -= len(current)
            observed[name] = _digest(canonical(current))
        except FileNotFoundError:
            observed[name] = None
        if observed[name]!=expected:
            changed.append(name)
    book,_ = input_files.read(root/'knowledge/index.json',MIB,keep=True)
    return dict(version=inventory['product_version'], knowledge_revision=_json(book).get('revision'),
        inventory=inventory, hashes={}, observed=observed, local_changes=sorted(changed), inventory_sha256=identity['sha256'])


def _diff(old, new):
    return dict(added=sorted(new.keys()-old.keys()), removed=sorted(old.keys()-new.keys()),
        changed=sorted(name for name in new.keys()&old.keys() if new[name] != old[name]))


def compare_packages(current, candidate, *, compare_supplemental=True):
    old, new = current['inventory'], candidate['inventory']
    components = {}
    for group in old['components']:
        before = {name:old['members'][name] for name in old['components'][group]}
        after = {name:new['members'][name] for name in new['components'][group]}
        components[group] = _diff(before, after)
    def supplemental(package):
        # Supplemental material has exact byte identities and no load-time role.
        declared = package['inventory']['members']
        return {name: identity for name, identity in package['hashes'].items() if name not in declared and name != MANIFEST}
    if compare_supplemental:
        components['supplemental'] = _diff(supplemental(current), supplemental(candidate))
    knowledge = any(components['knowledge'].values())
    program = any(any(diff.values()) for group,diff in components.items() if group != 'knowledge')
    kind = 'product' if program or old['product_version'] != new['product_version'] else 'knowledge_only' if knowledge else 'unchanged'
    return dict(kind=kind, components=components,
        comparison_scope='complete_packages' if compare_supplemental else 'declared_bundle_members')
