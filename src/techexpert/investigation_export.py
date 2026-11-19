"""Reviewed local export of an exact saved investigation revision."""
from collections import Counter, deque
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path, PurePosixPath
import os
import re
import shutil
import stat

from . import investigation_materials as materials, investigations, operation_state as fs
from .inputs import InputError, MAX_FILE_BYTES, json_value, read_snapshot


CONTENTS = {
    'report': 'exact_private_report',
    'metadata': 'allowlisted_technical_fields',
    'evidence': 'pseudonymized_draft_excerpts',
    'private': 'exact_private_reports_and_retained_evidence',
}
MAX_BYTES = 512 * 1024**2
MAX_ENTRIES = 4096
MAX_MANIFEST_BYTES = 2 * 1024**2
HEX = re.compile(r'[a-f0-9]{64}')
PART = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,100}')
EVIDENCE_PATH = re.compile(r'evidence/E-[A-F0-9]{12}\.txt')
RESERVED = {'CON', 'PRN', 'AUX', 'NUL', *(f'{p}{n}' for p in ('COM', 'LPT') for n in range(1, 10))}
DRAFT_CATEGORIES = {'ENV', 'DB', 'PATH', 'CONNECTION', 'NODE', 'USER', 'EMAIL', 'ID', 'IP',
                    'secret', 'sql_text', 'private_url', 'code', 'image', 'link'}


def _hash(data):
    return sha256(data).hexdigest()


def _relative(value):
    if type(value) is not str or not 1 <= len(value) <= 400:
        raise InputError('invalid portable export member name')
    parts = value.split('/')
    if any(not PART.fullmatch(part) or part.endswith('.') or part.split('.')[0].upper() in RESERVED for part in parts):
        raise InputError('invalid portable export member name')
    return PurePosixPath(*parts)


def _file(path):
    path = fs.safe(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise InputError('export requires a regular saved file')
    return path, info


def _read(path, limit=MAX_FILE_BYTES):
    path, before = _file(path)
    data = read_snapshot(path, limit, share_delete=True)
    after = fs.safe(path).lstat()
    if not os.path.samestat(before, after) or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise InputError('saved file changed while reading the export')
    return data


def _write_new(path, data):
    with fs.safe(path).open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


class Files:
    def __init__(self):
        self.records = {}
        self.names = set()
        self.total = 0
        self.cases = set()

    def add(self, name, source, *, expected=None, size=None):
        _relative(name)
        data = source if isinstance(source, bytes) else _read(source)
        digest = _hash(data)
        if (expected is not None and digest != expected) or (size is not None and len(data) != size):
            raise InputError('saved export member integrity mismatch')
        if (name.casefold() in self.names or len(self.records) >= MAX_ENTRIES
                or self.total + len(data) > MAX_BYTES):
            raise InputError('export member count, names or byte limit exceeded')
        self.total += len(data)
        self.names.add(name.casefold())
        self.records[name] = (dict(path=name, bytes=len(data), sha256=digest), source)
        return data

    def entries(self):
        return [self.records[name][0] for name in sorted(self.records)]


def _report_files(files, folder, prefix):
    receipt_path = fs.safe(folder / 'receipt.json')
    data = _read(receipt_path, 8192)
    receipt = json_value(data.decode('utf-8'), reject_duplicates=True)
    if type(receipt) is not dict:
        raise InputError('invalid saved report receipt')
    for name, key in (('report.json', 'report_sha256'), ('report.md', 'markdown_sha256')):
        if type(receipt.get(key)) is not str or not HEX.fullmatch(receipt[key]):
            raise InputError('invalid saved report receipt')
        files.add(prefix + name, folder / name, expected=receipt[key])
    return receipt_path, receipt, _hash(data)


def _product_files(state, files, key):
    from .case_retention import require_available

    kind, identifier = key
    locate, member, read_record = materials.PRODUCTS[kind]
    folder = fs.safe(locate(state, identifier))
    receipt_path = fs.safe(folder / 'receipt.json')
    path = 'state/' + folder.relative_to(state).as_posix() + '/'
    data = files.add(path + 'receipt.json', receipt_path)
    receipt = json_value(data.decode('utf-8'), reject_duplicates=True)
    if type(receipt) is not dict:
        raise InputError('invalid saved export product receipt')
    _file(folder / 'report.json')
    _file(folder / member)
    if kind == 'case':
        report, digest = read_record(state, identifier, with_digest=True)
        files.cases.add(identifier)
    else:
        report, digest = read_record(state, identifier)
    if digest != receipt['report_sha256']:
        raise InputError('saved export product receipt changed')
    files.add(path + 'report.json', folder / 'report.json', expected=digest)
    receipt_field = {'case': 'manifest_sha256', 'artifact': 'request_sha256', 'comparison': 'markdown_sha256'}[kind]
    files.add(path + member, folder / member, expected=receipt[receipt_field])
    if kind != 'comparison':
        members = materials._source_members(folder, kind, report)
        for source, (source_path, length) in zip(report['sources'], members, strict=True):
            if kind == 'case':
                require_available(state, identifier, source['id'])
            files.add(path + 'sources/' + source_path.name, source_path, expected=source['sha256'], size=length)
    return materials._hashes(report, digest, receipt), materials._inputs(kind, report)


def _revisions(state, identifier, revision):
    head = investigations._read_head(state, identifier)
    investigations.revision_folder(state, identifier, revision)
    for number in range(revision, 0, -1):
        folder = investigations.revision_folder(state, identifier, number)
        for name in ('report.json', 'report.md', 'receipt.json'):
            _file(folder / name)
    return investigations._revision_chain(state, identifier, head, revision)


def _private_files(state, identifier, revision):
    files = Files()
    queue = deque()
    origin = None
    prefix = f'state/investigations/{identifier}/'
    for doc in _revisions(state, identifier, revision):
        number = doc['revision']
        folder = fs.safe(investigations.revision_folder(state, identifier, number))
        report_prefix = f'{prefix}revisions/{number:06d}/'
        receipt_path, receipt, digest = _report_files(files, folder, report_prefix)
        files.add(report_prefix + 'receipt.json', receipt_path, expected=digest)
        if number == revision:
            origin = dict(investigation_id=identifier, revision=revision, report_sha256=receipt['report_sha256'])
            files.add(prefix + 'head.json', fs.encode(dict(revision=revision, report_sha256=receipt['report_sha256'])))
        for attachment in investigations._list(doc['attachments'], 16):
            queue.append(materials._binding(attachment['kind'], attachment['target_id'], 'attachment', attachment['report_sha256']))
    checked = {}
    while queue:
        key, basis, digest = queue.popleft()
        if key not in checked:
            checked[key], dependencies = _product_files(state, files, key)
            queue.extend(dependencies)
        if checked[key][basis] != digest:
            raise InputError('export attachment disagrees with its saved report digest')
    return files, origin


def _metadata(doc):
    version = doc['versions'].get('product')
    version = version if isinstance(version, str) and re.fullmatch(r'[0-9]{1,8}\.[0-9]{1,8}\.[0-9]{1,8}', version) else None
    counts = Counter(item['kind'] for item in doc['attachments'])
    return dict(schema_version=1, product_version=version, investigation_schema=doc['schema_version'],
        revision=doc['revision'], execution_status=doc['execution_status'], cause_state=doc['cause_state'],
        attachment_counts={kind: counts[kind] for kind in materials.PRODUCTS}, evidence_count=len(doc['evidence']))


def _check_metadata(data):
    value = json_value(data.decode('utf-8'), reject_duplicates=True)
    fields = {'schema_version', 'product_version', 'investigation_schema', 'revision', 'execution_status',
              'cause_state', 'attachment_counts', 'evidence_count'}
    if type(value) is not dict or set(value) != fields:
        raise InputError('invalid export technical metadata')
    version = value['product_version']
    counts = value['attachment_counts']
    if (type(value['schema_version']) is not int or value['schema_version'] != 1
            or type(value['investigation_schema']) is not int or value['investigation_schema'] not in (1, 2)
            or type(value['revision']) is not int or not 1 <= value['revision'] <= 1000
            or version is not None and (type(version) is not str or not re.fullmatch(r'[0-9]{1,8}\.[0-9]{1,8}\.[0-9]{1,8}', version))
            or value['execution_status'] not in investigations.EXECUTIONS or value['cause_state'] not in investigations.CAUSES
            or type(value['evidence_count']) is not int or not 0 <= value['evidence_count'] <= 200
            or type(counts) is not dict or set(counts) != materials.PRODUCTS.keys()
            or any(type(count) is not int or not 0 <= count <= 16 for count in counts.values())
            or sum(counts.values()) > 16):
        raise InputError('invalid export technical metadata')


def _selection(state, identifier, revision, content, draft):
    if content not in CONTENTS or (draft is not None) != (content == 'evidence'):
        raise InputError('select a content type and a reviewed draft only for pseudonymized evidence')
    if content == 'private':
        files, origin = _private_files(state, identifier, revision)
        review = None
    else:
        chain = _revisions(state, identifier, revision)
        doc = next(chain)
        for _ in chain:
            pass
        files = Files()
        origin = review = None
        if content == 'report':
            folder = investigations.revision_folder(state, identifier, revision)
            _, receipt, _ = _report_files(files, folder, '')
            origin = dict(investigation_id=identifier, revision=revision, report_sha256=receipt['report_sha256'])
        elif content == 'metadata':
            files.add('technical-metadata.json', fs.encode(_metadata(doc)))
        else:
            from .incident_drafts import _load, draft_folder

            fs.inventory(fs.safe(draft_folder(state, draft)))
            view, payload, source, _ = _load(state, draft)
            if source['investigation_id'] != identifier or source['investigation_revision'] != revision:
                raise InputError('reviewed evidence draft belongs to another investigation revision')
            for name, data in payload.items():
                if EVIDENCE_PATH.fullmatch(name):
                    files.add(name, data)
            if not files.records:
                raise InputError('select cleaned evidence excerpts in the reviewed draft')
            review = dict(preview_sha256=view['preview_sha256'], draft_redactions=view['redactions'])
    manifest = dict(schema_version=1, content=content, cleanup=CONTENTS[content],
                    origin=origin, review=review, files=files.entries(), payload_bytes=files.total)
    _checked_members(manifest)
    if len(fs.encode(manifest)) > MAX_MANIFEST_BYTES:
        raise InputError('export manifest exceeds its byte limit')
    return files, manifest


def _destination(state, destination):
    target = fs.safe(destination)
    if target == target.parent or not target.parent.is_dir() or target.is_relative_to(state) or state.is_relative_to(target):
        raise InputError('export requires an independent folder in an existing local directory')
    return target


def _approval(state, identifier, target, revision, draft, manifest):
    return fs.digest(dict(state=str(state), investigation_id=identifier, destination=str(target), revision=revision,
                          draft_id=draft, manifest=manifest))


def plan(state, identifier, destination, *, revision=None, content='private', draft=None):
    state = fs.safe(state)
    target = _destination(state, destination)
    if target.exists():
        raise InputError('export preview requires a new destination folder')
    if revision is None:
        revision = investigations._read_head(state, identifier)['revision']
    _, manifest = _selection(state, identifier, revision, content, draft)
    marker = fs.encode(manifest)
    return dict(status='preview', investigation_id=identifier, revision=revision, destination=str(target),
        plan_sha256=_approval(state, identifier, target, revision, draft, manifest),
        manifest_sha256=_hash(marker), manifest_bytes=len(marker), **manifest)


def _checked_members(manifest):
    if type(manifest) is not dict or set(manifest) != {'schema_version', 'content', 'cleanup', 'origin', 'review', 'files', 'payload_bytes'}:
        raise InputError('invalid investigation export manifest')
    content = manifest['content']
    if (type(manifest['schema_version']) is not int or manifest['schema_version'] != 1 or type(content) is not str
            or content not in CONTENTS or manifest['cleanup'] != CONTENTS[content]):
        raise InputError('unsupported investigation export manifest')
    payload = manifest['files']
    if type(payload) is not list or not 1 <= len(payload) <= MAX_ENTRIES:
        raise InputError('invalid export file list')
    names, total = set(), 0
    for item in payload:
        if type(item) is not dict or set(item) != {'path', 'bytes', 'sha256'}:
            raise InputError('invalid export file description')
        _relative(item['path'])
        if (item['path'].casefold() in names or item['path'].casefold() == 'manifest.json'
                or type(item['bytes']) is not int or not 0 <= item['bytes'] <= MAX_FILE_BYTES
                or type(item['sha256']) is not str or not HEX.fullmatch(item['sha256'])):
            raise InputError('invalid export file digest, size or name')
        names.add(item['path'].casefold())
        total += item['bytes']
    if total > MAX_BYTES or type(manifest['payload_bytes']) is not int or total != manifest['payload_bytes']:
        raise InputError('invalid export byte total')
    paths = {item['path'] for item in payload}
    origin, review = manifest['origin'], manifest['review']
    if content in ('private', 'report'):
        if (type(origin) is not dict or set(origin) != {'investigation_id', 'revision', 'report_sha256'}
                or type(origin['investigation_id']) is not str or not re.fullmatch('[a-f0-9]{32}', origin['investigation_id'])
                or type(origin['revision']) is not int
                or not 1 <= origin['revision'] <= 1000 or type(origin['report_sha256']) is not str
                or not HEX.fullmatch(origin['report_sha256'])):
            raise InputError('invalid saved report origin')
    elif origin is not None:
        raise InputError('shareable exports omit private origins')
    if ((content == 'report' and paths != {'report.md', 'report.json'})
            or (content == 'metadata' and paths != {'technical-metadata.json'})):
        raise InputError('unexpected selected export members')
    if content == 'private' and any(not path.startswith('state/') for path in paths):
        raise InputError('invalid private package layout')
    if content == 'evidence':
        if (any(not EVIDENCE_PATH.fullmatch(path) for path in paths) or type(review) is not dict
                or set(review) != {'preview_sha256', 'draft_redactions'} or type(review['preview_sha256']) is not str
                or not HEX.fullmatch(review['preview_sha256']) or type(review['draft_redactions']) is not dict
                or any(key not in DRAFT_CATEGORIES or type(value) is not int or value < 0
                       for key, value in review['draft_redactions'].items())):
            raise InputError('invalid pseudonymized evidence export')
    elif review is not None:
        raise InputError('unexpected evidence review')
    return paths


def _verify_payload(folder, manifest, *, committed):
    paths = _checked_members(manifest)
    expected = paths | ({'manifest.json'} if committed else set())
    directories = {parent.as_posix() for name in paths for parent in PurePosixPath(name).parents if parent.as_posix() != '.'}
    observed = set()
    pending = [fs.safe(folder)]
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                child = fs.safe(entry.path)
                path = child.relative_to(folder).as_posix()
                if entry.is_dir(follow_symlinks=False):
                    if path not in directories:
                        raise InputError('unlisted export directory')
                    pending.append(child)
                elif path in expected:
                    observed.add(path)
                else:
                    raise InputError('unlisted export file')
    if observed != expected:
        raise InputError('export is incomplete or contains unavailable files')
    for item in manifest['files']:
        data = _read(folder / _relative(item['path']), item['bytes'])
        if len(data) != item['bytes'] or _hash(data) != item['sha256']:
            raise InputError('export member integrity mismatch')
        if manifest['content'] == 'metadata':
            _check_metadata(data)
    origin = manifest['origin']
    if manifest['content'] == 'private':
        state = folder / 'state'
        files, found = _private_files(state, origin['investigation_id'], origin['revision'])
        if found != origin or files.entries() != manifest['files']:
            raise InputError('export differs from the retained investigation dependencies')
        investigations.load(state, origin['investigation_id'], revision=origin['revision'])
    elif manifest['content'] == 'report':
        data = _read(folder / 'report.json', investigations.MAX_DOCUMENT)
        doc = json_value(data.decode('utf-8'), reject_duplicates=True)
        if (_hash(data) != origin['report_sha256'] or type(doc) is not dict
                or doc.get('investigation_id') != origin['investigation_id'] or doc.get('revision') != origin['revision']):
            raise InputError('exported report disagrees with its saved digest')


def _read_verified(folder, expected_sha256=None):
    folder = fs.safe(folder)
    marker = fs.safe(folder / 'manifest.json')
    if not marker.is_file():
        raise InputError('export is incomplete or the destination belongs to another file or folder')
    data = _read(marker, MAX_MANIFEST_BYTES)
    digest = _hash(data)
    if expected_sha256 is not None and expected_sha256 != digest:
        raise InputError('export manifest disagrees with its checked digest')
    manifest = json_value(data.decode('utf-8'), reject_duplicates=True)
    _verify_payload(folder, manifest, committed=True)
    if _read(marker, MAX_MANIFEST_BYTES) != data:
        raise InputError('export manifest changed during verification')
    return manifest, digest


def _receipt(folder, manifest, digest):
    return dict(status='verified', destination=str(folder), content=manifest['content'], files=len(manifest['files']),
        bytes=manifest['payload_bytes'], manifest_sha256=digest, replay_verified=manifest['content'] == 'private',
        replay_state_dir=str(folder / 'state') if manifest['content'] == 'private' else None, published=False)


def verify(destination, *, expected_sha256=None):
    folder = fs.safe(destination)
    manifest, digest = _read_verified(folder, expected_sha256)
    return _receipt(folder, manifest, digest)


def execute(state, identifier, destination, *, revision, content='private', draft=None, expected_sha256):
    from .case_retention import case_writers
    from .investigation_retention import writer
    from .windows_native import protect_directory

    state = fs.safe(state)
    target = _destination(state, destination)
    investigations.revision_folder(state, identifier, revision)
    if target.exists():
        manifest, digest = _read_verified(target)
        if manifest['content'] != content or _approval(state, identifier, target, revision, draft, manifest) != expected_sha256:
            raise InputError('destination already holds another export; review the preview')
        return dict(_receipt(target, manifest, digest), revision=revision, replayed=True)
    files, manifest = _selection(state, identifier, revision, content, draft)
    if _approval(state, identifier, target, revision, draft, manifest) != expected_sha256:
        raise InputError('export differs from the reviewed preview')
    if shutil.disk_usage(target.parent).free < files.total + 8 * 1024**2:
        raise InputError('not enough free space for the export')
    with ExitStack() as guards:
        guards.enter_context(writer(state, identifier))
        if files.cases:
            guards.enter_context(case_writers(state, files.cases))
        try:
            target.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise InputError('export destination is already being used') from exc
        protect_directory(target)
        for entry, source in files.records.values():
            output = fs.safe(target / _relative(entry['path']))
            output.parent.mkdir(parents=True, exist_ok=True)
            data = source if isinstance(source, bytes) else _read(source, entry['bytes'])
            if len(data) != entry['bytes'] or _hash(data) != entry['sha256']:
                raise InputError('export member changed after preview')
            _write_new(output, data)
        _verify_payload(target, manifest, committed=False)
        _write_new(target / 'manifest.json', fs.encode(manifest))
    return dict(_receipt(target, manifest, _hash(fs.encode(manifest))), revision=revision, replayed=False)
