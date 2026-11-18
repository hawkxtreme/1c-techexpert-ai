"""Read-only inventory of committed investigation revisions and retained evidence."""
from collections import defaultdict, deque
import re
import stat

from . import artifacts, investigations, operation_state as fs, storage
from .inputs import InputError, MAX_FILE_BYTES

CATEGORIES = ('reports', 'copies', 'metadata', 'evidence', 'working_copies', 'indexes')
PRODUCTS = {
    'case': (storage.case_folder, 'manifest.json', storage.load_case),
    'artifact': (artifacts.artifact_folder, 'request.json', artifacts.read_artifact_record),
    'comparison': (storage.comparison_folder, 'report.md', storage.read_comparison_record),
}
MAX_ROWS = 8192
MAX_METADATA_BYTES = 64 * 1024**2
MAX_USES_PER_EVIDENCE = 32


class Inventory:
    def __init__(self):
        self.rows = []
        self.metadata_bytes = 0
        self.issues = defaultdict(int)

    def append(self, row):
        if len(self.rows) >= MAX_ROWS:
            raise InputError('materials inventory exceeds the entry limit; select an earlier revision')
        self.rows.append(row)
        return row

    def file(self, path, category, owner, *, expected=None):
        size = None
        try:
            info = fs.safe(path).lstat()
            if not stat.S_ISREG(info.st_mode):
                status = 'unavailable'
            else:
                size = info.st_size
                status = 'size_mismatch' if expected is not None and size != expected else 'present'
        except FileNotFoundError:
            status = 'missing'
        except (OSError, InputError):
            status = 'unavailable'
        return self.append(dict(owner, category=category, path=str(path),
                                status=status, bytes=size, expected_bytes=expected))

    def metadata(self, folder, owner, members):
        records = [self.file(folder / name, category, owner) for name, category in members]
        self.reserve_metadata(sum(row['bytes'] or 0 for row in records))
        return all(row['status'] == 'present' for row in records)

    def reserve_metadata(self, size):
        self.metadata_bytes += size
        if self.metadata_bytes > MAX_METADATA_BYTES:
            raise InputError('materials inventory exceeds the metadata byte limit; select an earlier revision')

    def read_metadata(self, path, limit):
        info = fs.safe(path).lstat()
        if not stat.S_ISREG(info.st_mode):
            raise InputError('regular workspace metadata file required')
        self.reserve_metadata(info.st_size)
        return fs.read(path, limit)


def _target(kind, identifier):
    if kind not in PRODUCTS or not isinstance(identifier, str) or not re.fullmatch('[a-f0-9]{32}', identifier):
        raise InputError('invalid investigation material reference')
    return kind, identifier


def _binding(kind, identifier, basis, digest):
    if not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest):
        raise InputError('invalid saved material digest')
    return _target(kind, identifier), basis, digest


def _source_members(folder, kind, report):
    if kind == 'comparison':
        return []
    sources = report['sources']
    if type(sources) is not list or len(sources) > 32:
        raise InputError('invalid saved material source list')
    rows = []
    for index, source in enumerate(sources, 1):
        if type(source) is not dict or source.get('id') != f's{index}':
            raise InputError('invalid saved material source identity')
        if kind == 'artifact':
            name, size = artifacts.source_name(source, kind=report['kind']), source['bytes']
        else:
            name, size = f's{index}.bin', source.get('size')
        if size is not None and (type(size) is not int or not 0 <= size <= MAX_FILE_BYTES):
            raise InputError('invalid saved material source length')
        rows.append((folder / 'sources' / name, size))
    return rows


def _inputs(kind, report):
    if kind == 'comparison':
        references = report['input_reports']
        if type(references) is not list or not 1 <= len(references) <= 40:
            raise InputError('invalid saved comparison material list')
        return [_binding('case', item['case_id'], 'file', item['sha256']) for item in references]
    details = report if kind == 'case' else report['result']
    if type(details) is not dict:
        raise InputError('invalid saved material result')
    result = []
    if 'input_intake' in details:
        intake = details['input_intake']
        result.append(_binding('artifact', intake['artifact_id'], 'normalized', intake['plan_report_digest']))
    if kind == 'artifact' and report['kind'] == 'source_export' and details.get('source_artifact_id') is not None:
        result.append(_binding('artifact', details['source_artifact_id'], 'file', details['source_artifact_report_sha256']))
    return result


def _uses(doc, *, limit=MAX_USES_PER_EVIDENCE):
    counts = defaultdict(int)
    pairs = defaultdict(list)
    hypotheses = {item['id']: item['evidence'] for item in doc['hypotheses']}

    def append(reference, kind, identity=None):
        counts[reference] += 1
        if limit is None or len(pairs[reference]) < limit:
            pairs[reference].append(dict(kind=kind) if identity is None else dict(kind=kind, id=identity))

    for field, kind in (('facts', 'fact'), ('hypotheses', 'hypothesis'), ('contradictions', 'contradiction')):
        for item in doc[field]:
            references = item['evidence'] + [reference for identity in item.get('hypotheses', [])
                                             for reference in hypotheses[identity]]
            for reference in dict.fromkeys(references):
                append(reference, kind, item['id'])
    for field in ('assessment', 'improvement', 'observation_plan', 'occurrence'):
        item = doc.get(field) or {}
        references = item.get('evidence', []) + hypotheses.get(item.get('hypothesis_id'), [])
        for reference in dict.fromkeys(references):
            append(reference, field)
    for item in (doc.get('assessment') or {}).get('recommendations', []):
        references = (reference for identity in item['basis'] for reference in hypotheses.get(identity, [identity]))
        for reference in dict.fromkeys(references):
            append(reference, 'recommendation', item['id'])
    return counts, pairs


def _revision_links(inventory, doc):
    attachments = {}
    for item in doc['attachments']:
        attachments[item['id']] = _binding(item['kind'], item['target_id'], 'attachment', item['report_sha256'])
    counts, uses = _uses(doc)
    for item in doc['evidence']:
        kind, identifier = attachments[item['attachment']][0]
        inventory.append(dict(category='evidence', revision=doc['revision'], evidence_id=item['id'],
                              product_kind=kind, product_id=identifier, attachment_id=item['attachment'],
                              record=item['record'], used_by=uses[item['id']], use_count=counts[item['id']]))
    return attachments.values()


def _read_product(state, inventory, key):
    kind, identifier = key
    resolve, member, read = PRODUCTS[kind]
    folder = resolve(state, identifier)
    owner = dict(product_kind=kind, product_id=identifier)
    members = [('report.json', 'reports'), ('receipt.json', 'metadata'),
               (member, 'reports' if member == 'report.md' else 'metadata')]
    if not inventory.metadata(folder, owner, members):
        return None
    try:
        if kind == 'case':
            report, digest = read(state, identifier, with_digest=True)
        else:
            report, digest = read(state, identifier)
        hashes = dict(file=digest, attachment=investigations._digest(report), normalized=fs.digest(report))
        files, inputs = _source_members(folder, kind, report), _inputs(kind, report)
        working = None
        if kind == 'artifact' and report['kind'] == 'source_export' and report['result'].get('status') == 'completed':
            working = report['result']['private_working_copy']
        return hashes, files, inputs, working
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return None


def _working_copy(state, inventory, artifact_id, report_sha, working):
    from .export_retention import locate_working_copy
    try:
        plan, target, cleanup = locate_working_copy(state, artifact_id, report_sha, working,
                                                    read=inventory.read_metadata)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        inventory.issues['export_workspace_unavailable'] += 1
        return
    row = inventory.file(target, 'working_copies',
                         dict(product_kind='artifact', product_id=artifact_id, export_plan_id=plan))
    if cleanup is None:
        return
    row['cleanup'] = cleanup
    if cleanup['status'] == 'outcome_unverified':
        row.update(status='removal_unverified', bytes=None)
    elif cleanup['current_file_status'] == 'absent' and row['status'] == 'missing':
        row['status'] = 'removed'
    elif cleanup['current_file_status'] == 'path_reoccupied' or row['status'] == 'present':
        row.update(status='path_reoccupied', bytes=None)
    else:
        row.update(status='unavailable', bytes=None)


def _including_dependents(selected, parents):
    queue = deque(selected)
    while queue:
        for parent in parents[queue.popleft()]:
            if parent not in selected:
                selected.add(parent)
                queue.append(parent)
    return selected


def _case_index(state, inventory, owner, source_id):
    from .case_event_index import path_for
    try:
        path = path_for(state, owner['product_id'], source_id)
        path.lstat()
    except FileNotFoundError:
        return
    except (OSError, InputError):
        inventory.issues['case_index_unavailable'] += 1
        return
    entry = inventory.file(path, 'indexes', dict(owner, source_id=source_id))
    entry.update(rebuild_requires='verified_saved_source', evidence_dependency=False)


def _products(state, inventory, queue):
    from .case_retention import status as case_retirement
    visited = {}
    expanded = set()
    validated = set()
    parents = defaultdict(set)
    source_owners = set()
    unavailable = set()
    retirements = []
    while queue:
        link = queue.popleft()
        if link in validated:
            continue
        validated.add(link)
        key, basis, expected = link
        if key not in visited:
            visited[key] = _read_product(state, inventory, key)
        record = visited[key]
        if record is None:
            inventory.issues['product_record_unavailable'] += 1
            unavailable.add(key)
            continue
        hashes, files, children, working = record
        if hashes[basis] != expected:
            inventory.issues['product_binding_mismatch'] += 1
            unavailable.add(key)
            continue
        if key in expanded:
            continue
        expanded.add(key)
        owner = dict(product_kind=key[0], product_id=key[1])
        if files:
            source_owners.add(key)
        for path, size in files:
            row = inventory.file(path, 'copies', owner, expected=size)
            if key[0] == 'case':
                _case_index(state, inventory, owner, path.stem)
                try:
                    retirement = case_retirement(state, key[1], path.stem, read=inventory.read_metadata)
                except (OSError, ValueError, KeyError, TypeError, RecursionError):
                    inventory.issues['case_snapshot_retirement_unavailable'] += 1
                    row.update(status='unavailable', bytes=None)
                    retirement = None
                if retirement is not None:
                    retirements.append(retirement)
                    row.update(status='retired' if retirement['status'] == 'removed' else 'removal_unverified',
                               bytes=None, retirement={name: retirement[name] for name in
                                   ('status', 'plan_sha256', 'current_file_status', 'logical_bytes_removed')})
            if row['status'] != 'present':
                unavailable.add(key)
        if working is not None:
            _working_copy(state, inventory, key[1], hashes['file'], working)
        for child, _, _ in children:
            parents[child].add(key)
        queue.extend(children)
    return len(visited), _including_dependents(source_owners, parents), _including_dependents(unavailable, parents), retirements


def view(state, investigation_id, *, revision=None, category=None, offset=0, limit=60):
    if category is not None and category not in CATEGORIES:
        raise InputError('unknown investigation materials category')
    if type(offset) is not int or not 0 <= offset <= MAX_ROWS or type(limit) is not int or not 1 <= limit <= 100:
        raise InputError('materials offset and page size are out of range')
    state = fs.safe(state)
    from .investigation_retention import status as report_status
    retired = report_status(state, investigation_id)
    if retired is not None:
        return retired
    location = investigations.revision_folder(state, investigation_id, 1).parent.parent
    inventory = Inventory()
    owner = dict(product_kind='investigation', product_id=investigation_id)
    if not inventory.metadata(location, owner, [('head.json', 'metadata')]):
        raise InputError('investigation head is unavailable')
    head = investigations._read_head(state, investigation_id)
    if type(head) is not dict or type(head.get('revision')) is not int:
        raise InputError('invalid investigation head')
    selected = head['revision'] if revision is None else revision
    investigations.revision_folder(state, investigation_id, selected)
    if selected > head['revision']:
        raise InputError('investigation revision not committed')
    for number in range(selected, 0, -1):
        folder = investigations.revision_folder(state, investigation_id, number)
        if not inventory.metadata(folder, dict(owner, revision=number),
                                  [('report.json', 'reports'), ('report.md', 'reports'), ('receipt.json', 'metadata')]):
            raise InputError('committed investigation revision files are unavailable')
    queue = deque()
    revision_digests = {}
    for doc in investigations._revision_chain(state, investigation_id, head, selected):
        queue.extend(_revision_links(inventory, doc))
        revision_digests[doc['revision']] = investigations._digest(doc)
    products, depends_on_copies, unavailable, retirements = _products(state, inventory, queue)
    lost = defaultdict(list)
    for item in retirements:
        for revision in item['impact']['investigations']:
            if (revision['investigation_id'] == investigation_id
                    and revision_digests.get(revision['revision']) == revision['report_sha256']):
                for evidence in revision['evidence']:
                    lost[revision['revision'], evidence['evidence_id']].append(dict(case_id=item['case_id'],
                        source_id=item['source_id'], status=item['status'], plan_sha256=item['plan_sha256']))
    fs.safe(location / 'head.json')
    if investigations._read_head(state, investigation_id) != head:
        raise InputError('investigation head changed during inventory; reload before relying on the view')
    categories = {name: dict(files=0, observed_bytes=0, unavailable=0, references=0) for name in CATEGORIES}
    categories['copies']['dependent_evidence'] = 0
    for row in inventory.rows:
        summary = categories[row['category']]
        if row['category'] == 'evidence':
            # Evidence links are stored in reports, so they add no separate bytes.
            product = row['product_kind'], row['product_id']
            if product in depends_on_copies:
                row['depends_on_copies'] = True
                categories['copies']['dependent_evidence'] += 1
            else:
                row['depends_on_copies'] = None if product in unavailable else False
            row['material_status'] = 'unavailable_dependency' if product in unavailable else 'present'
            affected = lost.get((row['revision'], row['evidence_id']))
            if affected:
                row['retired_sources'] = affected
                row['material_status'] = ('retired_dependency' if all(item['status'] == 'removed' for item in affected)
                                          else 'retirement_unverified')
            summary['unavailable'] += product in unavailable
            summary['references'] += 1
        else:
            summary['files'] += 1
            summary['observed_bytes'] += row['bytes'] or 0
            summary['unavailable'] += row['status'] not in ('present', 'removed')
    rows = [row for row in inventory.rows if category is None or row['category'] == category]
    page = rows[offset:offset + limit]
    result = dict(schema_version=1, investigation_id=investigation_id, investigation_path=str(location),
                  through_revision=selected, head_revision=head['revision'], products=products,
                  categories=categories, category=category, entries=page, entry_count=len(rows),
                  next_offset=offset + limit if offset + limit < len(rows) else None,
                  issues=dict(inventory.issues),
                  status='partial' if inventory.issues or any(v['unavailable'] for v in categories.values()) else 'observed',
                  scope='committed revision files, attachments, supported sealed input links and linked export working databases',
                  source_byte_integrity='not_rechecked',
                  size_basis='logical_file_lengths_at_observation',
                  evidence_basis='saved_reference_and_uses')
    if len(fs.encode(result)) > 512 * 1024:
        raise InputError('materials page exceeds its output limit; request fewer entries')
    return result
