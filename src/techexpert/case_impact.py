"""Bounded observations of saved investigation and comparison dependencies."""
import os
from pathlib import Path
import re
import stat

from . import investigation_materials as materials, investigations, operation_state as fs, storage
from .inputs import InputError

_ID = re.compile(r'[a-f0-9]{32}')
MAX_IMPACT_BYTES = 448 * 1024


def _locations(root):
    try:
        entries = os.scandir(fs.safe(root))
    except FileNotFoundError:
        return []
    folders = []
    with entries:
        for entry in entries:
            if len(folders) >= materials.MAX_ROWS:
                raise InputError('saved dependency inventory exceeds its entry bound')
            if not _ID.fullmatch(entry.name) or not stat.S_ISDIR(fs.safe(entry.path).lstat().st_mode):
                raise InputError('cannot determine dependencies of an unknown saved product')
            folders.append(Path(entry.path))
    return sorted(folders)


def _require(inventory, folder, *names):
    if not inventory.metadata(folder, {}, [(name, 'metadata') for name in names]):
        raise InputError('saved dependency metadata is unavailable; review the affected reports')


def observed(state, case, file_digest, source_id):
    """Find affected committed uses and pin their report digests for review."""
    inventory = materials.Inventory()
    comparisons = []
    comparison_digests = {}
    budget = MAX_IMPACT_BYTES

    def add(rows, row):
        nonlocal budget
        budget -= len(fs.encode(row))
        if budget < 0:
            raise InputError('saved dependency impact exceeds the review limit')
        rows.append(row)

    for folder in _locations(state / 'comparisons'):
        _require(inventory, folder, 'report.json', 'report.md', 'receipt.json')
        report, digest = storage.read_comparison_record(state, folder.name)
        references = materials._inputs('comparison', report)
        matched = [expected for key, _, expected in references if key == ('case', case['case_id'])]
        if not matched:
            continue
        if any(expected != file_digest for expected in matched):
            raise InputError('saved comparison refers to a different case digest')
        add(comparisons, dict(id=folder.name, report_sha256=digest))
        comparison_digests[folder.name] = investigations._digest(report)

    affected = []
    case_digest = investigations._digest(case)
    for folder in _locations(state / 'investigations'):
        _require(inventory, folder, 'head.json')
        head = investigations._read_head(state, folder.name)
        if type(head) is not dict or type(head.get('revision')) is not int:
            raise InputError('saved investigation head is invalid')
        investigations.revision_folder(state, folder.name, head['revision'])
        for number in range(1, head['revision'] + 1):
            revision = investigations.revision_folder(state, folder.name, number)
            _require(inventory, revision, 'report.json', 'report.md', 'receipt.json')
        for doc in investigations._revision_chain(state, folder.name, head, None):
            direct, derived = [], []
            for attachment in doc['attachments']:
                kind, identifier = attachment['kind'], attachment['target_id']
                if (kind, identifier) == ('case', case['case_id']):
                    if attachment['report_sha256'] != case_digest:
                        raise InputError('saved investigation refers to a different case digest')
                    direct.append(attachment['id'])
                if kind == 'comparison' and identifier in comparison_digests:
                    if attachment['report_sha256'] != comparison_digests[identifier]:
                        raise InputError('saved investigation refers to a different comparison digest')
                    derived.append(attachment['id'])
            if not (direct or derived):
                continue
            counts, uses = materials._uses(doc, limit=None)
            evidence = [dict(evidence_id=item['id'], attachment_id=item['attachment'], record=item['record'],
                             used_by=uses[item['id']], use_count=counts[item['id']])
                        for item in doc['evidence'] if item['attachment'] in derived or (
                            item['attachment'] in direct and item['record'].partition(':')[0] == source_id)]
            add(affected, dict(investigation_id=folder.name, revision=doc['revision'],
                               report_sha256=investigations._digest(doc), attachments=direct + derived,
                               evidence=evidence))
    return dict(comparisons=comparisons, investigations=affected,
                scope='saved_case_and_comparison_attachments', case_reverification_lost=True)
