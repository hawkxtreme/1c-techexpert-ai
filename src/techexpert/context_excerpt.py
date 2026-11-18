"""Local review of a bounded excerpt from pinned 1C source snapshots."""
from hashlib import sha256
import re
import unicodedata

from . import artifacts, context_fields, context_policy as policy, investigations, source_code, storage
from . import operation_state as fs
from .inputs import InputError, read_snapshot


KIND = 'context_excerpt'
PROFILE = 'context-excerpt-v1'
READER_CAPABILITY = 2
VIEW = 'reviewed-excerpt'
CATEGORY = 'reviewed_excerpt'
APPROVAL = 'review-approval.json'
REVOCATION = 'review-revocation.json'
MAX_TEXT_BYTES = 2048
MAX_LINES = 32
MAX_RAW_RANGE = 8192
CASE_MEMBER = re.compile(r's(?:[1-9]|[12][0-9]|3[0-2])')


class ApprovalRequired(InputError):
    pass


class ApprovalRevoked(InputError):
    pass


def _attachment(doc, label):
    found = next((row for row in doc['attachments'] if row['id'] == label), None)
    if found is None:
        raise InputError('selected source attachment is unavailable')
    return found


def _selection(state, doc, label, member, start, count):
    from .operations import _guard_dependency_paths

    if type(start) is not int or not 1 <= start <= 1000000 or type(count) is not int or not 1 <= count <= MAX_LINES:
        raise InputError('select a starting line and 1 to 32 complete lines')
    if type(member) is not str:
        raise InputError('select a saved source member')
    attachment = _attachment(doc, label)
    target = attachment['target_id']
    kind = attachment['kind']
    if kind == 'case' and CASE_MEMBER.fullmatch(member):
        _guard_dependency_paths(state, 'cases', target)
        report = storage.load_case(state, target)
        source = next((row for row in report['sources'] if row['id'] == member), None)
        if source is None or source['format'] != '1c-source-text-v1':
            raise InputError('select a saved case source containing 1C code')
        raw = read_snapshot(fs.safe(storage.case_source_path(state, target, member)), source_code.MAX_BYTES)
        digest = source['sha256']
        if len(raw) != source['size'] or sha256(raw).hexdigest() != digest:
            raise InputError('saved source no longer matches its snapshot')
        encoding = 'utf-8'
    elif kind == 'artifact':
        _guard_dependency_paths(state, 'artifacts', target)
        report, _ = artifacts.read_artifact_record(state, target)
        _, raw, digest, encoding = source_code.saved_member(state, report, member)
    else:
        raise InputError('select a retained 1C code attachment')
    if investigations._digest(report) != attachment['report_sha256']:
        raise InputError('selected source differs from its pinned report')

    rows = raw.splitlines(keepends=True)
    end = start + count - 1
    if end > len(rows):
        raise InputError('line selection exceeds the saved source')
    before = sum(len(rows[index]) for index in range(start - 1))
    segment = b''.join(rows[start-1:end])
    if len(segment) > MAX_RAW_RANGE:
        raise InputError('select a smaller source excerpt')
    codec = 'utf-8-sig' if start == 1 and encoding == 'utf-8' else encoding
    text = segment.decode(codec).replace('\r\n', '\n').replace('\r', '\n')
    proof = dict(attachment=label, kind=kind, material_id=target, report_sha256=attachment['report_sha256'],
                 member=member, encoding=encoding, first_line=start, last_line=end,
                 byte_start=before, byte_end=before + len(segment), sha256=digest,
                 excerpt_sha256=sha256(segment).hexdigest())
    return proof, text


def _clean(text, aliases):
    from .incident_drafts import EMAIL, GUID, IPV4, IPV6, SECRET, URL, WINDOWS_PATH

    if any((ord(char) < 32 and char not in '\t\n') or ord(char) == 127 or unicodedata.category(char) == 'Cf' for char in text):
        raise InputError('choose a plain text source range')
    if re.search(r'-----\s*(?:BEGIN|END)[^-\n]*PRIVATE KEY\s*-----', text, re.I):
        raise InputError('source range includes a private key block')
    text, secrets = SECRET.subn('[SECRET_REMOVED]', text)
    counts = {'secret': secrets} if secrets else {}
    for label, pattern, alias in (('url', URL, 'excerpt_url'), ('email', EMAIL, 'user'),
                                  ('path', WINDOWS_PATH, 'excerpt_path'), ('identifier', GUID, 'excerpt_id'),
                                  ('ipv4', IPV4, 'excerpt_ip'), ('ipv6', IPV6, 'excerpt_ip')):
        text, count = pattern.subn(lambda match: aliases(alias, match[0]) or '[VALUE_REMOVED]', text)
        if count:
            counts[label] = count
    data = text.encode('utf-8')
    if not text.strip() or len(data) > MAX_TEXT_BYTES:
        raise InputError('select a nonempty excerpt of at most 2048 UTF-8 bytes')
    return data, counts


def _metadata(report):
    label = 'A-excerpt-' + report['artifact_id']
    return dict(artifact_id=report['artifact_id'], review_sha256=investigations._digest(report),
                attachment=dict(id=label, kind='artifact', target_id=report['artifact_id']))


def prepare(state, investigation_id, revision, *, attachment, member, start, lines):
    state = fs.safe(state)
    doc = policy.selected_investigation(state, investigation_id, revision)
    scope, _ = policy.scope(doc)
    folder = policy.policy_folder(state, scope)
    saved = policy.stored_policy(folder, scope)
    if saved is None or saved['rule_version'] != policy.RULE_VERSION:
        raise InputError('save the current environment policy before preparing a review')
    binding = dict(investigation_id=investigation_id, scope_sha256=scope, policy_sha256=fs.digest(saved))
    policy.verify_delivery(state, binding)
    proof, text = _selection(state, doc, attachment, member, start, lines)
    body, redactions = _clean(text, context_fields.Aliases(saved['alias_key'], investigation_id))
    with fs.writer(folder):
        policy.verify_delivery(state, binding)
        fs.safe(state/'artifacts')
        report = artifacts.save_artifact(state, KIND, dict(investigation_id=investigation_id, revision=revision),
            [('review.txt', body)], dict(profile=PROFILE, binding=binding, investigation_revision=revision,
            investigation_sha256=investigations._digest(doc), source=proof, redactions=redactions),
            source_names=['review.txt'])
    path = artifacts.source_path(artifacts.artifact_folder(state, report['artifact_id']), report['sources'][0], kind=KIND)
    return dict(_metadata(report), status='review_required', preview_path=str(path), source=proof,
                text_sha256=sha256(body).hexdigest(), text_bytes=len(body), redactions=redactions)


def _report(state, artifact_id):
    fs.safe(artifacts.artifact_folder(state, artifact_id))
    report, _ = artifacts.read_artifact_record(state, artifact_id)
    if (report['kind'] != KIND or report['result'].get('profile') != PROFILE or len(report['sources']) != 1 or
            artifacts.source_name(report['sources'][0], kind=KIND) != 'review.txt'):
        raise InputError('select a saved source excerpt review')
    return report


def _body(state, report):
    source = report['sources'][0]
    path = artifacts.source_path(artifacts.artifact_folder(state, report['artifact_id']), source, kind=KIND)
    data = read_snapshot(path, MAX_TEXT_BYTES)
    if len(data) != source['bytes'] or sha256(data).hexdigest() != source['sha256']:
        raise InputError('local preview changed; prepare a fresh excerpt')
    return data


def _verify_source_binding(doc, report):
    binding = report['result']['binding']
    source = report['result']['source']
    item = _attachment(doc, source['attachment'])
    if (doc['investigation_id'] != binding['investigation_id'] or policy.scope(doc)[0] != binding['scope_sha256'] or
            (item['kind'], item['target_id'], item['report_sha256']) != (source['kind'], source['material_id'], source['report_sha256'])):
        raise InputError('source excerpt belongs to a different investigation or source')


def _event(folder, name, artifact_id, digest, status):
    try:
        receipt = fs.read(folder / name, 8192)
    except FileNotFoundError:
        return None
    record = receipt['record']
    if (receipt['sha256'] != fs.digest(record) or type(record['schema_version']) is not int or
            record['schema_version'] != 1 or record['status'] != status or record['artifact_id'] != artifact_id or
            record['review_sha256'] != digest):
        raise InputError('excerpt review receipt does not match the reviewed material')
    return record


def require_approval(state, artifact_id, review_sha256):
    folder = artifacts.artifact_folder(state, artifact_id)
    approval = _event(folder, APPROVAL, artifact_id, review_sha256, 'approved')
    if _event(folder, REVOCATION, artifact_id, review_sha256, 'revoked') is not None:
        raise ApprovalRevoked('The reviewed excerpt was revoked.')
    if approval is None:
        raise ApprovalRequired('Review the exact local preview and confirm its digest.')
    return approval


def approve(state, artifact_id, expected_sha256):
    state = fs.safe(state)
    report = _report(state, artifact_id)
    meta = _metadata(report)
    if expected_sha256 != meta['review_sha256']:
        raise InputError('exact reviewed excerpt digest required')
    details = report['result']
    binding = details['binding']
    iid = binding['investigation_id']
    folder = artifacts.artifact_folder(state, artifact_id)
    policy_folder = policy.policy_folder(state, binding['scope_sha256'])
    policy.verify_delivery(state, binding)
    with fs.writer(policy_folder), fs.writer(folder):
        policy.verify_delivery(state, binding)
        preview = policy.selected_investigation(state, iid, details['investigation_revision'])
        if investigations._digest(preview) != details['investigation_sha256']:
            raise InputError('the reviewed investigation revision changed')
        head = investigations._read_head(state, iid)
        _verify_source_binding(policy.selected_investigation(state, iid, head['revision']), report)
        body = _body(state, report)
        try:
            existing = require_approval(state, artifact_id, expected_sha256)
        except ApprovalRequired:
            source = details['source']
            proof, text = _selection(state, preview, source['attachment'], source['member'], source['first_line'],
                                     source['last_line'] - source['first_line'] + 1)
            saved = policy.stored_policy(policy_folder, binding['scope_sha256'])
            checked, redactions = _clean(text, context_fields.Aliases(saved['alias_key'], iid))
            if proof != source or checked != body or redactions != details['redactions']:
                raise InputError('reviewed excerpt differs from the retained selected source')
            policy.verify_delivery(state, binding)
            existing = dict(schema_version=1, status='approved', artifact_id=artifact_id, review_sha256=expected_sha256,
                            text_sha256=sha256(body).hexdigest(), approved_at=fs.stamp())
            fs.write(folder / APPROVAL, dict(record=existing, sha256=fs.digest(existing)))
        if existing['text_sha256'] != sha256(body).hexdigest():
            raise InputError('approved excerpt text changed')
    return dict(meta, status='approved', text_sha256=existing['text_sha256'], approved_at=existing['approved_at'])


def revoke(state, artifact_id, expected_sha256):
    state = fs.safe(state)
    report = _report(state, artifact_id)
    if investigations._digest(report) != expected_sha256:
        raise InputError('exact reviewed excerpt digest required')
    folder = artifacts.artifact_folder(state, artifact_id)
    with fs.writer(folder):
        record = _event(folder, REVOCATION, artifact_id, expected_sha256, 'revoked')
        if record is None:
            record = dict(schema_version=1, status='revoked', artifact_id=artifact_id,
                          review_sha256=expected_sha256, revoked_at=fs.stamp())
            fs.write(folder / REVOCATION, dict(record=record, sha256=fs.digest(record)))
    return record


def read_view(state, doc, attachment, saved):
    artifact_id = attachment['target_id']
    reviewed = require_approval(state, artifact_id, attachment['report_sha256'])
    report = _report(state, artifact_id)
    if investigations._digest(report) != attachment['report_sha256']:
        raise InputError('excerpt report differs from the reviewed attachment')
    details = report['result']
    _verify_source_binding(doc, report)
    if details['binding']['policy_sha256'] != fs.digest(saved):
        raise InputError('reviewed excerpt belongs to a different disclosure policy')
    body = _body(state, report)
    if sha256(body).hexdigest() != reviewed['text_sha256']:
        raise InputError('approved excerpt text changed')
    return dict(text=body.decode('utf-8'), text_sha256=reviewed['text_sha256'], source=details['source'],
                redactions=details['redactions'], untrusted_source_content=True,
                running_source_correspondence='not_established')
