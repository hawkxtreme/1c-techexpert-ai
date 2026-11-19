"""Private editorial revisions derived from an exact incident preview."""
import html
from pathlib import Path
import re

from . import incident_drafts, knowledge, operation_state as fs
from .inputs import InputError


REQUEST_LIMIT = 128 * 1024
DOCUMENT_LIMIT = 2 * 1024**2
MAX_REVISIONS = 32
ACTIONS = ('read', 'automated_retrieval', 'local_storage', 'adaptation', 'external_model_transfer', 'publication')
ALLOWED = ('allowed', 'allowed_with_conditions')
RIGHTS = (*ALLOWED, 'link_only', 'needs_clarification', 'excluded', 'not_requested')
EXCERPT = re.compile(r'evidence/(E-[A-F0-9]{12})\.txt\Z')


def _fields(value, required, optional=(), *, label):
    if not isinstance(value, dict) or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise InputError(f'invalid {label} fields')


def _schema(request):
    if type(request['schema_version']) is not int or request['schema_version'] != 1:
        raise InputError('unsupported knowledge proposal request')


def _hex(value, pattern, label):
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise InputError(f'invalid {label}')
    return value


def _text(value, limit):
    value = knowledge._text(value, limit)
    if not value.strip():
        raise InputError('knowledge proposal text must not be blank')
    return value


def _folder(state):
    return fs.safe(Path(state) / 'knowledge-proposals')


def _load(path):
    document = fs.read(path, DOCUMENT_LIMIT)
    try:
        entries = document['revisions']
        if (document['schema_version'] != 1 or document['proposal_id'] != path.stem
                or fs.digest(document['origin']) != path.stem
                or not isinstance(entries, list) or not 1 <= len(entries) <= MAX_REVISIONS):
            raise ValueError
        parent = None
        for number, entry in enumerate(entries, 1):
            record = entry['record']
            preview = record['source_preview']
            if (record['revision'] != number or record['parent_sha256'] != parent
                    or record['card']['status'] != 'draft' or fs.digest(record) != entry['sha256']
                    or any(preview[key] != value for key, value in document['origin'].items())):
                raise ValueError
            parent = entry['sha256']
            receipt = entry['review']
            if receipt is not None and (receipt['record']['proposal_sha256'] != parent
                                        or fs.digest(receipt['record']) != receipt['sha256']):
                raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise InputError('knowledge proposal integrity mismatch') from exc
    return document


def _save(path, document):
    if len(fs.encode(document)) > DOCUMENT_LIMIT:
        raise InputError('knowledge proposal exceeds retained document limit')
    fs.write(path, document)


def _view(document, entry, *, replayed=False):
    receipt = entry['review']
    return dict(entry['record'], proposal_id=document['proposal_id'], proposal_sha256=entry['sha256'],
                editorial_review=None if receipt is None else dict(receipt['record'], review_sha256=receipt['sha256']),
                replayed=replayed, catalogue_updated=False)


def show(state, proposal_id, *, revision=None):
    _hex(proposal_id, '[a-f0-9]{64}', 'knowledge proposal ID')
    document = _load(_folder(state) / (proposal_id + '.json'))
    entries = document['revisions']
    if revision is None:
        revision = len(entries)
    if type(revision) is not int or not 1 <= revision <= len(entries):
        raise InputError('unknown knowledge proposal revision')
    return _view(document, entries[revision - 1])


def _checks(items, claims, preview):
    if not isinstance(items, list) or len(items) != len(claims):
        raise InputError('each knowledge claim requires a verification procedure')
    evidence = {match[1] for item in preview['files'] if (match := EXCERPT.fullmatch(item['path']))}
    checks = {}
    for item in items:
        _fields(item, ('claim_id', 'procedure', 'expected'), ('evidence_ids',), label='claim check')
        cid = item['claim_id']
        if not isinstance(cid, str) or cid not in claims or cid in checks:
            raise InputError('unexpected or repeated claim check')
        ids = knowledge._ids(item.get('evidence_ids', []), 10)
        if set(ids) - evidence:
            raise InputError('claim evidence must refer to an excerpt in the verified preview')
        checks[cid] = dict(claim_id=cid, procedure=_text(item['procedure'], 2048),
                           expected=_text(item['expected'], 1024), evidence_ids=ids)
    return checks


def _inline(value):
    return re.sub(r'([\\`*_[\]{}!])', r'\\\1', html.escape(' '.join(value.split()), quote=False))


def _body(card, result, checks, sources):
    lines = [f"# {_inline(card['title'])}", '', _inline(card['applicability']), '', _inline(result)]
    for claim in card['claims']:
        check = checks[claim['id']]
        status = 'По источнику' if claim['status'] == 'documented' else 'Гипотеза'
        citations = ' '.join(f"<{sources[sid]['url']}>" for sid in claim['sources'])
        lines.extend(['', f"## {status}. {_inline(claim['text'])}", '', _inline(claim['applicability']),
                      '', _inline(check['procedure']), '', f"Ожидается {_inline(check['expected'])}"])
        if citations:
            lines.extend(['', citations])
    body = '\n'.join(lines) + '\n'
    if len(body.encode('utf-8')) > 64 * 1024:
        raise InputError('knowledge proposal card exceeds body limit')
    return body


def _source_metadata(source):
    permitted = ('id', 'url', 'title', 'author', 'publisher', 'rights_holder', 'date', 'version', 'section',
                 'access', 'checked_at', 'link', 'rights', 'lifecycle')
    return {key: source[key] for key in permitted if key in source}


def _candidate(state, request, document, library, request_sha256):
    preview = incident_drafts.preview(state, request['draft_id'])
    if preview['preview_sha256'] != request['expected_preview_sha256']:
        raise InputError('incident preview changed; inspect the current preview')
    source_preview = dict(document['origin'], revision=preview['revision'],
                          files=[{key: item[key] for key in ('path', 'bytes', 'sha256')} for item in preview['files']])
    claims = request['claims']
    if not isinstance(claims, list) or not 1 <= len(claims) <= 16:
        raise InputError('knowledge proposal requires 1..16 claims')
    sources = set()
    for claim in claims:
        if not isinstance(claim, dict):
            raise InputError('invalid knowledge claim')
        sources.update(knowledge._ids(claim.get('sources'), 8))
    if len(sources) > 16 or sources - library['sources'].keys():
        raise InputError('unregistered or too many knowledge proposal sources')
    related = knowledge._ids(request.get('related', []), 16)
    if set(related) - {card['id'] for card in library['cards']}:
        raise InputError('unregistered related knowledge card')
    environment = knowledge.validate_environment(request.get('environment'))
    revisions = document['revisions']
    card_id = 'CASE-' + document['proposal_id']
    created_at = fs.stamp()
    title = _text(preview['title'].removeprefix('[Кейс] '), 512)
    card = dict(id=card_id, title=title, path=f'cases/{card_id}.md', type='case', status='draft',
                author=_text(request['author'], 256), date=created_at[:10], revision=len(revisions) + 1,
                applicability=_text(request['applicability'], 2048), signs=[title], steps=[],
                applicability_constraints={key: [value] for key, value in environment.items() if value != 'unknown'},
                sources=sorted(sources), related=related, claims=claims,
                evidence_basis='Редакционный черновик по обезличенному предпросмотру с проверками по утверждениям.')
    knowledge.validate_card_annotations(card)
    if any(not claim['text'].strip() or not claim['applicability'].strip() for claim in claims):
        raise InputError('knowledge proposal claims must describe the statement and where it applies')
    checks = _checks(request['checks'], {claim['id'] for claim in claims}, preview)
    card['steps'] = [checks[claim['id']]['procedure'] for claim in claims]
    selected = {sid: _source_metadata(library['sources'][sid]) for sid in card['sources']}
    body = _body(card, _text(request['result'], 4096), checks, selected)
    return dict(revision=card['revision'], created_at=created_at, request_sha256=request_sha256,
                parent_sha256=revisions[-1]['sha256'] if revisions else None, source_preview=source_preview,
                knowledge_revision=library['revision'], knowledge_digest=library['digest'],
                card=card, body=body, checks=list(checks.values()), sources_metadata=selected)


def prepare(state, request, *, root=None):
    _fields(request, ('schema_version', 'draft_id', 'expected_preview_sha256', 'expected_knowledge_digest',
                      'author', 'applicability', 'result', 'claims', 'checks'),
            ('environment', 'related', 'expected_proposal_sha256'), label='knowledge proposal')
    _schema(request)
    origin = dict(draft_id=_hex(request['draft_id'], '[a-f0-9]{32}', 'incident draft ID'),
                  preview_sha256=_hex(request['expected_preview_sha256'], '[a-f0-9]{64}', 'incident preview digest'))
    knowledge_digest = _hex(request['expected_knowledge_digest'], '[a-f0-9]{64}', 'expected knowledge digest')
    expected = request.get('expected_proposal_sha256')
    if 'expected_proposal_sha256' in request:
        _hex(expected, '[a-f0-9]{64}', 'expected proposal digest')
    proposal_id = fs.digest(origin)
    folder = fs.private(_folder(state))
    path = folder / (proposal_id + '.json')
    request_sha256 = fs.digest(request)
    with fs.writer(folder):
        try:
            document = _load(path)
        except FileNotFoundError:
            document = dict(schema_version=1, proposal_id=proposal_id, origin=origin, revisions=[])
        entries = document['revisions']
        for entry in entries:
            if entry['record']['request_sha256'] == request_sha256:
                return _view(document, entry, replayed=True)
        if entries and expected is None:
            raise InputError('knowledge proposal already exists; specify the displayed proposal digest to edit it')
        if expected is not None and (not entries or entries[-1]['sha256'] != expected):
            raise InputError('knowledge proposal revision changed; inspect the current proposal')
        if len(entries) == MAX_REVISIONS:
            raise InputError('knowledge proposal revision limit reached')
        library = knowledge.load_library(root, expected_knowledge_digest=knowledge_digest)
        record = _candidate(state, request, document, library, request_sha256)
        entry = dict(record=record, sha256=fs.digest(record), review=None)
        entries.append(entry)
        _save(path, document)
        return _view(document, entry)


def _claim_decisions(items, claims, accepted):
    if not isinstance(items, list) or len(items) != len(claims):
        raise InputError('review requires a decision for each claim')
    decisions = {}
    for item in items:
        _fields(item, ('id', 'outcome', 'result'), label='claim review')
        cid, outcome = item['id'], item['outcome']
        if (not isinstance(cid, str) or cid not in claims or cid in decisions
                or outcome not in ('supported', 'hypothesis', 'unresolved')):
            raise InputError('invalid claim review decision')
        if accepted and outcome != ('supported' if claims[cid] == 'documented' else 'hypothesis'):
            raise InputError('claim review has unresolved findings or changes a hypothesis without revision')
        decisions[cid] = dict(id=cid, outcome=outcome, result=_text(item['result'], 2048))
    return list(decisions.values())


def _rights_decisions(items, sources, accepted):
    if not isinstance(items, list) or len(items) != len(sources):
        raise InputError('review requires rights decisions for each cited source')
    decisions = {}
    for item in items:
        _fields(item, ('source_id', 'basis', 'actions'), ('conditions_url',), label='source rights')
        sid, actions = item['source_id'], item['actions']
        if (not isinstance(sid, str) or sid not in sources or sid in decisions or not isinstance(actions, dict)
                or set(actions) != set(ACTIONS) or any(action not in RIGHTS for action in actions.values())):
            raise InputError('record all six source rights decisions separately')
        if accepted and (actions['read'] not in ALLOWED or actions['adaptation'] not in ALLOWED
                         or actions['publication'] not in (*ALLOWED, 'link_only')):
            raise InputError('source rights for the authored note need clarification before acceptance')
        registered = sources[sid]['rights']
        if accepted and registered['status'] == 'link_only' and actions['publication'] != 'link_only':
            raise InputError('registered source rights permit retaining only the source link')
        decision = dict(source_id=sid, basis=_text(item['basis'], 4096), actions=actions)
        url = item.get('conditions_url', registered.get('conditions_url'))
        if url is not None:
            decision['conditions_url'] = knowledge._url(url)
        if 'allowed_with_conditions' in actions.values() and url is None:
            raise InputError('conditional rights need a reference to the conditions')
        decisions[sid] = decision
    return list(decisions.values())


def _unchanged_sources(pinned, root):
    library = knowledge.load_library(root)
    for sid, source in pinned.items():
        current = _source_metadata(library['sources'].get(sid, {}))
        comparable = {key: value for key, value in source.items() if key not in ('link', 'checked_at')}
        if ({key: value for key, value in current.items() if key not in ('link', 'checked_at')} != comparable
                or source['lifecycle']['state'] != 'active'
                or source['rights']['status'] in ('needs_clarification', 'excluded')):
            raise InputError('knowledge source changed or requires clarification; revise the proposal before acceptance')
    return library['digest']


def record_review(state, proposal_id, request, *, expected_sha256, root=None):
    _hex(proposal_id, '[a-f0-9]{64}', 'knowledge proposal ID')
    _hex(expected_sha256, '[a-f0-9]{64}', 'expected proposal digest')
    _fields(request, ('schema_version', 'reviewer', 'verdict', 'claims', 'anonymization', 'rights'), label='knowledge review')
    _schema(request)
    verdict = request['verdict']
    if verdict not in ('accepted', 'needs_changes'):
        raise InputError('invalid knowledge review verdict')
    folder = _folder(state)
    path = folder / (proposal_id + '.json')
    request_sha256 = fs.digest(request)
    with fs.writer(folder):
        document = _load(path)
        entries = document['revisions']
        for entry in entries:
            receipt = entry['review']
            if entry['sha256'] == expected_sha256 and receipt and receipt['record']['request_sha256'] == request_sha256:
                return _view(document, entry, replayed=True)
        entry = entries[-1]
        if entry['sha256'] != expected_sha256:
            raise InputError('knowledge proposal revision changed; review the current proposal')
        if entry['review'] is not None:
            raise InputError('this proposal revision already has a review')
        record = entry['record']
        accepted = verdict == 'accepted'
        anonymization = request['anonymization']
        _fields(anonymization, ('status', 'basis'), label='anonymization review')
        if anonymization['status'] not in ('checked', 'needs_work') or (accepted and anonymization['status'] != 'checked'):
            raise InputError('accepted proposals require a recorded anonymization check')
        _text(anonymization['basis'], 2048)
        reviewer = _text(request['reviewer'], 256)
        claims = _claim_decisions(request['claims'], {item['id']: item['status'] for item in record['card']['claims']}, accepted)
        sources = record['sources_metadata']
        rights = _rights_decisions(request['rights'], sources, accepted)
        review = dict(proposal_sha256=expected_sha256, request_sha256=request_sha256, verdict=verdict,
                      reviewer=reviewer, recorded_at=fs.stamp(), claims=claims, anonymization=anonymization,
                      rights=rights, source_review_digest=_unchanged_sources(sources, root) if accepted else None,
                      reviewer_identity='caller_reported', technical_truth_judged=False)
        entry['review'] = dict(record=review, sha256=fs.digest(review))
        _save(path, document)
        return _view(document, entry)
