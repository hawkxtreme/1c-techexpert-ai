"""Bounded offline keyword and event retrieval over the versioned cards."""
from pathlib import Path
import re
import unicodedata

from .inputs import InputError


WORD = re.compile(r'[^\W_]+(?:[-_.:][^\W_]+)*')
RUSSIAN = re.compile('[а-я]{5,}')
VOWEL = re.compile('[аеиоуыэюя]')
EVENT = re.compile(r'[A-Za-z][A-Za-z0-9_.:-]{0,63}')
SHA256 = re.compile('[a-f0-9]{64}')
STOP = frozenset(('в во на с со и а но или для по из от к за под над у о об до это его ее их он она они '
                  'есть был было быть как что где когда то ли не нет ни мне нам уже вместо '
                  'a an the in on at is was be and or for to of how what when where').split())
# A conservative noun/adjective reduction, restricted to the region after
# the first vowel. It is a search heuristic, with no claim of lemmatization.
ENDINGS = tuple(sorted(set(('иями иях иям ием ией ия ие ию ии ями ям ях ами ам ах ов ев ей '
                         'ого его ому ему ыми ими ая яя ое ее ые ый ий ой ых их ым им ом ем ую юю ою ею '
                         'а я ы и у ю е о й ь').split()), key=lambda value: (-len(value), value)))
FIELDS = (('id', 10), ('title', 6), ('signs', 4), ('body', 1))
MAX_TERMS = 30
MAX_EVENTS = 8
MAX_SIGNALS = 12
MAX_EXCERPT = 6000
DASHES = str.maketrans('‐‑–—', '----')


def schema(cap):
    from .knowledge import ENVIRONMENT, MAX_CARDS

    return dict(environment=cap.obj({key: cap.string(128) for key in ENVIRONMENT}),
                events=dict(type='array', items=cap.string(64, pattern=EVENT.pattern), maxItems=MAX_EVENTS),
                card_type=cap.string(128),
                offset=dict(type='integer', minimum=0, maximum=MAX_CARDS),
                excerpt_chars=dict(type='integer', minimum=0, maximum=MAX_EXCERPT),
                expected_knowledge_digest=cap.SHA256)


def _words(text):
    normalized = unicodedata.normalize('NFKC', text).casefold().replace('ё', 'е')
    normalized = normalized.translate(DASHES)
    for match in WORD.finditer(normalized):
        token = match[0]
        if len(token) <= 128 and token not in STOP:
            yield '1с' if token == '1c' else token


def _key(word):
    if RUSSIAN.fullmatch(word) is not None:
        vowel = VOWEL.search(word)
        if vowel is not None:
            minimum = max(vowel.end(), 3)
            for ending in ENDINGS:
                if len(word) - len(ending) >= minimum and word.endswith(ending):
                    return word[:-len(ending)]
    return word


def _query_terms(query):
    keys = {}
    for token in _words(query):
        key = _key(token)
        if key not in keys and len(keys) == MAX_TERMS:
            continue
        keys.setdefault(key, set()).add(token)
    return keys


def _matches(card, query, events, declared, exact_id):
    terms = {}
    found_events = {token: dict(kind='event', term=token.upper(), field='event_types', basis='declared')
                    for token in declared}
    for field, weight in FIELDS:
        content = card[field]
        if field == 'signs':
            content = ' '.join(content)
        if field == 'id' and exact_id:
            token = content.casefold()
            terms[_key(token)] = weight * 2 + 1, dict(kind='text', term=token, field=field, basis='exact')
            continue
        for token in _words(content):
            key = _key(token)
            if key in query:
                exact = token in query[key]
                score = weight * 2 + exact
                if key not in terms or score > terms[key][0]:
                    terms[key] = score, dict(kind='text', term=token, field=field,
                                             basis='exact' if exact else 'word_form')
            if token in events and token not in found_events:
                found_events[token] = dict(kind='event', term=token.upper(), field=field, basis='exact')
    ordered = sorted(terms.values(), key=lambda item: (-item[0], item[1]['term'], item[1]['field']))
    score = sum(weight for weight, _ in ordered) + 12 * len(found_events)
    signals = [found_events[key] for key in sorted(found_events)] + [detail for _, detail in ordered]
    return score, signals[:MAX_SIGNALS], len(signals), len(found_events)


def _applicability(card, by_id, environment, review):
    dimensions = set()
    pending = [card['id']]
    seen = set()
    while pending:
        cid = pending.pop()
        if cid not in seen:
            seen.add(cid)
            dimensions.update(by_id[cid]['applicability_constraints'])
            pending.extend(by_id[cid]['depends_on'])
    outside = any(item['code'] == 'outside_recorded_applicability' for item in review['reasons'])
    missing = dimensions - environment.keys()
    if outside:
        status = 'outside_recorded_scope'
    elif missing:
        status = 'environment_unknown'
    elif dimensions:
        status = 'matches_reported_environment'
    else:
        status = 'no_indexed_constraints'
    return dict(status=status, checked_dimensions=sorted(dimensions & environment.keys()),
                unknown_dimensions=sorted(missing), environment_basis='caller_reported')


def _summary(card):
    keys = ('id', 'title', 'status', 'type', 'revision', 'applicability', 'event_types')
    return {key: card[key] for key in keys if key in card}


def _conflicts(rows, library, by_id, environment):
    from .knowledge import card_review

    wanted = {item['id'] for row in rows for item in row['open_conflicts']}
    output = []
    for conflict in library['open_conflicts']:
        if conflict['id'] not in wanted:
            continue
        positions = []
        for cid in conflict['cards']:
            card = by_id[cid]
            review = card_review(library, cid, environment=environment)
            positions.append(dict(_summary(card), lifecycle=card['lifecycle']['state'],
                                  applicability_check=_applicability(card, by_id, environment, review)))
        output.append(dict(conflict, positions=positions, technical_choice_made=False))
    return output


def search(query, *, limit=5, root=None, environment=None, events=(), card_type=None, offset=0, excerpt_chars=MAX_EXCERPT,
           expected_knowledge_digest=None):
    from .knowledge import MAX_CARDS, ROOT, card_review, load_library, validate_environment

    if not isinstance(query, str) or not 1 <= len(query.strip()) <= 500:
        raise InputError('knowledge query must contain 1..500 characters')
    if not (type(limit) is int and 1 <= limit <= 20 and type(offset) is int and 0 <= offset <= MAX_CARDS
            and type(excerpt_chars) is int and 0 <= excerpt_chars <= MAX_EXCERPT):
        raise InputError('knowledge offset, limit or excerpt size is out of range')
    if (not isinstance(events, (tuple, list)) or len(events) > MAX_EVENTS
            or any(not isinstance(value, str) or not EVENT.fullmatch(value) for value in events)):
        raise InputError('invalid observed knowledge event types')
    if card_type is not None and (not isinstance(card_type,str) or len(card_type)>128 or not card_type.strip()):
        raise InputError('invalid knowledge card type filter')
    if offset and expected_knowledge_digest is None:
        raise InputError('subsequent knowledge results require the same knowledge revision digest')
    environment = {key: value for key, value in validate_environment(environment).items()
                   if value != 'unknown'}
    library = load_library(root,expected_knowledge_digest=expected_knowledge_digest)
    root = ROOT/'knowledge' if root is None else Path(root)
    by_id = {card['id']: card for card in library['cards']}
    terms = _query_terms(query)
    literal = query.strip().casefold()
    event_words = {name.casefold() for name in events}
    ranked, excluded = [], []
    for card in library['cards']:
        if card['lifecycle']['state'] == 'withdrawn' or card['status'] == 'deprecated':
            continue
        if card_type is not None and card['type'] != card_type:
            continue
        declared = event_words.intersection(name.casefold() for name in card.get('event_types', ()))
        if card_type == 'tj_event' and event_words and not declared:
            continue
        score, signals, signal_count, event_count = _matches(card, terms, event_words, declared,
                                                             exact_id=card['id'].casefold() == literal)
        if not score:
            continue
        review = card_review(library, card['id'], environment=environment)
        applicability = _applicability(card, by_id, environment, review)
        provisional = card['status'] == 'draft' or review['review_required']
        summary = dict(_summary(card), score=score, matching=signals, matching_count=signal_count,
                       applicability_check=applicability, hypothesis_only=provisional, **review)
        if applicability['status'] == 'outside_recorded_scope':
            excluded.append(summary)
            continue
        exact_id = any(row['kind'] == 'text' and row['field'] == 'id' and row['basis'] == 'exact' for row in signals)
        rank = (not exact_id, provisional, -len(declared), -event_count, -score,
                applicability['status'] == 'environment_unknown', card['id'])
        ranked.append((rank, summary, card))
    ranked.sort(key=lambda item: item[0])
    excluded.sort(key=lambda item: (-item['score'], item['id']))
    matches = []
    for _, item, card in ranked[offset:offset+limit]:
        matches.append(dict(item, path=str(root/card['path']), related=card['related'],
            sources=[library['sources'][sid] for sid in card['sources']],
            excerpt=card['body'][:excerpt_chars], truncated=len(card['body']) > excerpt_chars,
            untrusted_reference_content=True, diagnosis_for_current_case_established=False))
    skipped = excluded[:20]
    return dict(knowledge_revision=library['revision'], knowledge_digest=library['digest'],
        scope='bundled_offline_cards', matches=matches, total_matches=len(ranked), offset=offset,
        next_offset=offset+len(matches) if offset+len(matches)<len(ranked) else None,
        excluded_matches=skipped, total_excluded=len(excluded), conflicts=_conflicts(matches+skipped, library, by_id, environment),
        requires_applicability_check=True, technical_truth_judged=False)
