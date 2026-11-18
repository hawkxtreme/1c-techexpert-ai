"""Resolve the materials cited beside a finding, hypothesis or recommendation."""
from collections import defaultdict
import re
from urllib.parse import urlsplit

from . import artifacts, knowledge_review
from .inputs import InputError
from .knowledge import _url


FORMAT = 1
LABELS = dict(documentation='Документация', publication='Публикация',
              discussion='Источник гипотезы', knowledge_card='Карточка базы знаний')
OBSERVATION_ARTIFACTS = {'apdex', 'client_ui', 'native-jr', 'os_metrics', 'postgresql', 'rac', 'sqlserver'}
HYPOTHESIS_STATUS = dict(proposed='предложена', testing='проверяется', supported='есть поддерживающие данные',
                         refuted='опровергнута', insufficient_data='недостаточно данных')
TELEGRAM_NON_MESSAGE_ROUTES = {'c', 's', 'joinchat', 'contact', 'addlist', 'share', 'msg'}


def observed_format(doc):
    assessment = doc.get('assessment') or {}
    if any(isinstance(item, dict) and 'kind' in item for item in assessment.get('references', [])):
        return FORMAT
    return None


def _discussion_url(url):
    location = urlsplit(url)
    if location.hostname.rstrip('.') in ('t.me', 'telegram.me', 'www.t.me', 'www.telegram.me'):
        slug, *ids = location.path.removeprefix('/').removesuffix('/').split('/')
        if slug.lower() == 'c':
            specific = len(ids) in (2, 3)
        else:
            if slug.lower() == 's' and ids:
                slug, *ids = ids
            specific = (re.fullmatch(r'[A-Za-z0-9_]+', slug) and slug.lower() not in TELEGRAM_NON_MESSAGE_ROUTES
                        and len(ids) in (1, 2))
        specific = specific and all(re.fullmatch(r'[1-9][0-9]*', value) for value in ids)
    else:
        specific = location.path.strip('/') or location.fragment
    if not specific:
        raise InputError('discussion reference requires a specific message or thread URL')


def _card(report, source_id):
    from .investigations import _text

    if report.get('kind') != 'knowledge_use':
        raise InputError('knowledge reference requires a saved knowledge-use artifact')
    snapshot = knowledge_review.checked_snapshot(report)
    matched = next((card for card in snapshot['result']['cards'] if card['source_id'] == source_id), None)
    if matched is None:
        raise InputError('knowledge reference requires a saved card source')
    card = matched['card']
    source = next(item for item in snapshot['sources'] if item['id'] == source_id)
    identifier = snapshot['artifact_id']
    local_link = f"../../../../artifacts/{identifier}/sources/{artifacts.source_name(source)}"
    sources = [dict(id=item['id'], url=_url(item['url']), publisher=_text(item['publisher'], 512),
                    link_status=item['link']['state']) for item in matched['sources_metadata']]
    return dict(id=matched['id'], title=_text(card['title'], 512), revision=card['revision'],
                applicability=_text(card['applicability']), status_at_capture=card['status'], artifact_id=identifier,
                source_id=source_id, local_link=local_link, content_sha256=source['sha256'], sources=sources)


def _set_resolved(item, field, value):
    if field in item and item[field] != value:
        raise InputError('resolved report reference disagrees with saved evidence')
    item[field] = value


def validate(assessment, hypotheses, evidence, attachments, reports):
    from .investigations import _list, _object, _references, _text

    references = _list(assessment['references'], 100)
    hypotheses = {item['id']: item for item in hypotheses}
    targets = {identity: item['evidence'] for identity, item in hypotheses.items()}
    targets['assessment'] = assessment['evidence']
    for item in assessment['recommendations']:
        targets[item['id']] = [eid for key in item['basis'] for eid in targets.get(key, [key])]
    evidence = {item['id']: item for item in evidence}
    attachments = {item['id']: item['kind'] for item in attachments}
    incident = {identity for identity, item in evidence.items()
                if attachments[item['attachment']] in ('case', 'comparison')
                or reports[item['attachment']].get('kind') in OBSERVATION_ARTIFACTS}

    if observed_format(dict(assessment=assessment)) and assessment['cause_state'] == 'confirmed':
        selected = hypotheses[assessment['hypothesis_id']]
        if not incident.intersection(selected['evidence']) or not incident.intersection(assessment['evidence']):
            raise InputError('confirmed cause with scoped references requires incident evidence')

    for item in references:
        if not isinstance(item, dict) or 'kind' not in item:
            fields = ('url', 'purpose', 'applicability')
            _object(item, fields, fields)
            _text(item['purpose'])
            _text(item['applicability'])
            url = _text(item['url'], 2048)
            parsed = urlsplit(url)
            if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or any(c.isspace() or c in '<>"' for c in url):
                raise InputError('reference must be a credential-free HTTPS URL')
            continue

        kind = item['kind']
        if not isinstance(kind, str) or kind not in LABELS:
            raise InputError('unsupported report reference kind')
        common = ('kind', 'targets', 'purpose', 'applicability')
        _text(item.get('purpose'))
        _text(item.get('applicability'))
        related = _references(_list(item.get('targets'), 32), targets, required=True)
        if kind == 'knowledge_card':
            _object(item, (*common, 'evidence', 'pinned_card'), (*common, 'evidence'))
            evidence_id = _text(item['evidence'], 62)
            if evidence_id not in evidence or any(evidence_id not in targets[target] for target in related):
                raise InputError('knowledge reference must be linked to the cited finding or recommendation')
            record = evidence[evidence_id]
            _set_resolved(item, 'pinned_card', _card(reports[record['attachment']], record['record']))
            continue

        required = (*common, 'url', 'version')
        _object(item, (*required, 'checks') if kind == 'discussion' else required, required)
        url = _url(item['url'])
        if '\\' in url:
            raise InputError('reference URL contains a backslash')
        if item['version'] is not None:
            _text(item['version'], 512)
        if kind == 'discussion':
            _discussion_url(url)
            _references(related, hypotheses, required=True)
            checks = []
            for target in related:
                state = hypotheses[target]['status']
                observations = [identity for identity in targets[target] if identity in incident]
                status = 'insufficient_data' if not observations and state in ('supported', 'refuted') else state
                checks.append(dict(hypothesis=target, status=status, harness_status=state, incident_evidence=observations))
            _set_resolved(item, 'checks', checks)


def by_target(assessment):
    result = defaultdict(list)
    for item in (assessment or {}).get('references', []):
        for target in item.get('targets', ['legacy']):
            result[target].append(item)
    return result


def markdown(item, target, escape, *, prefix='- '):
    label = LABELS[item['kind']]
    if item['kind'] == 'knowledge_card':
        card = item['pinned_card']
        title = escape(card['title'])
        material = f"[{title}]({card['local_link']}), {escape(card['id'])}, ревизия {card['revision']}"
        details = f". Область применения карточки — {escape(card['applicability'])}. Основание {item['evidence']}"
        sources = [f"{escape(source['publisher'])} <{source['url']}>" +
                   (' (недоступна при проверке)' if source['link_status'] == 'unavailable' else '')
                   for source in card['sources']]
        if sources:
            details += '. Карточка ссылается на ' + ', '.join(sources)
    else:
        material = '<' + item['url'] + '>'
        details = '. Версия ' + (escape(item['version']) if item['version'] is not None else 'не указана')
        if item['kind'] == 'discussion':
            check = next(row for row in item['checks'] if row['hypothesis'] == target)
            details += f". Состояние гипотезы у агента — {HYPOTHESIS_STATUS[check['harness_status']]}"
            observations = ', '.join(check['incident_evidence'])
            if observations:
                details += '. Привязаны наблюдения ' + observations
            else:
                details += '. Ссылок на наблюдения пока нет'
    return f"{prefix}{label} {material}. {escape(item['purpose'])}. {escape(item['applicability'])}{details}."
