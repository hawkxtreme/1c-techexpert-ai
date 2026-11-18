"""Private knowledge-use snapshots and read-only reuse warnings, never truth judgments."""
from copy import deepcopy
import hashlib
import json

from .inputs import InputError
from .knowledge import ID,card_review,digest,load_library,validate_environment

ERRORS=(OSError,ValueError,TypeError,KeyError,AttributeError,RecursionError)

def pin_use(state_dir,card_ids,*,root=None,purpose='recommendation',environment=None):
    environment=validate_environment(environment)
    if (not isinstance(card_ids,list) or not 1<=len(card_ids)<=16 or
        any(not isinstance(cid,str) or not ID.fullmatch(cid) for cid in card_ids) or len(set(card_ids))!=len(card_ids)):
        raise InputError('knowledge-use requires1..16 distinct card IDs')
    if purpose not in ('recommendation','reference'):raise InputError('invalid knowledge-use purpose')
    library=load_library(root);by_id={card['id']:card for card in library['cards']}
    if set(card_ids)-by_id.keys():raise InputError('unknown knowledge card')
    selected=list(card_ids)
    for cid in selected:
        card=by_id[cid]
        if cid in card_ids and purpose=='recommendation' and (card['lifecycle']['state']=='withdrawn' or card['status']=='deprecated'):
            raise InputError('withdrawn/deprecated card cannot be pinned for a new recommendation')
        for dependency in card['depends_on']:
            if dependency not in selected:selected.append(dependency)
        if len(selected)>16:raise InputError('knowledge-use dependency closure exceeds16cards')
    snapshots=[];sources=[]
    for cid in selected:
        card=by_id[cid];review=card_review(library,cid,environment=environment)
        metadata={k:deepcopy(v) for k,v in card.items() if k not in ('body','content_sha256','metadata_sha256')}
        data=card['body'].encode('utf-8') if card['path'] is not None else json.dumps(metadata,ensure_ascii=False,sort_keys=True).encode('utf-8')
        source_id='s'+str(len(sources)+1);sources.append((cid+('.md' if card['path'] is not None else '.tombstone.json'),data))
        snapshots.append(dict(id=cid,requested=cid in card_ids,source_id=source_id,card=metadata,
            content_sha256=card['content_sha256'],metadata_sha256=card['metadata_sha256'],
            content_kind='authored_note' if card['path'] is not None else 'tombstone_metadata',
            sources_metadata=[deepcopy(library['sources'][sid]) for sid in card['sources']],review_at_capture=review))
    result=dict(schema_version=1,library_revision=library['revision'],library_digest=library['digest'],
        library_legacy_digest=library['legacy_digest'],requested_card_ids=card_ids,purpose=purpose,cards=snapshots,
        content_normalization='utf8-lf-v1',environment=environment or {},environment_basis='caller_reported_not_independently_verified',
        capture_consistency=library['capture_consistency'],
        technical_truth_judged=False,requires_applicability_check=True,untrusted_reference_content=True)
    from .artifacts import save_artifact
    return save_artifact(state_dir,'knowledge_use',dict(card_ids=card_ids,purpose=purpose,environment=environment or {}),sources,result)

def _snapshot(state_dir,artifact_id):
    from .artifacts import load_artifact
    return checked_snapshot(load_artifact(state_dir,artifact_id))


def checked_snapshot(report):
    if report['kind']!='knowledge_use':raise InputError('artifact is not a knowledge-use snapshot')
    result=report.get('result')
    if (not isinstance(result,dict) or type(result.get('schema_version')) is not int or result['schema_version']!=1
        or result.get('content_normalization')!='utf8-lf-v1' or result.get('purpose') not in ('recommendation','reference')):
        raise InputError('unsupported knowledge-use schema')
    validate_environment(result.get('environment'))
    cards=result.get('cards')
    if not isinstance(cards,list) or not 1<=len(cards)<=16:raise InputError('invalid knowledge-use card count')
    ids=set();source_ids=set();sources={source['id']:source for source in report['sources']}
    if len(sources)!=len(cards):raise InputError('knowledge-use requires one evidence source per card')
    for card in cards:
        if (not isinstance(card,dict) or not isinstance(card.get('id'),str) or not ID.fullmatch(card['id'])
            or card['id'] in ids or not isinstance(card.get('source_id'),str) or card['source_id'] not in sources
            or card['source_id'] in source_ids or type(card.get('requested')) is not bool or not isinstance(card.get('card'),dict)
            or card['card'].get('id')!=card['id'] or card.get('content_kind') not in ('authored_note','tombstone_metadata')
            or digest(card['card'])!=card.get('metadata_sha256')):raise InputError('invalid knowledge-use card snapshot')
        if card.get('content_kind')=='authored_note' and card.get('content_sha256')!=sources[card['source_id']]['sha256']:
            raise InputError('knowledge-use content hash mismatch')
        if card['content_kind']=='tombstone_metadata':
            data=json.dumps(card['card'],ensure_ascii=False,sort_keys=True).encode('utf-8')
            if card['card'].get('path') is not None or hashlib.sha256(data).hexdigest()!=sources[card['source_id']]['sha256']:
                raise InputError('knowledge-use tombstone mismatch')
        metadata_sources=card.get('sources_metadata')
        if (not isinstance(metadata_sources,list) or len(metadata_sources)>64 or any(not isinstance(s,dict)
            or not isinstance(s.get('id'),str) or not ID.fullmatch(s['id']) for s in metadata_sources)):
            raise InputError('invalid knowledge-use source provenance')
        if len({s['id'] for s in metadata_sources})!=len(metadata_sources) or {s['id'] for s in metadata_sources}!=set(card['card'].get('sources',[])):
            raise InputError('knowledge-use source provenance disagrees with card')
        ids.add(card['id']);source_ids.add(card['source_id'])
    requested=result.get('requested_card_ids')
    if (not isinstance(requested,list) or not 1<=len(requested)<=16 or any(not isinstance(cid,str) or cid not in ids for cid in requested)
        or len(set(requested))!=len(requested) or set(requested)!={c['id'] for c in cards if c['requested']}):
        raise InputError('unresolved knowledge-use requested cards')
    for card in cards:
        dependencies=card['card'].get('depends_on')
        if not isinstance(dependencies,list) or len(dependencies)>16 or any(not isinstance(cid,str) or cid not in ids for cid in dependencies):
            raise InputError('unresolved knowledge-use dependency')
    return report

def review_use(state_dir,artifact_id,*,root=None,environment=None):
    if environment is not None:environment=validate_environment(environment)
    report=_snapshot(state_dir,artifact_id);snapshot=report['result']
    try:library=load_library(root)
    except ERRORS:
        return dict(status='current_library_unavailable',artifact_id=artifact_id,saved_snapshot_integrity_verified=True,
            snapshot_revision=snapshot['library_revision'],current_revision=None,technical_truth_judged=False,
            cards=[dict(id=c['id'],source_id=c['source_id'],requested=c['requested'],review_required=True,
                reasons=[dict(code='current_library_unavailable')],link_warnings=[]) for c in snapshot['cards']])
    current={card['id']:card for card in library['cards']};old={card['id']:card for card in snapshot['cards']};changes={}
    for cid,item in old.items():
        card=current.get(cid);reasons=[];links=[]
        if card is None:reasons.append(dict(code='card_missing_from_current_revision',card=cid))
        else:
            baseline=card_review(library,cid,environment=snapshot.get('environment') if environment is None else environment)
            reasons.extend(baseline['reasons']);links.extend(baseline['link_warnings'])
            if card['content_sha256']!=item['content_sha256']:reasons.append(dict(code='card_content_changed',card=cid))
            if card['metadata_sha256']!=item['metadata_sha256']:reasons.append(dict(code='card_metadata_changed',card=cid))
            for source in item.get('sources_metadata',[]):
                sid=source['id'];now=library['sources'].get(sid)
                if now is None:reasons.append(dict(code='source_missing_from_current_revision',card=cid,source=sid))
                elif {k:v for k,v in now.items() if k not in ('link','checked_at')}!={k:v for k,v in source.items() if k not in ('link','checked_at')}:
                    reasons.append(dict(code='source_metadata_changed',card=cid,source=sid))
        changes[cid]=dict(reasons=reasons,link_warnings=links)
    output=[]
    for cid,item in old.items():
        queue=[cid];seen=set();reasons=[];links=[]
        while queue:
            dependency=queue.pop(0)
            if dependency in seen:continue
            seen.add(dependency)
            if dependency in changes:
                reasons.extend(changes[dependency]['reasons']);links.extend(changes[dependency]['link_warnings'])
            elif dependency not in old:reasons.append(dict(code='new_dependency_not_in_snapshot',card=dependency))
            if dependency in old:queue.extend(old[dependency]['card'].get('depends_on',[]))
            if dependency in current:queue.extend(current[dependency]['depends_on'])
        # Multiple dependency paths keep one deterministic instance of each warning.
        unique=lambda values:list({digest(value):value for value in values}.values())
        reasons=unique(reasons);links=unique(links)
        output.append(dict(id=cid,source_id=item['source_id'],requested=item['requested'],review_required=bool(reasons),
            reasons=reasons,link_warnings=links,technical_truth_judged=False))
    return dict(status='review_required' if any(c['review_required'] for c in output) else 'unchanged',
        artifact_id=artifact_id,snapshot_revision=snapshot['library_revision'],current_revision=library['revision'],
        saved_snapshot_integrity_verified=True,cards=output,technical_truth_judged=False,
        environment_basis='caller_reported_not_independently_verified',requires_applicability_check=True)

def review_investigation(state_dir,doc,*,root=None,environment=None):
    from .artifacts import load_artifact
    usages=[];affected=set();knowledge_evidence=set()
    for attachment in doc['attachments']:
        if attachment['kind']!='artifact':continue
        report=load_artifact(state_dir,attachment['target_id'])
        if report['kind']!='knowledge_use':continue
        review=review_use(state_dir,report['artifact_id'],root=root,environment=environment)
        usages.append(dict(attachment=attachment['id'],review=review))
        bad_sources={card['source_id'] for card in review['cards'] if card['review_required']}
        known_sources={card['source_id'] for card in review['cards']}
        for evidence in doc['evidence']:
            if evidence['attachment']==attachment['id']:
                if evidence['record'] in known_sources:knowledge_evidence.add(evidence['id'])
                if evidence['record'] in bad_sources:affected.add(evidence['id'])
    hypotheses={h['id']:h['evidence'] for h in doc['hypotheses']}
    recommendations=doc['assessment']['recommendations'] if doc['assessment'] else []
    changed=[];untracked=[]
    for recommendation in recommendations:
        evidence=set()
        for basis in recommendation['basis']:evidence.update(hypotheses.get(basis,[basis]))
        if evidence&affected:changed.append(recommendation['id'])
        if not evidence&knowledge_evidence:untracked.append(recommendation['id'])
    legacy=None
    if not usages or untracked:
        try:
            library=load_library(root)
            if doc['versions']['knowledge']!=library['legacy_digest']:
                legacy=dict(code='knowledge_revision_changed_usage_untracked',impact='Unknown without explicit card-use evidence; review applicability, not automatic falsehood.')
        except ERRORS:legacy=dict(code='current_library_unavailable',impact='Historical report remains unchanged; current applicability cannot be checked.')
    review_required=bool(changed or legacy or any(u['review']['status']!='unchanged' for u in usages))
    return dict(status='review_required' if review_required else 'unchanged',investigation_id=doc['investigation_id'],revision=doc['revision'],
        usages=usages,recommendations_requiring_review=changed,legacy_warning=legacy,
        untracked_recommendation_ids=untracked if legacy else [],
        stored_assessment_changed=False,stored_cause_state=doc['cause_state'],technical_truth_judged=False,
        scope='Explicit knowledge artifact evidence and hypothesis basis; implicit knowledge use remains unknown.')

def review_legacy_report(report,*,root=None):
    try:
        library=load_library(root);changed=report.get('knowledge_revision')!=library['legacy_digest']
        return dict(status='review_required' if changed else 'unchanged',
            reason='knowledge_revision_changed_usage_untracked' if changed else None,current_revision=library['revision'],
            stored_report_changed=False,technical_truth_judged=False)
    except ERRORS:return dict(status='current_library_unavailable',stored_report_changed=False,technical_truth_judged=False)
