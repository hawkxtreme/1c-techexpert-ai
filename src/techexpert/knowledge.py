"""Offline authored knowledge, explicit dependencies and noncausal review flags."""
import hashlib
import json
from pathlib import Path,PurePosixPath
import re
import stat
from urllib.parse import urlsplit

from .inputs import InputError,read_snapshot,json_value
from .storage import ROOT

MAX_CARDS=256
MAX_TOTAL=8*1024*1024
ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
ENVIRONMENT=('platform_version','database_mode','dbms_engine','dbms_version','bsp_version','configuration_version')

def canonical(data):return data.decode('utf-8-sig').replace('\r\n','\n').encode('utf-8')
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode()).hexdigest()

def _text(value,limit=8192):
    if not isinstance(value,str) or not value or len(value)>limit or any(ord(c)<32 and c not in '\n\t\r' for c in value):raise InputError('invalid knowledge text')
    return value

def _url(value):
    parsed=urlsplit(_text(value,2048))
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or any(c.isspace() or c in '<>"' for c in value):
        raise InputError('knowledge references require credential-free HTTPS URLs')
    try:parsed.port
    except ValueError as exc:raise InputError('invalid knowledge reference port') from exc
    return value

def validate_environment(value):
    value={} if value is None else value
    if not isinstance(value,dict) or set(value)-set(ENVIRONMENT):raise InputError('invalid applicability environment')
    for item in value.values():_text(item,128)
    return dict(value)

def _ids(value,limit=64):
    if not isinstance(value,list) or len(value)>limit or any(not isinstance(v,str) or not ID.fullmatch(v) for v in value) or len(set(value))!=len(value):
        raise InputError('invalid knowledge identifier list')
    return value

def _member(root,name):
    if not isinstance(name,str) or not name or '\\' in name or ':' in name or any(ord(c)<32 for c in name):raise InputError('invalid knowledge member')
    path=PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or path.as_posix()!=name:raise InputError('invalid knowledge member')
    current=root
    for part in path.parts:
        current=current/part;info=current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise InputError('linked knowledge member rejected')
    if not stat.S_ISREG(info.st_mode):raise InputError('knowledge member is not a regular file')
    return current

def _lifecycle(value):
    if value is None:return dict(state='active')
    if not isinstance(value,dict) or set(value)-{'state','reason','effective_at'} or value.get('state') not in ('active','under_review','withdrawn'):
        raise InputError('invalid knowledge lifecycle')
    if value['state']!='active':_text(value.get('reason'),2048)
    if 'reason' in value:_text(value['reason'],2048)
    if 'effective_at' in value:_text(value['effective_at'],128)
    return dict(value)

def _link(value):
    if value is None:return dict(state='not_checked')
    if not isinstance(value,dict) or set(value)-{'state','checked_at','reason'} or value.get('state') not in ('not_checked','available','unavailable'):
        raise InputError('invalid source link state')
    if value['state']!='not_checked':_text(value.get('checked_at'),128)
    for key in ('checked_at','reason'):
        if key in value and value[key] is not None:_text(value[key],2048)
    return dict(value)

def _rights(value):
    if value is None:return dict(status='link_only',basis='Original republication not established; only URL and authored notes are stored.')
    if not isinstance(value,dict) or set(value)-{'status','basis','conditions_url','attribution','allowed_actions'} or value.get('status') not in ('allowed','allowed_with_conditions','link_only','needs_clarification','excluded'):
        raise InputError('invalid source rights state')
    _text(value.get('basis'))
    for key in ('conditions_url','attribution'):
        if key in value:_text(value[key],2048)
    if 'conditions_url' in value:_url(value['conditions_url'])
    actions=value.get('allowed_actions',[])
    if not isinstance(actions,list) or len(actions)>16 or any(not isinstance(a,str) or len(a)>256 for a in actions):raise InputError('invalid permitted source actions')
    return dict(value)

def load_library(root=None):
    root=Path(ROOT/'knowledge' if root is None else root).absolute()
    if '..' in root.parts:raise InputError('knowledge root must not contain parent traversal')
    # Preserve the selected boundary until every ancestor has been inspected.
    for component in (root,*root.parents):
        info=component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
            raise InputError('linked knowledge root or ancestor rejected')
    root=root.resolve()
    metadata=read_snapshot(_member(root,'index.json'),1024*1024)
    index=json_value(metadata.decode('utf-8'),reject_duplicates=True)
    if not isinstance(index,dict) or type(index.get('schema_version')) is not int or index['schema_version'] not in (1,2):raise InputError('unsupported knowledge index')
    _text(index.get('revision'),128)
    source_items=index.get('sources',[])
    if not isinstance(source_items,list) or len(source_items)>256:raise InputError('invalid knowledge source count')
    sources={};cards=[];raw_members={'index.json':metadata};total=len(metadata)
    for item in source_items:
        if not isinstance(item,dict) or not isinstance(item.get('id'),str) or not ID.fullmatch(item['id']) or item['id'] in sources:raise InputError('duplicate or invalid knowledge source')
        _url(item.get('url'))
        if item.get('storage')!='url_only':raise InputError('original source storage is not permitted')
        _text(item.get('checked_at'),128);_text(item.get('publisher'),512)
        sources[item['id']]=dict(item,lifecycle=_lifecycle(item.get('lifecycle')),link=_link(item.get('link')),rights=_rights(item.get('rights')))
    entries=index.get('cards')
    if not isinstance(entries,list) or len(entries)>MAX_CARDS:raise InputError('invalid knowledge card count')
    ids=set();paths=set()
    for card in entries:
        required={'id','title','type','status','author','date','revision','applicability','signs','steps','evidence_basis','related','sources','path'}
        if not isinstance(card,dict) or required-set(card):raise InputError('knowledge card metadata missing')
        if set(card)&{'body','content_sha256','metadata_sha256','review_required','technical_truth_judged','link_warnings','reasons'}:
            raise InputError('reserved computed knowledge fields')
        if not isinstance(card['id'],str) or not ID.fullmatch(card['id']) or card['id'] in ids or card['status'] not in ('draft','reviewed','validated_in_lab','deprecated'):raise InputError('invalid card identity/status')
        for key in ('title','author','date','applicability','evidence_basis','type'):_text(card[key])
        if type(card['revision']) not in (str,int) or isinstance(card['revision'],str) and not 1<=len(card['revision'])<=128:raise InputError('invalid card revision')
        for key in ('signs','steps'):
            if not isinstance(card[key],list) or len(card[key])>64:raise InputError('invalid card steps/signs')
            for value in card[key]:_text(value)
        for key in ('related','sources'):_ids(card[key])
        dependencies=_ids(card.get('depends_on',[]));lifecycle=_lifecycle(card.get('lifecycle'))
        if set(card['sources'])-sources.keys():raise InputError('unregistered knowledge source')
        constraints=card.get('applicability_constraints',{})
        if not isinstance(constraints,dict) or set(constraints)-set(ENVIRONMENT):raise InputError('invalid applicability dimensions')
        for values in constraints.values():
            if not isinstance(values,list) or not 1<=len(values)<=64:raise InputError('invalid applicability values')
            for value in values:_text(value,128)
        normalized=dict(card,depends_on=dependencies,lifecycle=lifecycle,applicability_constraints=constraints)
        body=''
        if lifecycle['state']=='withdrawn':
            if card['path'] is not None:raise InputError('withdrawn card requires a body-free tombstone')
        else:
            path=card['path']
            if not isinstance(path,str) or PurePosixPath(path).suffix!='.md' or path in paths:raise InputError('invalid or repeated knowledge card path')
            data=read_snapshot(_member(root,path),min(64*1024,MAX_TOTAL-total));total+=len(data);raw_members[path]=data;paths.add(path)
            body=canonical(data).decode('utf-8')
        cards.append(dict(normalized,body=body,content_sha256=hashlib.sha256(body.encode()).hexdigest(),metadata_sha256=digest(normalized)))
        ids.add(card['id'])
    if any(set(card['related'])-ids or set(card['depends_on'])-ids for card in cards):raise InputError('broken knowledge card relation')
    by_id={card['id']:card for card in cards};visited=set();active=set()
    def visit(cid):
        if cid in active:raise InputError('cyclic knowledge dependency')
        if cid in visited:return
        active.add(cid)
        for dependency in by_id[cid]['depends_on']:visit(dependency)
        active.remove(cid);visited.add(cid)
    for cid in by_id:visit(cid)
    conflicts=index.get('open_conflicts',[])
    if not isinstance(conflicts,list) or len(conflicts)>64:raise InputError('too many knowledge conflicts')
    conflict_ids=set()
    for conflict in conflicts:
        if (not isinstance(conflict,dict) or set(conflict)!={'id','cards','summary'} or not isinstance(conflict.get('id'),str)
            or not ID.fullmatch(conflict['id']) or conflict['id'] in conflict_ids):raise InputError('invalid knowledge conflict')
        members=_ids(conflict['cards'],8)
        if len(members)<2 or set(members)-ids:raise InputError('unresolved conflict positions')
        _text(conflict['summary'],2048);conflict_ids.add(conflict['id'])
    readme=root/'README.md'
    if readme.exists():
        data=read_snapshot(_member(root,'README.md'),min(64*1024,MAX_TOTAL-total));raw_members['README.md']=data
    legacy=hashlib.sha256()
    for name,data in sorted(raw_members.items()):legacy.update(('knowledge/'+name).encode());legacy.update(data)
    fingerprint=dict(index=index,cards=[dict(id=c['id'],content_sha256=c['content_sha256']) for c in cards])
    return dict(schema_version=index['schema_version'],revision=index['revision'],digest=digest(fingerprint),legacy_digest=legacy.hexdigest(),
        digest_normalization='canonical_json_and_utf8_lf',cards=cards,sources=sources,open_conflicts=conflicts,
        package_members=sorted(raw_members),original_materials_stored=False,capture_consistency='per_file_stable_reads_not_atomic_library_snapshot')

def package_members(root=None):return load_library(root)['package_members']

def card_review(library,card_id,*,environment=None):
    environment=validate_environment(environment)
    by_id={card['id']:card for card in library['cards']};queue=[card_id];seen=set();reasons=[];links=[];conflicts=[]
    while queue:
        cid=queue.pop(0)
        if cid in seen:continue
        seen.add(cid);card=by_id[cid]
        if card['lifecycle']['state']!='active':reasons.append(dict(code='card_'+card['lifecycle']['state'],card=cid,reason=card['lifecycle'].get('reason')))
        if card['status']=='deprecated':reasons.append(dict(code='card_deprecated',card=cid))
        for key,values in card['applicability_constraints'].items():
            if key in environment and environment[key] not in values:reasons.append(dict(code='outside_recorded_applicability',card=cid,dimension=key,recorded=values,reported=environment[key]))
        for sid in card['sources']:
            source=library['sources'][sid]
            if source['lifecycle']['state']!='active':reasons.append(dict(code='source_'+source['lifecycle']['state'],card=cid,source=sid,reason=source['lifecycle'].get('reason')))
            if source['rights']['status']=='excluded':reasons.append(dict(code='source_rights_excluded',card=cid,source=sid))
            if source['link']['state']=='unavailable':links.append(dict(code='source_link_unavailable',card=cid,source=sid,url=source['url'],observation=source['link']))
        for conflict in library['open_conflicts']:
            if cid in conflict['cards'] and conflict not in conflicts:
                conflicts.append(conflict);reasons.append(dict(code='open_conflict',card=cid,conflict=conflict['id']))
        queue.extend(card['depends_on'])
    return dict(review_required=bool(reasons),reasons=reasons,link_warnings=links,open_conflicts=conflicts,
        technical_truth_judged=False,requires_applicability_check=True)

def get_card(card_id,*,root=None):
    library=load_library(root);card=next((c for c in library['cards'] if c['id']==card_id),None)
    if card is None:raise InputError('unknown knowledge card')
    return dict(card,knowledge_revision=library['revision'],sources_metadata=[library['sources'][s] for s in card['sources']],
        untrusted_reference_content=True,**card_review(library,card_id))

def search(query,*,limit=5,root=None):
    if not isinstance(query,str) or not 1<=len(query.strip())<=500:raise InputError('knowledge query must contain 1..500 characters')
    if type(limit) is not int or not 1<=limit<=20:raise InputError('knowledge limit must be 1..20')
    library=load_library(root);terms=re.findall(r'[\w-]+',query.casefold())[:30];matches=[]
    for card in library['cards']:
        if card['lifecycle']['state']=='withdrawn' or card['status']=='deprecated':continue
        title=card['title'].casefold();body=card['body'].casefold();tags=' '.join(card['signs']).casefold()
        score=sum(4*(term in title)+2*(term in tags)+(term in body) for term in terms)
        if score:
            matches.append(dict(id=card['id'],title=card['title'],status=card['status'],type=card['type'],
                applicability=card['applicability'],path=str((ROOT/'knowledge' if root is None else Path(root))/card['path']),
                score=score,related=card['related'],sources=[library['sources'][s] for s in card['sources']],
                excerpt=card['body'][:6000],truncated=len(card['body'])>6000,
                untrusted_reference_content=True,diagnosis_for_current_case_established=False,**card_review(library,card['id'])))
    return dict(knowledge_revision=library['revision'],knowledge_digest=library['digest'],scope='bundled_offline_cards',
        matches=sorted(matches,key=lambda m:(-m['score'],m['id']))[:limit],requires_applicability_check=True,technical_truth_judged=False)
