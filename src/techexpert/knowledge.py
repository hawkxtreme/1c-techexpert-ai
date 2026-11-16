"""Offline, linked knowledge cards with explicit applicability and provenance."""
import hashlib
from pathlib import Path,PurePosixPath
import re
from urllib.parse import urlsplit

from .inputs import InputError,read_snapshot,json_value
from .storage import ROOT


def load_library(root=None):
    root=Path(root or ROOT/'knowledge').resolve()
    metadata=read_snapshot(root/'index.json',1024*1024)
    index=json_value(metadata.decode('utf-8'),reject_duplicates=True)
    if index.get('schema_version')!=1 or not isinstance(index.get('revision'),str):raise InputError('unsupported knowledge index')
    digest=hashlib.sha256(metadata);sources={};cards=[];ids=set()
    for item in index.get('sources',[]):
        if not isinstance(item,dict) or not isinstance(item.get('id'),str) or item['id'] in sources:raise InputError('duplicate knowledge source')
        url=urlsplit(item.get('url',''))
        if url.scheme!='https' or not url.hostname or url.username or url.password:raise InputError('knowledge sources require credential-free HTTPS URLs')
        if item.get('storage')!='url_only' or not item.get('checked_at') or not item.get('publisher'):
            raise InputError('knowledge source provenance missing')
        sources[item['id']]=item
    entries=index.get('cards')
    if not isinstance(entries,list) or len(entries)>10000:raise InputError('invalid knowledge card count')
    for card in entries:
        required={'id','title','type','status','author','date','revision','applicability','signs','steps','evidence_basis','related','sources','path'}
        if not isinstance(card,dict) or required-set(card):raise InputError('knowledge card metadata missing')
        if card['id'] in ids or card['status'] not in ('draft','reviewed','validated_in_lab','deprecated'):raise InputError('invalid card identity/status')
        if any(not isinstance(card[k],str) or not card[k] for k in ('id','title','author','date','applicability','evidence_basis')):raise InputError('invalid card description')
        for key in ('signs','steps','related','sources'):
            if not isinstance(card[key],list) or any(not isinstance(x,str) for x in card[key]):raise InputError('invalid card links/steps')
        if set(card['sources'])-sources.keys():raise InputError('unregistered knowledge source')
        path=PurePosixPath(card['path'])
        if path.is_absolute() or '..' in path.parts or '\\' in str(path) or path.suffix!='.md':raise InputError('invalid knowledge card path')
        target=root/Path(path)
        if not target.resolve().is_relative_to(root):raise InputError('knowledge path leaves package')
        for part in (target,*list(target.parents)[:len(path.parts)-1]):
            if part.is_symlink() or getattr(part.lstat(),'st_file_attributes',0)&0x400:raise InputError('linked knowledge card rejected')
        data=read_snapshot(target,64*1024);body=data.decode('utf-8-sig')
        digest.update(str(path).encode());digest.update(data)
        cards.append(dict(card,body=body));ids.add(card['id'])
    if any(set(card['related'])-ids for card in cards):raise InputError('broken knowledge card relation')
    return dict(revision=index['revision'],digest=digest.hexdigest(),cards=cards,sources=sources,
                original_materials_stored=False)


def search(query,*,limit=5,root=None):
    if not isinstance(query,str) or not 1<=len(query.strip())<=500:raise InputError('knowledge query must contain 1..500 characters')
    if type(limit) is not int or not 1<=limit<=20:raise InputError('knowledge limit must be 1..20')
    library=load_library(root);terms=re.findall(r'[\w-]+',query.casefold())[:30];matches=[]
    for card in library['cards']:
        title=card['title'].casefold();body=card['body'].casefold();tags=' '.join(card['signs']).casefold()
        score=sum(4*(term in title)+2*(term in tags)+(term in body) for term in terms)
        if score:
            matches.append(dict(id=card['id'],title=card['title'],status=card['status'],type=card['type'],
                applicability=card['applicability'],path=str(ROOT/'knowledge'/card['path']) if root is None else str(Path(root)/card['path']),
                score=score,related=card['related'],sources=[library['sources'][s] for s in card['sources']],
                excerpt=card['body'][:6000],truncated=len(card['body'])>6000,
                untrusted_reference_content=True,diagnosis_for_current_case_established=False))
    return dict(knowledge_revision=library['revision'],knowledge_digest=library['digest'],
                scope='bundled_offline_cards',matches=sorted(matches,key=lambda m:(-m['score'],m['id']))[:limit],
                requires_applicability_check=True)
