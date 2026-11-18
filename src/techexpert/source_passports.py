"""Source ownership evidence over pinned reports, never probes of original paths.

Configuration is a reported association. A verified snapshot checks retained bytes;
it does not independently authenticate a server or prove historical ownership.
"""
from copy import deepcopy
from datetime import datetime
import hashlib
import json
import re

from .inputs import InputError

FIELDS=('base_alias','node_alias','node_identity','cluster_identity','infobase_identity',
    'database_mode','connection_method','dbms_instance_identity','sql_database_name',
    'dbms_database_identity','source_configuration_version','runtime_configuration_version',
    'extensions','source_commit','journal_identity','process_identity','session_identity',
    'clock_alignment','recorded_run')
KINDS={'native-jr':'jr','onec_source':'source','postgresql':'sql','sqlserver':'sql','rac':'rac','os_metrics':'os','apdex':'apdex'}
CASE_KINDS={'1c-tj-text-v1':'tj','1c-source-text-v1':'source','normalized-events-v1':'normalized_events'}


def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode()).hexdigest()


def _object(value,allowed,required=()):
    if type(value) is not dict or set(value)-set(allowed) or set(required)-set(value):raise InputError('invalid source passport properties')
    return value


def _text(value,limit=256):
    if type(value) is not str or not value.strip() or len(value)>limit or any(ord(c)<32 for c in value):raise InputError('invalid source passport text')
    if re.search(r'(?i)(?:pwd|password|token|secret|authorization)\s*[=:]|://[^/]*@',value):raise InputError('credentials are not source identity facts')
    return value


def _ids(values,prefix):
    if type(values) is not list or len(values)>100:raise InputError('source passport list exceeds limit')
    found=set()
    for value in values:
        if type(value) is not dict or type(value.get('id')) is not str or not re.fullmatch(prefix+r'-[A-Za-z0-9-]{1,60}',value['id']) or value['id'] in found:raise InputError('invalid or duplicate source passport identifier')
        found.add(value['id'])
    return found


def interval(value):
    value=_object(value,('start','end'))
    result=dict(start=value.get('start'),end=value.get('end'))
    for key,item in result.items():
        if item is not None:
            try:
                _text(item,80);parsed=datetime.fromisoformat(item)
                if parsed.utcoffset() is None or item.endswith('-00:00'):raise ValueError()
            except (ValueError,OverflowError) as exc:raise InputError('source applicability requires explicit timezone or null') from exc
    if all(result.values()) and datetime.fromisoformat(result['start'])>=datetime.fromisoformat(result['end']):raise InputError('source applicability start must precede end')
    return result


def _fact(claims):
    known=[claim for claim in claims if claim['value'] is not None]
    values={digest(c['value']) for c in known}
    if len(values)>1:return dict(value=None,basis='conflicting',claims=claims)
    if not known:return dict(value=None,basis='unknown',claims=[])
    basis='observed' if any(c['basis']=='observed' for c in known) else 'reported'
    return dict(value=deepcopy(known[0]['value']),basis=basis,claims=claims)


def _connection_method(base):
    value=base['connection']
    if not value:return None
    if re.match(r'https?://',value):return 'web'
    if re.match(r'(?i)(?:File|Srvr)=',value):return 'direct'
    if base['mode']=='file' and not re.match(r'\w+=',value):return 'direct'
    return None


def _passport(profile,binding,attachment,target):
    snapshot=dict(kind=attachment['kind'],target_id=attachment['target_id'],report_sha256=digest(target))
    if target.get('case_id' if attachment['kind']=='case' else 'artifact_id')!=attachment['target_id']:raise InputError('source snapshot identity mismatch')
    claims={key:[] for key in FIELDS};declared=[];source=None;resource_refs=None
    def claim(key,value,basis,proof):
        if value is not None and value!='':claims[key].append(dict(value=deepcopy(value),basis=basis,proof=proof))
    def observed(key,value,pointer):claim(key,value,'observed',dict(snapshot,pointer=pointer))
    if binding.get('profile_source_id') is not None:
        if profile is None:raise InputError('source profile membership is unavailable')
        from .profile_resources import effective_profile
        configured=effective_profile(profile)
        source=next((s for s in configured['sources'] if s['id']==binding['profile_source_id']),None)
        if source is None:raise InputError('source is absent from the pinned profile')
        declared=list(source['base_ids'])
        if binding.get('base_id') is not None:
            if binding['base_id'] not in declared:raise InputError('source does not declare this base')
            declared=[binding['base_id']]
        bases=[b for b in configured['bases'] if b['id'] in declared]
        proof=dict(profile_revision=profile.get('revision'),profile_sha256=digest(profile),source_id=source['id'],basis='configured_association_not_runtime_ownership')
        for field,key in [('base_alias','name'),('database_mode','mode')]:
            values={b[key] for b in bases}
            if len(values)==1:
                value=next(iter(values));claim(field,None if field=='database_mode' and value=='unknown' else value,'reported',proof)
        node_alias=source['host'];raw_bases=[]
        if profile['schema_version']==2:
            from .profiles import validate_profile
            graph=validate_profile(profile)
            raw=next(s for s in graph['sources'] if s['id']==source['id']);raw_bases=[b for b in graph['bases'] if b['id'] in declared]
            instance=next((r for r in graph['dbms_instances'] if r['id']==raw['dbms_instance_id']),None)
            node_id=raw['node_id'] or (instance['node_id'] if instance else None)
            cluster_ids={b['cluster_id'] for b in raw_bases}
            cluster_id=raw['cluster_id'] or (next(iter(cluster_ids)) if len(cluster_ids)==1 else None)
            node=next((r for r in graph['nodes'] if r['id']==node_id),None)
            cluster=next((r for r in graph['clusters'] if r['id']==cluster_id),None)
            if node:
                node_alias=node['name'];claim('node_identity',node['reported_identity'],'reported',dict(proof,entity='nodes',entity_id=node_id))
            if cluster:claim('cluster_identity',cluster['reported_identity'],'reported',dict(proof,entity='clusters',entity_id=cluster_id))
            if instance:claim('dbms_instance_identity',instance['reported_identity'],'reported',dict(proof,entity='dbms_instances',entity_id=instance['id']))
            for base in raw_bases:claim('infobase_identity',base['reported_identity'],'reported',dict(proof,entity='bases',entity_id=base['id']))
            resource_refs=dict(node_id=node_id,cluster_id=cluster_id,dbms_instance_id=raw['dbms_instance_id'],connection_id=raw['connection_id'] or (instance['connection_id'] if instance else None),database_ids=list(raw['database_ids']))
        claim('node_alias',node_alias,'reported',proof)
        methods={None if b['connection_method']=='unknown' else b['connection_method'] for b in raw_bases} if raw_bases else {_connection_method(base) for base in bases}
        if len(methods)==1:claim('connection_method',next(iter(methods)),'reported',proof)
        sql_names={source['settings'].get('databases',{}).get(bid,source['settings'].get('database')) for bid in declared}
        if len(sql_names)==1:claim('sql_database_name',next(iter(sql_names)),'reported',proof)
    elif binding.get('base_id') is not None:raise InputError('base selection requires a profile source')
    sources=target.get('sources',[])
    selected=binding.get('record_source')
    if selected is not None:
        if not any(s.get('id')==selected for s in sources):raise InputError('source record selection is absent from the snapshot')
        sources=[s for s in sources if s['id']==selected]
    result=target.get('result',{})
    if attachment['kind']=='case':
        formats=sorted({s['format'] for s in sources})
        kind=CASE_KINDS.get(formats[0],'auxiliary') if len(formats)==1 else 'mixed'
    else:
        kind=KINDS.get(target.get('kind'),target.get('kind'))
        formats=[result['profile']] if result.get('profile') is not None else []
    if source is not None and source['type']!=kind:raise InputError('source type disagrees with saved adapter report; select the matching source record')
    content=[dict(id=s['id'],sha256=s['sha256'],bytes=s['size'] if attachment['kind']=='case' else s['bytes']) for s in sources]
    if kind=='jr':observed('journal_identity',result.get('journal_id'),'/result/journal_id')
    if kind=='source':
        origin=result.get('origin',{})
        if origin.get('kind')=='git':observed('source_commit',origin.get('commit'),'/result/origin/commit')
        for index,row in enumerate(result.get('observed_versions',[])):
            if row.get('version') is not None:observed('source_configuration_version',row['version'],'/result/observed_versions/'+str(index)+'/version')
    if kind=='sql' and result.get('status')=='observed':observed('sql_database_name',result.get('database'),'/result/database')
    if attachment['kind']=='case':
        link=target.get('job_correlation',{}).get('native_link',{})
        if link.get('status')=='established' and any(s['id']==link.get('identity',{}).get('source') and s['format']=='1c-tj-text-v1' for s in sources):
            observed('recorded_run',link['identity'],'/job_correlation/native_link/identity')
    reported=_object(binding.get('reported',{}),FIELDS)
    for key,value in reported.items():
        if value is not None:
            value=_text(value)
            if key in ('database_mode','connection_method'):
                choices=('file','server','unknown') if key=='database_mode' else ('direct','web','unknown')
                if value not in choices:raise InputError('invalid reported source mode/method')
                if value=='unknown':continue
            claim(key,value,'reported',dict(basis='caller_reported_not_independent_tool_confirmation'))
    passport=dict(schema_version=1,type=kind,profile_source_id=binding.get('profile_source_id'),
        declared_base_ids=declared,snapshot=snapshot,content=content,
        access_scope=dict(profile_revision=profile.get('revision') if profile else None,source_id=source['id'] if source else None,record_source=selected,
            connection_scope=deepcopy(result.get('connection_scope')),connection_scope_basis='client_settings_not_verified_server_identity'),
        capabilities=dict(adapter_profile=formats[0] if len(formats)==1 else None,adapter_profiles=formats,observation_status=result.get('status'),
            historical_coverage='not_established_by_passport',untrusted_content_executed=False),
        applicability=interval(binding.get('applicability',{})),facts={key:_fact(value) for key,value in claims.items()},
        limitations=['Configured source/base membership and user confirmation remain reported evidence.',
            'Snapshot integrity does not authenticate a server or prove historical ownership.',
            'Journal UUID, SQL database name and session number do not establish infobase identity.',
            'Static source revision is separate from runtime configuration/extensions.',
            'Capture time does not establish applicability or cross-host clock alignment.'])
    if resource_refs is not None:passport['access_scope']['configured_resource_refs']=resource_refs
    return passport


def normalize_bindings(profile,attachments,targets,values,*,profiles=None):
    _ids(values,'S');result=[]
    for value in values:
        _object(value,('id','attachment','profile_source_id','profile_revision','base_id','record_source','applicability','reported','passport'),('id','attachment'))
        attachment=next((a for a in attachments if a['id']==value['attachment']),None)
        if attachment is None or attachment['kind'] not in ('artifact','case') or value['attachment'] not in targets:raise InputError('source passport requires a verified case/artifact attachment')
        selected_profile=None;number=value.get('profile_revision')
        if value.get('profile_source_id') is not None:
            if number is None:number=profile.get('revision') if profile else None
            if type(number) is not int or number<1:raise InputError('source membership requires a pinned profile revision')
            selected_profile=(profiles or {}).get(number)
            if selected_profile is None and profile is not None and profile.get('revision')==number:selected_profile=profile
            if selected_profile is None:raise InputError('source profile revision is not pinned in this investigation')
        elif number is not None:raise InputError('profile revision requires a profile source')
        passport=_passport(selected_profile,value,attachment,targets[value['attachment']])
        if value.get('passport',passport)!=passport:raise InputError('source passport computed evidence mismatch')
        result.append(dict(deepcopy(value),profile_revision=number,passport=passport))
    return result


def _check(left,right,claim,reported):
    facts=[left['facts'],right['facts']];reasons=[];status='reported' if reported else 'unknown';exact=False;scope='independent_analysis_only'
    periods=[p['applicability'] for p in (left,right)]
    if any(first['end'] and second['start'] and datetime.fromisoformat(first['end'])<=datetime.fromisoformat(second['start'])
           for first,second in (periods,periods[::-1])):reasons.append('applicability_disjoint')
    if set(left['declared_base_ids']) and set(right['declared_base_ids']) and not set(left['declared_base_ids'])&set(right['declared_base_ids']):reasons.append('different_declared_bases')
    if any(f['basis']=='conflicting' for group in facts for f in group.values()):reasons.append('conflicting_source_facts')
    if claim=='same_snapshot' and left['content'] and left['content']==right['content']:
        status='confirmed';exact=True;scope='identical_retained_bytes_only_not_database_ownership'
    elif claim=='same_source_version':
        commits=[group['source_commit'] for group in facts]
        if all(c['basis']=='observed' and c['value'] for c in commits):
            status='confirmed' if commits[0]['value']==commits[1]['value'] else 'conflict';exact=status=='confirmed';scope='static_git_revision_only_not_runtime_configuration'
        else:
            versions=[group['source_configuration_version'] for group in facts]
            if all(v['basis']=='observed' and v['value'] for v in versions):
                status='candidate' if versions[0]['value']==versions[1]['value'] else 'conflict'
            reasons.append('runtime_source_correspondence_not_established')
    elif claim=='same_run' and not reasons:
        runs=[group['recorded_run'] for group in facts]
        if all(run['basis']=='observed' and run['value'] for run in runs):
            keys=('job_uuid','nonce','sha256','session_uuid','session_number','process_label','os_thread')
            identities=[tuple(run['value'].get(k) for k in keys) for run in runs]
            if all(all(v is not None for v in identity) for identity in identities):
                status='confirmed' if identities[0]==identities[1] else 'conflict';exact=status=='confirmed';scope='verified_retained_marker_window_only_not_whole_job_or_other_hosts'
    if claim in ('same_infobase','same_run') and not exact:
        reasons.extend(['infobase_or_run_identity_not_established','clock_alignment_not_established'])
        if not all(p['applicability']['start'] and p['applicability']['end'] for p in (left,right)):reasons.append('applicability_unknown')
    if 'conflicting_source_facts' in reasons and not exact:status='conflict'
    return dict(status=status,exact_correlation_allowed=exact,runtime_correlation_allowed=False,scope=scope,reasons=reasons,
        clarification=None if exact else 'Уточните только принадлежность и период этих двух источников, необходимые для выбранного вывода; имена и номера сеансов недостаточны.')


def normalize_links(bindings,values):
    _ids(values,'L');sources={value['id']:value['passport'] for value in bindings};result=[]
    for value in values:
        _object(value,('id','left','right','claim','reported','check'),('id','left','right','claim'))
        if value['left'] not in sources or value['right'] not in sources or value['left']==value['right']:raise InputError('source link requires two existing distinct bindings')
        if value['claim'] not in ('same_infobase','same_snapshot','same_source_version','same_run') or type(value.get('reported',False)) is not bool:raise InputError('unsupported source link claim')
        check=_check(sources[value['left']],sources[value['right']],value['claim'],value.get('reported',False))
        if value.get('check',check)!=check:raise InputError('source link computed result mismatch')
        result.append(dict(deepcopy(value),check=check))
    return result


def context(doc):
    """Private concise linkage context; does not change a saved assessment."""
    links={value['id']:value for value in doc.get('source_links',[])};dependencies=[]
    def add(identifier,kind,selected):
        selected=sorted(set(selected))
        if selected:dependencies.append(dict(conclusion_id=identifier,kind=kind,source_links=selected,
            unresolved_source_links=[key for key in selected if not links[key]['check']['exact_correlation_allowed']]))
    for kind in ('facts','hypotheses'):
        for item in doc[kind]:add(item['id'],kind[:-1] if kind=='facts' else 'hypothesis',item.get('source_links',[]))
    hypothesis_links={item['id']:item.get('source_links',[]) for item in doc['hypotheses']}
    assessment=doc.get('assessment')
    if assessment:
        add('assessment','assessment',hypothesis_links.get(assessment.get('hypothesis_id'),[]))
        for item in assessment['recommendations']:
            inherited=[key for basis in item['basis'] for key in hypothesis_links.get(basis,[])]
            add(item['id'],'recommendation',item.get('source_links',[])+inherited)
    unresolved=sorted({key for item in dependencies for key in item['unresolved_source_links']})
    return dict(schema_version=1,investigation_id=doc['investigation_id'],revision=doc['revision'],
        profile_revision=doc['profile_snapshot'].get('revision') if doc.get('profile_snapshot') else None,
        status='legacy_unknown' if doc['schema_version']==1 else 'needs_clarification' if unresolved else 'recorded',
        bindings=deepcopy(doc.get('source_bindings',[])),links=deepcopy(list(links.values())),dependencies=dependencies,
        needs_clarification=bool(unresolved),clarifications=[dict(source_link=key,question=links[key]['check']['clarification']) for key in unresolved],
        assessment_status=doc['assessment_status'],
        limitations=['Dependencies are explicitly recorded by the harness; missing dependency declarations are unknown, not proof of independence.',
            'Reported configuration/user confirmation is distinct from verified retained observations; hashes do not certify causal truth.',
            'Unresolved unrelated links do not require a full infrastructure form or block independent source analysis.'])


def setup_states(doc):
    review=context(doc)
    unresolved={item['source_link'] for item in review['clarifications']}
    needed={link[key] for link in doc.get('source_links',[]) if link['id'] in unresolved for key in ('left','right')}
    result={}
    for binding in doc.get('source_bindings',[]):
        sid=binding.get('profile_source_id')
        if sid is None:continue
        row=result.setdefault(sid,dict(basis='reported_configuration',needs_clarification=False,binding_profile_revisions=[]))
        row['needs_clarification']|=binding['id'] in needed
        number=binding.get('profile_revision')
        if number not in row['binding_profile_revisions']:row['binding_profile_revisions'].append(number)
    return result


def public_review(doc):
    review=context(doc)
    return dict(status=review['status'],unresolved_link_count=len(review['clarifications']),
        dependent_conclusion_count=sum(bool(row['unresolved_source_links']) for row in review['dependencies']),
        scope='explicit_harness_dependencies_only; legacy_source_use_unknown; no_private_passport_fields')
