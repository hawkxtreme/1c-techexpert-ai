"""Private revisioned harness reasoning over immutable, integrity-checked evidence.

This module validates structure and references. It does not judge causal truth or
execute a diagnostic plan. Budgets here account for reported tool runs only.
"""
from copy import deepcopy
from datetime import datetime,timezone
import hashlib
import html
import json
import math
import os
from pathlib import Path
import re
import uuid

from . import __version__
from . import report_references
from .artifacts import load_artifact,artifact_evidence,encoded
from .incident_templates import catalogue as templates,plan as template_plan
from .inputs import InputError,json_value,read_snapshot
from .profiles import load_profile,validate_profile
from .storage import ROOT,verified_case,load_comparison,read_evidence,knowledge_revision,write_json

MAX_DOCUMENT=2*1024*1024
EDITABLE={'episode','attachments','evidence','facts','hypotheses','contradictions','open_questions','tool_runs',
          'assessment','improvement','observation_plan','execution_status','harness',
          'template_id','template_revision','variant','time_mode','scale','profile_revision','workflow_stage','occurrence',
          'source_bindings','source_links'}
CAUSES=('confirmed','hypothesis','insufficient_data')

def _digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode()).hexdigest()
def _object(value,allowed,required=()):
    if not isinstance(value,dict) or set(value)-set(allowed) or set(required)-set(value):raise InputError('invalid investigation object properties')
    return value
def _text(value,limit=8192,empty=False):
    if not isinstance(value,str) or len(value)>limit or (not empty and not value.strip()) or any(ord(c)<32 and c not in '\n\r\t' for c in value):raise InputError('invalid investigation text')
    return value
def _list(value,maximum=1000):
    if not isinstance(value,list) or len(value)>maximum:raise InputError('investigation list exceeds limit')
    return value
def _texts(value,maximum=1000):
    return [_text(item) for item in _list(value,maximum)]
def _ids(items,prefix):
    found=set()
    for item in items:
        if not isinstance(item,dict) or not isinstance(item.get('id'),str) or not re.fullmatch(prefix+r'-[A-Za-z0-9-]{1,60}',item['id']) or item['id'] in found:raise InputError('invalid or duplicate investigation identifier')
        found.add(item['id'])
    return found
def _references(values,allowed,*,required=False):
    values=_texts(values,200)
    if len(values)!=len(set(values)) or any(v not in allowed for v in values) or (required and not values):raise InputError('unresolved investigation evidence reference')
    return values

def revision_folder(state_dir,investigation_id,revision):
    if not isinstance(investigation_id,str) or not re.fullmatch('[a-f0-9]{32}',investigation_id):raise InputError('invalid investigation identifier')
    if type(revision) is not int or not 1<=revision<=1000:raise InputError('invalid investigation revision')
    return Path(state_dir)/'investigations'/investigation_id/'revisions'/str(revision).zfill(6)

def _target(state_dir,item):
    functions={'case':verified_case,'artifact':load_artifact,'comparison':load_comparison}
    if item.get('kind') not in functions:raise InputError('unsupported investigation attachment kind')
    return functions[item['kind']](state_dir,item.get('target_id'))

def _pointer(value,pointer):
    _text(pointer,1024,empty=True)
    if pointer and not pointer.startswith('/'):raise InputError('measurement requires a JSON pointer')
    try:
        for part in pointer.split('/')[1:]:
            if re.search('~(?![01])',part):raise InputError('invalid JSON pointer escape')
            part=part.replace('~1','/').replace('~0','~')
            if isinstance(value,list):
                if not re.fullmatch('0|[1-9][0-9]*',part):raise InputError('invalid JSON array index')
                value=value[int(part)]
            elif isinstance(value,dict):value=value[part]
            else:raise InputError('measurement pointer crosses a scalar')
    except (KeyError,IndexError) as exc:raise InputError('measurement pointer does not exist') from exc
    if isinstance(value,(list,dict)) or (isinstance(value,str) and len(value)>8192):raise InputError('measurement must select one bounded scalar')
    return value

def _verify_evidence(state_dir,doc):
    attachments=_list(doc['attachments'],16);aids=_ids(attachments,'A');targets={}
    for item in attachments:
        _object(item,('id','kind','target_id','report_sha256','source_origin'),('id','kind','target_id'))
        if doc['schema_version']==2:
            from .operations import _guard_dependency_paths
            kinds=dict(case='cases',artifact='artifacts',comparison='comparisons')
            if item['kind'] not in kinds:raise InputError('unsupported investigation attachment kind')
            _guard_dependency_paths(state_dir,kinds[item['kind']],item['target_id'])
        target=_target(state_dir,item);digest=_digest(target)
        if item.get('report_sha256',digest)!=digest:raise InputError('investigation attachment integrity mismatch')
        origin=target.get('origin',target.get('result',{}).get('origin','not_established'))
        if item.get('source_origin',origin)!=origin:raise InputError('attachment origin disagrees with saved tool report')
        item.update(report_sha256=digest,source_origin=origin);targets[item['id']]=target
    evidence=_list(doc['evidence'],200);eids=_ids(evidence,'E')
    for item in evidence:
        _object(item,('id','attachment','record','proof'),('id','attachment','record'))
        if item['attachment'] not in aids:raise InputError('unknown investigation attachment')
        attachment=next(a for a in attachments if a['id']==item['attachment']);record=item['record']
        if attachment['kind']=='case':proof=read_evidence(state_dir,attachment['target_id'],record)
        elif attachment['kind']=='artifact':
            if targets[item['attachment']]['kind']=='native-jr' and isinstance(record,str) and ':r' in record:
                from .native_jr import read_record
                found=read_record(state_dir,attachment['target_id'],record)['record']
                proof={k:found[k] for k in ('source','file','byte_start','byte_end','sha256')}
            else:
                found=artifact_evidence(state_dir,attachment['target_id'],record)
                source=next(s for s in targets[item['attachment']]['sources'] if s['id']==record)
                proof=dict(source=record,file=source['name'],sha256=found['sha256'],byte_start=0,byte_end=source['bytes'])
        else:
            if record!='report':raise InputError('comparison evidence record must be report')
            proof=dict(kind='calculation',sha256=attachment['report_sha256'],method='saved_comparison_report')
        proof={k:v for k,v in proof.items() if k not in ('text','untrusted_source_content','truncated')}
        if item.get('proof',proof)!=proof:raise InputError('investigation evidence integrity mismatch')
        item['proof']=proof
    return aids,eids,targets

def _source_profiles(state_dir,doc):
    """Resolve only profiles pinned in this immutable history, never current.json."""
    result={};profile=doc.get('profile_snapshot')
    if profile is not None:result[profile['revision']]=profile
    needed=set()
    for binding in _list(doc.get('source_bindings',[]),100):
        if type(binding) is not dict:raise InputError('invalid source binding')
        number=binding.get('profile_revision')
        if number is not None:
            if type(number) is not int or number<1:raise InputError('invalid source profile revision')
            needed.add(number)
    expected=doc.get('parent_sha256')
    for number in range(doc['revision']-1,0,-1):
        if needed<=result.keys():break
        parent,_=_read_revision(state_dir,doc['investigation_id'],number)
        if _digest(parent)!=expected:raise InputError('source profile history integrity mismatch')
        profile=parent.get('profile_snapshot');expected=parent.get('parent_sha256')
        if profile is not None and profile['revision'] in needed:
            validate_profile(profile)
            if _digest(profile)!=parent['profile_sha256']:raise InputError('source profile snapshot integrity mismatch')
            result.setdefault(profile['revision'],profile)
    if not needed<=result.keys():raise InputError('source profile revision is not pinned in this investigation')
    return result


def _validate(state_dir,doc):
    encoded(doc,MAX_DOCUMENT)
    if doc['time_mode'] not in ('unknown','past','current','reproduce') or doc['scale'] not in ('one','several','all','background','unknown'):raise InputError('invalid investigation time or scale')
    if doc['execution_status'] not in ('completed','partial','error','cancelled'):raise InputError('invalid execution status')
    _text(doc['task']);_object(doc['episode'],('description','start','end','utc_offset','database_mode','operation','user_reported_baseline','client_context','recurrence_seconds','requested_window_seconds'))
    for key,value in doc['episode'].items():
        if key in ('recurrence_seconds','requested_window_seconds'):
            if value is not None and (type(value) not in (int,float) or not math.isfinite(value) or not 0<value<=31*86400):raise InputError('invalid periodic incident interval')
        elif value is not None:_text(value)
    if doc['episode'].get('database_mode','unknown') not in ('file','server','unknown'):raise InputError('invalid database mode')
    aids,eids,targets=_verify_evidence(state_dir,doc)
    source_links=set()
    if doc['schema_version']==2:
        from .source_passports import normalize_bindings,normalize_links
        profile=doc['profile_snapshot']
        if profile is not None:
            validate_profile(profile)
            if _digest(profile)!=doc['profile_sha256']:raise InputError('source passport profile snapshot integrity mismatch')
        doc['source_bindings']=normalize_bindings(profile,doc['attachments'],targets,doc['source_bindings'],profiles=_source_profiles(state_dir,doc))
        doc['source_links']=normalize_links(doc['source_bindings'],doc['source_links'])
        source_links={item['id'] for item in doc['source_links']}
    elif 'source_bindings' in doc or 'source_links' in doc:raise InputError('source passports require investigation schema2')
    facts=_list(doc['facts'],200);fids=_ids(facts,'F')
    for fact in facts:
        _object(fact,('id','text','evidence','measurement','statement_basis','source_links'),('id','text','evidence'))
        _text(fact['text']);_references(fact['evidence'],eids,required=True)
        if 'source_links' in fact:_references(fact['source_links'],source_links)
        fact['statement_basis']='harness_claim_with_linked_evidence; semantic_truth_not_checked'
        if 'measurement' in fact:
            measurement=fact['measurement'];_object(measurement,('attachment','pointer','value','basis'),('attachment','pointer'))
            if measurement['attachment'] not in aids:raise InputError('measurement attachment is missing')
            if not any(e['id'] in fact['evidence'] and e['attachment']==measurement['attachment'] for e in doc['evidence']):raise InputError('measurement must cite evidence from its attachment')
            value=_pointer(targets[measurement['attachment']],measurement['pointer'])
            if 'value' in measurement and (type(measurement['value']) is not type(value) or measurement['value']!=value):raise InputError('measurement disagrees with verified tool report')
            measurement.update(value=value,basis='verified_tool_report')
    hypotheses=_list(doc['hypotheses'],100);hids=_ids(hypotheses,'H')
    for item in hypotheses:
        _object(item,('id','text','status','evidence','source_links'),('id','text','status','evidence'));_text(item['text'])
        if 'source_links' in item:_references(item['source_links'],source_links)
        if item['status'] not in ('proposed','testing','supported','refuted','insufficient_data'):raise InputError('invalid hypothesis status')
        _references(item['evidence'],eids,required=item['status'] in ('supported','refuted'))
    _ids(_list(doc['contradictions'],100),'C')
    for item in doc['contradictions']:
        _object(item,('id','text','evidence','hypotheses','status','resolution'),('id','text','evidence','hypotheses','status'))
        _text(item['text']);_references(item['evidence'],eids,required=True);_references(item['hypotheses'],hids)
        if item['status'] not in ('unresolved','resolved'):raise InputError('invalid contradiction status')
        if item['status']=='resolved':_text(item.get('resolution'))
    _texts(doc['open_questions'])
    _object(doc['harness'],('name','version','model'))
    for key in ('name','version','model'):doc['harness'].setdefault(key,None)
    for value in doc['harness'].values():
        if value is not None:_text(value,512)
    runs=_list(doc['tool_runs'],100);_ids(runs,'T');elapsed=0;output=0
    for item in runs:
        _object(item,('id','operation','status','elapsed_seconds','output_bytes','attachment','parameters'),('id','operation','status','elapsed_seconds','output_bytes'))
        _text(item['operation'],120)
        if item['status'] not in ('planned','running','completed','partial','error','cancelled','interrupted_unknown'):raise InputError('invalid tool run status')
        seconds=item['elapsed_seconds'];size=item['output_bytes']
        if type(seconds) not in (int,float) or not math.isfinite(seconds) or seconds<0 or type(size) is not int or size<0:raise InputError('invalid tool run accounting')
        if item.get('attachment') is not None and item['attachment'] not in aids:raise InputError('tool run attachment is missing')
        if 'parameters' in item:
            params=_object(item['parameters'],('operation','source_id','profile_revision','duration_seconds','interval_seconds'))
            encoded(params,8192)
        elapsed+=seconds;output+=size
    doc['budget_accounting']=dict(tool_runs=len(runs),elapsed_seconds=elapsed,output_bytes=output,tokens=None,
        basis='harness_reported; not_a_global_execution_gate',remaining_harness_tokens=None)
    doc['unfinished_tool_runs']=[r['id'] for r in runs if r['status']=='running']
    plan=doc['observation_plan']
    if plan is not None:
        _object(plan,('operations','sources','metrics','thresholds','duration_seconds','max_bytes','responsible','rollback','verification','status','evidence','start','end','collection_method','collection_state','rotation'),
                ('operations','sources','metrics','duration_seconds','max_bytes','responsible','rollback','verification','status'))
        for key in ('operations','sources','metrics','thresholds'):
            if key in plan:_texts(plan[key],100)
        for key in ('responsible','rollback','verification'):_text(plan[key])
        if type(plan['duration_seconds']) not in (int,float) or not 0<plan['duration_seconds']<=7*86400 or not math.isfinite(plan['duration_seconds']):raise InputError('invalid observation duration')
        if type(plan['max_bytes']) is not int or not 0<plan['max_bytes']<=64*1024*1024:raise InputError('invalid observation byte limit')
        if plan['status'] not in ('proposed','configured_reported','data_verified','cancelled'):raise InputError('invalid observation status')
        _references(plan.get('evidence',[]),eids,required=plan['status']=='data_verified')
        if plan.get('collection_state','unknown') not in ('unknown','not_started','launch_reported','receiving_data','stopped_reported'):raise InputError('invalid collection state')
        if plan.get('collection_state')=='receiving_data':_references(plan.get('evidence',[]),eids,required=True)
        for key in ('collection_method','rotation'):
            if key in plan:_text(plan[key])
        dates=[]
        for key in ('start','end'):
            value=plan.get(key)
            if value is not None:
                date=datetime.fromisoformat(_text(value,128))
                if date.utcoffset() is None:raise InputError('observation window requires a time zone')
                dates.append(date)
        if len(dates)==2 and (dates[1]-dates[0]).total_seconds()!=plan['duration_seconds']:raise InputError('observation window disagrees with duration')
    improvement=doc['improvement']
    if improvement is not None:
        _object(improvement,('applied','comparability','effect','goal','recurrence','window','evidence'),('applied','comparability','effect','goal','recurrence','window','evidence'))
        enums=dict(applied=('proposed','reported','evidenced'),comparability=('comparable','not_comparable','unknown'),effect=('better','no_confirmed_change','worse','unknown'),goal=('reached','not_reached','unknown'),recurrence=('observed','not_observed_in_window','unknown'))
        for key,allowed in enums.items():
            if improvement[key] not in allowed:raise InputError('invalid improvement status')
        _references(improvement['evidence'],eids,required=improvement['applied']=='evidenced' or improvement['effect']!='unknown' or improvement['goal']!='unknown' or improvement['recurrence']!='unknown')
        if improvement['window'] is not None:_text(improvement['window'],1024)
        if improvement['recurrence']=='not_observed_in_window' and not improvement['window']:raise InputError('nonrecurrence requires an explicit observation window')
    assessment=doc['assessment'];doc['cause_state']='insufficient_data'
    if assessment is not None:
        _object(assessment,('summary','cause_state','hypothesis_id','mechanism','verification','evidence','alternatives','limitations','recommendations','references'),
            ('summary','cause_state','evidence','limitations','recommendations','references'))
        _text(assessment['summary']);_texts(assessment['limitations'],100)
        cause=assessment['cause_state']
        if cause not in CAUSES:raise InputError('invalid cause state')
        _references(assessment['evidence'],eids,required=cause!='insufficient_data')
        if cause!='insufficient_data':
            hypothesis=next((h for h in hypotheses if h['id']==assessment.get('hypothesis_id')),None)
            if hypothesis is None or hypothesis['status'] in ('refuted','insufficient_data'):raise InputError('cause needs a supported or pending hypothesis')
            _text(assessment.get('mechanism'))
            if cause=='confirmed':
                if hypothesis['status']!='supported':raise InputError('confirmed cause needs a supported hypothesis')
                _text(assessment.get('verification'));_texts(assessment.get('alternatives'),100)
                if not assessment['alternatives']:raise InputError('confirmed cause needs evaluated alternatives')
                if any(c['status']=='unresolved' and hypothesis['id'] in c['hypotheses'] for c in doc['contradictions']):raise InputError('unresolved contradiction prevents cause confirmation')
        recommendations=_list(assessment['recommendations'],100)
        for item in recommendations:
            _object(item,('id','kind','basis','goal','prerequisites','expected_effect','verification','limitations','risk','rollback','source_links'),
                ('id','kind','basis','goal','prerequisites','expected_effect','verification','limitations'))
            if item['kind'] not in ('diagnostic','lab_change','production_change'):raise InputError('invalid recommendation kind')
            _references(item['basis'],eids|hids,required=True)
            if 'source_links' in item:_references(item['source_links'],source_links)
            for key in ('goal','prerequisites','expected_effect','verification','limitations'):_text(item[key])
            if item['kind']!='diagnostic':_text(item.get('risk'));_text(item.get('rollback'))
        _ids(recommendations,'R')
        report_references.validate(assessment, hypotheses, doc['evidence'], doc['attachments'], targets)
        doc['cause_state']=cause
    if 'workflow_stage' in doc:
        stage=doc['workflow_stage']
        if stage not in ('initial_analysis','prepare_observation','awaiting_occurrence','analyze_episode','verify_fix','closed'):raise InputError('invalid investigation workflow stage')
        occurrence=doc.get('occurrence')
        if occurrence is not None:
            _object(occurrence,('id','source','message','reported_at','started_at','ended_at','evidence','link_basis','status'),
                ('id','source','message','reported_at','started_at','ended_at','evidence'))
            if occurrence['source'] not in ('user','external_monitoring'):raise InputError('invalid occurrence report source')
            _text(occurrence['message']);_references(occurrence['evidence'],eids)
            dates=[]
            for key in ('started_at','ended_at','reported_at'):
                if occurrence[key] is not None:
                    date=datetime.fromisoformat(_text(occurrence[key],128))
                    if date.utcoffset() is None:raise InputError('occurrence timestamps require a time zone or unknown')
                    if key!='reported_at':dates.append(date)
            if len(dates)==2 and dates[1]<dates[0]:raise InputError('occurrence end precedes start')
            if occurrence['evidence']:_text(occurrence.get('link_basis'))
            occurrence['status']='evidenced_by_harness' if occurrence['evidence'] else 'reported_not_verified'
        if stage=='awaiting_occurrence':
            if plan is None or plan['status'] not in ('configured_reported','data_verified'):raise InputError('awaiting occurrence requires reported or evidenced preparation')
            doc['execution_status']='partial'
        doc['stage_execution_status']='completed' if stage=='awaiting_occurrence' else doc['execution_status']
        doc['continuation']=dict(trigger='user_or_external_occurrence_report' if stage=='awaiting_occurrence' else 'current_harness',
            model_polling_required=False,same_investigation_id=doc['investigation_id'],
            preparation_basis=plan['status'] if plan else 'not_prepared',collection_state=plan.get('collection_state','unknown') if plan else 'unknown',
            message='Этап подготовки завершён. После сообщения о повторении вернитесь в этот же чат и укажите доступное время или признаки события.' if stage=='awaiting_occurrence' else 'Продолжить текущий этап по сохранённым данным.')
    doc['structural_validation_only']=True
    return doc

def _basis(doc):
    value={k:doc.get(k) for k in ('episode','attachments','evidence','facts','hypotheses','contradictions','template','variant','time_mode','scale','profile_sha256','occurrence')}
    for key in ('source_bindings','source_links'):
        if doc.get(key):value[key]=doc[key]
    return _digest(value)

def _md(value):
    return re.sub(r'([\\`*_{}\[\]()#+\-.!|>])',r'\\\1',html.escape(str(value),quote=False))

def render(doc):
    from .source_passports import context
    source_review=context(doc) if doc['schema_version']==2 else None
    assessment=doc['assessment']
    citations=report_references.by_target(assessment)
    summary_references=[]
    if citations['assessment']:
        summary_references.append('')
        if assessment['evidence']:
            summary_references.append('Вывод опирается на '+', '.join(assessment['evidence'])+'.')
        summary_references.extend(report_references.markdown(item,'assessment',_md) for item in citations['assessment'])
    lines=['# Расследование '+doc['investigation_id'], '',f"Ревизия: {doc['revision']}. Выполнение: {doc['execution_status']}. Причина: {doc['cause_state']}.", '',
           'Этап: '+doc.get('workflow_stage','initial_analysis')+'.',
           _md(doc['continuation']['message']) if doc.get('continuation') else '',
           _md(doc['task']),'',_md(doc['assessment']['summary']) if doc['assessment'] else 'Причина не установлена. Сохранены наблюдения и следующие проверки.',
           *summary_references,
           '', 'Проверены структура и ссылки. Причинное объяснение принадлежит указанному harness; правильность механизма инструментом не доказана.',
           *(['','Принадлежность источников для части выводов требует отдельной проверки.'] if source_review and source_review['needs_clarification'] else []),
           '', '## Контекст', '',f"Шаблон: {doc['template']['id']}, ревизия {doc['template']['revision']}. Время: {doc['time_mode']}. Масштаб: {doc['scale']}.",
           '',_md(json.dumps(doc['episode'],ensure_ascii=False)), '', '## Наблюдения', '']
    for fact in doc['facts']:
        lines.append('- '+fact['id']+': '+_md(fact['text'])+' ('+', '.join(fact['evidence'])+').')
        if 'measurement' in fact:lines.append('  Значение инструмента: '+_md(fact['measurement']['value'])+'; '+_md(fact['measurement']['pointer'])+'.')
    if source_review and doc['source_bindings']:
        lines+=['','## Принадлежность источников','']
        for binding in doc['source_bindings']:
            lines.append('- '+binding['id']+': '+_md(binding['passport']['type'])+'; профиль '+str(binding['profile_revision'])+'; '+binding['attachment']+'.')
        for link in doc['source_links']:
            lines.append('- '+link['id']+': '+link['left']+' / '+link['right']+'; '+_md(link['claim'])+'; '+_md(link['check']['status'])+'; область '+_md(link['check']['scope'])+'.')
        for item in source_review['dependencies']:
            if item['unresolved_source_links']:lines.append('- '+item['conclusion_id']+': вывод зависит от неподтверждённых связей '+', '.join(item['unresolved_source_links'])+'.')
    lines+=['','## Гипотезы и противоречия','']
    for item in doc['hypotheses']:
        lines.append('- '+item['id']+' ['+item['status']+']: '+_md(item['text']))
        lines.extend(report_references.markdown(link,item['id'],_md,prefix='  - ') for link in citations[item['id']])
    for item in doc['contradictions']:lines.append('- '+item['id']+' ['+item['status']+']: '+_md(item['text']))
    lines+=['','## Доказательства','']
    for item in doc['attachments']:lines.append('- '+item['id']+': '+item['kind']+' / '+item['target_id']+'; origin='+_md(item['source_origin'])+'; report_sha256='+item['report_sha256'])
    for item in doc['evidence']:lines.append('- '+item['id']+': '+item['attachment']+', '+_md(item['record'])+'; '+_md(json.dumps(item['proof'],ensure_ascii=False)))
    lines+=['','## Следующие проверки','']+['- '+_md(x) for x in doc['open_questions']]
    if doc['assessment']:
        for item in doc['assessment']['recommendations']:
            lines+=['','### '+item['id']+' · '+_md(item['goal']),'']
            for key in ('kind','basis','prerequisites','expected_effect','verification','limitations','risk','rollback'):
                if key in item:lines.append(_md(key)+': '+_md(item[key])+'  ')
            if citations[item['id']]:
                lines.append('')
                lines.extend(report_references.markdown(link,item['id'],_md) for link in citations[item['id']])
        lines+=['','## Ограничения','']+['- '+_md(x) for x in doc['assessment']['limitations']]
        if citations['legacy']:
            lines+=['','## Ссылки','']
            for item in citations['legacy']:
                lines.append('- '+_md(item['purpose'])+': <'+item['url']+'>; '+_md(item['applicability']))
    lines+=['','## Проверка исправления','',_md(json.dumps(doc['improvement'],ensure_ascii=False)),
            '', '## План наблюдения','',_md(json.dumps(doc['observation_plan'],ensure_ascii=False)),
            '', '## Версии и ограничения учёта','',_md(json.dumps(doc['versions'],ensure_ascii=False)),
            '',_md(json.dumps(dict(current_harness=doc['harness'],assessment_harness=doc['assessment_harness']),ensure_ascii=False)),
            '', 'Расход записан со слов harness; общий исполнитель плана и подсчёт его токенов здесь не реализованы.', '']
    return '\n'.join(lines)

def _persist(state_dir,doc):
    report=encoded(doc,MAX_DOCUMENT);markdown=render(doc).encode('utf-8')
    if len(markdown)>MAX_DOCUMENT:raise InputError('investigation report exceeds byte limit')
    folder=revision_folder(state_dir,doc['investigation_id'],doc['revision']);folder.mkdir(parents=True,exist_ok=False)
    if os.name!='nt':folder.parent.parent.chmod(0o700)
    (folder/'report.json').write_bytes(report);(folder/'report.md').write_bytes(markdown)
    receipt=dict(schema_version=1,revision=doc['revision'],report_sha256=hashlib.sha256(report).hexdigest(),markdown_sha256=hashlib.sha256(markdown).hexdigest())
    write_json(folder/'receipt.json',receipt)
    write_json(folder.parent.parent/'head.json',dict(revision=doc['revision'],report_sha256=receipt['report_sha256']))
    return doc

def _read_revision(state_dir,iid,revision):
    folder=revision_folder(state_dir,iid,revision)
    receipt=json_value(read_snapshot(folder/'receipt.json',8192).decode('utf-8'),reject_duplicates=True)
    if type(receipt) is not dict:raise InputError('invalid saved investigation receipt')
    data=read_snapshot(folder/'report.json',MAX_DOCUMENT);markdown=read_snapshot(folder/'report.md',MAX_DOCUMENT)
    if hashlib.sha256(data).hexdigest()!=receipt.get('report_sha256') or hashlib.sha256(markdown).hexdigest()!=receipt.get('markdown_sha256'):raise InputError('investigation report integrity mismatch')
    doc=json_value(data.decode('utf-8'),reject_duplicates=True)
    if type(doc) is not dict or type(doc.get('schema_version')) is not int or doc['schema_version'] not in (1,2) or doc.get('investigation_id')!=iid or doc.get('revision')!=revision:raise InputError('unsupported investigation schema or identity')
    return doc,receipt

def _read_head(state_dir, investigation_id):
    from .investigation_retention import require_available
    from .operation_state import safe
    require_available(state_dir, investigation_id)
    first=revision_folder(state_dir,investigation_id,1).parent.parent
    return json_value(read_snapshot(safe(first/'head.json'),8192).decode('utf-8'),reject_duplicates=True)


def _revision_chain(state_dir, investigation_id, head, revision):
    if type(head) is not dict or type(head.get('revision')) is not int:raise InputError('invalid investigation head')
    selected=head['revision'] if revision is None else revision
    if type(selected) is not int or selected>head['revision']:raise InputError('investigation revision not committed')
    revision_folder(state_dir, investigation_id, selected)
    expected_parent=None
    for number in range(selected,0,-1):
        current,receipt=_read_revision(state_dir,investigation_id,number)
        if number==head['revision'] and receipt['report_sha256']!=head.get('report_sha256'):raise InputError('investigation head integrity mismatch')
        if number!=selected and expected_parent!=_digest(current):raise InputError('investigation history integrity mismatch')
        expected_parent=current.get('parent_sha256')
        yield current


def _committed_revision(state_dir, investigation_id, revision):
    head=_read_head(state_dir,investigation_id)
    chain=_revision_chain(state_dir,investigation_id,head,revision)
    doc=next(chain)
    for _ in chain:
        pass
    return doc


def load(state_dir,investigation_id,*,revision=None):
    doc = _committed_revision(state_dir, investigation_id, revision)
    original=_digest(doc);_validate(state_dir,doc)
    if _digest(doc)!=original:raise InputError('investigation computed fields integrity mismatch')
    return doc


def read_for_display(state_dir, investigation_id, *, revision=None):
    from .case_retention import SnapshotRetirement, for_report
    try:
        return load(state_dir, investigation_id, revision=revision)
    except SnapshotRetirement:
        doc = _committed_revision(state_dir, investigation_id, revision)
        losses = for_report(state_dir, doc)
        if not losses:
            raise
        return dict(doc, reproducibility=dict(
            status='intentionally_incomplete' if all(loss['status'] == 'removed' for loss in losses)
                   else 'retirement_outcome_unverified',
            scope='sealed_historical_report_remaining_evidence_not_reverified', retired_sources=losses))

def source_context(state_dir,investigation_id,*,revision=None):
    from .source_passports import context
    from .operations import _verify_target
    if revision is None:
        revision=_read_head(state_dir,investigation_id).get('revision')
    return context(_verify_target(state_dir,'investigations',investigation_id,revision=revision))


def create(state_dir,request):
    _object(request,('task','template_id','template_revision','variant','time_mode','scale','episode','harness'),('task',))
    request=dict(dict(template_id='TPL-00'),**request)
    _text(request['task']);book=templates()
    if (('time_mode' in request and request['time_mode'] not in book['time_modes'])
        or ('scale' in request and request['scale'] not in book['scales'])):raise InputError('invalid investigation time or scale')
    if 'template_revision' in request and (type(request['template_revision']) is not int or request['template_revision']<1):
        raise InputError('invalid requested template revision')
    selected=template_plan(request['template_id'],variant=request.get('variant'),time_mode=request.get('time_mode'),
                           state_dir=state_dir,revision=request.get('template_revision'))
    defaults=selected['defaults']
    episode={}
    if 'database_mode' in defaults:episode['database_mode']=defaults['database_mode']
    supplied=request.get('episode',{})
    if not isinstance(supplied,dict):raise InputError('invalid investigation episode')
    episode.update(deepcopy(supplied))
    profile=load_profile(state_dir)
    skill_digest=hashlib.sha256()
    for path in sorted((ROOT/'skills').rglob('SKILL.md')):
        skill_digest.update(path.relative_to(ROOT).as_posix().encode());skill_digest.update(read_snapshot(path,256*1024))
    doc=dict(schema_version=2,investigation_id=uuid.uuid4().hex,revision=1,parent_sha256=None,
        created_at=datetime.now(timezone.utc).isoformat(),task=request['task'],template=selected['template'],variant=selected['variant'],
        template_catalogue_sha256=selected['catalogue_sha256'],time_mode=selected['time_mode'],
        scale=request.get('scale',defaults.get('scale','unknown')),episode=episode,
        profile_snapshot=profile,profile_sha256=_digest(profile) if profile else None,
        versions=dict(product=__version__,knowledge=knowledge_revision(),skills_sha256=skill_digest.hexdigest(),instructions_sha256=hashlib.sha256(read_snapshot(ROOT/'AGENTS.md',256*1024)).hexdigest()),
        harness=deepcopy(request.get('harness',dict(name=None,version=None,model=None))),execution_status='partial',cause_state='insufficient_data',
        attachments=[],evidence=[],facts=[],hypotheses=[],contradictions=[],open_questions=[],tool_runs=[],assessment=None,
        assessment_status='not_provided',assessment_harness=None,improvement=None,observation_plan=None,structural_validation_only=True,
        workflow_stage='initial_analysis',occurrence=None,source_bindings=[],source_links=[])
    _validate(state_dir,doc);doc['analysis_basis_sha256']=_basis(doc)
    return _persist(state_dir,doc)

def revise(state_dir,investigation_id,patch,*,expected_revision):
    _object(patch,EDITABLE)
    if type(expected_revision) is not int:raise InputError('expected revision required')
    from .investigation_retention import writer
    with writer(state_dir, investigation_id):
        return _revise(state_dir, investigation_id, patch, expected_revision=expected_revision)


def _revise(state_dir,investigation_id,patch,*,expected_revision):
    folder=revision_folder(state_dir,investigation_id,1).parent.parent
    lock=folder/'write.lock'
    try:
        with lock.open('x',encoding='ascii') as stream:stream.write(str(os.getpid()))
    except FileExistsError as exc:raise InputError('investigation writer is active or interrupted; inspect its lock before retrying') from exc
    try:
        previous = read_for_display(state_dir, investigation_id)
        previous.pop('reproducibility', None)
        if previous['revision']!=expected_revision:raise InputError('investigation revision changed; reload before editing')
        if expected_revision>=1000:raise InputError('investigation revision limit reached; retain history and start a linked investigation')
        doc=deepcopy(previous);changes=deepcopy(patch)
        doc['schema_version']=2;doc.setdefault('source_bindings',[]);doc.setdefault('source_links',[])
        doc.setdefault('workflow_stage','initial_analysis');doc.setdefault('occurrence',None)
        if changes.get('occurrence') is not None:
            occurrence=changes['occurrence']
            _object(occurrence,('source','message','started_at','ended_at','evidence','link_basis'),('source','message','started_at','ended_at','evidence'))
            occurrence.update(id=uuid.uuid4().hex,reported_at=datetime.now(timezone.utc).isoformat())
            changes.setdefault('workflow_stage','analyze_episode')
        if 'template_id' in changes or 'template_revision' in changes or 'variant' in changes:
            tid=changes.pop('template_id',previous['template']['id'])
            number=changes.pop('template_revision',None)
            if 'template_revision' in patch and (type(number) is not int or number<1):
                raise InputError('invalid requested template revision')
            variant=changes.pop('variant',previous['variant']['id'] if tid==previous['template']['id'] and previous['variant'] else None)
            if tid==previous['template']['id'] and (number is None or number==previous['template']['revision']):
                selected_variant=next((item for item in previous['template']['variants'] if item['id']==variant),None)
                if variant is not None and selected_variant is None:raise InputError('unknown pinned template variant')
                doc['variant']=deepcopy(selected_variant)
            else:
                selected=template_plan(tid,variant=variant,time_mode=changes.get('time_mode',previous['time_mode']),
                                       state_dir=state_dir,revision=number)
                doc.update(template=selected['template'],variant=selected['variant'],template_catalogue_sha256=selected['catalogue_sha256'])
        if 'profile_revision' in changes:
            number=changes.pop('profile_revision')
            if type(number) is not int or number<1:raise InputError('invalid environment profile revision')
            profile=json_value(read_snapshot(Path(state_dir)/'profiles'/(str(number)+'.json'),1024*1024).decode('utf-8'),reject_duplicates=True)
            validate_profile(profile)
            if profile.get('revision')!=number:raise InputError('profile revision identity mismatch')
            doc.update(profile_snapshot=profile,profile_sha256=_digest(profile))
        doc.update(changes);doc['revision']+=1;doc['parent_sha256']=_digest(previous)
        doc['created_at']=datetime.now(timezone.utc).isoformat()
        # Compute normalized evidence before detecting whether an old assessment is stale.
        old_assessment=doc['assessment'];doc['assessment']=None;_validate(state_dir,doc)
        basis=_basis(doc)
        if 'assessment' in patch:
            doc['assessment']=old_assessment;doc['assessment_status']='provided_by_harness' if old_assessment else 'not_provided'
            doc['assessment_harness']=deepcopy(doc['harness']) if old_assessment else None
        elif basis!=previous['analysis_basis_sha256']:
            doc['assessment_status']='stale_due_to_revision' if previous['assessment'] else 'not_provided'
            doc['assessment_harness']=None
        else:doc['assessment']=old_assessment
        if basis!=previous['analysis_basis_sha256'] and 'improvement' not in patch:doc['improvement']=None
        doc['analysis_basis_sha256']=basis
        _validate(state_dir,doc)
        from .case_retention import attachment_case_ids, case_writers
        with case_writers(state_dir, attachment_case_ids(state_dir, doc['attachments'])):
            return _persist(state_dir,doc)
    finally:lock.unlink()
