"""Local, reviewable incident drafts. No command in this module publishes anything."""
from collections import Counter
import hashlib
import hmac
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
from urllib.parse import urlsplit,parse_qsl,unquote
import uuid
import zipfile
import unicodedata
from datetime import datetime,timezone

from .artifacts import artifact_evidence,encoded,load_artifact
from .inputs import InputError,json_value,read_snapshot
from .investigations import load as load_investigation
from .knowledge import load_library as knowledge_catalogue
from .storage import read_evidence,write_json,verified_case,load_comparison

MAX_PUBLIC=512*1024
MAX_BODY=128*1024
SANITIZER_VERSION=11
EXCERPT_HEADING='\n## Выбранные очищенные фрагменты\n'
SECRET_NAME=r'(?:password|pwd|token|secret|authorization|api[_-]?key|пароль|токен|секрет|авторизация|api[_-]?ключ)'
SECRET=re.compile(r'''(?ix)(?<!\w)["']?'''+SECRET_NAME+r'''["']?\s*[=:]\s*(?:"(?:\\.|[^"\\])*(?:"|$)|'(?:\\.|[^'\\])*(?:'|$)|[^\s,;}\]]+)|\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+''')
URL=re.compile(r'(?i)\b[a-z][a-z0-9+.-]{1,20}://[^\s<>"\[\]]+')
GUID=re.compile(r'(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b')
EMAIL=re.compile(r'(?iu)\b[\w.+%-]+@(?:[\w-]+\.)+[\w-]{2,63}\b')
IPV4=re.compile(r'(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])')
IPV6=re.compile(r'(?i)(?<![\w:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]{0,39}(?:%[a-z0-9_.-]+)?(?![\w:])')
DNS=re.compile(r'(?i)\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\b')
PUBLIC_TECH_NAMES={'logcfg.xml','1cv8.exe','1cv8.lgf','1cv8.lgd','1cv8.1cd','manifest.json','report.json','report.md'}
WINDOWS_PATH=re.compile(r'(?i)(?:\b[A-Z]:[\\/]|\\\\)[^\s<>"`|]+')
UNIX_PATH=re.compile(r'(?<![\w/])/(?:[^\s<>"`|/]+/)*[^\s<>"`|/]+')

def _hash(data):return hashlib.sha256(data).hexdigest()
def _digest(value):return _hash(encoded(value,2*1024*1024))
def _identifier(value):
    if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{32}',value):raise InputError('invalid incident draft identifier')
    return value
def draft_folder(state_dir,draft_id):return Path(state_dir)/'incident-drafts'/_identifier(draft_id)
def _safe_file(name):
    if name not in ('issue.md','report.json') and not re.fullmatch(r'evidence/E-[A-Za-z0-9-]{1,60}\.txt',name):raise InputError('invalid draft public file')
    return name

def _alias_name(salt,category,value):return category+'_'+hmac.new(salt,(category+'\0'+value).encode(),hashlib.sha256).hexdigest()[:12].upper()

def _public_evidence_id(privacy,value):return 'E-'+privacy.alias('ID',value)[3:]

def _privacy_document(path):
    if path.is_symlink() or getattr(path.lstat(),'st_file_attributes',0)&0x400:raise InputError('linked pseudonym table is not accepted')
    document=json_value(read_snapshot(path,2*1024*1024).decode('utf-8'),reject_duplicates=True)
    if document.get('schema_version')!=1 or not isinstance(document.get('salt'),str) or not re.fullmatch('[a-f0-9]{64}',document['salt']):raise InputError('invalid private pseudonym table')
    salt=bytes.fromhex(document['salt']);entries={}
    if not isinstance(document.get('entries'),list) or len(document['entries'])>2048:raise InputError('pseudonym table exceeds limit')
    for item in document['entries']:
        key=(item.get('category'),item.get('value'))
        if (not all(isinstance(x,str) for x in key) or key[0] not in ('ENV','DB','PATH','CONNECTION','NODE','USER','EMAIL','ID','IP')
            or len(key[1])>4096 or item.get('alias')!=_alias_name(salt,*key) or key in entries):raise InputError('private pseudonym table integrity mismatch')
        entries[key]=item['alias']
    return document,entries

class _Privacy:
    def __init__(self,state_dir,iid):
        self.folder=Path(state_dir)/'incident-private';self.folder.mkdir(parents=True,exist_ok=True)
        if os.name!='nt':self.folder.chmod(0o700)
        self.path=self.folder/(_identifier(iid)+'.json');self.lock=self.path.with_suffix('.lock');self.counts=Counter();self.used=set()
    def __enter__(self):
        try:
            with self.lock.open('x',encoding='ascii') as stream:stream.write(str(os.getpid()))
        except FileExistsError as exc:raise InputError('incident pseudonyms are being updated; inspect interrupted writer before retry') from exc
        try:
            if self.path.exists():
                self.document,self.entries=_privacy_document(self.path)
            else:self.document=dict(schema_version=1,salt=secrets.token_hex(32),entries=[]);self.entries={}
            self.salt=bytes.fromhex(self.document['salt'])
            return self
        except BaseException:
            self.lock.unlink();raise
    def _name(self,category,value):return _alias_name(self.salt,category,value)
    def alias(self,category,value):
        if SECRET.search(value) or (urlsplit(value).scheme in ('http','https') and '@' in value):
            self.counts['secret']+=1;return '[SECRET_REMOVED]'
        key=(category,value)
        if key not in self.entries:
            if len(self.entries)>=2048 or len(value)>4096:raise InputError('pseudonym table exceeds limit')
            self.entries[key]=self._name(category,value)
        self.counts[category]+=1
        self.used.add(self.entries[key])
        return self.entries[key]
    def __exit__(self,kind,value,traceback):
        try:
            if kind is None:
                self.document['entries']=[dict(category=k[0],value=k[1],alias=v) for k,v in sorted(self.entries.items())]
                write_json(self.path,self.document)
                if os.name!='nt':self.path.chmod(0o600)
        finally:self.lock.unlink()

def _public_url(value):
    if not isinstance(value,str) or not 1<=len(value)<=2048:return False
    try:parsed=urlsplit(value);host=(parsed.hostname or '').rstrip('.')
    except ValueError:return False
    if parsed.scheme!='https' or not host or parsed.username or parsed.password or SECRET.search(value) or any(c.isspace() or c in '<>"' for c in value):return False
    for key,_ in parse_qsl(parsed.query,keep_blank_values=True,max_num_fields=100):
        for _ in range(3):key=unquote(key)
        if '%' in key or re.search(r'(?i)password|pwd|token|secret|authorization|api[_-]?key|пароль|токен|секрет',key):return False
    try:address=ipaddress.ip_address(host)
    except ValueError:
        return host!='localhost' and bool(re.fullmatch(r'(?i)(?:[a-z0-9][a-z0-9-]*\.)+[a-z][a-z0-9-]*',host)) and not host.endswith(('.local','.internal'))
    return address.is_global

def _public_urls(extra):
    # Catalogue contains source URLs, not copies of the cited publications.
    book=knowledge_catalogue()
    urls={s['url'] for s in book['sources'].values() if _public_url(s['url'])}
    if not isinstance(extra,list) or len(extra)>50:raise InputError('at most 50 public reference URLs allowed')
    for value in extra:
        if not _public_url(value):raise InputError('public references require nonprivate credential-free HTTPS URLs')
        urls.add(value)
    return urls

def _known(doc,state_dir):
    values={}
    profile=doc.get('profile_snapshot') or {}
    graph=profile if profile.get('schema_version')==2 else None
    if graph:
        from .profiles import validate_profile
        from .profile_resources import effective_profile
        graph=validate_profile(graph)
        profile=effective_profile(graph)
    def add(category,value):
        if isinstance(value,str) and 2<=len(value)<=4096 and not SECRET.search(value):values.setdefault(value,category)
    add('ENV',profile.get('name'))
    for base in profile.get('bases',[]):add('DB',base.get('name'));add('PATH' if base.get('mode')=='file' else 'CONNECTION',base.get('connection'))
    for source in profile.get('sources',[]):
        add('NODE',source.get('host'));add('PATH',source.get('path'));add('USER',source.get('settings',{}).get('user'))
        for value in source.get('settings',{}).get('databases',{}).values():add('DB',value)
    if graph:
        public_labels={'кластер','субд','postgresql','microsoft sql server','sql server','ras','os','1с','1c'}
        def label(value):
            if value.casefold() not in public_labels:add('ID',value)
        for base in graph['bases']:
            add('ID',base['reported_identity']);params=base['connection_parameters']
            add('DB',params.get('ref'));add('PATH',params.get('file_path'));add('PATH',params.get('publication'))
            for registration in base.get('registrations',[]):
                add('PATH',registration.get('source_path'));add('ID',registration.get('source_sha256'))
                add('ID',registration.get('entry_id'));add('DB',registration.get('entry_name'))
                add('CONNECTION',registration.get('connection'))
                from .discovery import connection_parameters
                try:parts=connection_parameters(registration.get('connection',''))
                except InputError:parts={}
                add('NODE',parts.get('srvr'));add('DB',parts.get('ref'))
                try:add('NODE',urlsplit('//'+parts.get('srvr','')).hostname)
                except ValueError:pass
                for key in ('cluster_id','infobase_id','snapshot_sha256','ras_connection_sha256','docker_container'):add('ID',registration.get(key))
                add('CONNECTION',registration.get('endpoint'));add('NODE',registration.get('cluster_host'));add('DB',registration.get('ref'))
                add('PATH',registration.get('executable'))
                properties=registration.get('properties',{});add('NODE',properties.get('db-server'));add('DB',properties.get('db-name'));add('DB',properties.get('name'))
        for node in graph['nodes']:add('NODE',node['name']);add('ID',node['reported_identity'])
        for kind in ('clusters','dbms_instances'):
            for resource in graph[kind]:add('ID',resource['reported_identity']);label(resource['name'])
        for database in graph['database_bindings']:add('DB',database['name'])
        for connection in graph['connections']:
            add('CONNECTION',connection['address']);add('ID',connection['credential_ref']);label(connection['name'])
            add('USER',connection['settings'].get('user'));add('ID',connection['settings'].get('docker_container'))
    categories=dict(base_alias='DB',node_alias='NODE',node_identity='ID',cluster_identity='ID',infobase_identity='DB',
        dbms_instance_identity='ID',sql_database_name='DB',dbms_database_identity='ID',source_commit='ID',journal_identity='ID',
        process_identity='ID',session_identity='ID')
    run_categories=dict.fromkeys(('job_uuid','nonce','session_uuid','os_thread','process_id','epoch'),'ID')
    run_categories.update(database_file='PATH',node='NODE')
    for binding in doc.get('source_bindings',[]):
        for key,fact in binding['passport']['facts'].items():
            if key in categories:
                for claim in fact['claims']:add(categories[key],claim['value'])
            elif key=='recorded_run':
                for claim in fact['claims']:
                    run=claim['value']
                    if isinstance(run,str):add('ID',run)
                    elif isinstance(run,dict):
                        for field,category in run_categories.items():add(category,run.get(field))
                        label=run.get('process_label')
                        if isinstance(label,str) and not re.fullmatch(r'(?i)(?:1cv8c?|1cv8s|ragent|rmngr|rphost)(?:\.exe)?',label):add('ID',label)
    for evidence in doc['evidence']:values[evidence['id']]='EVIDENCE'
    fields=dict.fromkeys(('host','hostname','node','observed_hostname','requested_node_label','computer','computer_name'),'NODE')
    fields.update(dict.fromkeys(('database','database_name','datname','base_name'),'DB'))
    fields.update(dict.fromkeys(('user','username','usename','login'),'USER'))
    loaders=dict(case=verified_case,artifact=load_artifact,comparison=load_comparison)
    visited=0
    for attachment in doc['attachments']:
        report=loaders[attachment['kind']](state_dir,attachment['target_id']);stack=[(report,0)]
        while stack:
            item,depth=stack.pop();visited+=1
            if visited>200000 or depth>32:raise InputError('incident identifier discovery exceeds bounds')
            if isinstance(item,dict):
                for key,value in item.items():
                    category=fields.get(key)
                    if category:add(category,value)
                    if key=='role' and report.get('kind')=='postgresql':add('USER',value)
                    if report.get('kind')=='sqlserver':
                        if key in ('server_name','machine_name','instance_name','host_name'):add('NODE',value)
                        elif key=='login_name':add('USER',value)
                        elif key=='program_name':add('ID',value)
                    if isinstance(value,(dict,list)):stack.append((value,depth+1))
            elif isinstance(item,list):stack.extend((value,depth+1) for value in item)
        if len(values)>2048:raise InputError('incident identifier catalogue exceeds bounds')
    if len(values)>2048:raise InputError('incident identifier catalogue exceeds bounds')
    return values

def _json_secrets(text,privacy):
    candidate=text.lstrip()
    if candidate.startswith('['):
        # Plain labels such as [Кейс] are not JSON arrays. A recognized JSON
        # value prefix must still fail closed on duplicate/truncated input.
        tail=candidate[1:].lstrip()
        if tail and tail[0] not in '[{"]0123456789-' and not re.match(r'(?:true|false|null)\b',tail):return text
    elif not candidate.startswith('{'):return text
    try:value=json_value(text,reject_duplicates=True)
    except (ValueError,RecursionError) as exc:raise InputError('JSON excerpt cannot be safely decoded; provide complete bounded JSON or separately prepared text') from exc
    stack=[(value,0)];visited=0
    while stack:
        item,depth=stack.pop();visited+=1
        if visited>8192 or depth>32:raise InputError('JSON excerpt requires bounded prepared text')
        if isinstance(item,dict):
            for key,child in item.items():
                if re.fullmatch(SECRET_NAME,key,re.I):
                    item[key]='[SECRET_REMOVED]';privacy.counts['secret']+=1
                elif key in ('query','query_text','batch_text','query_sql_text','sql_text','statement','query_plan') and isinstance(child,str):
                    item[key]='[SQL_TEXT_OMITTED]';privacy.counts['sql_text']+=1
                elif isinstance(child,(dict,list)):stack.append((child,depth+1))
        elif isinstance(item,list):stack.extend((child,depth+1) for child in item)
    return json.dumps(value,ensure_ascii=False)

def _sanitize(text,privacy,known,public_urls):
    if not isinstance(text,str) or len(text.encode('utf-8'))>MAX_BODY:raise InputError('incident text exceeds 128 KiB')
    text=_json_secrets(text,privacy)
    if any((ord(c)<32 and c not in '\n\r\t') or ord(c)==127 or unicodedata.category(c)=='Cf' for c in text):raise InputError('incident excerpt requires plain text preparation; hidden control characters are not exported')
    def removed(category,replacement):
        def apply(match):privacy.counts[category]+=1;return replacement
        return apply
    text=re.sub(r'!\[[^\]]*\]\([^)]*\)',removed('image','[IMAGE_OMITTED]'),text)
    text=re.sub(r'```.*?```',removed('code','[CODE_OMITTED]'),text,flags=re.S)
    text=re.sub(r'(?i)\]\(\s*(?:javascript|data|file|vbscript):[^)]*\)',removed('link',']([LINK_OMITTED])'),text)
    protected={}
    def url(match):
        value=match[0];trailing=''
        while value and value[-1] in '.,;):':trailing=value[-1]+trailing;value=value[:-1]
        if value in public_urls:
            token='PUBREF'+secrets.token_hex(12).upper()
            while token in text:token='PUBREF'+secrets.token_hex(12).upper()
            protected[token]=value;return token+trailing
        privacy.counts['private_url']+=1;return '[PRIVATE_URL_REMOVED]'+trailing
    text=URL.sub(url,text)
    text=SECRET.sub(removed('secret','[SECRET_REMOVED]'),text)
    if known:
        pattern=re.compile(r'(?<!\w)(?:'+'|'.join(re.escape(value) for value in sorted(known,key=len,reverse=True))+r')(?!\w)')
        text=pattern.sub(lambda m:_public_evidence_id(privacy,m[0]) if known[m[0]]=='EVIDENCE' else privacy.alias(known[m[0]],m[0]),text)
    text=EMAIL.sub(lambda m:privacy.alias('EMAIL',m[0]),text)
    text=GUID.sub(lambda m:privacy.alias('ID',m[0].lower()),text)
    def ip(match):
        try:ipaddress.ip_address(match[0])
        except ValueError:return match[0]
        return privacy.alias('IP',match[0])
    text=IPV4.sub(ip,text)
    text=IPV6.sub(ip,text)
    text=WINDOWS_PATH.sub(lambda m:privacy.alias('PATH',m[0]),text)
    text=UNIX_PATH.sub(lambda m:privacy.alias('PATH',m[0]),text)
    text=DNS.sub(lambda m:m[0] if m[0].casefold() in PUBLIC_TECH_NAMES else privacy.alias('NODE',m[0]),text)
    text=text.replace('<','&lt;').replace('>','&gt;')
    for key,value in protected.items():text=text.replace(key,value)
    return text

def _source_bytes(state_dir,doc,evidence_id):
    evidence=next((e for e in doc['evidence'] if e['id']==evidence_id),None)
    if evidence is None:raise InputError('unknown evidence selected for draft')
    attachment=next(a for a in doc['attachments'] if a['id']==evidence['attachment'])
    if attachment['kind']=='case':result=read_evidence(state_dir,attachment['target_id'],evidence['record'])
    elif attachment['kind']=='artifact':
        kind=load_artifact(state_dir,attachment['target_id'])['kind']
        if kind=='onec_source':
            raise InputError('encoded source snapshots require a separate prepared text excerpt; raw source bundles are not exported')
        if kind=='knowledge_use':
            raise InputError('private knowledge-use snapshots are not public excerpts; cite the card/source URL or provide separately reviewed observation text')
        if kind in ('logcfg_proposal','logcfg_rollback'):
            raise InputError('private configuration XML and diffs require separate prepared text; raw logcfg artifacts are not public excerpts')
        if kind=='remote_capture':
            raise InputError('raw remote transfers require separate prepared text; use parsed reviewed observations, not transport bundles')
        if kind=='native-jr':
            raise InputError('native JR dictionaries, parts and serialized records require separate prepared text; use parsed observations in the proposal')
        else:result=artifact_evidence(state_dir,attachment['target_id'],evidence['record'])
    else:
        result=dict(text=json.dumps(dict(kind='calculation',report_digest=attachment['report_sha256']),ensure_ascii=False),truncated=False)
    text=result['text'];return text[:8192],bool(result.get('truncated')) or len(text)>8192,evidence['proof']

def _content(doc,excluded):
    allowed={'summary','facts','hypotheses','recommendations','questions','references','improvement'}
    if not isinstance(excluded,list) or set(excluded)-allowed:raise InputError('unsupported incident section exclusion')
    assessment=doc.get('assessment') or {}
    causes=dict(confirmed='Причина подтверждена в указанной области',hypothesis='Есть обоснованная гипотеза',insufficient_data='Недостаточно данных для объяснения причины')
    lines=['## Симптом','',doc['task'],'','## Состояние объяснения','',causes[doc['cause_state']]]
    from .source_passports import public_review
    source_review=public_review(doc)
    if source_review['unresolved_link_count']:
        lines+=['','## Принадлежность источников','','Часть выводов зависит от неподтверждённых связей между источниками. '
            'Эти связи требуют отдельной проверки; сохранённое объяснение остаётся заявлением harness. '
            'Затронуто выводов: '+str(source_review['dependent_conclusion_count'])+'.']
    if 'summary' not in excluded and assessment.get('summary'):lines+=['',assessment['summary']]
    if 'facts' not in excluded:
        lines+=['','## Наблюдения','']
        for fact in doc['facts']:
            line='- '+fact['text']
            if 'measurement' in fact and type(fact['measurement']['value']) in (int,float,bool,type(None)):line+=' — '+json.dumps(fact['measurement']['value'])
            lines.append(line)
    if 'hypotheses' not in excluded:
        statuses=dict(proposed='Предложено',testing='Проверяется',supported='Поддержано свидетельствами',refuted='Опровергнуто',insufficient_data='Данных недостаточно')
        lines+=['','## Проверяемые объяснения','']+['- '+statuses[h['status']]+': '+h['text'] for h in doc['hypotheses']]
        if assessment.get('mechanism'):lines+=['',assessment['mechanism']]
        if assessment.get('verification'):lines+=['',assessment['verification']]
    if 'recommendations' not in excluded:
        lines+=['','## Дальнейшие действия','']
        for rec in assessment.get('recommendations',[]):
            lines+=['- '+rec['goal'], 'Условия: '+rec['prerequisites'], 'Ожидаемый эффект: '+rec['expected_effect'],
                'Проверка: '+rec['verification'], 'Ограничения: '+rec['limitations']]
            if rec['kind']!='diagnostic':lines+=['Риск: '+rec['risk'],'Возврат: '+rec['rollback']]
    if 'questions' not in excluded:lines+=['','## Открытые вопросы','']+['- '+q for q in doc['open_questions']]
    lines+=['','## Ограничения','']+['- '+s for s in assessment.get('limitations',[])]
    if 'improvement' not in excluded and doc['improvement']:
        labels=dict(applied='Применение',comparability='Сопоставимость',effect='Изменение скорости',goal='Достижение цели',recurrence='Повторение')
        statuses=dict(proposed='Предложено',reported='Сообщено',evidenced='Подкреплено свидетельствами',comparable='Сопоставимо',not_comparable='Несопоставимо',
            unknown='Неизвестно',better='Стало быстрее',no_confirmed_change='Подтверждённого изменения нет',worse='Стало медленнее',reached='Достигнута',
            not_reached='Не достигнута',observed='Наблюдалось',not_observed_in_window='Не наблюдалось в указанном окне')
        lines+=['','## Проверка исправления','']+['- '+label+': '+statuses[doc['improvement'][key]] for key,label in labels.items()]
        lines+=['- Окно проверки: '+(doc['improvement']['window'] or 'Не указано')]
    if 'references' not in excluded:lines+=['','## Ссылки','']+['- '+r['purpose']+': '+r['url']+'; '+r['applicability'] for r in assessment.get('references',[])]
    return '\n'.join(lines).strip()+'\n'

def _with_excerpts(body,excerpts):
    if not excerpts:return body.strip()+'\n'
    lines=[]
    for name,data in sorted(excerpts.items()):
        eid=name.split('/')[1][:-4]
        lines+=['### '+eid,'']+['> '+line for line in data.decode('utf-8').splitlines()]+['']
    return body.strip()+'\n'+EXCERPT_HEADING+'\n'+'\n'.join(lines).rstrip()+'\n'

def _preview_html(title,body,files,digest):
    sections=[];listing=False
    for line in body.splitlines():
        bullet=line.startswith('- ')
        if listing and not bullet:sections.append('</ul>');listing=False
        if bullet:
            if not listing:sections.append('<ul>');listing=True
            sections.append('<li>'+html.escape(line[2:])+'</li>')
        elif line.startswith('## '):sections.append('<h2>'+html.escape(line[3:])+'</h2>')
        elif line.startswith('### '):sections.append('<h3>'+html.escape(line[4:])+'</h3>')
        elif line.strip():sections.append('<p>'+html.escape(line)+'</p>')
    if listing:sections.append('</ul>')
    for name,data in sorted(files.items()):
        if name!='issue.md':sections.append('<details><summary>'+html.escape(name)+'</summary><pre>'+html.escape(data.decode('utf-8'))+'</pre></details>')
    page='''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Предпросмотр предложения кейса</title><style>body{margin:0;background:#f6f4ee;color:#302c22;font:16px/1.55 system-ui,sans-serif}header{background:#ffe15a;padding:22px}main{max-width:940px;padding:24px;margin:auto}h1{font-size:25px}h2{font-size:20px;margin-top:28px}.note{color:#6b6355}pre,code{white-space:pre-wrap;overflow-wrap:anywhere}details{padding:14px;background:white;border:1px solid #dcd6c9;margin:15px 0}summary{cursor:pointer}p{overflow-wrap:anywhere}</style><header><strong>1C TechExpert AI · локальный предпросмотр</strong></header><main>'''
    page+='<h1>'+html.escape(title)+'</h1><p class="note">Проверьте текст и все включённые файлы. Автоматическая очистка не гарантирует полной анонимности. Для исправления или исключения фрагмента вернитесь к агенту в текущем чате. Внешняя отправка выполняется отдельным явным действием.</p>'
    page+='<p class="note">Хэш предпросмотра: <code>'+digest+'</code></p>'+''.join(sections)+'</main></html>'
    return page.encode('utf-8')

def _persist(folder,revision,title,body,report,excerpts,redactions,source):
    if type(revision) is not int or not 1<=revision<=1000:raise InputError('draft revision limit reached')
    if not isinstance(title,str) or not 1<=len(title)<=120 or any(ord(c)<32 for c in title):raise InputError('invalid incident title')
    if not isinstance(body,str) or len(body.encode())>MAX_BODY:raise InputError('incident body exceeds byte limit')
    report=dict(report,title=title,body=body)
    files={'issue.md':body.encode('utf-8'),'report.json':encoded(report,MAX_BODY*2),**excerpts}
    if len(files)>12 or sum(map(len,files.values()))>MAX_PUBLIC:raise InputError('draft public files exceed limit')
    metadata=[dict(path=_safe_file(name),bytes=len(data),sha256=_hash(data),sanitized=True) for name,data in sorted(files.items())]
    manifest=dict(schema_version=1,title=title,files=metadata,redactions=dict(redactions),
        cleanup_applied=True,full_anonymity_guaranteed=False,source_files_included=False,
        archive_profile='fixed 1980-01-01 timestamps; generic file attributes; public files only')
    manifest_bytes=encoded(manifest,65536);digest=_hash(manifest_bytes)
    revision_root=folder/'revisions'/str(revision).zfill(6);public=revision_root/'public';public.mkdir(parents=True,exist_ok=False)
    if os.name!='nt':folder.chmod(0o700)
    for name,data in files.items():
        path=public/name;path.parent.mkdir(exist_ok=True);path.write_bytes(data)
    (public/'manifest.json').write_bytes(manifest_bytes)
    rendered=_preview_html(title,body,dict(files,**{'manifest.json':manifest_bytes}),digest)
    if len(rendered)>MAX_PUBLIC*5:raise InputError('local human preview exceeds byte limit')
    (revision_root/'preview.html').write_bytes(rendered)
    source_data=encoded(source,65536);(revision_root/'source.json').write_bytes(source_data)
    write_json(revision_root/'receipt.json',dict(schema_version=1,preview_sha256=digest,source_sha256=_hash(source_data),html_sha256=_hash(rendered)))
    return dict(revision=revision,preview_sha256=digest)

def _load(state_dir,draft_id):
    folder=draft_folder(state_dir,draft_id)
    head=json_value(read_snapshot(folder/'head.json',8192).decode(),reject_duplicates=True);number=head.get('revision')
    if type(number) is not int or not 1<=number<=1000:raise InputError('invalid draft revision')
    revision=folder/'revisions'/str(number).zfill(6);receipt=json_value(read_snapshot(revision/'receipt.json',8192).decode(),reject_duplicates=True)
    manifest_bytes=read_snapshot(revision/'public/manifest.json',65536);digest=_hash(manifest_bytes)
    if digest!=head.get('preview_sha256') or digest!=receipt.get('preview_sha256'):raise InputError('incident preview integrity mismatch')
    source_bytes=read_snapshot(revision/'source.json',65536)
    if _hash(source_bytes)!=receipt.get('source_sha256'):raise InputError('incident source integrity mismatch')
    source=json_value(source_bytes.decode(),reject_duplicates=True)
    if source.get('sanitizer_version')!=SANITIZER_VERSION:raise InputError('incident cleanup policy changed; prepare a new draft from the investigation')
    doc=load_investigation(state_dir,source['investigation_id'],revision=source['investigation_revision'])
    if _digest(doc)!=source['investigation_digest']:raise InputError('incident source investigation integrity mismatch')
    _,entries=_privacy_document(Path(state_dir)/'incident-private'/(_identifier(source['investigation_id'])+'.json'))
    if not isinstance(source.get('aliases'),list) or set(source['aliases'])-set(entries.values()):raise InputError('private incident correspondences are incomplete')
    manifest=json_value(manifest_bytes.decode(),reject_duplicates=True);files={};total=0
    if manifest.get('schema_version')!=1 or not isinstance(manifest.get('files'),list) or not 2<=len(manifest['files'])<=12:raise InputError('unsupported incident manifest')
    for item in manifest['files']:
        name=_safe_file(item['path'])
        if name in files:raise InputError('duplicate incident file')
        data=read_snapshot(revision/'public'/name,MAX_PUBLIC);total+=len(data)
        if total>MAX_PUBLIC or len(data)!=item.get('bytes') or _hash(data)!=item.get('sha256'):raise InputError('incident file integrity mismatch')
        files[name]=data
    if not {'issue.md','report.json'}<=set(files):raise InputError('incomplete incident draft')
    body=files['issue.md'].decode('utf-8');report=json_value(files['report.json'].decode('utf-8'),reject_duplicates=True)
    if report.get('body')!=body or report.get('title')!=manifest.get('title'):raise InputError('incident representations disagree')
    rendered=read_snapshot(revision/'preview.html',MAX_PUBLIC*5)
    if _hash(rendered)!=receipt.get('html_sha256') or rendered!=_preview_html(manifest['title'],body,dict(files,**{'manifest.json':manifest_bytes}),digest):raise InputError('local incident preview integrity mismatch')
    view=dict(draft_id=draft_id,revision=number,title=manifest['title'],body=body,preview_sha256=digest,
        files=[dict(**item,text=files[item['path']].decode('utf-8')) for item in manifest['files']],
        redactions=manifest['redactions'],requires_human_review=True,published=False,local_provenance_preserved=True,
        local_preview_path=str((revision/'preview.html').absolute()),
        limitations=['Псевдонимы и автоматическое удаление не гарантируют полной анонимности.',
            'Проверьте свободный текст, коммерческие сведения и смысл очищенных фрагментов перед внешней передачей.',
            'Исходные журналы, профиль и локальные соответствия не входят в этот публичный комплект.'])
    files['manifest.json']=manifest_bytes
    return view,files,source,report

def preview(state_dir,draft_id):return _load(state_dir,draft_id)[0]

def prepare(state_dir,investigation_id,*,revision=None,include_versions=False,exclude_sections=None,public_urls=None,evidence_ids=None):
    if type(include_versions) is not bool:raise InputError('include_versions must be boolean')
    doc=load_investigation(state_dir,investigation_id,revision=revision)
    excluded=[] if exclude_sections is None else exclude_sections;urls=[] if public_urls is None else public_urls
    selected=[] if evidence_ids is None else evidence_ids
    if not isinstance(selected,list) or len(selected)>10 or any(not isinstance(e,str) for e in selected) or len(set(selected))!=len(selected):raise InputError('select at most 10 distinct evidence records')
    allowed_urls=_public_urls(urls);known=_known(doc,state_dir)
    options=dict(include_versions=include_versions,exclude_sections=excluded,public_urls=urls,evidence_ids=selected)
    key=_digest(dict(investigation_id=investigation_id,revision=doc['revision'],digest=_digest(doc),options=options,sanitizer_version=SANITIZER_VERSION))
    root=Path(state_dir)/'incident-drafts';root.mkdir(parents=True,exist_ok=True);lock=root/'write.lock'
    try:
        with lock.open('x',encoding='ascii') as stream:stream.write(str(os.getpid()))
    except FileExistsError as exc:raise InputError('incident draft writer is active or interrupted') from exc
    try:
        index=json_value(read_snapshot(root/'index.json',256*1024).decode(),reject_duplicates=True) if (root/'index.json').exists() else {}
        if key in index:return preview(state_dir,index[key])
        if len(index)>=1000:raise InputError('incident index limit reached; retain existing drafts')
        excerpts={};provenance={}
        with _Privacy(state_dir,investigation_id) as privacy:
            originals={eid:_source_bytes(state_dir,doc,eid) for eid in selected}
            title=('[Кейс] '+_sanitize(doc['task'],privacy,known,allowed_urls).replace('\n',' '))[:120]
            body=_sanitize(_content(doc,excluded),privacy,known,allowed_urls).strip()+'\n'
            for eid in selected:
                raw,truncated,proof=originals[eid]
                cleaned=_sanitize(raw,privacy,known,allowed_urls).encode('utf-8')
                public_eid=_public_evidence_id(privacy,eid)
                excerpts['evidence/'+public_eid+'.txt']=cleaned
                provenance[public_eid]=dict(original_evidence_id=eid,original=proof,truncated_before_cleanup=truncated,sanitized_sha256=_hash(cleaned))
            body=_with_excerpts(body,excerpts)
            scopes={'synthetic','provided','controlled_real_background_job','controlled_loopback_http_service','not_established'}
            report=dict(schema_version=1,source_origin_scopes=sorted({a['source_origin'] if isinstance(a['source_origin'],str) and a['source_origin'] in scopes else 'unknown' for a in doc['attachments']}),
                        evidence=[dict(id=eid,truncated=record['truncated_before_cleanup'],sanitized_sha256=record['sanitized_sha256']) for eid,record in provenance.items()])
            from .source_passports import public_review
            report['source_review']=public_review(doc)
            if include_versions:
                report['versions']={key:value if isinstance(value,str) and (bool(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?',value)) if key=='product' else bool(re.fullmatch('[a-f0-9]{64}',value))) else None
                    for key,value in doc['versions'].items() if key in ('product','knowledge','skills_sha256','instructions_sha256')}
            source=dict(sanitizer_version=SANITIZER_VERSION,investigation_id=investigation_id,investigation_revision=doc['revision'],investigation_digest=_digest(doc),options=options,evidence_provenance=provenance,aliases=sorted(privacy.used))
            draft_id=uuid.uuid4().hex;head=_persist(draft_folder(state_dir,draft_id),1,title,body,report,excerpts,privacy.counts,source)
        write_json(draft_folder(state_dir,draft_id)/'head.json',head)
        index[key]=draft_id;write_json(root/'index.json',index)
        return preview(state_dir,draft_id)
    finally:lock.unlink()

def _expected(view,value):
    if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{64}',value) or not hmac.compare_digest(view['preview_sha256'],value):raise InputError('incident preview changed; inspect the current preview before continuing')

def edit(state_dir,draft_id,*,title,body,expected_sha256,exclude_evidence_ids=None):
    folder=draft_folder(state_dir,draft_id);lock=folder/'write.lock'
    try:
        with lock.open('x',encoding='ascii') as stream:stream.write(str(os.getpid()))
    except FileExistsError as exc:raise InputError('incident draft is being edited') from exc
    try:
        view,files,source,report=_load(state_dir,draft_id);_expected(view,expected_sha256)
        doc=load_investigation(state_dir,source['investigation_id'],revision=source['investigation_revision'])
        excluded=[] if exclude_evidence_ids is None else exclude_evidence_ids
        ids={p.split('/')[1][:-4] for p in files if p.startswith('evidence/')}
        if not isinstance(excluded,list) or any(e not in ids for e in excluded):raise InputError('unknown excluded incident evidence')
        with _Privacy(state_dir,source['investigation_id']) as privacy:
            known=_known(doc,state_dir);urls=_public_urls(source['options']['public_urls'])
            if not isinstance(body,str):raise InputError('incident body requires text')
            _,_,old_tail=view['body'].partition(EXCERPT_HEADING)
            supplied_body,_,supplied_tail=body.partition(EXCERPT_HEADING)
            if old_tail!=supplied_tail:raise InputError('prepared excerpts are immutable; use exclude_evidence_ids or prepare another text excerpt')
            title=_sanitize(title,privacy,known,urls).strip();body=_sanitize(supplied_body,privacy,known,urls).strip()+'\n'
            excerpts={name:data for name,data in files.items() if name.startswith('evidence/') and name.split('/')[1][:-4] not in excluded}
            body=_with_excerpts(body,excerpts)
            if title==view['title'] and body==view['body'] and not excluded:return view
            report['evidence']=[e for e in report['evidence'] if e['id'] not in excluded]
            counts=Counter(view['redactions']);counts.update(privacy.counts)
            source['aliases']=sorted(set(source['aliases'])|privacy.used)
            head=_persist(folder,view['revision']+1,title,body,report,excerpts,counts,source)
        write_json(folder/'head.json',head)
        return preview(state_dir,draft_id)
    finally:lock.unlink()

def export(state_dir,draft_id,output,*,expected_sha256):
    view,files,_,_=_load(state_dir,draft_id);_expected(view,expected_sha256)
    output=Path(output)
    if not output.parent.is_dir() or output.suffix.lower()!='.zip':raise InputError('export requires an existing destination directory and new ZIP filename')
    if shutil.disk_usage(output.parent).free<sum(map(len,files.values()))+8*1024*1024:raise InputError('not enough free space for incident export')
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED) as archive:
        for name,data in sorted(files.items()):
            info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0));info.create_system=3
            info.external_attr=0o100600<<16;info.compress_type=zipfile.ZIP_DEFLATED
            archive.writestr(info,data)
    raw=read_snapshot(output,MAX_PUBLIC*2)
    return dict(path=str(output.absolute()),bytes=len(raw),sha256=_hash(raw),preview_sha256=view['preview_sha256'],published=False)

def _issue_url(value,repository):
    if not isinstance(value,str) or len(value)>2048:raise InputError('invalid issue URL')
    parsed=urlsplit(value)
    if (parsed.scheme!='https' or parsed.netloc.lower()!='github.com' or parsed.query or parsed.fragment
        or not re.fullmatch('/'+re.escape(repository)+r'/issues/[1-9][0-9]*',parsed.path,re.I)):raise InputError('GitHub issue URL does not match the previewed repository')

def _submission(value,payload,action_sha256):
    keys={'schema_version','url','repository','preview_sha256','action_sha256','title_sha256','body_sha256','reported_at','verification','publication_reported'}
    if not isinstance(value,dict) or set(value)!=keys:raise InputError('invalid incident submission receipt')
    expected=dict(schema_version=1,repository=payload['repository'],preview_sha256=payload['preview_sha256'],action_sha256=action_sha256,
        title_sha256=_hash(payload['title'].encode()),body_sha256=_hash(payload['body'].encode()),
        verification='matching_readback_supplied_by_current_harness; no_network_request_here',publication_reported=True)
    if any(value.get(key)!=item for key,item in expected.items()):raise InputError('incident submission receipt disagrees with the preview')
    try:
        _issue_url(value['url'],payload['repository'])
        if datetime.fromisoformat(value['reported_at']).utcoffset() is None:raise ValueError('time zone missing')
    except (ValueError,TypeError) as exc:raise InputError('invalid incident submission receipt') from exc
    return value

def send_plan(state_dir,draft_id,repository,*,expected_sha256):
    view,_,_,_=_load(state_dir,draft_id);_expected(view,expected_sha256)
    if not isinstance(repository,str) or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}',repository) or repository.split('/')[-1] in ('.','..'):raise InputError('repository must be an owner/name slug')
    if len(view['body'])>60000:raise InputError('send plan is limited to 60000 characters; reduce and preview the proposal before sending')
    payload=dict(repository=repository,title=view['title'],body=view['body'],attachments=[],preview_sha256=view['preview_sha256'])
    action_sha256=_digest(payload)
    previous=draft_folder(state_dir,draft_id)/'submissions'/(action_sha256+'.json')
    prior=_submission(json_value(read_snapshot(previous,8192).decode(),reject_duplicates=True),payload,action_sha256) if previous.exists() else None
    return dict(action='recheck_reported_github_issue' if prior else 'create_github_issue_via_current_harness',**payload,
                action_sha256=action_sha256,previous_submission=prior,requires_explicit_user_send=True,published=False,
                note='Only an explicit user send of this exact preview authorizes the current harness GitHub connector. No network request was made.')

def record_submission(state_dir,draft_id,repository,response,*,expected_sha256,expected_action_sha256):
    plan=send_plan(state_dir,draft_id,repository,expected_sha256=expected_sha256)
    if not isinstance(expected_action_sha256,str) or not re.fullmatch('[a-f0-9]{64}',expected_action_sha256) or not hmac.compare_digest(plan['action_sha256'],expected_action_sha256):raise InputError('incident destination or payload changed; inspect the send plan again')
    if not isinstance(response,dict) or set(response)!={'url','title','body'}:raise InputError('read-back requires only URL, title and body')
    if response['title']!=plan['title'] or response['body']!=plan['body']:raise InputError('GitHub read-back differs from the previewed payload')
    _issue_url(response['url'],repository)
    receipt=dict(schema_version=1,url=response['url'],repository=repository,preview_sha256=expected_sha256,
        action_sha256=expected_action_sha256,title_sha256=_hash(plan['title'].encode()),body_sha256=_hash(plan['body'].encode()),
        reported_at=datetime.now(timezone.utc).isoformat(),verification='matching_readback_supplied_by_current_harness; no_network_request_here',publication_reported=True)
    folder=draft_folder(state_dir,draft_id)/'submissions';folder.mkdir(exist_ok=True);path=folder/(expected_action_sha256+'.json')
    data=encoded(receipt,8192)
    try:
        with path.open('xb') as stream:stream.write(data)
    except FileExistsError:
        previous=_submission(json_value(read_snapshot(path,8192).decode(),reject_duplicates=True),plan,expected_action_sha256)
        if any(previous.get(key)!=value for key,value in receipt.items() if key!='reported_at'):raise InputError('a different Issue is already reported for this exact proposal')
        return previous
    return receipt
