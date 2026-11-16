"""Bounded reader for the sequential JR profile observed on 8.3.27.1989.

Grammar/field research: https://infostart.ru/1c/articles/182061/ . This is an
independent parser, not vendor code. LGD, archives and other versions are excluded.
"""
from collections import Counter
from datetime import datetime
import hashlib
from pathlib import Path
import re
import stat

from .artifacts import artifact_folder, load_artifact, save_artifact
from .inputs import InputError, MAX_EVENTS, MAX_FILE_BYTES, MAX_RECORD_BYTES, MAX_TOTAL_BYTES, read_snapshot

PROFILE='1c-jr-sequential-8.3.27.1989-v1'
HEADER=re.compile(rb'(?:\xef\xbb\xbf)?1CV8LOG\(ver 2\.0\)\r?\n([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})\r?\n')

class _Incomplete(Exception):pass
class _Syntax(Exception):pass

class _Parser:
    def __init__(self,data,start):self.data=data;self.pos=start;self.start=start
    def skip(self):
        while self.pos<len(self.data) and self.data[self.pos] in b' \t\r\n':self.pos+=1
    def value(self,depth=0):
        if depth>32:raise InputError('JR nesting exceeds 32 levels')
        self.skip()
        if self.pos-self.start>MAX_RECORD_BYTES:raise InputError('JR record exceeds byte limit')
        if self.pos>=len(self.data):raise _Incomplete()
        marker=self.data[self.pos];self.pos+=1
        if marker==123:
            result=[];self.skip()
            if self.pos<len(self.data) and self.data[self.pos]==125:self.pos+=1;return result
            while True:
                result.append(self.value(depth+1));self.skip()
                if self.pos>=len(self.data):raise _Incomplete()
                separator=self.data[self.pos];self.pos+=1
                if self.pos-self.start>MAX_RECORD_BYTES:raise InputError('JR record exceeds byte limit')
                if separator==125:return result
                if separator!=44:raise _Syntax()
        if marker==34:
            pieces=[];start=self.pos
            while self.pos<len(self.data):
                if self.pos-self.start>MAX_RECORD_BYTES:raise InputError('JR record exceeds byte limit')
                if self.data[self.pos]==34:
                    pieces.append(self.data[start:self.pos]);self.pos+=1
                    if self.pos<len(self.data) and self.data[self.pos]==34:
                        pieces.append(b'"');self.pos+=1;start=self.pos;continue
                    return b''.join(pieces).decode('utf-8')
                self.pos+=1
            raise _Incomplete()
        start=self.pos-1
        while self.pos<len(self.data) and self.data[self.pos] not in b',{}\r\n':
            if self.pos-self.start>MAX_RECORD_BYTES:raise InputError('JR record exceeds byte limit')
            self.pos+=1
        token=self.data[start:self.pos].strip()
        if not token or any(c in token for c in b'"{}'):raise _Syntax()
        return token.decode('utf-8')

def _scan(data,source):
    match=HEADER.match(data)
    if not match:raise InputError('JR requires verified sequential 1CV8LOG(ver 2.0) header and journal UUID')
    parser=_Parser(data,match.end());records=[];issues=[];need_separator=False
    while True:
        parser.skip()
        if parser.pos==len(data):break
        if need_separator:
            if data[parser.pos]!=44:
                issues.append(dict(code='unparsed_tail',source=source,byte_start=parser.pos,byte_end=len(data)));break
            parser.pos+=1;parser.skip()
            if parser.pos==len(data):break
        start=parser.start=parser.pos
        if data[start]!=123:
            issues.append(dict(code='unparsed_tail',source=source,byte_start=start,byte_end=len(data)));break
        try:values=parser.value()
        except (_Incomplete,_Syntax,UnicodeError) as exc:
            issues.append(dict(code='incomplete_record' if isinstance(exc,_Incomplete) else 'invalid_record_encoding_or_syntax',
                               source=source,byte_start=start,byte_end=len(data)));break
        if parser.pos-start>MAX_RECORD_BYTES:raise InputError('JR record exceeds byte limit')
        records.append((start,parser.pos,values));need_separator=True
        if len(records)>MAX_EVENTS:raise InputError('JR record count exceeds limit')
    return match[1].decode('ascii').lower(),records,issues

def parse_snapshot(sources,*,utc_offset=None):
    if utc_offset is not None and (not isinstance(utc_offset,str) or not re.fullmatch(r'[+-](?:[01]\d|2[0-3]):[0-5]\d',utc_offset) or utc_offset=='-00:00'):
        raise InputError('JR requires an explicit valid UTC offset or unknown')
    if not isinstance(sources,list) or not 1<=len(sources)<=32:raise InputError('JR requires 1..32 native files')
    scanned=[];issues=[];total=0;names=set();count=0
    for number,(name,data) in enumerate(sources,1):
        if not isinstance(name,str) or name.lower() in names or Path(name).name!=name or not isinstance(data,bytes):raise InputError('invalid JR file entry')
        names.add(name.lower());total+=len(data)
        if len(data)>MAX_FILE_BYTES or total>MAX_TOTAL_BYTES:raise InputError('JR snapshot exceeds byte limit')
        if name.lower()!='1cv8.lgf' and not name.lower().endswith('.lgp'):raise InputError('only sequential LGF/LGP files supported')
        journal,records,errors=_scan(data,'s'+str(number));issues.extend(errors);count+=len(records)
        if count>MAX_EVENTS:raise InputError('JR record count exceeds limit')
        scanned.append((name,data,journal,records,'s'+str(number)))
    dictionaries=[s for s in scanned if s[0].lower()=='1cv8.lgf']
    if len(dictionaries)!=1:raise InputError('JR requires one 1Cv8.lgf dictionary')
    journal=dictionaries[0][2]
    if any(s[2]!=journal for s in scanned):raise InputError('JR journal UUID mismatch between dictionary and parts')
    dictionary={};unknown_tags=Counter()
    for start,end,values in dictionaries[0][3]:
        valid=(len(values) in (3,4) and values[0] in tuple(str(i) for i in range(1,9))
               and isinstance(values[-1],str) and values[-1].isdecimal()
               and isinstance(values[-2],str) and (len(values)==3 or isinstance(values[1],str)))
        if not valid:
            unknown_tags[str(values[0])[:80] if values else 'empty']+=1;continue
        key=(values[0],values[-1]);item=dict(value=values[-2],uuid=values[1] if len(values)==4 else None)
        if key in dictionary and dictionary[key]!=item:
            dictionary[key]=None
            issues.append(dict(code='ambiguous_dictionary',source=dictionaries[0][4],byte_start=start,byte_end=end))
        else:dictionary[key]=item
    records=[];counts=Counter();unresolved=Counter()
    for name,data,_,entries,source in scanned:
        if name.lower()=='1cv8.lgf':continue
        for ordinal,(start,end,values) in enumerate(entries,1):
            try:
                if (len(values)<19 or values[1] not in ('N','U','R','C') or values[8] not in ('I','E','W','N')
                    or not isinstance(values[17],str) or not values[17].isdecimal() or len(values)!=19+int(values[17])
                    or any(not isinstance(values[i],str) or not values[i].isdecimal() for i in (3,4,5,6,7,10,13,14,15,16))
                    or not isinstance(values[9],str) or not isinstance(values[11],list)):
                    raise ValueError()
                if not re.fullmatch('[0-9]{14}',values[0]):raise ValueError()
                local=datetime.strptime(values[0],'%Y%m%d%H%M%S').isoformat()
                timestamp=datetime.fromisoformat(local+utc_offset).isoformat() if utc_offset else None
            except (ValueError,TypeError,IndexError):
                issues.append(dict(code='invalid_event_record',source=source,byte_start=start,byte_end=end));continue
            def resolved(tag,index):
                item=dictionary.get((tag,index))
                if item is None and index!='0':unresolved[tag+':'+index]+=1
                return item['value'] if item is not None else None
            record=dict(id=source+':r'+str(ordinal),source=source,file=name,byte_start=start,byte_end=end,
                sha256=hashlib.sha256(data[start:end]).hexdigest(),journal_id=journal,
                source_time=values[0],local_time=local,timestamp=timestamp,utc_offset=utc_offset,precision_seconds=1,
                transaction_state=values[1],transaction_raw=values[2],user_index=values[3],computer_index=values[4],
                application_index=values[5],connection=values[6],event_index=values[7],severity=values[8],
                event=resolved('4',values[7]),user=resolved('1',values[3]),computer=resolved('2',values[4]),
                application=resolved('3',values[5]),metadata=resolved('5',values[10]),session=values[16],
                comment=values[9],data=values[11],uninterpreted_tail=values[12:],
                database_identity=None,lifetime_epoch=None,job_identity=None)
            records.append(record);counts[record['event'] or 'unresolved_event']+=1
    if unresolved:issues.append(dict(code='unresolved_dictionary_references',counts=dict(unresolved)))
    return dict(profile=PROFILE,journal_id=journal,utc_offset=utc_offset,event_count=len(records),records=records,counts=dict(counts),
        status='partial' if issues else 'parsed',issues=issues,uninterpreted_dictionary_tags=dict(unknown_tags),
        observed_local_range=[min((r['local_time'] for r in records),default=None),max((r['local_time'] for r in records),default=None)],
        database_identity=None,complete_incident_coverage=None,requires_ai_interpretation=True,
        limitations=['Observed timestamps do not prove complete incident coverage.',
                    'UTC offset and platform version are supplied declarations; clock skew is unknown.',
                    'Journal UUID is not a verified infobase identifier. Session/connection numbers have no proven lifetime epoch.',
                    'Job events alone do not establish the identity or whole duration of a particular background run.',
                    'Data and trailing fields are retained without evaluating 1C serialized values.'])

def _inventory(path):
    entries=[]
    for child in path.iterdir():
        if child.name.lower()=='1cv8.lgd':raise InputError('LGD profile is not supported or verified')
        if child.name.lower()=='1cv8.lgf' or child.suffix.lower()=='.lgp':
            info=child.lstat()
            if not stat.S_ISREG(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise InputError('JR links and nonregular files are not accepted')
            entries.append((child.name,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_ino))
    entries.sort(key=lambda item:(item[0].lower()!='1cv8.lgf',item[0]))
    if not 2<=len(entries)<=32 or not any(e[0].lower()=='1cv8.lgf' for e in entries):raise InputError('JR requires 1Cv8.lgf and 1..31 LGP parts')
    return entries

def read_journal(state_dir,path,*,platform_version,utc_offset=None,consistency='unknown'):
    if platform_version!='8.3.27.1989':raise InputError('JR profile currently requires platform 8.3.27.1989')
    if consistency not in ('unknown','stopped_writer','provided_snapshot'):raise InputError('invalid JR consistency declaration')
    path=Path(path);info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise InputError('JR input must be a native directory, not a link or XML file')
    before=_inventory(path)
    if sum(item[1] for item in before)>MAX_TOTAL_BYTES:raise InputError('JR snapshot exceeds byte limit')
    sources=[(item[0],read_snapshot(path/item[0])) for item in before]
    if before!=_inventory(path):raise InputError('JR file set changed; provide a stable native snapshot')
    result=parse_snapshot(sources,utc_offset=utc_offset);result.pop('records')
    result.update(consistency=consistency,consistency_basis='unknown' if consistency=='unknown' else 'user_declaration_only',
                  atomic_snapshot_verified=False)
    request=dict(path=str(path.absolute()),platform_version=platform_version,utc_offset=utc_offset,consistency=consistency)
    return save_artifact(state_dir,'native-jr',request,sources,result)

def _saved(state_dir,artifact_id):
    report=load_artifact(state_dir,artifact_id)
    if report['kind']!='native-jr' or report['result'].get('profile')!=PROFILE:raise InputError('artifact is not a supported native JR snapshot')
    sources=[]
    for source in report['sources']:
        data=read_snapshot(artifact_folder(state_dir,artifact_id)/'sources'/(source['id']+'.bin'))
        if len(data)!=source['bytes'] or hashlib.sha256(data).hexdigest()!=source['sha256']:
            raise InputError('JR snapshot integrity mismatch during read')
        sources.append((source['name'],data))
    return sources,parse_snapshot(sources,utc_offset=report['result']['utc_offset'])

def list_events(state_dir,artifact_id,*,event=None,offset=0,limit=20):
    if type(offset) is not int or offset<0 or type(limit) is not int or not 1<=limit<=100:raise InputError('invalid JR pagination')
    _,result=_saved(state_dir,artifact_id)
    selected=[r for r in result['records'] if event is None or r['event']==event]
    output=[]
    for record in selected[offset:offset+limit]:
        item={k:v for k,v in record.items() if k not in ('data','uninterpreted_tail','comment')}
        item.update(comment=record['comment'][:2000],comment_truncated=len(record['comment'])>2000)
        item['truncated_fields']=[]
        for key,value in tuple(item.items()):
            if isinstance(value,str) and len(value)>2000:
                item[key]=value[:2000];item['truncated_fields'].append(key)
        output.append(item)
    return dict(artifact_id=artifact_id,profile=PROFILE,total_matched=len(selected),offset=offset,records=output,
                untrusted_source_content=True,integrity_verified=True,complete_incident_coverage=None)

def read_record(state_dir,artifact_id,record_id):
    sources,result=_saved(state_dir,artifact_id)
    record=next((r for r in result['records'] if r['id']==record_id),None)
    if record is None:raise InputError('unknown JR record identifier')
    source_number=int(record['source'][1:])-1
    raw=sources[source_number][1][record['byte_start']:record['byte_end']]
    return dict(artifact_id=artifact_id,record=record,text=raw.decode('utf-8'),integrity_verified=True,untrusted_source_content=True)
