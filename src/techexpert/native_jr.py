"""Bounded readers for sequential JR and self-contained legacy SQLite snapshots.

Sequential grammar research: https://infostart.ru/1c/articles/182061/ .
"""
from collections import Counter
from datetime import datetime
import hashlib
from pathlib import Path, PurePosixPath
import re
import stat

from . import input_files, native_jr_sqlite as lgd
from .artifacts import artifact_folder, read_artifact_record, save_artifact, source_path
from .analysis import parse_time
from .inputs import InputError, MAX_EVENTS, MAX_FILE_BYTES, MAX_RECORD_BYTES, MAX_TOTAL_BYTES, read_snapshot

PROFILE='1c-jr-sequential-8.3.27.1989-v1'
PLATFORM='8.3.27.1989'
PLATFORM_VERSION=r'8\.3\.[0-9]{1,3}\.[0-9]{1,6}'
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
        if child.name.lower()=='1cv8.lgf' or child.suffix.lower() in ('.lgp','.lgd'):
            info=child.lstat()
            if not stat.S_ISREG(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise InputError('JR links and nonregular files are not accepted')
            entries.append((child.name,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_ino))
            if len(entries)>32:raise InputError('JR input file count exceeds limit')
    entries.sort(key=lambda item:(item[0].lower()!='1cv8.lgf',item[0]))
    return entries


def _profile(names):
    names = [name.casefold() for name in names]
    sqlite = [name for name in names if name.endswith('.lgd')]
    if sqlite:
        if len(names)!=1:
            raise InputError('multiple JR profiles or snapshots; select one LGD file or one sequential group')
        return lgd.PROFILE
    if not 2<=len(names)<=32 or names.count('1cv8.lgf')!=1 or any(
            name!='1cv8.lgf' and not name.endswith('.lgp') for name in names):
        raise InputError('JR requires 1Cv8.lgf and 1..31 LGP parts')
    return PROFILE


def reject_sidecars(path):
    path = Path(path)
    input_files.chain(path)
    for suffix in lgd.SIDECARS:
        try:
            path.with_name(path.name+suffix).lstat()
        except FileNotFoundError:
            continue
        raise InputError('LGD snapshot still has a SQLite sidecar; provide a closed standalone copy')


def _check_profile_settings(profile, platform_version, utc_offset, consistency):
    if profile==lgd.PROFILE:
        if consistency=='unknown':
            raise InputError('LGD requires a provided snapshot or a stopped writer')
        if utc_offset not in (None,'+00:00'):
            raise InputError('LGD records use native UTC; do not apply a local offset')
    elif platform_version!=PLATFORM:
        raise InputError('sequential JR profile requires platform '+PLATFORM)


def reject_catalogue_sidecars(selected, relative_paths):
    selected = PurePosixPath(selected)
    companions = {selected.name.casefold()+suffix for suffix in lgd.SIDECARS}
    for member in map(PurePosixPath, relative_paths):
        if member.parent==selected.parent and member.name.casefold() in companions:
            raise InputError('LGD catalogue contains a SQLite sidecar; provide a standalone snapshot')


def check_catalogue_selection(plan, selection, settings):
    def group(item):
        return item['root'], PurePosixPath(item['relative_path']).parent

    parent = group(selection[0])
    if any(group(item)!=parent for item in selection):
        raise InputError('select one native JR group')
    names = [PurePosixPath(item['relative_path']).name for item in selection]
    profile = _profile(names)
    _check_profile_settings(profile,settings.get('platform_version'),settings.get('utc_offset'),settings.get('consistency','unknown'))
    if profile!=lgd.PROFILE:
        return profile,None
    saved = plan['result']
    reject_catalogue_sidecars(selection[0]['relative_path'],
                             (item['relative_path'] for item in saved['members'] if item['root']==parent[0]))
    root = saved['roots'][parent[0]]
    if root['kind'] in ('file','directory'):
        source = Path(root['path'])
        if root['kind']=='directory':
            source = source.joinpath(*PurePosixPath(selection[0]['relative_path']).parts)
        reject_sidecars(source)
        return profile,source
    return profile,None


def _sqlite_snapshot(path):
    reject_sidecars(path)
    raw, observed = input_files.read(path, MAX_FILE_BYTES, keep=True)
    input_files.read(path, MAX_FILE_BYTES, expected=observed)
    reject_sidecars(path)
    return (path.name,raw), lgd.parse_snapshot(raw,path.name)


def read_journal(state_dir,path,*,platform_version=None,utc_offset=None,consistency='unknown',intake=None):
    if platform_version is not None and (not isinstance(platform_version,str) or not re.fullmatch(PLATFORM_VERSION,platform_version)):
        raise InputError('invalid declared JR platform version')
    if consistency not in ('unknown','stopped_writer','provided_snapshot'):raise InputError('invalid JR consistency declaration')
    path = Path(path).absolute()
    ancestry = input_files.chain(path)
    info = path.lstat()
    if getattr(info,'st_file_attributes',0)&0x400 or not (stat.S_ISDIR(info.st_mode)
            or stat.S_ISREG(info.st_mode) and path.suffix.casefold()=='.lgd'):
        raise InputError('JR input must be a native journal directory or a standalone LGD file')
    before = _inventory(path) if stat.S_ISDIR(info.st_mode) else None
    profile = _profile([item[0] for item in before] if before is not None else [path.name])
    _check_profile_settings(profile,platform_version,utc_offset,consistency)
    if profile==lgd.PROFILE:
        member = path if before is None else path/before[0][0]
        source,result = _sqlite_snapshot(member)
        sources = [source]
        result['declared_writer_version'] = platform_version
    else:
        if sum(item[1] for item in before)>MAX_TOTAL_BYTES:raise InputError('JR snapshot exceeds byte limit')
        sources=[(item[0],read_snapshot(path/item[0])) for item in before]
        result=parse_snapshot(sources,utc_offset=utc_offset)
    if input_files.chain(path)!=ancestry or (before is not None and before!=_inventory(path)):
        raise InputError('JR file set changed; provide a stable native snapshot')
    result.pop('records')
    result.update(consistency=consistency,consistency_basis='unknown' if consistency=='unknown' else 'user_declaration_only',
                  atomic_snapshot_verified=False)
    request=dict(path=str(path),platform_version=platform_version,utc_offset=utc_offset,consistency=consistency)
    return save_artifact(state_dir,'native-jr',request,sources,result,input_intake=intake)

def _saved(state_dir,artifact_id):
    report,_=read_artifact_record(state_dir,artifact_id)
    profile=report['result'].get('profile')
    if report['kind']!='native-jr' or profile not in (PROFILE,lgd.PROFILE):raise InputError('artifact is not a supported native JR snapshot')
    sources=[]
    for source in report['sources']:
        data=read_snapshot(source_path(artifact_folder(state_dir,artifact_id),source))
        if len(data)!=source['bytes'] or hashlib.sha256(data).hexdigest()!=source['sha256']:
            raise InputError('JR snapshot integrity mismatch during read')
        sources.append((source['name'],data))
    if _profile([name for name,_ in sources])!=profile:
        raise InputError('saved JR sources disagree with the retained profile')
    if profile==lgd.PROFILE:
        name,raw=sources[0]
        return sources,lgd.parse_snapshot(raw,name)
    return sources,parse_snapshot(sources,utc_offset=report['result']['utc_offset'])

def _window_rows(result, window):
    """Select recorded instants and describe the observations that were comparable."""
    start, end = parse_time(window['start']), parse_time(window['end'])
    first = last = None
    unplaced = 0
    selected = []
    for record in result['records']:
        try:
            stamp = parse_time(record['timestamp'])
        except (ValueError, OverflowError):
            unplaced += 1
            continue
        first = stamp if first is None else min(first, stamp)
        last = stamp if last is None else max(last, stamp)
        if start <= stamp < end:
            selected.append(record)
    if result['utc_offset'] is None:
        status = 'time_zone_unknown'
    elif first is None:
        status = 'no_parseable_timestamps'
    elif selected:
        status = 'observed_timestamps_in_window'
    else:
        status = 'no_recorded_timestamps_in_window'
    coverage = dict(
        status=status, parse_status=result['status'], issue_count=len(result['issues']),
        parsed_records=result['event_count'], unplaced_records=unplaced,
        records_in_window=None if first is None else len(selected),
        observed_local_range=result['observed_local_range'],
        observed_utc_range=[stamp.isoformat() if stamp is not None else None for stamp in (first, last)],
        span_intersects_window=None if first is None else last >= start and first < end,
        utc_offset=result['utc_offset'], precision_seconds=result.get('precision_seconds',1), boundaries='half_open',
        time_basis=result.get('time_basis','declared_fixed_offset' if result['utc_offset'] is not None else 'unknown'),
        clock_alignment='not_verified', can_establish_absence=False,
    )
    return selected, coverage


def list_events(state_dir,artifact_id,*,event=None,offset=0,limit=20,window=None):
    from .source_coverage import validate_request

    if type(offset) is not int or offset<0 or type(limit) is not int or not 1<=limit<=100:raise InputError('invalid JR pagination')
    window = validate_request(window=window)['window']
    _,result=_saved(state_dir,artifact_id)
    records, coverage = _window_rows(result, window) if window else (result['records'], None)
    selected = records if event is None else [record for record in records if record['event']==event]
    output=[]
    for record in selected[offset:offset+limit]:
        item={k:v for k,v in record.items() if k not in ('data','uninterpreted_tail','comment','row_values')}
        comment=record['comment']
        item.update(comment=comment[:2000] if comment is not None else None,comment_truncated=bool(comment and len(comment)>2000))
        item['truncated_fields']=[]
        for key,value in tuple(item.items()):
            if isinstance(value,str) and len(value)>2000:
                item[key]=value[:2000];item['truncated_fields'].append(key)
        if 'metadata_values' in item:
            names=[name[:256] for name in item['metadata_values'][:8]]
            if names!=item['metadata_values']:
                item['metadata_values']=names;item['truncated_fields'].append('metadata_values')
        output.append(item)
    following = offset + len(output)
    response = dict(artifact_id=artifact_id,profile=result['profile'],total_matched=len(selected),offset=offset,records=output,
                    next_offset=following if following<len(selected) else None,
                    untrusted_source_content=True,integrity_verified=True,complete_incident_coverage=None)
    if coverage is not None:
        response.update(window=window, coverage=coverage)
    return response

def read_record(state_dir,artifact_id,record_id):
    sources,result=_saved(state_dir,artifact_id)
    record=next((r for r in result['records'] if r['id']==record_id),None)
    if record is None:raise InputError('unknown JR record identifier')
    source_number=int(record['source'][1:])-1
    if result['profile']==lgd.PROFILE:
        text=lgd.projection_text(record['row_values'])
        return dict(artifact_id=artifact_id,record=record,text=text,text_basis='sqlite_row_projection',
                    source_sha256=hashlib.sha256(sources[source_number][1]).hexdigest(),
                    integrity_verified=True,untrusted_source_content=True)
    raw=sources[source_number][1][record['byte_start']:record['byte_end']]
    return dict(artifact_id=artifact_id,record=record,text=raw.decode('utf-8'),integrity_verified=True,untrusted_source_content=True)
