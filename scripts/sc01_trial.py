"""Private finite disclosure stages for a supplied SC01 case, never a model runner."""
from copy import deepcopy
import hashlib
import os
from pathlib import Path,PurePosixPath
import re
import shutil
import stat

from src.techexpert import operation_state as fs
from src.techexpert.inputs import InputError,json_value,load_manifest,read_snapshot
from src.techexpert.readiness import MANIFEST,canonical
from scripts.sc01_kit import copy_toolkit,verification_schema

ROOT=Path(__file__).resolve().parents[1]
MAX_INPUT_BYTES=64*1024*1024
MAX_TREE_BYTES=80*1024*1024
MAX_DOCUMENT=512*1024
MAX_FILES=2048


def digest(data):return hashlib.sha256(data).hexdigest()


def _relative(root,name):
    if not isinstance(name,str) or not name or '\\' in name or ':' in name:raise InputError('invalid trial member')
    path=PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or path.as_posix()!=name:raise InputError('invalid trial member')
    return fs.safe(Path(root)/name)


def inventory(root,*,participant=False):
    root=fs.safe(root);result={};total=0;count=0;pending=[root]
    while pending:
        current=pending.pop()
        with os.scandir(fs.safe(current)) as entries:
            for entry in entries:
                count+=1
                if count>MAX_FILES:raise InputError('trial member limit exceeded')
                path=fs.safe(current/entry.name);info=path.lstat()
                if stat.S_ISDIR(info.st_mode):
                    if entry.name=='__pycache__' or participant and current==root and entry.name in ('state','verification'):continue
                    pending.append(path)
                elif stat.S_ISREG(info.st_mode):
                    if participant and current==root and entry.name in ('answer.json','transcript.jsonl'):continue
                    data=read_snapshot(path,min(16*1024*1024,MAX_TREE_BYTES-total));total+=len(data)
                    result[path.relative_to(root).as_posix()]=digest(data)
                else:raise InputError('unsupported trial member')
    return dict(sorted(result.items()))


def fingerprints(bundle):
    return dict(manifest=bundle['manifest_sha256'],sources=[dict(format=s['format'],sha256=s['sha256']) for s in bundle['sources']])


def materialize(bundle,target,index,*,with_source):
    if bundle['manifest'].get('workload_profile')!='sc01-order-load-v1':raise InputError('controlled order-load profile required')
    manifest=deepcopy(bundle['manifest']);manifest['symptom']='Фоновая загрузка заказов выполняется дольше ожидаемого. Контролируемые лабораторные наблюдения.'
    specs=[];entries=[]
    if len(bundle['sources'])!=len(manifest['sources']):raise InputError('complete supplied source list required')
    for number,(spec,source) in enumerate(zip(manifest['sources'],bundle['sources']),1):
        if source['format']=='1c-source-text-v1' and not with_source:continue
        name='data/run-'+str(index).zfill(2)+'/input-'+str(number).zfill(2)+'.bin'
        file=_relative(target,name);file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(source['data'])
        specs.append(dict(spec,path=file.name));entries.append(dict(path=name,format=source['format'],original_sha256=source['sha256']))
    manifest['sources']=specs;name='data/run-'+str(index).zfill(2)+'/manifest.json';fs.write(_relative(target,name),manifest)
    return name,entries


def _captures(bundles,output):
    private=fs.private(output/'private-inputs');rows=[]
    for index,bundle in enumerate(bundles,1):
        folder=fs.private(private/('run-'+str(index).zfill(3)))
        (folder/'manifest.bin').write_bytes(bundle['manifest_data']);sources=[]
        for number,source in enumerate(bundle['sources'],1):
            name='run-'+str(index).zfill(3)+'/input-'+str(number).zfill(2)+'.bin'
            _relative(private,name).write_bytes(source['data'])
            sources.append(dict(path=name,format=source['format'],sha256=source['sha256'],bytes=len(source['data'])))
        rows.append(dict(manifest='run-'+str(index).zfill(3)+'/manifest.bin',manifest_sha256=bundle['manifest_sha256'],sources=sources))
    return rows


def _bundle(output,row):
    private=output/'private-inputs';raw=read_snapshot(_relative(private,row['manifest']),1024*1024)
    if digest(raw)!=row['manifest_sha256']:raise InputError('private capture manifest integrity mismatch')
    manifest=json_value(raw.decode('utf-8-sig'),reject_duplicates=True);sources=[]
    if len(manifest['sources'])!=len(row['sources']):raise InputError('private capture source count mismatch')
    for spec,source in zip(manifest['sources'],row['sources']):
        data=read_snapshot(_relative(private,source['path']))
        if (source['format']!=spec['format'] or len(data)!=source['bytes'] or digest(data)!=source['sha256']):
            raise InputError('private capture snapshot integrity mismatch')
        sources.append(dict(source,data=data))
    return dict(manifest=manifest,manifest_data=raw,manifest_sha256=digest(raw),sources=sources)


def prepare(root,output,before,after):
    root=fs.safe(root);output=fs.safe(output)
    if output.exists():raise InputError('evaluation output must be new')
    if output==root or output.is_relative_to(root):raise InputError('private trial must be outside the source bundle')
    if not before or not after or len(before)!=len(after) or len(before)>20:raise InputError('equal nonempty groups of at most twenty captures required')
    existing=next(path for path in (output.parent,*output.parents) if path.exists())
    if shutil.disk_usage(existing).free<10*1024**3:raise InputError('at least 10 GiB free required')
    bundles=[];total=0
    for path in list(before)+list(after):
        loaded=load_manifest(path)
        if loaded['manifest'].get('workload_profile')!='sc01-order-load-v1' or len(loaded['sources'])!=len(loaded['manifest']['sources']):
            raise InputError('complete controlled order-load captures required')
        if len(loaded['manifest_data'])>1024*1024:raise InputError('trial manifest byte limit')
        total+=len(loaded['manifest_data'])+sum(len(s['data']) for s in loaded['sources'])
        if total>MAX_INPUT_BYTES:raise InputError('trial input byte limit exceeded')
        bundles.append(dict(manifest=loaded['manifest'],manifest_data=loaded['manifest_data'],manifest_sha256=loaded['manifest_sha256'],
            sources=[dict(format=s['format'],sha256=s['sha256'],data=s['data']) for s in loaded['sources']]))
    output.mkdir(parents=True,exist_ok=False);fs.private(output)
    with fs.writer(output):
        rows=_captures(bundles,output);target=output/'diagnosis';profile=copy_toolkit(root,target)
        cases=[];entries=[]
        for index,bundle in enumerate(bundles[:len(before)],1):
            name,one=materialize(bundle,target,index,with_source=False);cases.append(name);entries+=one
        fs.write(target/'intake.json',dict(scenario='SC-01',cases=cases,unavailable=['source text','subsequent measurements'],
            scope='Supplied controlled Windows/file/8.3.27.1989 captures; source authenticity is not established by preparation'))
        (target/'prompt.txt').write_text('$techexpert\nФоновая загрузка заказов стала выполняться дольше ожидаемого. '
            'Исследуй предоставленные наблюдения из intake.json через навык. Сам выполни нужные команды и проверь доказательства. '
            'Объясни наиболее обоснованный механизм задержки, предложи конкретное изменение и способ проверки; сохраняй неизвестные факты. '
            'Сейчас доступны только исходные прогоны; дополнительные материалы будут переданы после сохранения твоего ответа. '
            'Работай в этой папке, сохраняй ./state. Ответь по-русски в answer.json по answer-schema.json. '
            'При нехватке данных дай полезный план продолжения. Никакие команды подготовки не запускают модель.\n',encoding='utf-8')
        doc=dict(schema=2,before=[str(Path(p).absolute()) for p in before],after=[str(Path(p).absolute()) for p in after],
            pair_count=len(before),captures=rows,input_bytes=total,input_fingerprints=[fingerprints(b) for b in bundles],
            diagnosis_sources=entries,diagnosis_inventory=inventory(target,participant=True),private_inventory=inventory(output/'private-inputs'),
            source_bundle_manifest_sha256=profile['source_bundle_manifest_sha256'],product_version=profile['product_version'],
            workspace='diagnosis',created_at=fs.stamp(),release_status='withheld',security_boundary=False,model_launched_by_controller=False,
            limits=dict(input_bytes=MAX_INPUT_BYTES,tree_bytes=MAX_TREE_BYTES,tree_members=MAX_FILES,pairs=20))
        fs.write(output/'preparation.json',doc);fs.write(output/'preparation-receipt.json',dict(sha256=fs.digest(doc)))
        fs.write(output/'head.json',dict(stage='prepared'))
    return doc


def _hash_receipt(path):
    value=fs.read(path,8192)
    if (not isinstance(value,dict) or set(value)!={'sha256'} or not isinstance(value['sha256'],str)
        or not re.fullmatch('[a-f0-9]{64}',value['sha256'])):raise InputError('invalid trial hash receipt')
    return value['sha256']


def _head(output):
    value=fs.read(output/'head.json',8192)
    if (not isinstance(value,dict) or set(value)!={'stage'}
        or value['stage'] not in ('prepared','releasing','released')):raise InputError('invalid trial phase')
    return value['stage']


def verify_prepared(output):
    output=fs.safe(output);doc=fs.read(output/'preparation.json',MAX_DOCUMENT)
    if not isinstance(doc,dict) or doc.get('schema')!=2:raise InputError('legacy trial schema requires its original controller; no automatic migration')
    if fs.digest(doc)!=_hash_receipt(output/'preparation-receipt.json'):raise InputError('trial preparation integrity mismatch')
    if inventory(output/'diagnosis',participant=True)!=doc['diagnosis_inventory']:raise InputError('prepared participant input inventory changed')
    if inventory(output/'private-inputs')!=doc['private_inventory']:raise InputError('private capture inventory integrity mismatch')
    return doc


def _answer(raw):
    doc=json_value(raw.decode('utf-8-sig'),reject_duplicates=True)
    required={'status','cause_hypothesis','proposed_change','evidence','limitations'}
    if not isinstance(doc,dict) or not required<=doc.keys() or set(doc)-required-{'next_steps'}:raise InputError('invalid diagnosis answer schema')
    if doc['status'] not in ('confirmed','hypothesis','insufficient_data'):raise InputError('invalid diagnosis answer status')
    def text(value):return isinstance(value,str) and 1<=len(value)<=8192 and bool(value.strip()) and all(ord(c)>=32 or c in '\r\n\t' for c in value)
    for key in ('cause_hypothesis','proposed_change'):
        if doc[key] is not None and not text(doc[key]) or doc['status']!='insufficient_data' and not text(doc[key]):raise InputError('a substantive interpretation/change is required')
    for key in ('limitations','next_steps'):
        values=doc.get(key,[])
        if not isinstance(values,list) or len(values)>32 or any(not text(v) for v in values):raise InputError('invalid answer text list')
    if doc['status']=='insufficient_data' and not doc.get('next_steps'):raise InputError('insufficient data requires a useful continuation')
    refs=doc['evidence']
    if not isinstance(refs,list) or len(refs)>32 or doc['status']!='insufficient_data' and not refs:raise InputError('diagnosis evidence required')
    for ref in refs:
        if (not isinstance(ref,dict) or set(ref)!={'case_id','id','observation'} or not isinstance(ref['case_id'],str)
            or not re.fullmatch('[a-f0-9]{32}',ref['case_id']) or not isinstance(ref['id'],str) or not 1<=len(ref['id'])<=128
            or not text(ref['observation'])):raise InputError('invalid diagnosis evidence reference')
    return doc


def _evidence(output,doc,response):
    from src.techexpert.context_disclosure import verify_case_summary
    from src.techexpert.operations import _guard_dependency_paths
    from src.techexpert.storage import verified_case,read_evidence
    allowed={s['original_sha256'] for s in doc['diagnosis_sources']};state=output/'diagnosis/state';result=[]
    for ref in response['evidence']:
        cid=ref['case_id'];_guard_dependency_paths(state,'cases',cid);case=verified_case(state,cid)
        if not case['sources'] or any(source['sha256'] not in allowed for source in case['sources']):raise InputError('cited case is not based on the prepared participant inputs')
        identifier=ref['id']
        if identifier.startswith('view:'):
            proof=verify_case_summary(state,identifier,case)
        else:
            record=read_evidence(state,cid,identifier)
            proof={key:record[key] for key in ('sha256','line','byte_start','byte_end') if key in record}
        result.append(dict(case_id=cid,id=identifier,case_report_sha256=fs.digest(case),proof=proof))
    return result


def release(output,response_path):
    output=fs.safe(output)
    with fs.writer(output):
        if _head(output)!='prepared':raise InputError('trial already released or partial/releasing; inspect status, never restart')
        doc=verify_prepared(output);target=output/'diagnosis/verification'
        if target.exists():raise InputError('partial verification directory already exists; retain it')
        if digest(canonical(read_snapshot(ROOT/MANIFEST,1024*1024)))!=doc['source_bundle_manifest_sha256']:
            raise InputError('use the exact source bundle version pinned by preparation')
        raw=read_snapshot(response_path,1024*1024);response=_answer(raw);proofs=_evidence(output,doc,response)
        bundles=[_bundle(output,row) for row in doc['captures']]
        if [fingerprints(b) for b in bundles]!=doc['input_fingerprints']:raise InputError('private snapshot fingerprint integrity mismatch')
        fs.write(output/'head.json',dict(stage='releasing'))
        fs.private(target);(output/'frozen-diagnosis.json').write_bytes(raw);(target/'previous-answer.json').write_bytes(raw)
        groups={};entries=[];index=0
        for group,selected in (('before',bundles[:doc['pair_count']]),('after',bundles[doc['pair_count']:])):
            names=[]
            for bundle in selected:
                index+=1;name,one=materialize(bundle,target,index,with_source=True)
                names.append('verification/'+name);entries+=[dict(row,path='verification/'+row['path']) for row in one]
            groups[group]=names
        fs.write(target/'intake.json',dict(scenario='SC-01',**groups,pair_order='same index; use all supplied runs',paths_relative_to='participant workspace'))
        fs.write(target/'answer-schema.json',verification_schema())
        (target/'prompt.txt').write_text('$techexpert\nПродолжи в том же чате, рабочей папке и ./state. '
            'Твой сохранённый ответ — verification/previous-answer.json; полные исходные и последующие прогоны перечислены '
            'в verification/intake.json, пути указаны от этой рабочей папки. Исходники теперь доступны. '
            'Через навык самостоятельно проверь соответствие изменения гипотезе, сопоставимость, эффект и правильность результата. '
            'Используй все прогоны, сохрани старые случаи и ссылки; при противоречиях или нехватке повторов не объявляй успех. '
            'Ответь по-русски в verification/answer.json по verification/answer-schema.json.\n',encoding='utf-8')
        result=dict(schema=2,release_status='released',workspace=str(output/'diagnosis'),prompt='verification/prompt.txt',
            state_dir='state',frozen_diagnosis_sha256=digest(raw),sources=entries,inventory=inventory(target,participant=True),
            evidence_verified_at_release=proofs,original_inputs_read=False,causal_truth_judged=False,security_boundary=False,model_launched_by_controller=False)
        fs.write(output/'release.json',result);fs.write(output/'release-receipt.json',dict(sha256=fs.digest(result)))
        fs.write(output/'head.json',dict(stage='released'))
    return result


def status(output):
    output=fs.safe(output);doc=verify_prepared(output);stage=_head(output)
    result=dict(schema=2,workspace=str(output/'diagnosis'),release_status='withheld' if stage=='prepared' else stage,
        material_integrity='verified',security_boundary=False,model_launched_by_controller=False,participant_state_checked=False)
    if stage=='released':
        released=fs.read(output/'release.json',MAX_DOCUMENT)
        if (not isinstance(released,dict) or fs.digest(released)!=_hash_receipt(output/'release-receipt.json')
            or inventory(output/'diagnosis/verification',participant=True)!=released['inventory']):
            raise InputError('released participant input integrity mismatch')
        if digest(read_snapshot(output/'frozen-diagnosis.json',1024*1024))!=released['frozen_diagnosis_sha256']:
            raise InputError('frozen diagnosis integrity mismatch')
        result['release']=released
    return result
