"""Private, inert user template revisions; no source access or tool execution."""
from copy import deepcopy
from pathlib import Path
import re

from .inputs import InputError
from . import operation_state as fs

MAX_DOCUMENT=64*1024
MAX_TEMPLATES=32
MAX_REVISIONS=100
SOURCES={'tj','jr','source','os','sql','rac','client'}
DEFAULTS=dict(time_mode={'unknown','past','current','reproduce'},
              scale={'one','several','all','background','unknown'},database_mode={'file','server','unknown'})
CHANGES={'title','applicability','questions','sources','checks','optional_fields','defaults'}


def _id(value):
    if not isinstance(value,str) or not re.fullmatch(r'USR-[a-z0-9][a-z0-9-]{0,47}',value):
        raise InputError('invalid private template ID')
    return value


def _text(value,limit):
    if (not isinstance(value,str) or not value.strip() or len(value)>limit
        or any(ord(c)<32 and c not in '\n\r\t' for c in value)):
        raise InputError('invalid or oversized template text')


def _texts(values,maximum,limit):
    if not isinstance(values,list) or len(values)>maximum:raise InputError('template list exceeds limit')
    for value in values:_text(value,limit)
    if len(set(values))!=len(values):raise InputError('duplicate template values')


def _fields(template,optional_fields):
    _text(template['title'],160);_text(template['applicability'],2048)
    _texts(template['questions'],32,2048);_texts(template['sources'],7,32)
    if set(template['sources'])-SOURCES:raise InputError('unsupported template source')
    for key in ('checks','optional_fields'):
        _texts(template[key],32,64)
        if key=='checks' and any(not re.fullmatch('[a-z][a-z0-9-]*',item) for item in template[key]):
            raise InputError('template check must be an inert identifier')
    if set(template['optional_fields'])-optional_fields:raise InputError('unsupported optional template field')
    defaults=template['defaults']
    if not isinstance(defaults,dict) or set(defaults)-DEFAULTS.keys():raise InputError('unsupported template default field')
    for key,value in defaults.items():
        if not isinstance(value,str) or value not in DEFAULTS[key]:raise InputError('invalid template default')


def _root(state_dir):return fs.safe(Path(state_dir)/'custom-templates')


def _folder(state_dir,template_id):return fs.safe(_root(state_dir)/_id(template_id))


def _revision(folder,number):return fs.safe(folder/'revisions'/str(number).zfill(6))


def _record(path,template_id,number):
    doc=fs.read(path,MAX_DOCUMENT)
    if (not isinstance(doc,dict) or set(doc)!={'schema_version','id','revision','created_at','parent_sha256',
            'base_template','base_variant','template','untrusted_user_content','grants_permissions'}
        or type(doc.get('schema_version')) is not int or doc['schema_version']!=1
        or doc.get('id')!=template_id or type(doc.get('revision')) is not int or doc['revision']!=number
        or doc['untrusted_user_content'] is not True or doc['grants_permissions'] is not False):
        raise InputError('private template identity/schema integrity mismatch')
    parent=doc['parent_sha256']
    if (number==1 and parent is not None) or (number>1 and (not isinstance(parent,str) or not re.fullmatch('[a-f0-9]{64}',parent))):
        raise InputError('private template parent integrity mismatch')
    template=doc['template'];base=doc['base_template'];variant=doc['base_variant']
    if (not isinstance(template,dict) or set(template)!={'id','revision','title','applicability','optional_fields',
            'questions','sources','checks','variants','defaults','origin'}
        or template['id']!=template_id or type(template['revision']) is not int or template['revision']!=number
        or template['variants']!=[] or not isinstance(base,dict)
        or not re.fullmatch(r'TPL-(?:0[0-9]|10)',str(base.get('id')))
        or type(base.get('revision')) is not int or base['revision']<1):
        raise InputError('private template body integrity mismatch')
    if (set(base)!={'id','revision','title','applicability','optional_fields','questions','sources','checks','variants'}
        or not isinstance(base['variants'],list) or len(base['variants'])>16):
        raise InputError('private template base schema integrity mismatch')
    for item in base['variants']:
        if not isinstance(item,dict) or set(item)!={'id','title','questions'}:raise InputError('invalid base variant')
        _text(item['id'],64);_text(item['title'],160);_texts(item['questions'],32,2048)
    if variant is not None and (not isinstance(variant,dict) or variant not in base['variants']):
        raise InputError('private template base variant integrity mismatch')
    _texts(base['optional_fields'],32,64)
    _fields(dict(base,defaults={}),set(base['optional_fields']))
    origin=dict(kind='private_user_template',base_id=base['id'],base_revision=base['revision'],
                base_variant=variant['id'] if isinstance(variant,dict) else None,
                base_sha256=fs.digest(dict(template=base,variant=variant)))
    if template['origin']!=origin:raise InputError('private template base integrity mismatch')
    # Validate stored values without consulting a potentially newer bundled base.
    _texts(template['optional_fields'],32,64)
    optional=set(template['optional_fields'])
    if any(not isinstance(x,str) or not re.fullmatch('[a-z][a-z0-9_]*',x) for x in optional):
        raise InputError('invalid private template optional fields')
    _fields(template,optional);_text(doc['created_at'],64)
    return doc


def load(state_dir,template_id,*,revision=None):
    folder=_folder(state_dir,template_id)
    head=fs.read(folder/'head.json',8192)
    if (not isinstance(head,dict) or set(head)!={'id','revision','sha256'} or head['id']!=template_id
        or type(head['revision']) is not int or not 1<=head['revision']<=MAX_REVISIONS
        or not isinstance(head['sha256'],str) or not re.fullmatch('[a-f0-9]{64}',head['sha256'])):
        raise InputError('private template head integrity mismatch')
    selected=head['revision'] if revision is None else revision
    if type(selected) is not int or not 1<=selected<=head['revision']:raise InputError('private template revision is unavailable')
    expected=head['sha256'];result=None
    for number in range(head['revision'],0,-1):
        doc=_record(_revision(folder,number)/'report.json',template_id,number)
        if fs.digest(doc)!=expected:raise InputError('private template history integrity mismatch')
        if number==selected:result=doc
        expected=doc['parent_sha256']
    return result


def list_templates(state_dir):
    root=_root(state_dir)
    if not root.exists():return []
    paths=[]
    for path in root.iterdir():
        fs.safe(path)
        if path.name=='writer.lock' and path.is_file():continue
        _id(path.name)
        if not path.is_dir():raise InputError('unsupported private template state member')
        paths.append(path)
        if len(paths)>MAX_TEMPLATES:raise InputError('private template count exceeds limit')
    return [load(state_dir,path.name) for path in sorted(paths)]


def save(state_dir,request,*,expected_revision):
    if (not isinstance(request,dict) or set(request)-CHANGES-{'id','base_template_id','base_template_revision','base_variant'}
        or 'id' not in request or type(expected_revision) is not int or not 0<=expected_revision<MAX_REVISIONS):
        raise InputError('invalid private template request or expected revision')
    tid=_id(request['id']);folder=_folder(state_dir,tid)
    if expected_revision:
        if set(request)&{'base_template_id','base_template_revision','base_variant'}:
            raise InputError('a saved template base is immutable; save a different ID to change it')
        previous=load(state_dir,tid)
        if previous['revision']!=expected_revision:raise InputError('private template revision changed; reload before editing')
        template=deepcopy(previous['template']);base=previous['base_template'];variant=previous['base_variant']
    else:
        if folder.exists():raise InputError('private template already exists or has unfinished state; inspect before retry')
        from .incident_templates import catalogue
        book=catalogue();base=next((item for item in book['templates'] if item['id']==request.get('base_template_id')),None)
        if base is None or type(request.get('base_template_revision')) is not int or request['base_template_revision']!=base['revision']:
            raise InputError('select an exact bundled base template revision')
        variant=next((item for item in base['variants'] if item['id']==request.get('base_variant')),None)
        if request.get('base_variant') is not None and variant is None:raise InputError('unknown base template variant')
        template=deepcopy(base);template.update(variants=[],defaults={})
        if variant:template['questions']+=variant['questions']
        template['origin']=dict(kind='private_user_template',base_id=base['id'],base_revision=base['revision'],
            base_variant=variant['id'] if variant else None,base_sha256=fs.digest(dict(template=base,variant=variant)))
        previous=None
    template.update({key:deepcopy(value) for key,value in request.items() if key in CHANGES})
    template.update(id=tid,revision=expected_revision+1)
    from .incident_templates import catalogue
    optional_fields={field for item in catalogue()['templates'] for field in item['optional_fields']}
    _fields(template,optional_fields)
    doc=dict(schema_version=1,id=tid,revision=expected_revision+1,created_at=fs.stamp(),
        parent_sha256=fs.digest(previous) if previous else None,base_template=base,base_variant=variant,template=template,
        untrusted_user_content=True,grants_permissions=False)
    if len(fs.encode(doc))>MAX_DOCUMENT:raise InputError('private template document exceeds limit')
    root=fs.private(_root(state_dir))
    with fs.writer(root):
        if previous:
            if load(state_dir,tid)!=previous:raise InputError('private template revision changed; reload before editing')
        else:
            if folder.exists():raise InputError('private template already exists or has unfinished state')
            if len(list_templates(state_dir))>=MAX_TEMPLATES:raise InputError('private template count exceeds limit')
        target=_revision(folder,doc['revision'])
        if target.exists():raise InputError('unfinished private template revision exists; retained without retry')
        fs.private(target)
        fs.write(target/'report.json',doc)
        _record(target/'report.json',tid,doc['revision'])
        fs.write(folder/'head.json',dict(id=tid,revision=doc['revision'],sha256=fs.digest(doc)))
    return doc
