"""One offline template catalogue for the harness and auxiliary interfaces."""
import hashlib
from pathlib import Path

from .inputs import InputError,json_value,read_snapshot

def catalogue(*,root=None,state_dir=None):
    path=Path(root)/'src/techexpert/assets/incident-templates.json' if root is not None else Path(__file__).parent/'assets/incident-templates.json'
    data=read_snapshot(path,256*1024)
    value=json_value(data.decode('utf-8'),reject_duplicates=True)
    expected={'TPL-'+str(i).zfill(2) for i in range(0,11)}
    if value.get('schema_version')!=1 or not isinstance(value.get('templates'),list):raise InputError('unsupported template catalogue')
    if {t.get('id') for t in value['templates']}!=expected or len(value['templates'])!=11:raise InputError('incomplete template catalogue')
    value['sha256']=hashlib.sha256(data).hexdigest()
    if state_dir is not None:
        from .template_store import list_templates
        private=list_templates(state_dir)
        if private:
            from .operation_state import digest
            value['bundled_sha256']=value['sha256']
            value['templates']+=[item['template'] for item in private]
            value['sha256']=digest(dict(bundled=value['bundled_sha256'],private=[digest(item) for item in private]))
    return value

def save_custom(state_dir,request,*,expected_revision):
    from .template_store import save
    return save(state_dir,request,expected_revision=expected_revision)

def plan(template_id,*,variant=None,database_mode=None,time_mode=None,state_dir=None,revision=None):
    book=catalogue()
    template=next((t for t in book['templates'] if t['id']==template_id),None)
    private=False;catalogue_sha256=book['sha256']
    if isinstance(template_id,str) and template_id.startswith('USR-'):
        if state_dir is None:raise InputError('private template requires the selected local state')
        from .template_store import load
        from .operation_state import digest
        saved=load(state_dir,template_id,revision=revision);template=saved['template'];private=True
        catalogue_sha256=digest(dict(bundled=book['sha256'],private=digest(saved)))
    elif revision is not None and (type(revision) is not int or template is None or revision!=template['revision']):
        raise InputError('bundled template revision is unavailable')
    defaults=template.get('defaults',{}) if template else {}
    if database_mode is None:database_mode=defaults.get('database_mode','unknown')
    if time_mode is None:time_mode=defaults.get('time_mode','unknown')
    if template is None or database_mode not in ('file','server','unknown') or time_mode not in book['time_modes']:raise InputError('invalid template, database mode or time mode')
    selected=next((v for v in template['variants'] if v['id']==variant),None) if variant else None
    if variant and selected is None:raise InputError('unknown template variant')
    sources=[]
    for kind in template['sources']:
        if kind in ('sql','rac') and database_mode!='server':continue
        sources.append(dict(type=kind,required=False,temporal_requirement='unknown' if time_mode=='unknown' else 'retained_history' if time_mode=='past' else 'bounded_current_or_reproduction',
                            note='Full client action can include refreshing open forms and dynamic lists.' if kind=='client' else None))
    checks=[dict(id=check,capability='harness_interpretation',status='guidance_only') for check in template['checks']]
    if any(s['type']=='client' for s in sources):checks.append(dict(id='client-observation',capability='testpilot',status='not_implemented'))
    if any(s['type']=='sql' for s in sources):checks.append(dict(id='sql-visibility',capability='postgresql_or_sqlserver_2022_fixed_catalogue',status='requires_engine_and_access_check',sql_server='fixed_catalogue_requires_sqlcmd_and_existing_read_rights'))
    return dict(schema_version=1,template=template,variant=selected,catalogue_revision=book['revision'],catalogue_sha256=catalogue_sha256,
        defaults=defaults,untrusted_user_content=private,grants_permissions=False,
        time_mode=time_mode,database_mode=database_mode,scales=book['scales'],unknown_allowed=True,
        questions=book['common_questions']+template['questions']+(selected['questions'] if selected else []),sources=sources,checks=checks,
        stop_conditions=book['stop_conditions'],expected_report=book['expected_report'],
        os_preset=dict(duration_seconds=300,interval_seconds=1),collection_started=False,
        cause_preassigned=False,limitations=['Templates guide checks; they do not implement or verify all scenarios.',
            'Current collection cannot reconstruct missing past history. SQL/RAC require confirmed server mode.'])
