"""One offline template catalogue for the harness and auxiliary interfaces."""
import hashlib
from pathlib import Path

from .inputs import InputError,json_value,read_snapshot

def catalogue():
    data=read_snapshot(Path(__file__).parent/'assets/incident-templates.json',256*1024)
    value=json_value(data.decode('utf-8'),reject_duplicates=True)
    expected={'TPL-'+str(i).zfill(2) for i in range(1,11)}
    if value.get('schema_version')!=1 or not isinstance(value.get('templates'),list):raise InputError('unsupported template catalogue')
    if {t.get('id') for t in value['templates']}!=expected or len(value['templates'])!=10:raise InputError('incomplete template catalogue')
    value['sha256']=hashlib.sha256(data).hexdigest()
    return value

def plan(template_id,*,variant=None,database_mode='unknown',time_mode='past'):
    book=catalogue()
    template=next((t for t in book['templates'] if t['id']==template_id),None)
    if template is None or database_mode not in ('file','server','unknown') or time_mode not in book['time_modes']:raise InputError('invalid template, database mode or time mode')
    selected=next((v for v in template['variants'] if v['id']==variant),None) if variant else None
    if variant and selected is None:raise InputError('unknown template variant')
    sources=[]
    for kind in template['sources']:
        if kind in ('sql','rac') and database_mode!='server':continue
        sources.append(dict(type=kind,required=False,temporal_requirement='retained_history' if time_mode=='past' else 'bounded_current_or_reproduction',
                            note='Full client action can include refreshing open forms and dynamic lists.' if kind=='client' else None))
    checks=[dict(id=check,capability='harness_interpretation',status='guidance_only') for check in template['checks']]
    if any(s['type']=='client' for s in sources):checks.append(dict(id='client-observation',capability='testpilot',status='not_implemented'))
    if any(s['type']=='sql' for s in sources):checks.append(dict(id='sql-visibility',capability='postgresql_fixed_catalogue',status='requires_engine_and_access_check',sql_server='not_implemented'))
    return dict(schema_version=1,template=template,variant=selected,catalogue_revision=book['revision'],catalogue_sha256=book['sha256'],
        time_mode=time_mode,database_mode=database_mode,scales=book['scales'],unknown_allowed=True,
        questions=book['common_questions']+template['questions']+(selected['questions'] if selected else []),sources=sources,checks=checks,
        stop_conditions=book['stop_conditions'],expected_report=book['expected_report'],
        os_preset=dict(duration_seconds=300,interval_seconds=1),collection_started=False,
        cause_preassigned=False,limitations=['Templates guide checks; they do not implement or verify all scenarios.',
            'Current collection cannot reconstruct missing past history. SQL/RAC require confirmed server mode.'])
