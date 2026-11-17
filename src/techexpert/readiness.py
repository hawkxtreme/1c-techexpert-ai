"""Offline capability checks for the existing harness; never connects to sources."""
import hashlib
import re
import sys
from pathlib import Path,PurePosixPath

from . import __version__
from .inputs import InputError,json_value,read_snapshot,load_manifest
from .storage import ROOT,investigate,load_case,write_json,read_evidence
from .profiles import load_profile
from .knowledge import load_library,search
from .incident_templates import catalogue as templates
from .source_help import catalogue as source_help
from .analysis import analyze_events

MANIFEST='src/techexpert/assets/bundle-manifest.json'
ENTRY='skills/techexpert/SKILL.md'
SKILLS=('techexpert','investigate','logcfg','rac','tech-log','event-log','onec-cluster','postgresql','sql-server',
    'onec-source','os-metrics','client-ui-performance','apdex-and-observation','verify-improvement',
    'report-and-evidence','setup-and-access','code-mode-analysis','external-research')
REQUIRED=dict(runtime={'techexpert.py','.codex-plugin/plugin.json','plugin.json','mcp.json','.mcp.json','.agents/plugins/marketplace.json','src/techexpert/__init__.py',
    'src/techexpert/readiness.py','src/techexpert/cli.py','src/techexpert/storage.py','src/techexpert/inputs.py',
    'src/techexpert/gui.py','src/techexpert/assets/init.html'},
    instructions={'AGENTS.md','.agents/skills/techexpert/SKILL.md',*('skills/'+name+'/SKILL.md' for name in SKILLS)},
    catalogues={'src/techexpert/assets/incident-templates.json','src/techexpert/assets/source-help.json'},
    knowledge={'knowledge/index.json'},demo={'examples/sc01/case.json','examples/sc01/events.jsonl'})
ERRORS=(OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError)

def canonical(data):return data.decode('utf-8').replace('\r\n','\n').encode('utf-8')

def _member(root,name):
    if not isinstance(name,str) or not name or any(ord(c)<32 for c in name) or '\\' in name or ':' in name:
        raise InputError('invalid bundle member')
    parts=PurePosixPath(name)
    if parts.is_absolute() or '..' in parts.parts or parts.as_posix()!=name:raise InputError('invalid bundle member')
    current=root
    for part in parts.parts:
        current=current/part;stat=current.lstat()
        if current.is_symlink() or getattr(stat,'st_file_attributes',0)&0x400:raise InputError('linked bundle member')
    if not current.is_file():raise InputError('bundle member is not a regular file')
    return current

def _inventory(root):
    doc=json_value(read_snapshot(_member(root,MANIFEST),1024*1024).decode('utf-8'),reject_duplicates=True)
    if (not isinstance(doc,dict) or type(doc.get('schema_version')) is not int or doc['schema_version']!=1
        or doc.get('product_version')!=__version__ or doc.get('normalization')!='utf8-lf-v1'
        or set(doc)!={'schema_version','product_version','normalization','components','members'}):
        raise InputError('incompatible bundle inventory')
    groups=doc['components'];members=doc['members']
    if not isinstance(groups,dict) or set(groups)!=set(REQUIRED) or not isinstance(members,dict) or not 1<=len(members)<=256:
        raise InputError('incomplete bundle inventory')
    declared=[]
    for group,essential in REQUIRED.items():
        names=groups[group]
        if not isinstance(names,list) or any(not isinstance(n,str) for n in names) or not essential.issubset(names):
            raise InputError('incomplete bundle component')
        declared.extend(names)
    if len(declared)!=len(set(declared)) or set(declared)!=set(members):raise InputError('ambiguous bundle inventory')
    # Validate ALL declared paths before reading any member; a rehashed manifest is not permission to read outside the bundle.
    for name,digest in members.items():
        if not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest):raise InputError('invalid bundle digest')
        parts=PurePosixPath(name)
        if (not name or parts.is_absolute() or '..' in parts.parts or parts.as_posix()!=name
            or '\\' in name or ':' in name or any(ord(c)<32 for c in name) or name==MANIFEST):
            raise InputError('invalid bundle path')
    good={};checks=[];total=0
    for group,names in groups.items():
        bad=[]
        for name in names:
            try:
                data=read_snapshot(_member(root,name),min(1024*1024,8*1024*1024-total));total+=len(data)
                if hashlib.sha256(canonical(data)).hexdigest()!=members[name]:raise InputError('bundle hash mismatch')
            except ERRORS:bad.append(name)
        good[group]=not bad
        checks.append(dict(id=group,status='ready' if not bad else 'damaged',members=len(names),damaged_members=bad[:10],
            truncated=len(bad)>10,action=None if not bad else 'restore_complete_bundle'))
    return doc,good,checks

def _demo_input(root):
    path=_member(root,'examples/sc01/case.json')
    manifest=json_value(read_snapshot(path,64*1024).decode('utf-8'),reject_duplicates=True)
    if manifest.get('origin')!='synthetic' or manifest.get('scenario')!='SC-01' or manifest.get('correlation_profile') or manifest.get('workload_profile'):
        raise InputError('installation demo requires synthetic normalized SC01')
    if manifest.get('sources')!=[{'path':'events.jsonl','format':'normalized-events-v1'}]:
        raise InputError('installation demo cannot select external or native inputs')
    _member(root,'examples/sc01/events.jsonl')
    bundle=load_manifest(path)
    report=analyze_events(bundle['events'],bundle['manifest']['selection'])
    if bundle['limitations'] or report['durations_seconds']!=dict(queue=240.0,execution=2460.0,total=2700.0):
        raise InputError('synthetic installation example is incomplete')
    return path

def _profile(state_dir,investigation_id):
    try:
        if investigation_id:
            from .investigations import load
            profile=load(state_dir,investigation_id)['profile_snapshot']
        else:profile=load_profile(state_dir)
        if profile is None:return dict(status='not_configured',revision=None),[]
        return dict(status='configured_not_connected',name=profile['name'],revision=profile['revision'],
            bases=len(profile['bases']),sources=len(profile['sources'])),profile['bases']
    except ERRORS:return dict(status='invalid',revision=None,action='inspect_saved_context_without_overwriting'),[]

def read_demo(state_dir):
    path=Path(state_dir)/'readiness/demo.json'
    if not path.exists():return dict(status='not_run')
    receipt=json_value(read_snapshot(path,8192).decode('utf-8'),reject_duplicates=True)
    if (not isinstance(receipt,dict) or type(receipt.get('schema_version')) is not int or receipt['schema_version']!=1
        or not isinstance(receipt.get('case_id'),str) or not re.fullmatch('[a-f0-9]{32}',receipt['case_id'])):
        raise InputError('invalid installation demo receipt')
    report,digest=load_case(state_dir,receipt['case_id'],with_digest=True)
    if (digest!=receipt.get('report_sha256') or report.get('origin')!='synthetic'
        or len(report.get('sources',[]))!=1 or report['sources'][0].get('format')!='normalized-events-v1'):
        raise InputError('installation demo integrity mismatch')
    read_evidence(state_dir,report['case_id'],'s1:1')
    return dict(status='completed',case_id=report['case_id'],product_version=report['product_version'],
        origin='synthetic',durations_seconds=report['durations_seconds'],integrity_verified=True,
        cause_requires_harness_interpretation=True)

def check(state_dir,*,root=None,entrypoint_sha256=None,investigation_id=None):
    root=Path(ROOT if root is None else root).resolve()
    if entrypoint_sha256 is not None and (not isinstance(entrypoint_sha256,str) or not re.fullmatch('[a-f0-9]{64}',entrypoint_sha256)):
        raise InputError('entrypoint hash must be a lowercase SHA-256')
    try:
        inventory,good,checks=_inventory(root)
        entry_hash=inventory['members'][ENTRY]
    except ERRORS:
        inventory=None;good=dict.fromkeys(REQUIRED,False);entry_hash=None
        checks=[dict(id='bundle',status='damaged',action='restore_complete_bundle')]
    def damaged(group):
        good[group]=False
        for item in checks:
            if item['id']==group:item.update(status='damaged',action='restore_complete_bundle')
    knowledge=dict(status='damaged',search_verified=False)
    if good['knowledge']:
        try:
            index=json_value(read_snapshot(_member(root,'knowledge/index.json'),1024*1024).decode('utf-8'),reject_duplicates=True)
            # The semantic validator/search may only open inventoried, already checked cards.
            cards=index.get('cards')
            if not isinstance(cards,list) or not cards or len(cards)>256:raise InputError('invalid installed knowledge cards')
            if any(not isinstance(card,dict) or (not (card.get('path') is None and card.get('lifecycle',{}).get('state')=='withdrawn')
                and 'knowledge/'+str(card.get('path','')) not in inventory['components']['knowledge']) for card in cards):
                raise InputError('uninventoried knowledge card')
            library=load_library(root/'knowledge');found=search('SC-01',root=root/'knowledge')
            if not library['cards'] or not found['matches']:raise InputError('bundled knowledge search not ready')
            knowledge=dict(status='ready',revision=library['revision'],digest=library['digest'],cards=len(library['cards']),search_verified=True)
        except ERRORS:damaged('knowledge')
    if good['catalogues']:
        try:templates(root=root);source_help(root=root)
        except ERRORS:damaged('catalogues')
    if good['runtime']:
        try:
            plugin=json_value(read_snapshot(_member(root,'.codex-plugin/plugin.json'),64*1024).decode('utf-8'),reject_duplicates=True)
            if plugin.get('version')!=__version__ or sys.version_info<(3,11):raise InputError('incompatible runtime')
        except ERRORS:damaged('runtime')
    if good['demo']:
        try:_demo_input(root)
        except ERRORS:damaged('demo')
    local_ready=all(good[key] for key in ('runtime','instructions','catalogues','knowledge'))
    harness_status='not_confirmed' if entrypoint_sha256 is None else 'caller_reported_loaded' if entrypoint_sha256==entry_hash and good['instructions'] else 'stale_entrypoint'
    profile,bases=_profile(state_dir,investigation_id)
    try:demonstration=read_demo(state_dir)
    except ERRORS:demonstration=dict(status='damaged',action='inspect_saved_demo_without_rerunning')
    file_only=bool(bases) and all(base['mode']=='file' for base in bases)
    harness_ready=harness_status=='caller_reported_loaded'
    return dict(schema_version=1,product_version=__version__,scenario='SC-01',
        status='blocked' if not local_ready else 'ready_for_supplied_files' if harness_ready else 'needs_harness_confirmation',
        checks=checks,knowledge=knowledge,
        harness=dict(status=harness_status,entrypoint=ENTRY,expected_sha256=entry_hash,hash_normalization='utf8-lf-v1',
            independently_attested=False,action=None if harness_ready else 'read_entrypoint_in_current_harness'),
        capabilities=dict(analyze_supplied_files=local_ready and harness_ready,run_synthetic_demo=local_ready and good['demo']),
        profile=profile,sources=dict(status='configured_not_checked' if profile.get('sources',0) else 'not_configured',paths_probed=False),
        specialized=dict(sql='not_applicable' if file_only else 'not_checked',rac='not_applicable' if file_only else 'not_checked',
            testpilot='not_required_for_background_SC01',server_license='not_required_for_supplied_file_analysis'),
        demonstration=demonstration,
        actions=dict(restore_complete_bundle='Восстановите полную совместимую поставку, сохранив частные расследования. Не собирайте базу знаний вручную.',
            read_entrypoint_in_current_harness='Агенту: прочитать точку входа этого комплекта и подтвердить её текущую ревизию в том же чате.'),
        side_effects=dict(source_connections=False,collection_started=False,profile_changed=False,demo_started=False,state_created=False),
        limitations=['Integrity hashes detect inconsistent package content; they do not authenticate the publisher.',
            'Harness loading is caller-reported, not independent model attestation.',
            'Configured paths are not connectivity/format/coverage checks; write access is not probed.'])

def run_demo(state_dir,*,root=None):
    root=Path(ROOT if root is None else root).resolve()
    if not check(state_dir,root=root)['capabilities']['run_synthetic_demo']:
        raise InputError('Восстановите полный совместимый комплект: безопасный демонстрационный SC-01 недоступен.')
    path=_demo_input(root)
    result=investigate(path,state_dir)
    _,digest=load_case(state_dir,result['case_id'],with_digest=True)
    folder=Path(state_dir)/'readiness';folder.mkdir(parents=True,exist_ok=True)
    from .windows_native import protect_directory
    protect_directory(folder)
    write_json(folder/'demo.json',dict(schema_version=1,case_id=result['case_id'],report_sha256=digest))
    return result
