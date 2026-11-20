"""JSON boundary for the user's existing AI harness."""
import argparse
import json
import sys
from pathlib import Path

from .inputs import InputError
from .profiles import doctor, load_profile
from .storage import (ROOT, default_state_dir, investigate, load_case, read_evidence, list_native_events,
                      compare_cases, load_comparison)


def emit(value):
    print(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False), flush=True)


def main(argv=None):
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8',newline='\n')
    parser = argparse.ArgumentParser(description='1C TechExpert AI: local evidence tools for your AI harness')
    parser.add_argument('--state-dir', type=Path, default=default_state_dir())
    commands = parser.add_subparsers(dest='command', required=True)
    mcp=commands.add_parser('mcp-stdio',help='local finite-tool MCP server over stdio; no network listener')
    mcp.add_argument('--profile',choices=['full','direct','program','context'],default='full')
    catalogue=commands.add_parser('capabilities');catalogue.add_argument('operation',nargs='?')
    operation_run=commands.add_parser('operation-run');operation_run.add_argument('request',type=Path)
    for name in ('operation-status','operation-result','operation-reconcile','operation-cancel'):
        operation=commands.add_parser(name);operation.add_argument('run_id')
        if name=='operation-cancel':operation.add_argument('--executor-id',required=True)
    kernel_call=commands.add_parser('kernel-call');kernel_call.add_argument('call_id')
    commands.add_parser('doctor')
    starter=commands.add_parser('starter-inspect',help='read only the selected starter list; omitted path selects the current user default')
    starter.add_argument('path',type=Path,nargs='?')
    readiness=commands.add_parser('readiness')
    readiness.add_argument('--entrypoint-sha256')
    readiness.add_argument('--investigation')
    update_check=commands.add_parser('update-check',help='inspect an explicit local product package')
    update_check.add_argument('package',type=Path);update_check.add_argument('--current-root',type=Path,default=ROOT)
    for name in ('update-stage','update-apply'):
        update_action=commands.add_parser(name)
        update_action.add_argument('plan',type=Path);update_action.add_argument('--expected-sha256',required=True)
    update_plan=commands.add_parser('update-plan')
    update_plan.add_argument('release_id');update_plan.add_argument('--installed-root',type=Path)
    update_plan.add_argument('--codex-profile',type=Path);update_plan.add_argument('--maintenance-window',action='store_true')
    commands.add_parser('update-status')
    profile_command=commands.add_parser('profile');profile_command.add_argument('--resolved',action='store_true')
    profile_files_command = commands.add_parser('profile-files', help='check selected local paths or find journal locations for file infobases')
    profile_files_command.add_argument('document', nargs='?', type=Path, help='explicit profile JSON, or the current saved profile')
    journal_discovery = profile_files_command.add_mutually_exclusive_group()
    journal_discovery.add_argument('--find-journals', dest='find', action='store_const', const='file_jr')
    journal_discovery.add_argument('--find-tj', dest='find', action='store_const', const='file_tj')
    for name in ('profile-upgrade','profile-resolve'):
        commands.add_parser(name).add_argument('document',type=Path)
    profile_impact=commands.add_parser('profile-impact');profile_impact.add_argument('before',type=Path);profile_impact.add_argument('after',type=Path)
    profile_save=commands.add_parser('profile-save');profile_save.add_argument('document',type=Path);profile_save.add_argument('--expected-revision',type=int,required=True)
    from . import context_disclosure, context_policy
    commands.add_parser('context-intake', help='save selected diagnostics with a metadata-only response').add_argument('request',type=Path)
    context_attach=commands.add_parser('context-attach', help='link an existing protected intake to the chosen investigation revision')
    context_attach.add_argument('run_id')
    context_attach.add_argument('--revision',type=int,required=True)
    preview=commands.add_parser('context-excerpt-prepare', help='prepare a local text preview from a retained source')
    preview.add_argument('investigation_id')
    preview.add_argument('--revision', type=int, required=True)
    preview.add_argument('--attachment', required=True)
    preview.add_argument('--member', required=True)
    preview.add_argument('--start', type=int, required=True)
    preview.add_argument('--lines', type=int, required=True)
    for name, help_text in (('context-excerpt-approve','confirm the exact locally reviewed text'),
                            ('context-excerpt-revoke','withdraw approval of the exact excerpt')):
        review=commands.add_parser(name, help=help_text)
        review.add_argument('artifact_id')
        review.add_argument('--expected-sha256', required=True)
    for name, help_text in (
        ('context-policy', 'show allowed model data for a saved environment'),
        ('context-policy-plan', 'preview a change to model data permissions'),
        ('context-policy-save', 'save the exactly reviewed model data permissions'),
        ('context-history', 'review metadata for previously prepared context views'),
        ('context-read', 'read typed evidence under a saved disclosure policy'),
    ):
        context_command = commands.add_parser(name, help=help_text)
        context_command.add_argument('investigation_id')
        context_command.add_argument('--revision', type=int, required=True)
        if name in ('context-policy-plan','context-policy-save'):
            context_command.add_argument('--allow', action='append', choices=context_policy.CATEGORIES, default=[])
            context_command.add_argument('--max-bytes', type=int, default=context_policy.DEFAULT_BYTES)
        if name == 'context-policy-save':
            context_command.add_argument('--expected-sha256', required=True)
        if name in ('context-history','context-read'):
            context_command.add_argument('--limit', type=int)
            context_command.add_argument('--offset', type=int)
        if name == 'context-read':
            context_command.add_argument('kind', choices=context_disclosure.VIEWS)
            context_command.add_argument('--attachment', action='append', required=True,
                                         help='attachment label; repeat for summaries of one kind')
            for option in ('record','source','event','start','end','metric-group'):
                context_command.add_argument('--'+option)
            context_command.add_argument('--anchor-attachment')
            context_command.add_argument('--within-seconds', type=int)
            context_command.add_argument('--linked-run', action='store_true', default=None)
    commands.add_parser('demo')
    analyze = commands.add_parser('analyze')
    analyze.add_argument('manifest', type=Path)
    analyze.add_argument('--reference-sha256')
    commands.add_parser('tj-reference-plan', help='review a local external TJ window without reading its records').add_argument('manifest',type=Path)
    show = commands.add_parser('show')
    show.add_argument('case_id')
    for operation in ('source-check','coverage'):
        command=commands.add_parser(operation)
        command.add_argument('manifest' if operation=='source-check' else 'case_id',type=Path if operation=='source-check' else str)
        command.add_argument('--start');command.add_argument('--end')
        command.add_argument('--require-event',action='append',default=[])
        command.add_argument('--require-field',action='append',default=[])
    compare=commands.add_parser('compare')
    compare.add_argument('--before',nargs='+',required=True)
    compare.add_argument('--after',nargs='+',required=True)
    comparison=commands.add_parser('comparison')
    comparison.add_argument('comparison_id')
    proof = commands.add_parser('evidence')
    proof.add_argument('case_id')
    proof.add_argument('evidence_id')
    events = commands.add_parser('events')
    events.add_argument('case_id')
    events.add_argument('--source')
    events.add_argument('--event')
    events.add_argument('--property', action='append', default=[], dest='properties')
    events.add_argument('--offset', type=int, default=0)
    events.add_argument('--limit', type=int, default=20)
    events.add_argument('--linked-run', action='store_true', help='only records inside the verified job marker window')
    events.add_argument('--start');events.add_argument('--end')
    init = commands.add_parser('init')
    init.add_argument('--open-browser', action='store_true')
    init.add_argument('--ttl', type=int, default=900)
    init.add_argument('--investigation')
    init.add_argument('--entrypoint-sha256')
    knowledge = commands.add_parser('knowledge')
    knowledge.add_argument('query')
    knowledge.add_argument('--environment',type=Path)
    knowledge.add_argument('--event',action='append',default=[])
    knowledge.add_argument('--card-type')
    knowledge.add_argument('--limit',type=int,default=5)
    knowledge.add_argument('--offset',type=int,default=0)
    knowledge.add_argument('--excerpt-chars',type=int,default=6000)
    card=commands.add_parser('knowledge-card');card.add_argument('card_id');card.add_argument('--offset',type=int,default=0);card.add_argument('--limit',type=int,default=6000)
    use=commands.add_parser('knowledge-use');use.add_argument('card_ids',nargs='+');use.add_argument('--purpose',choices=('recommendation','reference'),default='recommendation');use.add_argument('--environment',type=Path)
    for command in (knowledge, card, use):
        command.add_argument('--expected-knowledge-digest')
    review=commands.add_parser('knowledge-review');review.add_argument('target_id');review.add_argument('--kind',choices=('artifact','investigation'),default='investigation');review.add_argument('--revision',type=int);review.add_argument('--environment',type=Path)
    proposal_prepare = commands.add_parser('knowledge-proposal-prepare', help='save a private editorial draft from the displayed incident preview')
    proposal_prepare.add_argument('request', type=Path)
    proposal = commands.add_parser('knowledge-proposal', help='read a retained editorial revision')
    proposal.add_argument('proposal_id')
    proposal.add_argument('--revision', type=int)
    proposal_review = commands.add_parser('knowledge-proposal-review', help='record a reported editor decision on a retained revision')
    proposal_review.add_argument('proposal_id')
    proposal_review.add_argument('request', type=Path)
    proposal_review.add_argument('--expected-sha256', required=True)
    apdex = commands.add_parser('apdex')
    apdex.add_argument('measurements',type=Path)
    apdex_mode = apdex.add_mutually_exclusive_group(required=True)
    apdex_mode.add_argument('--target', type=float)
    apdex_mode.add_argument('--inventory', action='store_true', help='retain normalized measurements before choosing a target')
    apdex.add_argument('--operation')
    apdex.add_argument('--start')
    apdex.add_argument('--end')
    artifact = commands.add_parser('artifact')
    artifact.add_argument('artifact_id')
    artifact.add_argument('--source')
    rac = commands.add_parser('rac')
    rac.add_argument('operation',choices=('clusters','infobases','sessions','connections','processes','servers','infobase_info'))
    rac.add_argument('--endpoint',required=True)
    rac.add_argument('--cluster')
    rac.add_argument('--infobase')
    rac.add_argument('--executable',default='rac')
    rac.add_argument('--docker-container')
    for name in ('os-plan','os-collect'):
        os_command=commands.add_parser(name)
        os_command.add_argument('--duration',type=float,default=300)
        os_command.add_argument('--interval',type=float,default=1)
        os_command.add_argument('--transport',choices=('local','ssh','winrm'),default='local')
        os_command.add_argument('--host',default='')
        os_command.add_argument('--port',type=int)
        os_command.add_argument('--node')
        os_command.add_argument('--role',choices=('onec','sql','storage','client','terminal','web','other'),default='onec')
        os_command.add_argument('--python')
        os_command.add_argument('--use-ssl',action='store_true')
        os_command.add_argument('--identity-file')
        os_command.add_argument('--known-hosts-file')
        os_command.add_argument('--storage-path')
    os_import=commands.add_parser('os-import')
    os_observation=commands.add_parser('os-observation',help='preview, approve or inspect a saved OS observation')
    os_observation.add_argument('request',type=Path)
    os_import.add_argument('measurements',type=Path)
    os_import.add_argument('--expected-sha256')
    operator_plan=commands.add_parser('os-operator-plan',help='review or save one local collection for an operator')
    operator_plan.add_argument('request',type=Path)
    operator_plan.add_argument('--output',type=Path)
    operator_plan.add_argument('--expected-sha256')
    operator_run=commands.add_parser('os-operator-run',help='run the reviewed plan on its selected node')
    operator_run.add_argument('plan',type=Path)
    operator_run.add_argument('--expected-sha256',required=True)
    pg=commands.add_parser('postgresql')
    pg.add_argument('operation',choices=('capabilities','activity','locks','database_stats','statements'))
    pg.add_argument('--database',required=True)
    pg.add_argument('--host')
    pg.add_argument('--port',type=int,default=5432)
    pg.add_argument('--user')
    pg.add_argument('--executable',default='psql')
    pg.add_argument('--docker-container')
    sql=commands.add_parser('sqlserver')
    sql.add_argument('operation',choices=('capabilities','requests','waits','locks','query_store'))
    sql.add_argument('--database',required=True);sql.add_argument('--host',required=True)
    sql.add_argument('--port',type=int,default=1433);sql.add_argument('--user')
    sql.add_argument('--auth',choices=('integrated','sql'),default='integrated')
    sql.add_argument('--executable',default='sqlcmd');sql.add_argument('--docker-container')
    sql.add_argument('--client-variant',choices=('auto','go','odbc18'),default='auto')
    sql.add_argument('--trust-server-certificate',action='store_true');sql.add_argument('--start');sql.add_argument('--end')
    commands.add_parser('client-endpoint',help='passive identity check for an explicitly selected local TestClient port').add_argument('port',type=int)
    commands.add_parser('client-import',help='import supplied normalized client observations').add_argument('path',type=Path)
    source_snapshot=commands.add_parser('source-snapshot')
    source_snapshot.add_argument('path',type=Path)
    source_snapshot.add_argument('--kind',choices=('catalog','git'),default='catalog')
    source_snapshot.add_argument('--ref',default='HEAD')
    source_snapshot.add_argument('--encoding',choices=('utf-8','cp1251'),default='utf-8')
    source_search=commands.add_parser('source-search')
    source_search.add_argument('artifact_id');source_search.add_argument('query')
    source_search.add_argument('--limit',type=int,default=20)
    source_read=commands.add_parser('source-read')
    source_read.add_argument('artifact_id');source_read.add_argument('path')
    source_read.add_argument('--start',type=int,default=1);source_read.add_argument('--limit',type=int,default=50)
    export_plan=commands.add_parser('source-export-plan');export_plan.add_argument('request',type=Path)
    source_export=commands.add_parser('source-export');source_export.add_argument('plan_id');source_export.add_argument('--expected-sha256',required=True)
    export_status=commands.add_parser('source-export-status');export_status.add_argument('plan_id')
    cleanup_plan=commands.add_parser('source-export-cleanup-plan',help='review removal of one completed export working copy')
    cleanup_plan.add_argument('plan_id')
    cleanup_plan.add_argument('--use-policy',action='store_true')
    cleanup_apply=commands.add_parser('source-export-cleanup-apply')
    cleanup_apply.add_argument('document',type=Path)
    cleanup_apply.add_argument('--expected-sha256',required=True)
    case_cleanup=commands.add_parser('case-source-cleanup-plan',help='review one saved case snapshot and affected evidence')
    case_cleanup.add_argument('case_id');case_cleanup.add_argument('source_id')
    case_cleanup.add_argument('--use-policy',action='store_true')
    case_cleanup_apply=commands.add_parser('case-source-cleanup-apply')
    case_cleanup_apply.add_argument('document',type=Path)
    case_cleanup_apply.add_argument('--expected-sha256',required=True)
    case_cleanup_status=commands.add_parser('case-source-cleanup-status')
    case_cleanup_status.add_argument('case_id');case_cleanup_status.add_argument('source_id')
    for name in ('case-index-build', 'case-index-status', 'case-index-cleanup-plan'):
        case_index = commands.add_parser(name)
        case_index.add_argument('case_id');case_index.add_argument('source_id')
        if name=='case-index-cleanup-plan':case_index.add_argument('--use-policy',action='store_true')
    index_cleanup=commands.add_parser('case-index-cleanup-apply')
    index_cleanup.add_argument('document',type=Path)
    index_cleanup.add_argument('--expected-sha256',required=True)
    from .retention_policy import CATEGORIES as retention_categories, DEFAULT_CATEGORY
    policy=commands.add_parser('retention-policy',help='show the local retention choice')
    policy.add_argument('--category',choices=retention_categories,default=DEFAULT_CATEGORY)
    retention_save=commands.add_parser('retention-policy-save')
    retention_save.add_argument('document',type=Path)
    retention_save.add_argument('--expected-revision',type=int,required=True)
    retention_save.add_argument('--category',choices=retention_categories,default=DEFAULT_CATEGORY)
    jr=commands.add_parser('jr-import')
    jr.add_argument('path',type=Path);jr.add_argument('--platform-version')
    jr.add_argument('--utc-offset')
    jr.add_argument('--consistency',choices=('unknown','stopped_writer','provided_snapshot'),default='unknown')
    jr_events=commands.add_parser('jr-events');jr_events.add_argument('artifact_id')
    jr_events.add_argument('--event');jr_events.add_argument('--offset',type=int,default=0);jr_events.add_argument('--limit',type=int,default=20)
    jr_events.add_argument('--start');jr_events.add_argument('--end')
    jr_record=commands.add_parser('jr-record');jr_record.add_argument('artifact_id');jr_record.add_argument('record_id')
    commands.add_parser('templates')
    template_save=commands.add_parser('template-save',help='save an inert private template variant, without source access')
    template_save.add_argument('request',type=Path);template_save.add_argument('--expected-revision',type=int,required=True)
    help_source=commands.add_parser('source-help');help_source.add_argument('type',choices=('tj','jr','source','sql','rac','os'))
    template=commands.add_parser('template');template.add_argument('template_id');template.add_argument('--variant')
    template.add_argument('--revision',type=int)
    template.add_argument('--database-mode',choices=('file','server','unknown'))
    template.add_argument('--time-mode',choices=('unknown','past','current','reproduce'))
    investigation_create=commands.add_parser('investigation-create');investigation_create.add_argument('request',type=Path)
    task=commands.add_parser('investigation-task',help='save a new chat task or clarification')
    task.add_argument('request',type=Path)
    investigation=commands.add_parser('investigation');investigation.add_argument('investigation_id');investigation.add_argument('--revision',type=int)
    progress=commands.add_parser('investigation-progress',help='observe saved investigation and local check status')
    progress.add_argument('investigation_id')
    progress.add_argument('--from-revision',type=int,help='compare changes since this revision')
    progress.add_argument('--to-revision',type=int,help='pin the comparison endpoint')
    progress.add_argument('--offset',type=int)
    progress.add_argument('--limit',type=int)
    for command in (investigation_create,investigation):
        command.add_argument('--handle',action='store_true',help='show only the investigation identifier and revision')
    materials=commands.add_parser('investigation-materials',help='view retained files and evidence links for an investigation')
    materials.add_argument('investigation_id')
    materials.add_argument('--revision',type=int)
    from .investigation_materials import CATEGORIES
    materials.add_argument('--category',choices=CATEGORIES)
    materials.add_argument('--offset',type=int,default=0)
    materials.add_argument('--limit',type=int,default=60)
    from .investigation_export import CONTENTS
    bundle_plan=commands.add_parser('investigation-export-plan',help='review an exact local export before writing files')
    bundle_export=commands.add_parser('investigation-export',help='write the reviewed local investigation export')
    for command in (bundle_plan,bundle_export):
        command.add_argument('investigation_id')
        command.add_argument('destination',type=Path)
        command.add_argument('--revision',type=int,required=command is bundle_export)
        command.add_argument('--content',choices=CONTENTS,required=True)
        command.add_argument('--draft',help='reviewed draft ID for pseudonymized evidence')
    bundle_export.add_argument('--expected-sha256',required=True)
    bundle_verify=commands.add_parser('investigation-export-verify',help='check a portable investigation export offline')
    bundle_verify.add_argument('destination',type=Path)
    bundle_verify.add_argument('--expected-sha256')
    source_context=commands.add_parser('source-context');source_context.add_argument('investigation_id');source_context.add_argument('--revision',type=int,required=True)
    investigation_update=commands.add_parser('investigation-update');investigation_update.add_argument('investigation_id')
    investigation_update.add_argument('patch',type=Path);investigation_update.add_argument('--expected-revision',type=int,required=True)
    report_cleanup=commands.add_parser('investigation-cleanup-plan',help='review removal of one investigation report history')
    report_cleanup.add_argument('investigation_id');report_cleanup.add_argument('--use-policy',action='store_true')
    report_apply=commands.add_parser('investigation-cleanup-apply');report_apply.add_argument('document',type=Path)
    report_apply.add_argument('--expected-sha256',required=True)
    report_status=commands.add_parser('investigation-cleanup-status');report_status.add_argument('investigation_id')
    incident=commands.add_parser('incident-draft');incident.add_argument('investigation_id');incident.add_argument('--revision',type=int)
    incident.add_argument('--include-versions',action='store_true');incident.add_argument('--summary',action='store_true')
    incident.add_argument('--exclude-section',action='append',default=[]);incident.add_argument('--public-url',action='append',default=[])
    incident.add_argument('--evidence',action='append',default=[])
    incident_preview=commands.add_parser('incident-preview');incident_preview.add_argument('draft_id');incident_preview.add_argument('--summary',action='store_true')
    incident_edit=commands.add_parser('incident-edit');incident_edit.add_argument('draft_id');incident_edit.add_argument('document',type=Path)
    incident_edit.add_argument('--expected-sha256',required=True);incident_edit.add_argument('--summary',action='store_true')
    incident_export=commands.add_parser('incident-export');incident_export.add_argument('draft_id');incident_export.add_argument('output',type=Path)
    incident_export.add_argument('--expected-sha256',required=True)
    incident_send=commands.add_parser('incident-send-plan');incident_send.add_argument('draft_id');incident_send.add_argument('--repository',required=True)
    incident_send.add_argument('--expected-sha256',required=True)
    incident_record=commands.add_parser('incident-record-submission');incident_record.add_argument('draft_id');incident_record.add_argument('response',type=Path)
    incident_record.add_argument('--repository',required=True);incident_record.add_argument('--expected-sha256',required=True);incident_record.add_argument('--expected-action-sha256',required=True)
    args = parser.parse_args(argv)
    if args.command=='mcp-stdio':
        from .mcp_server import serve
        return serve(args.state_dir,profile=args.profile)
    try:
        if args.command=='capabilities':
            from .capabilities import catalogue
            result=catalogue(args.operation)
        elif args.command in ('context-intake','context-attach'):
            from . import kernel
            selection = (dict(request=str(args.request)) if args.command=='context-intake' else
                         dict(run_id=args.run_id,revision=str(args.revision)))
            call=kernel.invoke(args.state_dir,args.command,selection)
            kernel.emit(call,sys.stdout)
            return call['exit_code']
        elif args.command == 'context-excerpt-prepare':
            from .context_excerpt import prepare
            result=prepare(args.state_dir, args.investigation_id, args.revision, attachment=args.attachment,
                           member=args.member, start=args.start, lines=args.lines)
        elif args.command == 'context-excerpt-approve':
            from .context_excerpt import approve
            result=approve(args.state_dir, args.artifact_id, args.expected_sha256)
        elif args.command == 'context-excerpt-revoke':
            from .context_excerpt import revoke
            result=revoke(args.state_dir, args.artifact_id, args.expected_sha256)
        elif args.command.startswith('context-'):
            identity = (args.state_dir, args.investigation_id, args.revision)
            if args.command == 'context-policy':
                result = context_policy.show(*identity)
            elif args.command == 'context-policy-plan':
                result = context_policy.plan(*identity, args.allow, args.max_bytes)
            elif args.command == 'context-policy-save':
                result = context_policy.save(*identity, args.allow, args.max_bytes, args.expected_sha256)
            elif args.command == 'context-history':
                result = context_disclosure.history(*identity, offset=0 if args.offset is None else args.offset,
                                                      limit=20 if args.limit is None else args.limit)
            else:
                from . import kernel
                selection = {key: getattr(args,key) for key in ('investigation_id','revision','kind',
                    'record','event','source','offset','limit','linked_run','anchor_attachment','within_seconds','metric_group')
                    if getattr(args,key) is not None}
                if len(args.attachment) == 1:
                    selection['attachment'] = args.attachment[0]
                else:
                    selection['attachments'] = args.attachment
                if args.start is not None or args.end is not None:
                    selection['window'] = dict(start=args.start,end=args.end)
                call = kernel.invoke(args.state_dir, 'context-read',
                    dict(selection=context_disclosure.compact(context_disclosure.validate_selection(selection))))
                kernel.emit(call, sys.stdout)
                return call['exit_code']
        elif args.command.startswith('operation-') or args.command=='kernel-call':
            from . import kernel
            if args.command=='operation-run':
                action='run';arguments=dict(request=str(args.request))
            elif args.command=='kernel-call':action='inspect';arguments=dict(call_id=args.call_id)
            else:
                action=args.command.removeprefix('operation-');arguments=dict(run_id=args.run_id)
                if action=='cancel':arguments['executor_id']=args.executor_id
            call=kernel.invoke(args.state_dir,action,arguments)
            kernel.emit(call,sys.stdout)
            if call.get('diagnostics'):print(json.dumps(dict(kernel_call_id=call['call_id'],diagnostics=call['diagnostics']),ensure_ascii=False),file=sys.stderr)
            return call['exit_code']
        elif args.command == 'doctor':
            result = doctor(args.state_dir)
        elif args.command == 'starter-inspect':
            from .discovery import inspect_starter,default_starter_path
            path=args.path if args.path is not None else default_starter_path()
            if path is None:raise InputError('No default starter list is defined on this OS; select a .v8i file.')
            result=inspect_starter(path)
        elif args.command == 'readiness':
            from .readiness import check
            result=check(args.state_dir,entrypoint_sha256=args.entrypoint_sha256,investigation_id=args.investigation)
        elif args.command.startswith('update-'):
            from . import operation_state, updates
            if args.command=='update-check':
                result=updates.check(args.state_dir,args.package,current_root=args.current_root)
            elif args.command=='update-status':
                result=updates.selected(args.state_dir)
            elif args.command=='update-plan':
                if args.codex_profile:
                    if args.installed_root:
                        raise InputError('Codex activation derives its cache from the selected profile')
                    from .update_codex import plan_install
                    result=plan_install(args.state_dir,args.release_id,args.codex_profile,maintenance_window=args.maintenance_window)
                else:
                    if args.maintenance_window:
                        raise InputError('select the Codex profile for a maintenance window')
                    result=updates.select_plan(args.state_dir,args.release_id,installed_root=args.installed_root)
            else:
                plan=operation_state.read(args.plan,64*1024)
                if type(plan) is not dict:
                    raise InputError('update plan must be an object')
                procedure=updates.stage if args.command=='update-stage' else updates.select
                if args.command=='update-apply' and plan.get('kind')=='codex_install':
                    from .update_codex import install
                    procedure=install
                result=procedure(args.state_dir,plan,expected_sha256=args.expected_sha256)
        elif args.command == 'profile-save':
            from .profiles import save_profile
            from .inputs import read_snapshot,json_value
            result=save_profile(args.state_dir,json_value(read_snapshot(args.document,1024*1024).decode('utf-8-sig'),reject_duplicates=True),expected_revision=args.expected_revision)
        elif args.command == 'profile':
            result = load_profile(args.state_dir) or dict(status='not_configured', next_step='init')
            if args.resolved and result.get('schema_version'):
                from .profile_resources import effective_profile
                result=dict(canonical_schema_version=result['schema_version'],view=effective_profile(result),scope='ephemeral_adapter_configuration_not_runtime_ownership',saved=False,connected=False)
        elif args.command == 'profile-files':
            from . import kernel, profile_files
            from .inputs import json_value, read_snapshot

            profile = (load_profile(args.state_dir) if args.document is None else
                       json_value(read_snapshot(args.document, 1024 * 1024).decode('utf-8-sig'), reject_duplicates=True))
            if profile is None:
                raise InputError('select a profile before checking local paths')
            request = profile_files.from_profile(profile, find=args.find)
            call = kernel.invoke(args.state_dir, profile_files.ACTION, dict(request='inline-request.json'),
                                 limits=dict(query_seconds=20), request_document=request)
            kernel.emit(call, sys.stdout)
            return call['exit_code']
        elif args.command in ('profile-upgrade','profile-resolve','profile-impact'):
            from .inputs import read_snapshot,json_value
            from .profile_resources import upgrade_profile,effective_profile,resource_impact
            def document(path):return json_value(read_snapshot(path,1024*1024).decode('utf-8-sig'),reject_duplicates=True)
            if args.command=='profile-upgrade':result=upgrade_profile(document(args.document))
            elif args.command=='profile-resolve':
                value=document(args.document);result=dict(canonical_schema_version=value.get('schema_version'),view=effective_profile(value),scope='ephemeral_adapter_configuration_not_runtime_ownership',saved=False,connected=False)
            else:result=resource_impact(document(args.before),document(args.after))
        elif args.command in ('demo','analyze'):
            if args.command=='demo':
                from .readiness import run_demo
                result=run_demo(args.state_dir)
            else:result=investigate(args.manifest,args.state_dir,reference_sha256=args.reference_sha256)
        elif args.command=='tj-reference-plan':
            from .tj_reference import plan
            result=plan(args.manifest,args.state_dir)
        elif args.command == 'show':
            result = load_case(args.state_dir, args.case_id)
            from .knowledge_review import review_legacy_report
            result=dict(result,knowledge_review=review_legacy_report(result))
        elif args.command in ('source-check','coverage'):
            from .source_coverage import inspect_manifest,inspect_case
            window=None
            if args.start is not None or args.end is not None:
                if args.start is None or args.end is None:raise InputError('both --start and --end are required')
                window=dict(start=args.start,end=args.end)
            options=dict(window=window,required_events=args.require_event,required_fields=args.require_field)
            result=inspect_manifest(args.manifest,**options) if args.command=='source-check' else inspect_case(args.state_dir,args.case_id,**options)
        elif args.command == 'compare':
            result = compare_cases(args.state_dir,args.before,args.after)
        elif args.command == 'comparison':
            result = load_comparison(args.state_dir,args.comparison_id)
        elif args.command == 'evidence':
            result = read_evidence(args.state_dir, args.case_id, args.evidence_id)
        elif args.command == 'events':
            window=None
            if args.start is not None or args.end is not None:
                if args.start is None or args.end is None:raise InputError('both --start and --end are required')
                window=dict(start=args.start,end=args.end)
            filters = {}
            for item in args.properties:
                key, separator, value = item.partition('=')
                if not separator or not key or key in filters:
                    raise InputError('each property filter requires a unique NAME=VALUE')
                filters[key] = value
            result = list_native_events(args.state_dir, args.case_id, source_id=args.source, event=args.event,
                                        properties=filters, offset=args.offset, limit=args.limit, linked_run=args.linked_run,window=window)
        elif args.command == 'init':
            from .gui import run_gui
            run_gui(args.state_dir, open_browser=args.open_browser, ttl=args.ttl,investigation_id=args.investigation,entrypoint_sha256=args.entrypoint_sha256)
            return 0
        elif args.command == 'apdex':
            from .artifacts import import_apdex
            result=import_apdex(args.state_dir,args.measurements,args.target,inventory_only=args.inventory,
                                operation=args.operation,start=args.start,end=args.end)
        elif args.command == 'artifact':
            from .artifacts import load_artifact, artifact_evidence
            result=(artifact_evidence(args.state_dir,args.artifact_id,args.source) if args.source
                    else load_artifact(args.state_dir,args.artifact_id))
            if not args.source and result['kind']=='knowledge_use':
                from .knowledge_review import review_use
                result=dict(result,knowledge_review=review_use(args.state_dir,args.artifact_id))
        elif args.command == 'rac':
            from .rac import RacClient,collect_rac
            result=collect_rac(args.state_dir,RacClient(args.endpoint,executable=args.executable,
                docker_container=args.docker_container),args.operation,cluster=args.cluster,infobase=args.infobase)
        elif args.command in ('os-plan','os-collect'):
            from .os_metrics import validate_request,collect_os
            request=dict(transport=args.transport,host=args.host,duration_seconds=args.duration,
                         interval_seconds=args.interval,node=args.node,role=args.role,use_ssl=args.use_ssl)
            if args.port is not None:request['port']=args.port
            if args.python is not None:request['python']=args.python
            if args.identity_file is not None:request['identity_file']=args.identity_file
            if args.known_hosts_file is not None:request['known_hosts_file']=args.known_hosts_file
            if args.storage_path is not None:request['storage_path']=args.storage_path
            request=validate_request(request)
            result=(dict(status='planned_not_started',request=request,
                         prerequisites='Existing SSH/WinRM access and Python on remote nodes; no service or permission changes are automatic.')
                    if args.command=='os-plan' else collect_os(args.state_dir,request))
        elif args.command=='os-observation':
            from . import kernel
            call=kernel.invoke(args.state_dir,'os-observation',dict(request=str(args.request)))
            kernel.emit(call,sys.stdout)
            return call['exit_code']
        elif args.command=='os-operator-plan':
            from . import os_operator, operation_state
            result=os_operator.prepare(operation_state.read(args.request,8192),output=args.output,
                                       expected_sha256=args.expected_sha256)
        elif args.command=='os-operator-run':
            from .os_operator import run
            result=run(args.state_dir,args.plan,expected_sha256=args.expected_sha256)
            emit(result)
            return result['exit_code']
        elif args.command=='os-import':
            from .os_metrics import import_os
            result=import_os(args.state_dir,args.measurements,expected_sha256=args.expected_sha256)
        elif args.command=='postgresql':
            from .postgresql import PsqlClient,observe
            result=observe(args.state_dir,PsqlClient(database=args.database,host=args.host,port=args.port,
                user=args.user,executable=args.executable,docker_container=args.docker_container),args.operation)
        elif args.command=='sqlserver':
            from .sqlserver import SqlcmdClient,observe
            if bool(args.start)!=bool(args.end):raise InputError('SQL history start/end must be supplied together')
            result=observe(args.state_dir,SqlcmdClient(database=args.database,host=args.host,port=args.port,user=args.user,
                auth=args.auth,executable=args.executable,docker_container=args.docker_container,client_variant=args.client_variant,
                trust_server_certificate=args.trust_server_certificate),args.operation,window=dict(start=args.start,end=args.end) if args.start else None)
        elif args.command=='client-endpoint':
            from .client_endpoint import inspect_endpoint
            result=inspect_endpoint(args.port)
        elif args.command=='client-import':
            from .client_episode import import_episode
            result=import_episode(args.state_dir,args.path)
        elif args.command=='source-snapshot':
            from .source_code import snapshot_source
            result=snapshot_source(args.state_dir,args.path,kind=args.kind,ref=args.ref,encoding=args.encoding)
        elif args.command=='jr-import':
            from .native_jr import read_journal
            result=read_journal(args.state_dir,args.path,platform_version=args.platform_version,
                                utc_offset=args.utc_offset,consistency=args.consistency)
        elif args.command=='jr-events':
            from .native_jr import list_events
            window = None if args.start is None and args.end is None else dict(start=args.start,end=args.end)
            result=list_events(args.state_dir,args.artifact_id,event=args.event,offset=args.offset,limit=args.limit,window=window)
        elif args.command=='jr-record':
            from .native_jr import read_record
            result=read_record(args.state_dir,args.artifact_id,args.record_id)
        elif args.command=='templates':
            from .incident_templates import catalogue
            result=catalogue(state_dir=args.state_dir)
        elif args.command=='template-save':
            from .incident_templates import save_custom
            from .inputs import read_snapshot,json_value
            request=json_value(read_snapshot(args.request,64*1024).decode('utf-8-sig'),reject_duplicates=True)
            result=save_custom(args.state_dir,request,expected_revision=args.expected_revision)
        elif args.command=='source-help':
            from .source_help import source_help
            result=source_help(args.type)
        elif args.command=='template':
            from .incident_templates import plan
            result=plan(args.template_id,variant=args.variant,database_mode=args.database_mode,time_mode=args.time_mode,
                        state_dir=args.state_dir,revision=args.revision)
        elif args.command=='source-context':
            from .investigations import source_context
            result=source_context(args.state_dir,args.investigation_id,revision=args.revision)
        elif args.command=='investigation-progress':
            from . import kernel
            selection = dict(investigation_id=args.investigation_id)
            comparison = {key:value for key,value in (
                ('before_revision',args.from_revision),('after_revision',args.to_revision),
                ('offset',args.offset),('limit',args.limit)) if value is not None}
            if comparison:
                selection['comparison'] = json.dumps(comparison, separators=(',', ':'))
            call=kernel.invoke(args.state_dir,'investigation-progress',selection)
            kernel.emit(call,sys.stdout)
            return call['exit_code']
        elif args.command=='investigation-task':
            from . import investigation_task,kernel
            call=kernel.invoke(args.state_dir,investigation_task.ACTION,dict(request=str(args.request)))
            kernel.emit(call,sys.stdout)
            return call['exit_code']
        elif args.command=='investigation-materials':
            from .investigation_materials import view
            result=view(args.state_dir,args.investigation_id,revision=args.revision,
                        category=args.category,offset=args.offset,limit=args.limit)
        elif args.command in ('investigation-export-plan','investigation-export','investigation-export-verify'):
            from . import investigation_export
            if args.command=='investigation-export-verify':
                result=investigation_export.verify(args.destination,expected_sha256=args.expected_sha256)
            else:
                options=dict(revision=args.revision,content=args.content,draft=args.draft)
                if args.command=='investigation-export-plan':
                    result=investigation_export.plan(args.state_dir,args.investigation_id,args.destination,**options)
                else:
                    result=investigation_export.execute(args.state_dir,args.investigation_id,args.destination,
                        expected_sha256=args.expected_sha256,**options)
        elif args.command in ('investigation-create','investigation-update','investigation'):
            from .investigations import create,revise,read_for_display,revision_folder,_read_head
            from .inputs import read_snapshot,json_value
            if args.command=='investigation-create':
                result=create(args.state_dir,json_value(read_snapshot(args.request,1024*1024).decode('utf-8-sig'),reject_duplicates=True))
            elif args.command=='investigation-update':
                result=revise(args.state_dir,args.investigation_id,
                    json_value(read_snapshot(args.patch,1024*1024).decode('utf-8-sig'),reject_duplicates=True),expected_revision=args.expected_revision)
            elif args.handle:
                selected=args.revision if args.revision is not None else _read_head(args.state_dir,args.investigation_id)['revision']
                result=context_policy.selected_investigation(args.state_dir,args.investigation_id,selected)
            else:
                from .investigation_retention import status as report_status
                result=report_status(args.state_dir,args.investigation_id)
                if result is None:
                    result=read_for_display(args.state_dir,args.investigation_id,revision=args.revision)
            if getattr(args,'handle',False):
                result={key:result[key] for key in ('investigation_id','revision')}
            elif 'revision' in result:
                folder=revision_folder(args.state_dir,result['investigation_id'],result['revision']).absolute()
                result['local_reports']={suffix:str(folder/('report.'+suffix)) for suffix in ('json','md')}
                from .knowledge_review import review_investigation
                result['knowledge_review']=review_investigation(args.state_dir,result)
                from .source_passports import context as source_context
                review=source_context(result)
                result['source_review']={key:review[key] for key in ('status','dependencies','needs_clarification','clarifications','limitations')}
        elif args.command.startswith('investigation-cleanup-'):
            from . import investigation_retention as reports
            if args.command=='investigation-cleanup-plan':
                result=reports.preview(args.state_dir,args.investigation_id,use_policy=args.use_policy)
            elif args.command=='investigation-cleanup-status':
                result=reports.status(args.state_dir,args.investigation_id) or dict(status='not_recorded')
            else:
                from .inputs import read_snapshot,json_value
                document=json_value(read_snapshot(args.document,reports.MAX_PLAN_BYTES).decode('utf-8-sig'),reject_duplicates=True)
                result=reports.apply(args.state_dir,document,expected_sha256=args.expected_sha256)
        elif args.command in ('incident-draft','incident-preview','incident-edit','incident-export','incident-send-plan','incident-record-submission'):
            from . import incident_drafts as drafts
            if args.command=='incident-draft':
                result=drafts.prepare(args.state_dir,args.investigation_id,revision=args.revision,include_versions=args.include_versions,
                    exclude_sections=args.exclude_section,public_urls=args.public_url,evidence_ids=args.evidence)
            elif args.command=='incident-preview':result=drafts.preview(args.state_dir,args.draft_id)
            elif args.command=='incident-edit':
                from .inputs import read_snapshot,json_value
                document=json_value(read_snapshot(args.document,256*1024).decode('utf-8-sig'),reject_duplicates=True)
                if not isinstance(document,dict) or set(document)-{'title','body','exclude_evidence_ids'} or not {'title','body'}<=set(document):raise InputError('invalid incident edit properties')
                result=drafts.edit(args.state_dir,args.draft_id,expected_sha256=args.expected_sha256,**document)
            elif args.command=='incident-export':result=drafts.export(args.state_dir,args.draft_id,args.output,expected_sha256=args.expected_sha256)
            elif args.command=='incident-record-submission':
                from .inputs import read_snapshot,json_value
                result=drafts.record_submission(args.state_dir,args.draft_id,args.repository,
                    json_value(read_snapshot(args.response,512*1024).decode('utf-8-sig'),reject_duplicates=True),
                    expected_sha256=args.expected_sha256,expected_action_sha256=args.expected_action_sha256)
            else:result=drafts.send_plan(args.state_dir,args.draft_id,args.repository,expected_sha256=args.expected_sha256)
            if getattr(args,'summary',False):
                result.pop('body',None)
                if 'files' in result:result['files']=[{k:v for k,v in item.items() if k!='text'} for item in result['files']]
        elif args.command in ('retention-policy','retention-policy-save'):
            from . import retention_policy
            if args.command=='retention-policy':
                result=retention_policy.load(args.state_dir,category=args.category)
            else:
                from .inputs import read_snapshot,json_value
                document=json_value(read_snapshot(args.document,8192).decode('utf-8-sig'),reject_duplicates=True)
                result=retention_policy.save(args.state_dir,document,expected_revision=args.expected_revision,category=args.category)
        elif args.command in ('case-source-cleanup-plan','case-source-cleanup-apply','case-source-cleanup-status'):
            from . import case_retention
            if args.command=='case-source-cleanup-plan':
                result=case_retention.preview(args.state_dir,args.case_id,args.source_id,use_policy=args.use_policy)
            elif args.command=='case-source-cleanup-status':
                result=case_retention.status(args.state_dir,args.case_id,args.source_id) or dict(status='not_recorded')
            else:
                from .inputs import read_snapshot,json_value
                document=json_value(read_snapshot(args.document,case_retention.MAX_PLAN_BYTES).decode('utf-8-sig'),reject_duplicates=True)
                result=case_retention.apply(args.state_dir,document,expected_sha256=args.expected_sha256)
        elif args.command in ('case-index-build', 'case-index-status', 'case-index-cleanup-plan', 'case-index-cleanup-apply'):
            from . import case_event_index, index_retention
            if args.command=='case-index-build':
                result=case_event_index.build(args.state_dir,args.case_id,args.source_id)
            elif args.command=='case-index-status':
                result=case_event_index.inspect(args.state_dir,args.case_id,args.source_id)
            elif args.command=='case-index-cleanup-plan':
                result=index_retention.preview(args.state_dir,args.case_id,args.source_id,use_policy=args.use_policy)
            else:
                from .inputs import read_snapshot,json_value
                document=json_value(read_snapshot(args.document,32768).decode('utf-8-sig'),reject_duplicates=True)
                result=index_retention.apply(args.state_dir,document,expected_sha256=args.expected_sha256)
        elif args.command in ('source-export-cleanup-plan','source-export-cleanup-apply'):
            from . import export_retention
            if args.command=='source-export-cleanup-plan':
                result=export_retention.preview(args.state_dir,args.plan_id,use_policy=args.use_policy)
            else:
                from .inputs import read_snapshot,json_value
                document=json_value(read_snapshot(args.document,32*1024).decode('utf-8-sig'),reject_duplicates=True)
                result=export_retention.apply(args.state_dir,document,expected_sha256=args.expected_sha256)
        elif args.command in ('source-export-plan','source-export','source-export-status'):
            from .source_export import prepare,execute,status
            if args.command=='source-export-plan':
                from .inputs import read_snapshot,json_value
                result=prepare(args.state_dir,json_value(read_snapshot(args.request,1024*1024).decode('utf-8-sig'),reject_duplicates=True))
            elif args.command=='source-export':result=execute(args.state_dir,args.plan_id,expected_sha256=args.expected_sha256)
            else:result=status(args.state_dir,args.plan_id)
        elif args.command=='source-search':
            from .source_code import search_source
            result=search_source(args.state_dir,args.artifact_id,args.query,limit=args.limit)
        elif args.command=='source-read':
            from .source_code import read_source
            result=read_source(args.state_dir,args.artifact_id,args.path,start=args.start,limit=args.limit)
        elif args.command in ('knowledge-proposal-prepare', 'knowledge-proposal', 'knowledge-proposal-review'):
            from . import knowledge_proposals as proposals
            if args.command == 'knowledge-proposal':
                result = proposals.show(args.state_dir, args.proposal_id, revision=args.revision)
            else:
                from .inputs import json_value, read_snapshot
                request = json_value(read_snapshot(args.request, proposals.REQUEST_LIMIT).decode('utf-8-sig'), reject_duplicates=True)
                if args.command == 'knowledge-proposal-prepare':
                    result = proposals.prepare(args.state_dir, request)
                else:
                    result = proposals.record_review(args.state_dir, args.proposal_id, request, expected_sha256=args.expected_sha256)
        elif args.command=='knowledge-card':
            from .knowledge import get_card
            if args.offset<0 or not 1<=args.limit<=8192:raise InputError('knowledge-card requires offset>=0 and limit1..8192')
            result=get_card(args.card_id,expected_knowledge_digest=args.expected_knowledge_digest)
            body=result['body'];result['body']=body[args.offset:args.offset+args.limit]
            result.update(body_offset=args.offset,body_total_characters=len(body),body_truncated=args.offset>0 or args.offset+args.limit<len(body),
                          content_sha256_scope='complete_card_before_display_pagination')
        elif args.command in ('knowledge','knowledge-use','knowledge-review'):
            environment=None
            if args.environment is not None:
                from .inputs import read_snapshot,json_value
                environment=json_value(read_snapshot(args.environment,16*1024).decode('utf-8-sig'),reject_duplicates=True)
            if args.command=='knowledge':
                from .knowledge import search
                result=search(args.query,environment=environment,events=args.event,card_type=args.card_type,limit=args.limit,offset=args.offset,
                              excerpt_chars=args.excerpt_chars,expected_knowledge_digest=args.expected_knowledge_digest)
            else:
                from .knowledge_review import pin_use,review_use,review_investigation
                if args.command=='knowledge-use':
                    result=pin_use(args.state_dir,args.card_ids,purpose=args.purpose,environment=environment,
                                   expected_knowledge_digest=args.expected_knowledge_digest)
                elif args.kind=='artifact':
                    if args.revision is not None:raise InputError('artifact snapshots do not have investigation revisions')
                    result=review_use(args.state_dir,args.target_id,environment=environment)
                else:
                    from .investigations import load
                    result=review_investigation(args.state_dir,load(args.state_dir,args.target_id,revision=args.revision),environment=environment)
        emit(result)
        if args.command in ('rac','postgresql','sqlserver','apdex','jr-import','os-import','os-collect','client-import'):
            from .capabilities import outcome
            operation={'rac':'rac.observe','postgresql':'postgresql.observe','sqlserver':'sqlserver.observe','apdex':'apdex.import',
                'jr-import':'jr.import','os-import':'os.import','os-collect':'os.collect','client-import':'client.import'}[args.command]
            status,_=outcome(operation,result)
            return {'succeeded':0,'partial':1,'cancelled':130}[status]
        return 2 if args.command=='readiness' and result['status']=='blocked' else 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        if args.command == 'context-read' and isinstance(exc, PermissionError):
            from .context_disclosure import state_access_denied
            from .responses import normalize

            emit(normalize(state_access_denied()))
            return 2
        if args.command.startswith('context-') or getattr(args,'handle',False):
            emit(dict(status='error', code='context_input_or_state_error',
                      message='Verify the selected investigation, available local state and current policy plan.'))
            return 2
        emit(dict(status='error', code='input_or_state_error', message=str(exc)))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
