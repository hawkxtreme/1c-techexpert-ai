"""Selected catalogue imports reuse the existing JR/OS/APDEX parsers."""
from pathlib import Path

from .inputs import InputError
from .input_intake import read_plan,selected_members,capture_selected
from .operation_state import digest

OPERATIONS=('jr.import','os.import','apdex.import')


def fields(cap,*,single=False):
    return dict(input_plan=cap.CASE,members=dict(type='array',minItems=1,maxItems=1 if single else 32,
        items=cap.string(4,pattern='m[1-9][0-9]{0,2}')))


def normalize(args,*,single=False):
    result=dict(args)
    if ('input_plan' in result)!=('members' in result):raise InputError('input_plan and selected members must be supplied together')
    if 'input_plan' in result:
        import re
        members=result['members']
        if (type(result['input_plan']) is not str or not re.fullmatch('[a-f0-9]{32}',result['input_plan'])
            or type(members) is not list or not 1<=len(members)<=(1 if single else 32)
            or any(type(m) is not str or not re.fullmatch('m[1-9][0-9]{0,2}',m) for m in members)
            or len(set(members))!=len(members)):raise InputError('invalid selected diagnostic catalogue members')
    return result


def import_selected(operation,args,state,output):
    if operation not in OPERATIONS:raise InputError('unsupported selected-input adapter')
    from . import capabilities as cap,diagnostic_adapters as drivers
    args=cap.validate(args,cap.ROUTES[operation]['input_schema'])
    args=normalize(args,single=operation!='jr.import')
    if 'input_plan' not in args:raise InputError('selected adapter requires a saved input plan')
    if operation in drivers.OPERATIONS:args=drivers.normalize(operation,args)
    original=args['path' if operation=='jr.import' else 'measurements'];plan=read_plan(state,args['input_plan'])
    selection=selected_members(plan,args['members'],expected_root=original,flat=operation=='jr.import')
    if operation=='jr.import':
        from . import native_jr
        _,original_file=native_jr.check_catalogue_selection(plan,selection,args)
    stage,captured,intake=capture_selected(state,output,args['input_plan'],args['members'],expected_root=original,
        flat=operation=='jr.import',expected_plan_digest=digest(plan))
    if operation=='jr.import':
        if original_file is not None:native_jr.reject_sidecars(original_file)
        return native_jr.read_journal(output,stage,**{k:v for k,v in args.items() if k not in ('path','input_plan','members')},intake=intake)
    path=captured[args['members'][0]]['path']
    if operation=='os.import':
        from .os_metrics import import_os
        return import_os(output,path,intake=intake,expected_sha256=args.get('expected_sha256'))
    from .artifacts import import_apdex
    return import_apdex(output,path,**{k:v for k,v in args.items() if k not in ('measurements','input_plan','members')},intake=intake)
