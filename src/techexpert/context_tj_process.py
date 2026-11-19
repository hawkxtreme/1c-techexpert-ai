"""Compare the observed lifetime for a retained TJ source with a local OS capture."""
from . import context_coverage, context_fields as fields, context_os_window, source_passports, storage, tj_process
from .analysis import parse_time
from .inputs import InputError


VIEW = 'os-process-at-tj'
READER_CAPABILITY = 9


def _passports(doc, anchor, source_id, os_attachment, stamp, window):
    def selected(label, kind, source):
        return [entry for entry in doc.get('source_bindings',[]) if entry['attachment']==label
                and entry['passport']['type']==kind
                and any(member['id']==source for member in entry['passport']['content'])]

    tj = selected(anchor, 'tj', source_id)
    os = selected(os_attachment, 'os', 's1')
    if len(tj)!=1 or len(os)!=1:
        return dict(status='ambiguous' if len(tj)>1 or len(os)>1 else 'not_recorded')
    one,two = tj[0],os[0]
    left,right = one['passport'],two['passport']
    check = source_passports._check(left,right,'same_infobase',False)
    reasons = list(check['reasons'])
    conflict = check['status']=='conflict' or 'different_declared_bases' in reasons
    for field in ('infobase_identity','database_mode'):
        first,second = (passport['facts'][field]['value'] for passport in (left,right))
        if first is not None and second is not None and first!=second:
            conflict = True
            reasons.append('different_'+field)
    tj_scope,os_scope=left['applicability'],right['applicability']
    outside=bool(tj_scope['start'] and stamp<parse_time(tj_scope['start'])
                 or tj_scope['end'] and stamp>=parse_time(tj_scope['end'])
                 or os_scope['start'] and parse_time(window['start'])<parse_time(os_scope['start'])
                 or os_scope['end'] and parse_time(window['end'])>parse_time(os_scope['end']))
    if outside:
        reasons.append('outside_declared_applicability')
    status='conflict' if conflict else 'outside_applicability' if outside else 'unconfirmed'
    return dict(status=status,tj=one['id'],os=two['id'],reasons=reasons)


def _relation(reference, target, stamp, window):
    holder = tj_process.status(reference)
    relation=dict(status='journal_holder_unverified',journal_holder=holder,file_base='unknown',
                  record_time_within_process_bounds=None,exact_event_attribution=False,
                  record_in_requested_window=parse_time(window['start'])<=stamp<parse_time(window['end']),
                  clock_alignment='not_verified')
    if holder!='same_observed_file_holder':
        return relation
    before=reference['file_process']['before']
    relation['record_time_within_process_bounds']=(parse_time(before['process_started_at'])<=stamp<=parse_time(before['at']))
    if target is None or target['platform']!='windows':
        return dict(relation,status='os_process_unverified')
    identity=tj_process.process_key(target['pid'],target['lifetime'],target['domain_sha256'])
    if identity!=before['process_sha256']:
        return dict(relation,status='different_process')
    if tj_process._creation_time(target['lifetime'])!=before['process_started_at']:
        raise InputError('retained process creation times disagree')
    base=target.get('file_identity_sha256')
    if base is not None:
        relation['file_base']='same_observed_file' if base==before['base_file_sha256'] else 'different_observed_files'
    return dict(relation,status='same_observed_process')


def view(state, doc, attachment, anchor, args, aliases):
    from .operations import _guard_dependency_paths

    case=anchor['source_id']
    _guard_dependency_paths(state,'cases',case)
    pinned=dict(kind='case',target_id=case,report_sha256=anchor['source_report_sha256'])
    report=context_coverage._pinned_report(state,pinned)
    record=storage.read_evidence(state,case,anchor['record'],native_metadata=True)
    source_id=anchor['record'].split(':',1)[0]
    source=next((item for item in report['sources'] if item['id']==source_id),None)
    if source is None:
        raise InputError('select the retained TJ record source')
    os_data,target=context_os_window.process_view(state,doc,attachment,args,aliases,verify_identity=True)
    if not os_data['process_io'].get('sample_statuses',{}).get('observed'):
        target=None
    reference=source.get('reference_capture',{})
    stamp=parse_time(record['timestamp_utc'])
    relation=_relation(reference,target,stamp,os_data['window'])
    relation['passports']=_passports(doc,anchor['attachment'],source_id,attachment['id'],stamp,os_data['window'])
    if context_coverage._pinned_report(state,pinned)!=report:
        raise InputError('retained TJ source changed during verification')
    name=record['event']
    return dict(anchor=dict(attachment=anchor['attachment'],event=fields.enum(name,fields.TJ_NAMES,None) or aliases('event',name),
                            timestamp_utc=stamp.isoformat(),evidence=fields.proof(record),source_sha256=source['sha256']),
                os=os_data,relation=relation)
