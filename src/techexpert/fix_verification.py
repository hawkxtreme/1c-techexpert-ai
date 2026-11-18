"""Measure a reported change using explicitly selected, retained evidence."""
from collections import Counter
from pathlib import Path

from . import artifacts, investigations, operation_state as fs, sample_description as samples, storage
from .apdex import instant, measurement_category
from .inputs import InputError, MAX_TOTAL_BYTES
from .sample_statistics import duration
from .source_coverage import validate_request as window_request


OPERATION = 'fix.verify'
KIND = 'fix_verification'
PROFILE = 'fix-verification-v1'
READER_FORMAT = 1
MAX_DEPENDENCIES = 128
EXCLUDED = {'other_operation','outside_window','duplicate_input_view','conflicting_input_interpretation'}


def route(cap):
    attachment = cap.string(62,pattern='A-[A-Za-z0-9-]{1,60}')
    evidence = cap.string(62,pattern='E-[A-Za-z0-9-]{1,60}')
    seconds = dict(type='number',exclusiveMinimum=0,maximum=31536000)
    phase = dict(attachments=cap.array(attachment,16),window=cap.WINDOW)
    fields = dict(investigation_id=cap.CASE,revision=cap.integer(1,1000,1),measure=cap.string(512),
                  recommendation=cap.string(62,pattern='R-[A-Za-z0-9-]{1,60}'),operation=cap.string(256),
                  control=cap.string(1024),applied=cap.string(16,enum=['proposed','reported','evidenced'],default='proposed'),
                  application_evidence=dict(cap.array(evidence,8),default=[]),changed_at=cap.string(80),
                  minimum_observations=cap.integer(1,100000,1),comparison=attachment,
                  conditions=cap.obj({name:cap.string(512) for name in ('versions','workload','launch_conditions','differences')}),
                  goal=cap.obj(dict(kind=cap.string(16,enum=['duration','apdex']),value=dict(type='number',minimum=0,maximum=31536000),
                                    target_seconds=seconds),['kind','value']),
                  before=cap.obj(phase,['attachments']),after=cap.obj(phase,['attachments']),
                  observation=cap.obj(dict(phase,threshold_seconds=seconds),['attachments','window','threshold_seconds']))
    spec = cap.route(fields,['investigation_id','revision','measure','operation','control','goal','minimum_observations'],
        ['exact saved investigation revision and selected retained measurement attachments'],
        'save a private verification of supplied evidence; no collection, change or causal judgment',
        ['artifact_id','result','sources'])
    spec['data_schema']['properties'].update(artifact_id=cap.CASE,result=dict(type='object'),sources=dict(type='array',maxItems=0))
    spec['output_schema'] = cap.response_schema(spec['data_schema'])
    return spec


def normalize(args):
    args = dict(args)
    for name in ('measure','operation','control'):
        if not args[name].strip() or any(ord(char)<32 for char in args[name]):
            raise InputError('verification labels must be bounded single-line text')
    goal = args['goal']
    if goal['kind']=='apdex':
        if not 0<=goal['value']<=1 or 'target_seconds' not in goal or not 0<goal['target_seconds']<=31536000:
            raise InputError('APDEX verification needs a score from zero to one and one positive common target time')
    elif not 0<goal['value']<=31536000 or 'target_seconds' in goal:
        raise InputError('duration verification needs one positive duration ceiling')
    if bool(args['application_evidence']) != (args['applied']=='evidenced'):
        raise InputError('evidenced application requires selected investigation evidence')
    if len(set(args['application_evidence']))!=len(args['application_evidence']):
        raise InputError('duplicate application evidence')
    if 'comparison' in args and (goal['kind']!='duration' or 'before' in args or 'after' in args):
        raise InputError('select a controlled duration comparison or explicit before and after samples')
    for name in ('before','after','observation'):
        if name not in args:
            continue
        phase = args[name] = dict(args[name])
        labels = phase['attachments']
        if len(set(labels))!=len(labels):
            raise InputError('duplicate verification attachment')
        if 'window' in phase:
            phase['window'] = window_request(window=phase['window'])['window']
        if name=='observation' and not 0<phase['threshold_seconds']<=31536000:
            raise InputError('recurrence threshold requires a positive duration')
    if 'changed_at' in args:
        try:
            args['changed_at'] = instant(args['changed_at']).isoformat()
        except (ValueError,OverflowError) as exc:
            raise InputError('change time requires an explicit time zone') from exc
        if 'observation' in args and args['observation']['window']['start']<args['changed_at']:
            raise InputError('the recurrence window must begin at or after the reported change')
    return args


def _document(state, iid, revision):
    for number in range(1,revision+1):
        folder = investigations.revision_folder(state,iid,number)
        for name in ('report.json','report.md','receipt.json'):
            fs.safe(folder/name)
    document = investigations._committed_revision(state,iid,revision)
    receipt = fs.read(investigations.revision_folder(state,iid,revision)/'receipt.json',8192)
    return document,dict(id=iid,revision=revision,report_digest=fs.digest(document),receipt_digest=fs.digest(receipt))


def _attachment(document, label, kinds):
    result = next((item for item in document['attachments'] if item['id']==label),None)
    if result is None or result['kind'] not in kinds:
        raise InputError('verification requires a matching attachment from the selected investigation revision')
    return result


def _reference(state, kind, identifier, report):
    base = fs.safe(state/kind/identifier)
    return dict(kind=kind,id=identifier,report_digest=fs.digest(report),
                receipt_digest=fs.digest(fs.read(base/'receipt.json',8192)))


def _extend(dependencies, found):
    for ref in found:
        current = next((item for item in dependencies if (item['kind'],item['id'])==(ref['kind'],ref['id'])),None)
        if current is None:
            dependencies.append(ref)
        elif current!=ref:
            raise InputError('verification input changed between measurements')
    if len(dependencies)>MAX_DEPENDENCIES:
        raise InputError('verification retained dependency limit exceeded')


def _bounds(row, report):
    value = row['value_seconds']
    if value is None or not duration(value):
        return None
    if row['kind']=='artifact':
        return value,value
    life = report.get('job_correlation',{}).get('job_lifecycle',{})
    candidate = life.get('execution_bounds_seconds')
    if (life.get('status')=='established' and life.get('execution_seconds')==value and type(candidate) is list
            and len(candidate)==2 and all(duration(number) for number in candidate) and candidate[0]<=value<=candidate[1]):
        return tuple(candidate)
    return None


def _proof(row):
    result = {key:row[key] for key in ('kind','id','normalized_start_utc','row_index') if key in row}
    result['sources'] = row['evidence'][:4]
    return result


class _Measurements:
    def __init__(self, goal, name, changed_at):
        self.goal = goal
        self.name = name
        self.changed_at = instant(changed_at) if changed_at else None
        self.counts = Counter(selected=0,failed=0,unknown_duration=0,met=0,breaches=0,uncertain_bounds=0,
                              chronology_conflicts=0,unplaced=0,unknown_outcome=0,duplicate_observations=0)
        self.apdex = Counter(satisfied=0,tolerating=0,frustrated=0,unknown=0)
        self.evidence = []

    def observe(self, row, report):
        reason = row.get('reason')
        if reason in EXCLUDED:
            return
        if reason=='unknown_operation_start':
            self.counts['unplaced'] += 1
            return
        self.counts['selected'] += 1
        value = row['value_seconds']
        failed = row['outcome']=='failed'
        completed = row['outcome']=='success'
        self.counts['failed'] += int(failed)
        self.counts['unknown_outcome'] += int(not (failed or completed))
        self.counts['unknown_duration'] += int(value is None)
        admitted = True
        if self.changed_at is not None and self.name in ('before','after'):
            try:
                stamp = instant(row.get('normalized_start_utc') or row.get('started_at'))
            except (ValueError,OverflowError):
                self.counts['unplaced'] += 1
                admitted = False
            else:
                admitted = (stamp<self.changed_at)==(self.name=='before')
                self.counts['chronology_conflicts'] += int(not admitted)
        if self.goal['kind']=='apdex':
            self.apdex[measurement_category(not failed,value,self.goal['target_seconds'])] += 1
            return
        bounds = _bounds(row,report)
        if not admitted:
            return
        if (failed and self.name!='observation') or bounds and bounds[0]>self.goal['value']:
            self.counts['breaches'] += 1
            if len(self.evidence)<5:
                self.evidence.append(_proof(row))
        elif bounds and bounds[1]<=self.goal['value'] and (completed or self.name=='observation'):
            self.counts['met'] += 1
        elif value is not None and (bounds is None or bounds[1]>self.goal['value']):
            self.counts['uncertain_bounds'] += 1

    def summary(self, *, statistics, sources, selection_sha256=None, window=None, period=None, exclusions=None):
        counts = dict(self.counts)
        apdex = None
        if self.goal['kind']=='apdex':
            if counts['selected'] and not self.apdex['unknown']:
                value = (self.apdex['satisfied']+.5*self.apdex['tolerating'])/counts['selected']
            else:
                value = None
            apdex = dict(self.apdex)
        else:
            value = statistics.get('median')
        return dict(value=value,counts=counts,statistics=statistics,sources=sources,selection_sha256=selection_sha256,
                    window=window,period=period,exclusions=exclusions or {},evidence=self.evidence,apdex=apdex)


def _sample(state, document, name, phase, args, dependencies, remaining):
    if phase is None or not phase['attachments']:
        return None,remaining
    goal = dict(kind='duration',value=phase['threshold_seconds']) if name=='observation' else args['goal']
    allowed = ('artifact',) if goal['kind']=='apdex' else ('case','artifact')
    selected = [_attachment(document,label,allowed) for label in phase['attachments']]
    if len({item['kind'] for item in selected})!=1:
        raise InputError('choose one compatible measurement profile per verification sample')
    inputs = [dict(kind=item['kind'],id=item['target_id']) for item in selected]
    summary = _Measurements(goal,name,args.get('changed_at'))
    observed = samples.describe(state,inputs,args['operation'],window=phase.get('window'),limit=1,
                                observe=summary.observe,maximum_bytes=remaining)
    for chosen,seen in zip(selected,observed['inputs'],strict=True):
        base = fs.safe(state/samples.KINDS[seen['kind']]/seen['id']/'report.json')
        report = fs.read(base,storage.MAX_REPORT_BYTES)
        if fs.digest(report)!=seen['report_digest'] or investigations._digest(report)!=chosen['report_sha256']:
            raise InputError('verification input differs from the pinned investigation attachment')
    _extend(dependencies,observed['dependencies'])
    remaining -= sum(source['bytes'] for item in observed['inputs'] for source in item['sources'])
    result = summary.summary(statistics=observed['statistics'],sources=phase['attachments'],selection_sha256=observed['selection_sha256'],
                             window=phase.get('window'),period=observed['period'],exclusions=observed['exclusions'])
    result['profile'] = 'normalized_apdex_rows' if selected[0]['kind']=='artifact' else 'saved_case_execution'
    return result,remaining


def _check_group_separation(document, args):
    before,after = (args.get(name,{}) for name in ('before','after'))
    known = {item['id']:item['target_id'] for item in document['attachments']}
    left,right = ({known.get(label, label) for label in group.get('attachments',[])} for group in (before,after))
    if not left & right:
        return
    windows = [group.get('window') for group in (before,after)]
    if any(window is None for window in windows) or max(w['start'] for w in windows)<min(w['end'] for w in windows):
        raise InputError('one retained input can serve both groups only in disjoint recorded-time windows')


def _comparison_inputs(state, attachment, dependencies, remaining):
    identifier = attachment['target_id']
    fs.inventory(fs.safe(state/'comparisons'/identifier))
    saved,_ = storage.read_comparison_record(state,identifier)
    if investigations._digest(saved)!=attachment['report_sha256']:
        raise InputError('verification comparison differs from the pinned calculation')
    _extend(dependencies,[_reference(state,'comparisons',identifier,saved)])
    references = saved['input_reports']
    ids = saved['before_case_ids']+saved['after_case_ids']
    if not 2<=len(ids)<=40 or ids!=[item['case_id'] for item in references]:
        raise InputError('invalid retained comparison input binding')
    plans,resources = {},[]
    for ref in references:
        ident = ref['case_id']
        resource = samples._load(state,dict(kind='case',id=ident),remaining,plans)
        receipt = fs.read(state/'cases'/ident/'receipt.json',8192)
        if receipt['report_sha256']!=ref['sha256'] or fs.digest(receipt)!=resource['summary']['receipt_digest']:
            raise InputError('comparison input differs from its sealed digest')
        remaining -= resource['size']
        _extend(dependencies,resource['dependencies'])
        resources.append(resource)
    return saved,resources,remaining


def _comparison(state, document, args, dependencies, remaining):
    attachment = _attachment(document,args['comparison'],('comparison',))
    saved,resources,remaining = _comparison_inputs(state,attachment,dependencies,remaining)
    if saved.get('comparison_profile')!='sc01-order-load-v1':
        raise InputError('unsupported verification comparison profile')
    summaries = {name:_Measurements(args['goal'],name,args.get('changed_at')) for name in ('before','after')}
    seen = {phase:set() for phase in summaries}
    for position,resource in enumerate(resources):
        phase = 'before' if position<len(saved['before_case_ids']) else 'after'
        keys = {('case',resource['ref']['id'])}
        life = resource['report'].get('job_correlation',{}).get('job_lifecycle',{})
        if life.get('status')=='established' and type(life.get('job_uuid')) is str:
            keys.add(('job',life['job_uuid'].lower()))
        if seen[phase] & keys:
            summaries[phase].counts['duplicate_observations'] += 1
        seen[phase].update(keys)
        summaries[phase].observe(samples._case_row(state,resource),resource['report'])
    result = {}
    for phase in summaries:
        performance = saved['performance']
        statistics = performance.get(phase+'_distribution')
        if statistics is None:
            statistics = samples.describe_values([row[phase+'_seconds'] for row in saved['pairs']
                                                  if row[phase+'_case_id'] is not None])
        result[phase] = summaries[phase].summary(statistics=statistics,sources=[args['comparison']])
        result[phase]['profile'] = 'controlled_case_comparison'
    return saved,result,remaining


def _application(state, document, args, dependencies, remaining):
    items = []
    kinds = dict(case='cases',artifact='artifacts',comparison='comparisons')
    for identifier in args['application_evidence']:
        cited = next((item for item in document['evidence'] if item['id']==identifier),None)
        if cited is None:
            raise InputError('application evidence is not in the selected investigation revision')
        attachment = _attachment(document,cited['attachment'],kinds)
        kind, target = kinds[attachment['kind']],attachment['target_id']
        if kind=='comparisons':
            _,_,remaining = _comparison_inputs(state,attachment,dependencies,remaining)
        elif kind=='cases':
            resource = samples._load(state,dict(kind='case',id=target),remaining,{})
            if investigations._digest(resource['report'])!=attachment['report_sha256']:
                raise InputError('application evidence case differs from the pinned attachment')
            _extend(dependencies,resource['dependencies'])
            remaining -= resource['size']
        else:
            original = _artifact_input(state,target)
            size = sum(item['bytes'] for item in original['sources'])
            if size>remaining:
                raise InputError('verification retained sources exceed64MiB work limit')
            report = _load_input(state,kind,target)
            if fs.digest(report)!=fs.digest(original) or investigations._digest(report)!=attachment['report_sha256']:
                raise InputError('application evidence artifact differs from the pinned attachment')
            _extend(dependencies,[_reference(state,kind,target,report)])
            remaining -= size
        items.append(identifier)
    return dict(status=args['applied'],basis='harness_linked_evidence' if items else 'caller_declaration',
                evidence=items,changed_at=args.get('changed_at'))


def _effect(before, after, saved, goal, minimum):
    direction = 'unknown'
    timing_checked = bool(before and after) and all(not phase['counts']['chronology_conflicts']
        and not phase['counts']['unplaced'] for phase in (before,after))
    if timing_checked and before['profile']==after['profile'] and all(phase['value'] is not None for phase in (before,after)):
        left,right = before['value'],after['value']
        sign = (left>right)-(left<right)
        if goal['kind']=='apdex':
            sign = -sign
        direction = {1:'better',0:'no_confirmed_change',-1:'worse'}[sign]
    if saved is None:
        return dict(status='unknown',basis='nominal_supplied_samples',observed_direction=direction),dict(status='unknown',basis='runtime_conditions_not_verified')
    comparable = saved['comparability']['status']=='comparable' and timing_checked
    pairs = saved['pairs']
    required = max(minimum,saved['required_pairs'])
    qualified = comparable and len(pairs)>=required and all(row['before_bounds_seconds'] and row['after_bounds_seconds'] for row in pairs)
    status = 'unknown'
    if qualified:
        if all(row['after_bounds_seconds'][1]<row['before_bounds_seconds'][0] for row in pairs):
            status = 'better'
        elif all(row['after_bounds_seconds'][0]>row['before_bounds_seconds'][1] for row in pairs):
            status = 'worse'
        else:
            status = 'no_confirmed_change'
    return (dict(status=status,basis='controlled_paired_duration_bounds',observed_direction=direction,required_pairs=required),
            dict(status='comparable' if comparable else 'not_comparable',basis='sealed_controlled_comparison'))


def _goal(after, goal, minimum):
    status = 'unknown'
    if after is not None:
        counts = after['counts']
        if goal['kind']=='duration' and counts['breaches']:
            status = 'not_reached'
        elif not counts['chronology_conflicts'] and not counts['unplaced']:
            enough = counts['selected']-counts['duplicate_observations']>=minimum
            if goal['kind']=='duration':
                if enough and counts['met']==counts['selected']:
                    status = 'reached'
            elif enough and after['value'] is not None:
                status = 'reached' if after['value']>=goal['value'] else 'not_reached'
    return dict(status=status,criterion=goal,minimum_observations=minimum,scope='selected_control_observations',
                duration_requires_completion=goal['kind']=='duration')


def evaluate(state, output, args):
    state = Path(state)
    document,context = _document(state,args['investigation_id'],args['revision'])
    _check_group_separation(document,args)
    recommendation = args.get('recommendation')
    if recommendation and not any(item['id']==recommendation for item in (document['assessment'] or {}).get('recommendations',[])):
        raise InputError('the selected recommendation is absent from the investigation revision')
    dependencies = []
    remaining = MAX_TOTAL_BYTES
    saved = None
    if 'comparison' in args:
        saved,phases,remaining = _comparison(state,document,args,dependencies,remaining)
        before,after = phases['before'],phases['after']
    else:
        before,remaining = _sample(state,document,'before',args.get('before'),args,dependencies,remaining)
        after,remaining = _sample(state,document,'after',args.get('after'),args,dependencies,remaining)
    selected = args.get('observation')
    observed,remaining = _sample(state,document,'observation',selected,args,dependencies,remaining)
    counts = observed['counts'] if observed else {}
    recurrence = dict(status='observed' if counts.get('breaches',0) else 'unknown',basis='recorded_threshold_breach',
        window=selected['window'] if selected else None,threshold_seconds=selected['threshold_seconds'] if selected else None,
        breaches=counts.get('breaches',0),unknown_duration=counts.get('unknown_duration',0),complete_coverage=None,
        evidence=observed['evidence'] if observed else [],sample=observed)
    effect,comparability = _effect(before,after,saved,args['goal'],args['minimum_observations'])
    application = _application(state,document,args,dependencies,remaining)
    result = dict(profile=PROFILE,investigation=context,measure=args['measure'],recommendation=recommendation,
        operation=args['operation'],control=args['control'],reported_conditions=args.get('conditions',{}),application=application,
        before=before,after=after,goal=_goal(after,args['goal'],args['minimum_observations']),effect=effect,
        comparability=comparability,recurrence=recurrence,dependencies=dependencies,
        result_correctness=saved['result_correctness']['status'] if saved else 'not_verified',
        verification_scope=saved.get('verification_scope','retained_comparison') if saved else 'selected_reported_measurements',
        independent_runs=None,
        status='evaluated' if after else 'awaiting_measurements',untrusted_supplied_text=True,requires_ai_interpretation=True)
    return artifacts.save_artifact(output,KIND,args,[],result)


def _artifact_input(state, target):
    fs.inventory(fs.safe(state/'artifacts'/target))
    report,_ = artifacts.read_artifact_record(state,target)
    if report['kind']==KIND:
        raise InputError('a verification cannot use another verification as measurement evidence')
    return report


def _load_input(state, kind, target):
    from .operations import _verify_target

    if kind=='artifacts':
        _artifact_input(state,target)
    return _verify_target(state,kind,target)


def verify_inputs(state, artifact):
    state = Path(state)
    result = artifact['result']
    context = result['investigation']
    if result.get('profile')!=PROFILE or artifact['sources'] or len(result['dependencies'])>MAX_DEPENDENCIES:
        raise InputError('unsupported saved fix verification')
    _,replayed = _document(state,context['id'],context['revision'])
    if replayed!=context:
        raise InputError('saved fix verification investigation changed')
    for ref in result['dependencies']:
        report = _load_input(state,ref['kind'],ref['id'])
        if _reference(state,ref['kind'],ref['id'],report)!=ref:
            raise InputError('saved fix verification input changed')


def require_parent(artifact, document):
    binding = artifact['result']['investigation']
    if binding['id']!=document['investigation_id'] or binding['revision']>=document['revision']:
        raise InputError('verification belongs to another investigation or a later revision')
    return binding['revision']


def evidence(artifact, document):
    revision = require_parent(artifact,document)
    result = artifact['result']
    return dict(kind='calculation',method=PROFILE,sha256=investigations._digest(artifact),revision=revision,
                **{key:result[key]['status'] for key in ('application','comparability','effect','goal','recurrence')})


def case_dependencies(state, attachment):
    base = fs.safe(artifacts.artifact_folder(state,attachment['target_id']))
    for name in ('report.json','request.json','receipt.json'):
        fs.safe(base/name)
    report,_ = artifacts.read_artifact_record(state,attachment['target_id'])
    if (report['kind']!=KIND or report['result'].get('profile')!=PROFILE
            or investigations._digest(report)!=attachment['report_sha256']):
        raise InputError('saved verification attachment integrity mismatch')
    return {item['id']:item['report_digest'] for item in report['result']['dependencies'] if item['kind']=='cases'}


def summarize_proof(proof):
    labels = (
        ('применение','application',dict(proposed='предложено',reported='сообщено',evidenced='связано со свидетельством')),
        ('сопоставимость','comparability',dict(comparable='подтверждена условиями опыта',not_comparable='сравнение непригодно',unknown='не установлена')),
        ('эффект','effect',dict(better='лучше',worse='хуже',no_confirmed_change='изменение не подтверждено',unknown='неизвестен')),
        ('цель','goal',dict(reached='достигнута',not_reached='не достигнута',unknown='не определена по измерениям')),
        ('повтор','recurrence',dict(observed='порог превышен в наблюдении',unknown='покрытие не установлено')),
    )
    return ', '.join(f'{label} — {values[proof[key]]}' for label,key,values in labels)
