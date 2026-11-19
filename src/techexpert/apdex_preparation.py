"""Prepare APDEX for a chosen operation using verified local materials."""
from collections import Counter
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree

from . import artifacts, context_policy, investigations, operation_state as fs, sample_description, source_code
from .apdex import instant, measurement_category
from .inputs import InputError
from .source_coverage import validate_request as window_request


OPERATION = 'apdex.prepare'
KIND = 'apdex_preparation'
PROFILE = 'apdex-preparation-v1'
READER_FORMAT = 1
ATTACHMENT_LIMIT = 4
DEPENDENCY_LIMIT = 1 + 2 * ATTACHMENT_LIMIT
DEPENDENCY_KINDS = ('apdex', 'onec_source', 'input_catalog', 'remote_capture')
NS = '{http://v8.1c.ru/8.3/MDClasses}'
BSP_MARKERS = {
    ('Catalog', 'КлючевыеОперации'.casefold()): 'key_operations',
    ('InformationRegister', 'ЗамерыВремени'.casefold()): 'time_measurements',
    ('CommonModule', 'ОценкаПроизводительности'.casefold()): 'measurement_module',
    ('DataProcessor', 'ОценкаПроизводительности'.casefold()): 'assessment_processor',
    ('Subsystem', 'ОценкаПроизводительности'.casefold()): 'assessment_subsystem',
}
CONFIG_STATES = ('not_selected', 'metadata_not_found', 'ambiguous_export', 'unrecognized_metadata',
                 'markers_not_found', 'partial_markers', 'markers_declared')
SAMPLE_STATES = ('not_selected', 'no_rows', 'observed', 'incomplete')
ACTIONS = ('select_configuration_export', 'confirm_runtime_subsystem_and_export', 'define_operation_boundary',
           'choose_priority', 'choose_target', 'choose_score', 'choose_comparison_windows',
           'review_window_selection', 'obtain_normalized_measurements', 'check_first_sample')


def route(cap):
    attachment = cap.string(62, pattern='A-[A-Za-z0-9-]{1,60}')
    fields = dict(investigation_id=cap.CASE, revision=cap.integer(1, 1000, 1), operation=cap.string(256),
        configuration=attachment, measurement_attachments=cap.array(attachment, ATTACHMENT_LIMIT),
        priority=cap.string(12, enum=['low', 'normal', 'high']),
        boundary=cap.obj(dict(start=cap.string(512), end=cap.string(512)), ('start', 'end')),
        target_seconds=dict(type='number', exclusiveMinimum=0, maximum=31536000),
        target_score=dict(type='number', minimum=0, maximum=1), target_reason=cap.string(512),
        baseline_window=cap.WINDOW, verification_window=cap.WINDOW,
        configuration_access=cap.string(12, enum=['available', 'unavailable', 'unknown'], default='unknown'))
    return cap.route(fields, ('investigation_id', 'revision', 'operation'),
        ['exact saved investigation revision and optional selected configuration and measurement attachments'],
        'save a preparation plan and measurement preview; read no live configuration and start no collection',
        ['artifact_id', 'result', 'sources'])


def normalize(args):
    args = dict(args)
    text = [args['operation'], *args.get('boundary', {}).values()]
    if 'target_reason' in args:
        if 'target_seconds' not in args:
            raise InputError('a target rationale requires a selected target time')
        text.append(args['target_reason'])
    if any(not value.strip() or any(ord(char) < 32 for char in value) for value in text):
        raise InputError('APDEX preparation labels must be single-line text')
    if 'target_seconds' in args and not 0 < args['target_seconds'] <= 31536000:
        raise InputError('select a positive APDEX target time up to one year')
    if len(set(args['measurement_attachments'])) != len(args['measurement_attachments']):
        raise InputError('select distinct APDEX measurement attachments')
    for name in ('baseline_window', 'verification_window'):
        if name in args:
            args[name] = window_request(window=args[name])['window']
    return args


def _attachment(doc, label):
    selected = next((entry for entry in doc['attachments'] if entry['id'] == label), None)
    if selected is None or selected['kind'] != 'artifact':
        raise InputError('select a matching artifact from the pinned investigation revision')
    return selected


def _artifact(state, identifier):
    folder = fs.safe(artifacts.artifact_folder(state, identifier))
    fs.inventory(folder)
    report, _ = artifacts.read_artifact_record(state, identifier)
    if report['kind'] not in DEPENDENCY_KINDS:
        raise InputError('unsupported APDEX preparation input')
    receipt = fs.digest(fs.read(folder / 'receipt.json', 8192))
    if artifacts.load_artifact(state, identifier) != report or fs.digest(fs.read(folder / 'receipt.json', 8192)) != receipt:
        raise InputError('APDEX preparation input changed during verification')
    return report, dict(kind='artifacts', id=identifier, report_digest=fs.digest(report), receipt_digest=receipt)


def _declared_markers(metadata):
    if '<!DOCTYPE' in metadata.upper() or '<!ENTITY' in metadata.upper():
        raise InputError('XML entities and DTD are outside the supported metadata profile')
    try:
        root = ElementTree.fromstring(metadata)
    except ElementTree.ParseError:
        return None
    config = root.find(NS + 'Configuration') if root.tag == NS + 'MetaDataObject' else None
    if config is None:
        return None
    children = config.find(NS + 'ChildObjects')
    return sorted({marker for child in (() if children is None else children) if child.tag.startswith(NS)
                   and (marker := BSP_MARKERS.get((child.tag[len(NS):], (child.text or '').strip().casefold())))})


def _configuration(state, doc, label):
    result = dict(status='not_selected', runtime_availability='unknown', declared_markers=[], metadata_member=None)
    if label is None:
        return result, []
    pinned = _attachment(doc, label)
    report, dependency = _artifact(state, pinned['target_id'])
    if report['kind'] != 'onec_source' or investigations._digest(report) != pinned['report_sha256']:
        raise InputError('APDEX configuration requires a verified 1C source snapshot')
    candidates = [item['source_record_id'] for item in report['result']['files']
                  if PurePosixPath(item['path']).name.casefold() == 'configuration.xml']
    if len(candidates) != 1:
        result['status'] = 'ambiguous_export' if candidates else 'metadata_not_found'
        return result, [dependency]
    member, = candidates
    _, raw, _, encoding = source_code.saved_member(state, report, member)
    markers = _declared_markers(raw.decode('utf-8-sig' if encoding == 'utf-8' else encoding))
    if markers is None:
        status = 'unrecognized_metadata'
    elif {'key_operations', 'time_measurements'} <= set(markers) and len(markers) >= 3:
        status = 'markers_declared'
    else:
        status = 'partial_markers' if markers else 'markers_not_found'
    result.update(status=status, declared_markers=markers or [], metadata_member=member)
    return result, [dependency]


def _measurements(state, doc, args):
    if not args['measurement_attachments']:
        return dict(status='not_selected', selected=0, failed=0, unknown_duration=0,
                    duration_seconds={}, score_at_target=None, apdex=None), []
    pinned = [_attachment(doc, label) for label in args['measurement_attachments']]
    references = [dict(kind='artifact', id=item['target_id']) for item in pinned]
    if len({item['id'] for item in references}) != len(references):
        raise InputError('select each retained measurement artifact once')
    target = args.get('target_seconds')
    counts = Counter(selected=0, failed=0, unknown_duration=0)
    apdex = Counter(satisfied=0, tolerating=0, frustrated=0, unknown=0) if target is not None else None

    def observe(row, _report):
        if row['status'] == 'excluded' and row['reason'] not in ('unsuccessful_completion', 'duration_outside_supported_range'):
            return
        success = row['outcome'] == 'success'
        duration = row['value_seconds']
        counts['selected'] += 1
        counts['failed'] += int(not success)
        counts['unknown_duration'] += int(success and duration is None)
        if apdex is not None:
            apdex[measurement_category(success, duration, target)] += 1

    sample = sample_description.describe(state, references, args['operation'], window=args.get('baseline_window'),
                                         limit=1, observe=observe)
    for item, summary in zip(pinned, sample['inputs'], strict=True):
        report, _ = artifacts.read_artifact_record(state, item['target_id'])
        if investigations._digest(report) != item['report_sha256'] or fs.digest(report) != summary['report_digest']:
            raise InputError('APDEX measurements differ from the pinned attachment')
    count = counts['selected']
    stats = sample['statistics']
    score = (apdex['satisfied'] + .5 * apdex['tolerating']) / count if apdex is not None and count and not apdex['unknown'] else None
    status = 'incomplete' if counts['unknown_duration'] else 'observed' if count else 'no_rows'
    return dict(status=status, **counts, duration_seconds=dict(median=stats['median'],
        p90=stats['percentiles']['values']['90'], known=stats['count']), score_at_target=score,
        apdex=dict(apdex) if apdex is not None else None, selection_sha256=sample['selection_sha256']), sample['dependencies']


def _window_relation(baseline, verification):
    if baseline is None or verification is None:
        return 'unselected'
    if instant(verification['start']) >= instant(baseline['end']):
        return 'after_baseline'
    if instant(verification['end']) <= instant(baseline['start']):
        return 'before_baseline'
    return 'overlap'


def _actions(args, configuration, measurements, relation):
    needed = dict(
        select_configuration_export=configuration['status'] in ('not_selected', 'metadata_not_found', 'ambiguous_export', 'unrecognized_metadata'),
        confirm_runtime_subsystem_and_export=True,
        define_operation_boundary='boundary' not in args,
        choose_priority='priority' not in args,
        choose_target='target_seconds' not in args,
        choose_score='target_score' not in args,
        choose_comparison_windows=relation == 'unselected',
        review_window_selection=relation in ('overlap', 'before_baseline'),
        obtain_normalized_measurements=measurements['status'] != 'observed',
        check_first_sample=True,
    )
    return [name for name, active in needed.items() if active]


def evaluate(state, output, args):
    state = Path(state)
    iid, revision = args['investigation_id'], args['revision']
    doc = context_policy.selected_investigation(state, iid, revision)
    configuration, config_dependencies = _configuration(state, doc, args.get('configuration'))
    measurements, sample_dependencies = _measurements(state, doc, args)
    baseline, verification = args.get('baseline_window'), args.get('verification_window')
    relation = _window_relation(baseline, verification)
    result = dict(profile=PROFILE, investigation=dict(id=iid, revision=revision, sha256=investigations._digest(doc)),
        configuration=configuration, measurements=measurements, priority=args.get('priority'),
        operation=args['operation'], boundary=args.get('boundary'), target_reason=args.get('target_reason'),
        goal=dict(target_seconds=args.get('target_seconds'), target_score=args.get('target_score'),
                  threshold_origin='caller_selected' if 'target_seconds' in args else 'not_selected'),
        windows=dict(baseline=baseline, verification=verification, relation=relation),
        configuration_responsibility={'available': 'reported_operator', 'unavailable': 'administrator',
                                      'unknown': 'confirm_administrator'}[args['configuration_access']],
        next_actions=_actions(args, configuration, measurements, relation), dependencies=config_dependencies + sample_dependencies,
        requires_ai_interpretation=True,
        limitations=['Metadata declarations apply to the captured export. Runtime configuration, rights and native export format remain unverified.',
                     'Observed duration statistics describe the selected normalized sample. A user target is a goal, and the tool does not establish normal performance.'])
    return artifacts.save_artifact(output, KIND, args, [], result)


def verify_inputs(state, report):
    result = report['result']
    selected = result['investigation']
    doc = context_policy.selected_investigation(state, selected['id'], selected['revision'])
    if (result.get('profile') != PROFILE or report['sources'] or investigations._digest(doc) != selected['sha256']
            or not isinstance(result.get('dependencies'), list) or len(result['dependencies']) > DEPENDENCY_LIMIT):
        raise InputError('invalid retained APDEX preparation basis')
    for dependency in result['dependencies']:
        _, checked = _artifact(Path(state), dependency['id'])
        if checked != dependency:
            raise InputError('APDEX preparation input changed')


def require_parent(report, doc):
    selected = report['result']['investigation']
    if selected['id'] != doc['investigation_id'] or selected['revision'] >= doc['revision']:
        raise InputError('APDEX preparation belongs to another investigation or a later revision')
