"""Save the wording of a task and explicit clarifications in private revisions."""
import re

from . import operation_state as fs
from .inputs import InputError


FORMAT = 1
MAX_REQUEST = 64 * 1024
MAX_NOTES = 64
ACTION = 'context-task'
OPERATION = 'investigation.task'
SHA256 = re.compile('[a-f0-9]{64}')
TEMPLATE_FIELDS = ('template_id', 'template_revision', 'variant')
EDITABLE = (*TEMPLATE_FIELDS, 'time_mode', 'scale', 'episode')


class TaskError(InputError):
    def __init__(self, reason, message):
        super().__init__(message)
        self.reason = reason


def _episode_fields(cap):
    return dict(description=cap.string(2048, x_multiline=True), start=cap.string(128), end=cap.string(128),
                utc_offset=cap.string(32), operation=cap.string(512), user_reported_baseline=cap.string(512),
                client_context=cap.string(1024), database_mode=cap.string(8, enum=['file', 'server', 'unknown']),
                recurrence_seconds=dict(type='number', minimum=.001, maximum=31*86400),
                requested_window_seconds=dict(type='number', minimum=.001, maximum=31*86400))


def argument_schema():
    from . import capabilities as cap

    fields = {key: dict(anyOf=[schema, dict(type='null')]) for key, schema in _episode_fields(cap).items()}
    return cap.obj(dict(
        operation_key=cap.string(128, pattern='[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',
                                 description='Retain and repeat this key after an uncertain reply.'),
        text=cap.string(8192, x_multiline=True, description='The original wording from the current chat.'),
        context=cap.obj(dict(investigation_id=cap.CASE, expected_revision=cap.integer(1,1000,1)),
                        ('investigation_id','expected_revision')),
        template_id=cap.string(64), template_revision=dict(type='integer', minimum=1, maximum=100),
        variant=cap.string(64),
        time_mode=cap.string(12, enum=['unknown', 'past', 'current', 'reproduce']),
        scale=cap.string(12, enum=['one', 'several', 'all', 'background', 'unknown']),
        episode=dict(cap.obj(fields), description='Include only supplied details. Null clears a previously set field.')),
        ('operation_key',))


def normalize(value):
    from . import capabilities as cap

    if type(value) is not dict:
        raise InputError('Task note must be an object.')
    raw = dict(value)
    episode = raw.pop('episode', {})
    request = cap.validate(raw, argument_schema())
    fields = _episode_fields(cap)
    if type(episode) is not dict or set(episode) - fields.keys():
        raise InputError('Unsupported task episode fields.')
    if 'episode' in value:
        request['episode'] = {name: (None if item is None else cap.validate(item, fields[name]))
                              for name, item in episode.items()}
    text = request.get('text')
    if text is not None and not text.strip():
        raise InputError('Task note text is empty.')
    if text is None and ('context' in request or 'template_id' not in request):
        raise InputError('Supply the wording from the chat or select a template for a new task.')
    if len(fs.encode(request)) > MAX_REQUEST:
        raise InputError('Task note exceeds its byte limit.')
    return request


def saved(doc):
    if 'task_notes' not in doc:
        return []
    value = doc['task_notes']
    from .investigations import _text

    if (type(value) is not dict or set(value) != {'schema_version', 'entries'}
        or type(value['schema_version']) is not int or value['schema_version'] != FORMAT
        or type(value['entries']) is not list or not 1 <= len(value['entries']) <= MAX_NOTES):
        raise InputError('Invalid saved task note history.')
    previous = 0
    keys = set()
    for entry in value['entries']:
        if (type(entry) is not dict or set(entry) != {'key_sha256', 'request_sha256', 'revision', 'text'}
            or type(entry['revision']) is not int or not previous < entry['revision'] <= doc['revision']
            or not all(type(entry[name]) is str and SHA256.fullmatch(entry[name])
                       for name in ('key_sha256', 'request_sha256')) or entry['key_sha256'] in keys):
            raise InputError('Invalid saved task note identity.')
        if entry['text'] is not None:
            _text(entry['text'])
            if entry['revision']==1 and entry['text']!=doc['task']:
                raise InputError('Invalid saved task note text.')
        elif entry['revision'] != 1:
            raise InputError('A clarification requires saved text.')
        keys.add(entry['key_sha256'])
        previous = entry['revision']
    return value['entries']


def append(doc, entry):
    earlier = saved(doc)
    if len(earlier) >= MAX_NOTES:
        raise TaskError('task_notes_limit', 'This investigation reached its saved task note limit.')
    doc['task_notes'] = dict(schema_version=FORMAT, entries=[*earlier, entry])


def _update(fields, previous=None):
    result = {key: fields[key] for key in EDITABLE if key in fields}
    if 'episode' in result:
        episode = dict(previous or {})
        for name, value in result['episode'].items():
            if value is None and name != 'database_mode':
                episode.pop(name, None)
            else:
                episode[name] = value if value is not None else 'unknown'
        result['episode'] = episode
    return result


def _view(doc, recorded, *, replayed):
    data = dict(investigation_id=doc['investigation_id'], revision=doc['revision'], recorded_revision=recorded,
                replayed=replayed, template_id=doc['template']['id'], time_mode=doc['time_mode'], scale=doc['scale'],
                profile_available=doc['profile_sha256'] is not None, task_notes=len(saved(doc)),
                episode_fields=sorted(key for key, value in doc['episode'].items() if value is not None))
    return dict(status='succeeded', operation=OPERATION, data=data)


def record(state, value):
    from . import context_policy, investigations
    from .investigation_retention import writer

    request = normalize(value)
    context = request.get('context')
    key = fs.digest(dict(purpose=OPERATION, operation_key=request['operation_key']))
    identifier = context['investigation_id'] if context else key[:32]
    expected = context['expected_revision'] if context else 0
    note = dict(key_sha256=key, request_sha256=fs.digest(request), revision=expected+1, text=request.get('text'))
    state = fs.safe(state)
    directory = fs.safe(investigations.revision_folder(state, identifier, 1).parent.parent)
    with writer(state, identifier):
        if not context and not directory.exists():
            fields = _update(request)
            if note['text'] is not None:
                fields['task'] = note['text']
            doc = investigations._create(state, fields, identifier=identifier, task_note=note)
            return _view(doc, 1, replayed=False)
        try:
            head = investigations._read_head(state, identifier)
            current = context_policy.selected_investigation(state, identifier, head['revision'])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise TaskError('task_note_unavailable',
                            'Verify the retained investigation before retrying this request.') from exc
        for earlier in saved(current):
            if earlier['key_sha256'] == key:
                if earlier['request_sha256'] != note['request_sha256']:
                    raise TaskError('task_note_key_conflict', 'Task note key conflicts with the saved request.')
                return _view(current, earlier['revision'], replayed=True)
        if not context or current['revision'] != expected:
            raise TaskError('task_note_revision_conflict', 'Investigation revision changed. Reload before adding a new note.')
        updated = investigations._revise(state, identifier, _update(request, current['episode']),
                                         expected_revision=expected, task_note=note)
        return _view(updated, updated['revision'], replayed=False)
