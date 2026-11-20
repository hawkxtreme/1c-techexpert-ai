"""Configuration and revision-bound saves for setup without a browser."""

from . import investigations, operation_state as fs, profiles
from .inputs import InputError
from .investigation_retention import require_available, writer
from .profile_resources import editor_context, prepare_editor_profile


_SELECTION = {'state_dir', 'investigation_id', 'investigation_revision', 'profile_revision', 'profile_sha256'}
_PLAN = {'schema_version', 'selection', 'scope', 'profile'}
_LINK_ERRORS = (OSError, ValueError, KeyError, TypeError, RecursionError)


def _selection(state, investigation_id):
    current = profiles.load_profile(state)
    if investigation_id is None:
        context, before = None, current
        scope = 'current_only'
    else:
        require_available(state, investigation_id)
        context = investigations.read_for_display(state, investigation_id)
        before = context['profile_snapshot']
        scope = 'investigation_and_current' if before == current else 'investigation_only'
    identity = dict(state_dir=str(state), investigation_id=investigation_id,
                    investigation_revision=context['revision'] if context else None,
                    profile_revision=before['revision'] if before else 0,
                    profile_sha256=fs.digest(before) if before else None)
    return identity, context, before, scope


def inspect(state, investigation_id=None):
    selection, _, before, scope = _selection(fs.safe(state), investigation_id)
    return dict(selection=selection, scope=scope,
                editor=editor_context(before) if before else None, connected=False)


def _require_selection(state, expected):
    actual, context, before, scope = _selection(state, expected['investigation_id'])
    if actual != expected:
        raise InputError('profile or investigation revision changed; reload the setup selection')
    return context, before, scope


def _validate_selection(state, selection):
    if type(selection) is not dict or set(selection) != _SELECTION:
        raise InputError('use the exact selection returned by profile-setup inspect')
    if selection['state_dir'] != str(state):
        raise InputError('the reviewed setup targets a different service state directory')
    identifier = selection['investigation_id']
    if identifier is not None and type(identifier) is not str:
        raise InputError('invalid setup investigation identifier')
    if type(selection['profile_revision']) is not int:
        raise InputError('invalid selected profile revision')
    if identifier is not None and type(selection['investigation_revision']) is not int:
        raise InputError('invalid selected investigation revision')


def preview(state, request):
    state = fs.safe(state)
    if type(request) is not dict or set(request) != {'selection', 'edit'}:
        raise InputError('provide the inspected selection and profile editor changes')
    selection = request['selection']
    _validate_selection(state, selection)
    _, before, scope = _require_selection(state, selection)
    prepared = prepare_editor_profile(before, request['edit'])
    profile = prepared['profile']
    plan = dict(schema_version=1, selection=selection, scope=scope, profile=profile)
    return dict(status='preview', plan=plan, plan_sha256=fs.digest(plan), saved=False,
                impact=prepared['impact'], invalidated_claims=prepared['invalidated_claims'],
                matches=prepared['matches'], source_suggestions=prepared['source_suggestions'],
                preflight=profiles.check_profile(profile))


def _result(saved, *, identifier=None, revision=None, current_updated=False, status='applied'):
    return dict(status=status, investigation_id=identifier, investigation_revision=revision,
                profile_revision=saved['revision'], profile_sha256=fs.digest(saved),
                current_profile_updated=current_updated, connected=False)


def _save_investigation(state, plan, selection):
    identifier = selection['investigation_id']
    with writer(state, identifier):
        context, before, scope = _require_selection(state, selection)
        if scope != plan['scope']:
            raise InputError('default environment changed; review the setup scope again')
        if context['revision'] >= 1000:
            raise InputError('investigation revision limit reached; retain history and start a linked investigation')
        saved = profiles.save_profile(state, plan['profile'], expected_revision=selection['profile_revision'],
                                      pinned_profile=before, make_current=False)
        number = saved['revision']
        hashes = context['profile_sha256'], investigations._digest(saved)
        try:
            revised = investigations._revise(state, identifier, {'profile_revision': number},
                expected_revision=context['revision'], expected_profile_hashes=hashes)
        except _LINK_ERRORS:
            try:
                observed = investigations.read_for_display(state, identifier)
            except _LINK_ERRORS:
                return _result(saved, identifier=identifier, status='saved_link_unverified')
            if observed['revision'] == context['revision']:
                return _result(saved, identifier=identifier, status='saved_not_linked')
            if observed['revision'] != context['revision'] + 1 or observed['profile_sha256'] != hashes[1]:
                return _result(saved, identifier=identifier, status='saved_link_unverified')
            revised = observed

        updated = False
        if scope == 'investigation_and_current':
            try:
                updated = profiles.promote_saved_profile(state, saved, previous=before)
            except (OSError, InputError):
                updated = None
        return _result(saved, identifier=identifier, revision=revised['revision'], current_updated=updated)


def apply(state, plan, *, expected_sha256):
    state = fs.safe(state)
    if type(plan) is not dict or set(plan) != _PLAN or type(plan['schema_version']) is not int or plan['schema_version'] != 1:
        raise InputError('invalid profile setup plan')
    if fs.digest(plan) != expected_sha256:
        raise InputError('profile setup plan changed; review the preview again')
    selection = plan['selection']
    _validate_selection(state, selection)
    if selection['investigation_id'] is not None:
        return _save_investigation(state, plan, selection)
    _, _, scope = _require_selection(state, selection)
    if scope != plan['scope']:
        raise InputError('profile setup scope differs from the review')
    saved = profiles.save_profile(state, plan['profile'], expected_revision=selection['profile_revision'])
    return _result(saved, current_updated=True)
