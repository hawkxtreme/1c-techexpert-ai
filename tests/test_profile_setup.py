import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.techexpert import investigations, operation_state as fs, profiles


ROOT = Path(__file__).resolve().parents[1]


class ProfileSetupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / 'state'

    def cli(self, *args, expected_exit=0):
        invoked = subprocess.run(
            [sys.executable, '-B', '-X', 'utf8', str(ROOT / 'techexpert.py'),
             '--state-dir', str(self.state), 'profile-setup', *map(str, args)],
            cwd=ROOT, capture_output=True, timeout=20, encoding='utf-8')
        self.assertEqual(invoked.returncode, expected_exit, invoked.stdout + invoked.stderr)
        return json.loads(invoked.stdout)

    def file_profile(self, name='Orders'):
        return dict(schema_version=1, name=name, bases=[
            dict(id='orders', name='Orders', mode='file', connection=str(self.root / 'ib'))],
            sources=[dict(id='tj', type='tj', path=str(self.root / 'logs'), host='', base_ids=['orders'])])

    def case(self):
        return investigations.create(self.state, dict(task='Slow order loading', scale='background'))

    def preview(self, selection, edit):
        request = self.root / 'requested-settings.json'
        fs.write(request, dict(selection=selection, edit=edit))
        return self.cli('preview', request)

    def apply(self, review, *, expected_exit=0):
        file = self.root / 'reviewed-settings.json'
        fs.write(file, review['plan'])
        return self.cli('apply', file, '--expected-sha256', review['plan_sha256'], expected_exit=expected_exit)

    def test_cli_edits_the_pinned_file_base_and_keeps_another_active_environment(self):
        first = profiles.save_profile(self.state, self.file_profile(), expected_revision=0)
        before = self.case()
        iid = before['investigation_id']
        other = profiles.save_profile(self.state, self.file_profile('Another environment'), expected_revision=1)
        current = self.state / 'profiles/current.json'
        current_bytes = current.read_bytes()

        inspected = self.cli('inspect', '--investigation', iid)
        selection = inspected['selection']
        self.assertEqual((selection['investigation_revision'], selection['profile_revision']), (1, 1))
        view = inspected['editor']['view']
        self.assertEqual(view['name'], first['name'])
        view['sources'][0]['path'] = str(self.root / 'separate log directory')
        review = self.preview(selection, {'view': view})
        self.assertEqual(review['plan']['scope'], 'investigation_only')
        self.assertEqual(review['impact']['affected_source_ids'], ['tj'])
        self.assertFalse(review['preflight']['connected'])
        self.assertFalse((self.state / 'profiles/3.json').exists())

        result = self.apply(review)
        self.assertEqual(result['status'], 'applied')
        self.assertEqual((result['profile_revision'], result['investigation_revision']), (3, 2))
        self.assertFalse(result['current_profile_updated'])
        after = investigations.load(self.state, iid)
        self.assertEqual(after['profile_snapshot']['sources'][0]['path'], view['sources'][0]['path'])
        self.assertEqual(after['task'], before['task'])
        self.assertEqual(investigations.load(self.state, iid, revision=1), before)
        self.assertEqual(current.read_bytes(), current_bytes)
        self.assertEqual(profiles.load_profile(self.state), other)
        self.assertFalse((self.state / 'cases').exists())
        self.assertFalse(Path(view['sources'][0]['path']).exists())
        self.assertEqual(self.cli('inspect', '--investigation', iid)['selection']['profile_revision'], 3)

    def test_cli_can_bind_the_first_selected_starter_base_and_reuse_the_profile(self):
        before = self.case()
        iid = before['investigation_id']
        selection = self.cli('inspect', '--investigation', iid)['selection']
        self.assertEqual(selection['profile_revision'], 0)
        self.assertFalse((self.state / 'profiles').exists())
        starter = self.root / 'chosen.v8i'
        starter.write_text('[Orders]\nConnect=File="' + str(self.root / 'ib') + '";\n', encoding='utf-8-sig')
        from src.techexpert.discovery import inspect_starter

        found = inspect_starter(starter)
        view = dict(schema_version=1, name='First environment', bases=found['bases'], sources=[])
        review = self.preview(selection, dict(view=view, base_registrations=found['registrations']))
        self.assertEqual(review['plan']['scope'], 'investigation_and_current')
        self.assertFalse((self.state / 'profiles').exists())
        result = self.apply(review)
        self.assertEqual((result['profile_revision'], result['investigation_revision']), (1, 2))
        self.assertTrue(result['current_profile_updated'])
        default = profiles.load_profile(self.state)
        self.assertEqual(default, investigations.load(self.state, iid)['profile_snapshot'])
        self.assertEqual(default['bases'][0]['mode_origin']['origin'], 'starter_connect_file')
        self.assertFalse((self.root / 'ib').exists())

    def test_standalone_setup_rejects_tampered_preview_and_can_save_an_environment(self):
        selection = self.cli('inspect')['selection']
        self.assertIsNone(selection['investigation_id'])
        review = self.preview(selection, {'view': self.file_profile()})
        self.assertEqual(review['plan']['scope'], 'current_only')
        altered = dict(review, plan=dict(review['plan'], scope='investigation_only'))
        self.assertEqual(self.apply(altered, expected_exit=2)['status'], 'error')
        self.assertFalse((self.state / 'profiles').exists())
        result = self.apply(review)
        self.assertIsNone(result['investigation_revision'])
        self.assertTrue(result['current_profile_updated'])
        self.assertEqual(profiles.load_profile(self.state)['revision'], 1)
        self.assertFalse((self.state / 'investigations').exists())

    def test_case_and_default_scope_changes_require_a_fresh_preview(self):
        profiles.save_profile(self.state, self.file_profile(), expected_revision=0)
        case = self.case()
        iid = case['investigation_id']
        first = self.cli('inspect', '--investigation', iid)
        review = self.preview(first['selection'], {'view': first['editor']['view']})
        other = profiles.save_profile(self.state, self.file_profile('Separate environment'), expected_revision=1)
        self.assertEqual(self.apply(review, expected_exit=2)['status'], 'error')
        self.assertFalse((self.state / 'profiles/3.json').exists())

        review = self.preview(first['selection'], {'view': first['editor']['view']})
        changed = investigations.revise(self.state, iid, {'scale': 'one'}, expected_revision=1)
        self.assertEqual(self.apply(review, expected_exit=2)['status'], 'error')
        self.assertFalse((self.state / 'profiles/3.json').exists())
        self.assertEqual(investigations.load(self.state, iid), changed)
        self.assertEqual(profiles.load_profile(self.state), other)

    def test_failed_binding_retains_the_staged_profile_without_publishing_it(self):
        from src.techexpert import profile_setup

        original = profiles.save_profile(self.state, self.file_profile(), expected_revision=0)
        before = self.case()
        iid = before['investigation_id']
        first = profile_setup.inspect(self.state, iid)
        view = dict(first['editor']['view'], name='Prepared for this case')
        review = profile_setup.preview(self.state, {'selection': first['selection'], 'edit': {'view': view}})
        with patch.object(investigations, '_revise', side_effect=OSError('injected link write failure')):
            outcome = profile_setup.apply(self.state, review['plan'], expected_sha256=review['plan_sha256'])
        self.assertEqual(outcome['status'], 'saved_not_linked')
        self.assertFalse(outcome['current_profile_updated'])
        self.assertIsNone(outcome['investigation_revision'])
        self.assertEqual(profiles.load_profile(self.state, revision=2)['name'], view['name'])
        self.assertEqual(investigations.load(self.state, iid), before)
        self.assertEqual(profiles.load_profile(self.state), original)

    def test_binding_can_finish_when_another_writer_changes_the_default_during_apply(self):
        from src.techexpert import profile_setup

        profiles.save_profile(self.state, self.file_profile(), expected_revision=0)
        iid = self.case()['investigation_id']
        first = profile_setup.inspect(self.state, iid)
        view = dict(first['editor']['view'], name='Edited investigation')
        review = profile_setup.preview(self.state, {'selection': first['selection'], 'edit': {'view': view}})
        revise = investigations._revise

        def revise_after_default_change(*args, **kwargs):
            profiles.save_profile(self.state, self.file_profile('New default'), expected_revision=1)
            return revise(*args, **kwargs)

        with patch.object(investigations, '_revise', side_effect=revise_after_default_change):
            result = profile_setup.apply(self.state, review['plan'], expected_sha256=review['plan_sha256'])
        self.assertEqual(result['status'], 'applied')
        self.assertFalse(result['current_profile_updated'])
        self.assertEqual(investigations.load(self.state, iid)['profile_snapshot']['name'], view['name'])
        self.assertEqual(profiles.load_profile(self.state)['name'], 'New default')
