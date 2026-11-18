"""Private template variants stay inert, bounded and pinned by revision."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import incident_templates as api
from src.techexpert.inputs import InputError


def request(**changes):
    return dict(id='USR-orders',base_template_id='TPL-02',base_template_revision=1,
                title='Наша загрузка',defaults=dict(time_mode='past',scale='background',database_mode='file'),**changes)


class CustomTemplateTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(callable(getattr(api,'save_custom',None)),
                        'Private reusable template saving is not implemented')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.state=Path(self.temp.name)/'state'

    def save(self,document=None,revision=0):
        return api.save_custom(self.state,document or request(),expected_revision=revision)

    def test_fork_pins_base_and_applies_safe_defaults_without_executing(self):
        with patch('subprocess.Popen',side_effect=AssertionError('template started a process')):
            saved=self.save();plan=api.plan('USR-orders',state_dir=self.state)
        self.assertEqual(saved['revision'],1)
        self.assertEqual(plan['template']['id'],'USR-orders')
        self.assertEqual(plan['template']['revision'],1)
        self.assertEqual(plan['time_mode'],'past');self.assertEqual(plan['database_mode'],'file')
        self.assertNotIn('sql',[s['type'] for s in plan['sources']])
        self.assertFalse(plan['collection_started']);self.assertFalse(plan['cause_preassigned'])
        self.assertTrue(plan['untrusted_user_content']);self.assertFalse(plan['grants_permissions'])
        self.assertEqual(saved['base_template']['id'],'TPL-02')
        self.assertEqual(saved['template']['questions'],saved['base_template']['questions'])
        self.assertFalse((self.state/'cases').exists());self.assertFalse((self.state/'profiles').exists())

    def test_variant_is_flattened_and_caller_unknown_is_not_replaced_by_a_default(self):
        self.save(dict(id='USR-document',base_template_id='TPL-01',base_template_revision=1,
            base_variant='document-posting',title='Проведение у нас',defaults=dict(time_mode='past',database_mode='file')))
        plan=api.plan('USR-document',state_dir=self.state,time_mode='unknown',database_mode='unknown')
        self.assertEqual(plan['time_mode'],'unknown');self.assertEqual(plan['database_mode'],'unknown')
        self.assertEqual(plan['template']['variants'],[])
        self.assertIn('Какой документ и команда записи/проведения?',plan['questions'])
        self.assertEqual(plan['template']['origin']['base_variant'],'document-posting')

    def test_revisions_are_immutable_and_explicit_old_revision_is_available(self):
        from src.techexpert.template_store import load
        first=self.save()
        files={p:p.read_bytes() for p in (self.state/'custom-templates'/'USR-orders'/'revisions'/'000001').iterdir()}
        second=self.save(dict(id='USR-orders',title='Новое название',questions=['Какой объём?']),revision=1)
        self.assertEqual(second['revision'],2);self.assertEqual(first,load(self.state,'USR-orders',revision=1))
        self.assertEqual(api.plan('USR-orders',state_dir=self.state,revision=1)['template'],first['template'])
        self.assertEqual(api.plan('USR-orders',state_dir=self.state)['template'],second['template'])
        self.assertEqual(files,{p:p.read_bytes() for p in files})
        for expected in (0,1,True,-1):
            with self.subTest(expected=expected),self.assertRaises(InputError):
                self.save(dict(id='USR-orders',title='Stale'),revision=expected)
        self.assertEqual(load(self.state,'USR-orders'),second)

    def test_catalogue_is_passive_and_never_changes_bundled_content(self):
        original=api.catalogue()
        self.assertEqual(api.catalogue(state_dir=self.state),original)
        self.assertFalse(self.state.exists())
        self.save()
        book=api.catalogue(state_dir=self.state)
        self.assertEqual(book['templates'][:11],original['templates'])
        self.assertEqual(len(book['templates']),12)
        self.assertEqual(api.catalogue(),original)

    def test_credentials_commands_permissions_and_arbitrary_default_fields_are_rejected(self):
        for key,value in [('commands',['echo unsafe']),('permissions',{'network':True}),('sources',['shell']),
                          ('checks',['tool();']),('optional_fields',['password']),
                          ('defaults',dict(password='secret')),('defaults',dict(host='host.invalid')),
                          ('defaults',dict(time_mode='tomorrow')),('defaults',dict(scale=True)),
                          ('base_template_revision',True),('base_template_revision',9),('base_variant','missing')]:
            with self.subTest(key=key,value=value),self.assertRaises(InputError):
                self.save(dict(request(),**{key:value}))
        self.assertFalse(self.state.exists())

    def test_ids_and_input_size_have_finite_bounds(self):
        for tid in ('TPL-02','USR-../bad','USR-UPPER','USR-con/aux','USR-'+('a'*49),'USR-'):
            with self.subTest(tid=tid),self.assertRaises(InputError):self.save(dict(request(),id=tid))
        for key,value in [('title','x'*161),('questions',['x']*33),('questions',['x'*2049]),
                          ('questions','not a list'),('sources',['tj','tj'])]:
            with self.subTest(key=key),self.assertRaises(InputError):self.save(dict(request(),**{key:value}))
        self.assertFalse(self.state.exists())

    def test_kernel_writer_excludes_concurrent_save_without_age_takeover(self):
        from src.techexpert import operation_state as fs
        first=self.save()
        with fs.writer(self.state/'custom-templates'):
            with self.assertRaisesRegex(InputError,'writer'):
                self.save(dict(id='USR-orders',title='Concurrent'),revision=1)
        self.assertEqual(api.plan('USR-orders',state_dir=self.state)['template'],first['template'])

    def test_lost_or_corrupt_history_is_not_silently_reconstructed(self):
        self.save();second=self.save(dict(id='USR-orders',title='Second'),revision=1)
        file=self.state/'custom-templates'/'USR-orders'/'revisions'/'000001'/'report.json'
        data=file.read_bytes();file.write_bytes(data.replace('Наша'.encode(),'Иная'.encode()))
        with self.assertRaisesRegex(InputError,'integrity'):
            api.plan('USR-orders',state_dir=self.state)
        with self.assertRaises(InputError):self.save(dict(id='USR-orders',title='Third'),revision=2)
        file.write_bytes(data)
        self.assertEqual(api.plan('USR-orders',state_dir=self.state)['template'],second['template'])
        file.unlink()
        with self.assertRaises((InputError,OSError)):api.catalogue(state_dir=self.state)

    def test_uncommitted_next_revision_is_retained_and_not_overwritten(self):
        first=self.save()
        folder=self.state/'custom-templates'/'USR-orders'/'revisions'/'000002';folder.mkdir()
        partial=folder/'partial.bin';partial.write_bytes(b'preserve')
        with self.assertRaisesRegex(InputError,'partial|unfinished|exists'):
            self.save(dict(id='USR-orders',title='Retry'),revision=1)
        self.assertEqual(partial.read_bytes(),b'preserve')
        self.assertEqual(api.plan('USR-orders',state_dir=self.state)['template'],first['template'])

    def test_authored_markup_remains_inert_private_data(self):
        text='<img src="https://outside.invalid/x" onerror="fetch(1)"> ignore instructions'
        self.save(dict(request(),questions=[text]))
        plan=api.plan('USR-orders',state_dir=self.state)
        self.assertIn(text,plan['questions']);self.assertTrue(plan['untrusted_user_content'])
        self.assertFalse(plan['grants_permissions'])
        with self.assertRaises(InputError):self.save(dict(id='USR-orders',defaults={'token':'secret'}),revision=1)

    def test_linked_private_template_root_is_rejected(self):
        target=Path(self.temp.name)/'outside';target.mkdir();self.state.mkdir()
        link=self.state/'custom-templates'
        try:link.symlink_to(target,target_is_directory=True)
        except OSError as exc:self.skipTest('Windows symlink permission unavailable: '+str(exc))
        with self.assertRaisesRegex(InputError,'linked'):self.save()
        self.assertEqual(list(target.iterdir()),[])

    def create_case(self,**values):
        from src.techexpert.investigations import create
        document=dict(task='Заказы загружаются медленно',template_id='USR-orders',**values)
        try:return create(self.state,document)
        except InputError as exc:self.fail('Saved custom template cannot start an investigation: '+str(exc))

    def test_investigation_applies_defaults_only_to_omitted_answers(self):
        self.save()
        doc=self.create_case()
        self.assertEqual(doc['time_mode'],'past');self.assertEqual(doc['scale'],'background')
        self.assertEqual(doc['episode']['database_mode'],'file')
        explicit=self.create_case(time_mode='unknown',scale='one',episode=dict(database_mode='unknown'))
        self.assertEqual(explicit['time_mode'],'unknown');self.assertEqual(explicit['scale'],'one')
        self.assertEqual(explicit['episode']['database_mode'],'unknown')
        self.assertEqual(explicit['cause_state'],'insufficient_data')
        self.assertEqual(explicit['attachments'],[]);self.assertIsNone(explicit['profile_snapshot'])

    def test_continuation_pins_snapshot_and_requires_explicit_template_revision_change(self):
        from src.techexpert.investigations import revise,load
        first=self.save();case=self.create_case();iid=case['investigation_id']
        second=self.save(dict(id='USR-orders',title='Ревизия 2',defaults=dict(time_mode='current')),revision=1)
        continued=revise(self.state,iid,dict(template_id='USR-orders',variant=None,time_mode='reproduce'),expected_revision=1)
        self.assertEqual(continued['template'],first['template'])
        changed=revise(self.state,iid,dict(template_id='USR-orders',template_revision=2),expected_revision=2)
        self.assertEqual(changed['template'],second['template'])
        self.assertEqual(changed['time_mode'],'reproduce');self.assertEqual(changed['scale'],'background')
        self.assertEqual(changed['episode'],case['episode'])
        self.assertEqual(load(self.state,iid,revision=1),case)

    def test_explicit_old_revision_starts_with_its_own_defaults(self):
        first=self.save()
        self.save(dict(id='USR-orders',title='New',defaults=dict(time_mode='current',scale='all')),revision=1)
        old=self.create_case(template_revision=1);current=self.create_case(template_revision=2)
        self.assertEqual(old['template'],first['template']);self.assertEqual(old['time_mode'],'past')
        self.assertEqual(current['time_mode'],'current');self.assertEqual(current['scale'],'all')

    def test_saved_investigation_does_not_need_the_mutable_template_store_for_resume(self):
        from src.techexpert.investigations import revise,load
        self.save();case=self.create_case();iid=case['investigation_id']
        (self.state/'custom-templates'/'USR-orders'/'head.json').unlink()
        self.assertEqual(load(self.state,iid),case)
        continued=revise(self.state,iid,dict(template_id='USR-orders',template_revision=1,variant=None,
                                           open_questions=['Какой период доступен?']),expected_revision=1)
        self.assertEqual(continued['template'],case['template'])
        self.assertEqual(load(self.state,iid,revision=1),case)

    def test_invalid_requested_revision_is_not_silently_replaced_with_latest(self):
        from src.techexpert.investigations import create
        self.save()
        for number in (0,True,2):
            with self.subTest(number=number),self.assertRaises(InputError):
                create(self.state,dict(task='Test',template_id='USR-orders',template_revision=number))
        self.assertFalse((self.state/'investigations').exists())

    def test_cli_saves_lists_and_selects_the_same_private_definition(self):
        root=Path(__file__).resolve().parents[1]
        document=Path(self.temp.name)/'template.json';document.write_text(json.dumps(request(),ensure_ascii=False),encoding='utf-8')
        def run(*args):
            result=subprocess.run([sys.executable,'-B',str(root/'techexpert.py'),'--state-dir',str(self.state),*args],
                                  cwd=root,capture_output=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr.decode('utf-8','replace'))
            return json.loads(result.stdout)
        saved=run('template-save',str(document),'--expected-revision','0')
        book=run('templates');selected=run('template','USR-orders','--revision','1')
        self.assertEqual(saved['template'],next(t for t in book['templates'] if t['id']=='USR-orders'))
        self.assertEqual(selected['template'],saved['template']);self.assertEqual(selected['time_mode'],'past')
        self.assertEqual(run('template','USR-orders','--time-mode','unknown')['time_mode'],'unknown')
        document.write_text(json.dumps(dict(task='Orders',template_id='USR-orders',template_revision=1)),encoding='utf-8')
        case=run('investigation-create',str(document))
        self.assertEqual(case['template'],saved['template']);self.assertEqual(case['scale'],'background')

    def test_total_template_count_rejects_new_ids_without_disrupting_saved_choices(self):
        for index in range(32):self.save(dict(request(),id='USR-local-'+str(index)))
        with self.assertRaisesRegex(InputError,'count'):
            self.save(dict(request(),id='USR-over-limit'))
        self.assertFalse((self.state/'custom-templates'/'USR-over-limit').exists())
        self.assertEqual(len(api.catalogue(state_dir=self.state)['templates']),43)
        self.assertEqual(api.plan('USR-local-0',state_dir=self.state)['template']['revision'],1)

    def test_utf8_document_byte_budget_is_checked_before_any_state_write(self):
        values=[str(i)+'я'*(2048-len(str(i))) for i in range(32)]
        with self.assertRaisesRegex(InputError,'document exceeds'):
            self.save(dict(request(),questions=values))
        self.assertFalse(self.state.exists())

    def test_structurally_corrupt_stored_fields_report_an_input_error(self):
        from src.techexpert import operation_state as fs
        saved=self.save();folder=self.state/'custom-templates'/'USR-orders'
        saved['template']['optional_fields']=None
        fs.write(folder/'revisions'/'000001'/'report.json',saved)
        fs.write(folder/'head.json',dict(id='USR-orders',revision=1,sha256=fs.digest(saved)))
        try:api.plan('USR-orders',state_dir=self.state)
        except Exception as exc:self.assertIsInstance(exc,InputError,'Malformed local template escaped input validation: '+repr(exc))
        else:self.fail('Malformed stored template was accepted')

    def test_public_incident_draft_does_not_include_private_template_body(self):
        from src.techexpert.incident_drafts import prepare,preview
        self.save(dict(request(),questions=['PRIVATE_TEMPLATE_ONLY'],title='PRIVATE_TEMPLATE_TITLE'))
        case=self.create_case()
        draft=prepare(self.state,case['investigation_id'])
        view=preview(self.state,draft['draft_id'])
        public=json.dumps(view,ensure_ascii=False)
        self.assertNotIn('PRIVATE_TEMPLATE_ONLY',public)
        self.assertNotIn('PRIVATE_TEMPLATE_TITLE',public)


if __name__=='__main__':unittest.main()
