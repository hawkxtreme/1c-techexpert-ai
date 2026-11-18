"""Task intake and follow-up in one investigation without reading sources."""
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import incident_templates, investigation_task, investigations, kernel, mcp_tools, update_state
from src.techexpert import operation_state as fs
from src.techexpert.inputs import InputError


FIRST = 'Фоновая загрузка заказов теперь занимает 45 минут.\nОбычно было около пяти.'
FOLLOW_UP = 'Запуск был вчера около 19:00 по Москве. Точное время начала пока не известно.'
EARLIER = dict(operation='Загрузка заказов', user_reported_baseline='около пяти минут',
               database_mode='file', start='при первом наблюдении утром')


class InvestigationTaskTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.state = Path(folder.name) / 'state'

    def start(self, **extra):
        request = dict(operation_key='first-message', text=FIRST, episode=EARLIER, **extra)
        return investigation_task.record(self.state, request)['data']

    def clarification(self, first, **extra):
        return dict(operation_key='second-message',
                    context=dict(investigation_id=first['investigation_id'],expected_revision=first['revision']),
                    text=FOLLOW_UP,**extra)

    def test_original_intake_is_preserved_verbatim_and_uses_same_id_after_retry(self):
        first = self.start()
        replay = self.start()
        self.assertTrue(replay['replayed'])
        self.assertEqual(first['investigation_id'],replay['investigation_id'])
        self.assertEqual(first['revision'],replay['revision'])
        self.assertEqual(first['template_id'],'TPL-00')
        self.assertNotIn(FIRST,str(first))
        doc = investigations.load(self.state,first['investigation_id'])
        self.assertEqual(doc['task'],FIRST)
        self.assertEqual(doc['episode'],EARLIER)
        self.assertEqual(doc['task_notes']['entries'][0]['text'],FIRST)
        self.assertEqual(doc['facts'],[])
        self.assertEqual(doc['cause_state'],'insufficient_data')
        self.assertFalse((self.state/'operations').exists())
        self.assertEqual(update_state.inspect_state(self.state)['schemata']['investigation-task'],[1])
        with self.assertRaisesRegex(InputError,'Task note key conflicts'):
            investigation_task.record(self.state,dict(operation_key='first-message',text='Другая задача'))

    def test_clarification_only_updates_supplied_fields_and_survives_a_later_revision(self):
        first = self.start(template_id='TPL-02')
        iid = first['investigation_id']
        request = self.clarification(first,episode=dict(start=None,utc_offset='+03:00'),scale='background')
        updated = investigation_task.record(self.state,request)['data']
        self.assertEqual(updated['recorded_revision'],2)
        prior = investigations.load(self.state,iid,revision=1)
        current = investigations.load(self.state,iid,revision=2)
        self.assertEqual(prior['episode'],EARLIER)
        self.assertEqual(current['task'],FIRST)
        self.assertEqual(current['episode'],dict(operation='Загрузка заказов',
            user_reported_baseline='около пяти минут',database_mode='file',utc_offset='+03:00'))
        self.assertEqual(current['scale'],'background')
        self.assertEqual(current['facts'],[])
        self.assertEqual([note['text'] for note in current['task_notes']['entries']],[FIRST,FOLLOW_UP])
        investigations.revise(self.state,iid,dict(open_questions=['Найти запись о завершении']),expected_revision=2)
        latest = investigation_task.record(self.state,request)['data']
        self.assertTrue(latest['replayed'])
        self.assertEqual((latest['revision'],latest['recorded_revision']),(3,2))
        with self.assertRaisesRegex(InputError,'Reload'):
            investigation_task.record(self.state,dict(request,operation_key='late-clarification'))
        self.assertEqual(investigations.load(self.state,iid)['revision'],3)

    def test_legacy_task_accepts_a_note_and_a_selected_template_can_start_a_task(self):
        old = investigations.create(self.state,dict(task='Старый сценарий'))
        updated = investigation_task.record(self.state,self.clarification(old))['data']
        record = investigations.load(self.state,updated['investigation_id'])
        self.assertEqual(record['task'],'Старый сценарий')
        self.assertEqual(record['task_notes']['entries'][0]['revision'],2)
        template = investigation_task.record(self.state,dict(operation_key='template-only',template_id='TPL-02'))['data']
        saved = investigations.load(self.state,template['investigation_id'])
        self.assertEqual(saved['task'],saved['template']['title'])
        self.assertIsNone(saved['task_notes']['entries'][0]['text'])

    def test_omitted_template_revision_keeps_current_or_pinned_template(self):
        template_id = 'USR-task'
        incident_templates.save_custom(self.state,dict(id=template_id,base_template_id='TPL-02',
            base_template_revision=1,title='Первый шаблон'),expected_revision=0)
        incident_templates.save_custom(self.state,dict(id=template_id,title='Действующий шаблон'),expected_revision=1)
        first = self.start(template_id=template_id)
        iid = first['investigation_id']
        self.assertEqual(investigations.load(self.state,iid)['template']['revision'],2)
        incident_templates.save_custom(self.state,dict(id=template_id,title='Новый шаблон'),expected_revision=2)
        updated = investigation_task.record(self.state,self.clarification(first))['data']
        self.assertEqual(investigations.load(self.state,updated['investigation_id'])['template']['revision'],2)

    def test_cli_from_a_fresh_process_preserves_a_caller_supplied_request(self):
        root = Path(__file__).resolve().parents[1]
        source = self.state.parent/'user-request.json'
        source.write_text(json.dumps(dict(operation_key='fresh-cli',text=FIRST),ensure_ascii=False),encoding='utf-8')
        original = source.read_bytes()
        result = subprocess.run([sys.executable,'-B','-X','utf8',str(root/'techexpert.py'),
            '--state-dir',str(self.state),'investigation-task',str(source)],cwd=root,capture_output=True,timeout=25)
        self.assertEqual(result.returncode,0,result.stderr.decode('utf-8','replace'))
        data = json.loads(result.stdout)['data']
        self.assertEqual(investigations.load(self.state,data['investigation_id'])['task'],FIRST)
        self.assertEqual(source.read_bytes(),original)

    def test_context_tool_is_writable_local_metadata_only(self):
        name = 'techexpert_investigation_task'
        schema, = [tool for tool in mcp_tools.tools('context') if tool['name']==name]
        self.assertFalse(schema['annotations']['readOnlyHint'])
        self.assertTrue(schema['annotations']['idempotentHint'])
        action,args,request = mcp_tools.prepare(name,dict(operation_key='harness-user-turn',text=FIRST),'context')
        actual_run = kernel.kernel_process.run

        def observed_run(directory, **arguments):
            result = actual_run(directory, **arguments)
            self.assertTrue((directory/'request.json').is_file(),
                            'a running controller must not remove a file scanned by its owner')
            return result

        with patch.object(kernel.kernel_process,'run',side_effect=observed_run):
            call = kernel.invoke(self.state,action,args,wire_version=mcp_tools.LEGACY,request_document=request)
        output = io.StringIO()
        kernel.emit(call,output)
        reply = json.loads(output.getvalue())['structuredContent']
        self.assertEqual(reply['status'],'succeeded')
        self.assertEqual(reply['operation'],'investigation.task')
        self.assertNotIn('45 минут',output.getvalue())
        self.assertEqual(investigations.load(self.state,reply['data']['investigation_id'])['task'],FIRST)
        self.assertFalse((self.state/'cases').exists())
        self.assertFalse((Path(call['folder'])/'request.json').exists())
        self.assertEqual(kernel.inspect_call(self.state,call['call_id'])['task_request_input'],'removed_after_stop')

    def test_interrupted_creation_keeps_its_identity_for_the_next_request(self):
        key = fs.digest(dict(purpose='investigation.task',operation_key='unfinished-write'))[:32]
        folder = fs.private(self.state/'investigations'/key)
        with self.assertRaises(investigation_task.TaskError) as caught:
            investigation_task.record(self.state, dict(operation_key='unfinished-write',text=FIRST))
        self.assertEqual(caught.exception.reason,'task_note_unavailable')
        self.assertEqual(list((self.state/'investigations').iterdir()),[folder])
        self.assertFalse((folder/'head.json').exists())

    def test_extra_authority_is_rejected_before_private_state_is_created(self):
        with self.assertRaises(InputError):
            investigation_task.record(self.state,dict(operation_key='scope',text=FIRST,profile_revision=7))
        with self.assertRaises(InputError):
            investigation_task.record(self.state,dict(operation_key='scope',text=FIRST,episode=dict(source='unexpected')))
        self.assertFalse(self.state.exists())


if __name__=='__main__':
    unittest.main()
