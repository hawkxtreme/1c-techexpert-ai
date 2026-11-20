from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import cli, kernel, mcp_server, mcp_tools, operation_state as fs


class StateLocationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.app_data = self.root / 'profile data'
        self.default = self.app_data / '1c-techexpert-ai'
        self.settings = self.app_data / '1c-techexpert-ai-settings' / 'state-location.json'
        self.selected = self.root / 'выбранное состояние'
        self.later = self.root / 'later'
        environment = patch.dict(os.environ, LOCALAPPDATA=str(self.app_data), XDG_STATE_HOME=str(self.app_data))
        environment.start()
        self.addCleanup(environment.stop)

    def command(self, *arguments):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(io.StringIO()):
            try:
                code = cli.main(list(map(str, arguments)))
            except SystemExit as error:
                code = error.code
        return code, json.loads(output.getvalue()) if output.getvalue() else {}

    def select(self, path, revision):
        return self.command('state-location', '--select', path, '--expected-revision', revision)

    def tool(self, server, identifier):
        request = dict(name='techexpert_case_show', arguments=dict(
            operation_key='state-' + str(identifier), executor_id='test',
            arguments=dict(case_id='a' * 32)))
        server.launch(identifier, request, mcp_tools.MODERN)
        reply, entry = server.outgoing.get(timeout=10)
        server._release(entry)
        return reply

    def test_selection_uses_one_per_user_setting_and_checks_the_displayed_revision(self):
        code, first = self.command('state-location')
        self.assertEqual(code, 0, first)
        self.assertEqual((first['revision'], Path(first['state_dir'])), (0, self.default))
        self.assertFalse(self.app_data.exists())
        self.assertEqual(self.select('relative', 0)[0], 2)
        self.assertFalse(self.app_data.exists())

        code, chosen = self.select(self.selected, 0)
        self.assertEqual(code, 0, chosen)
        self.assertEqual((chosen['revision'], Path(chosen['state_dir'])), (1, self.selected))
        self.assertFalse(self.default.exists())
        self.assertFalse(self.selected.exists())
        self.assertTrue(self.settings.is_file())
        stored = self.settings.read_bytes()
        self.assertEqual(self.select(self.later, 0)[0], 2)
        self.assertEqual(self.settings.read_bytes(), stored)
        self.assertEqual(Path(self.command('doctor')[1]['state_dir']), self.selected)
        self.assertEqual(Path(self.command('--state-dir', self.default, 'doctor')[1]['state_dir']), self.default)
        self.assertFalse(self.default.exists())

    def test_unbound_mcp_can_use_the_new_selection_after_a_capacity_refusal(self):
        server = mcp_server.Server(None, None, None)
        session = dict(jsonrpc='2.0', id=1, method='tools/list', params={'_meta': {
            'io.modelcontextprotocol/protocolVersion': mcp_tools.MODERN,
            'io.modelcontextprotocol/clientCapabilities': {},
        }})
        server.handle(session)
        discovery, _ = server.outgoing.get(timeout=5)
        self.assertTrue(discovery['result']['tools'])
        self.assertIsNone(server.state)
        self.assertFalse(self.app_data.exists())

        with server.pool, patch.object(kernel, 'invoke', return_value={}) as invoke:
            with patch.object(fs, 'require_free_space', side_effect=fs.StateSpaceError(3)):
                denied = self.tool(server, 2)
            self.assertIsInstance(denied, dict)
            self.assertEqual(denied['result']['structuredContent']['stop_reason'], 'state_space_insufficient')
            invoke.assert_not_called()
            self.assertIsNone(server.state)

            self.assertEqual(self.select(self.selected, 0)[0], 0)
            self.tool(server, 3)
            self.assertEqual(invoke.call_args.args[0], self.selected)
            self.assertEqual(self.select(self.later, 1)[0], 0)
            self.tool(server, 4)
            self.assertEqual(invoke.call_args.args[0], self.selected)
        fresh = mcp_server.Server(None, None, None)
        with fresh.pool, patch.object(kernel, 'invoke', return_value={}) as invoke:
            self.tool(fresh, 5)
            self.assertEqual(invoke.call_args.args[0], self.later)
        self.assertFalse(self.default.exists())

    def test_bad_selection_refuses_default_runs_and_keeps_an_explicit_override_available(self):
        self.settings.parent.mkdir(parents=True)
        self.settings.write_text('{"schema_version":1,"revision":1,"state_dir":"relative"}', encoding='utf-8')
        old = self.settings.read_bytes()
        code, answer = self.command('readiness')
        self.assertEqual(code, 2)
        self.assertEqual(answer.get('stop_reason'), 'state_location_invalid')
        self.assertFalse(self.default.exists())
        self.assertEqual(self.select(self.selected, 0)[0], 2)
        self.assertEqual(self.settings.read_bytes(), old)
        code, override = self.command('--state-dir', self.selected, 'doctor')
        self.assertEqual(code, 0, override)
        self.assertEqual(Path(override['state_dir']), self.selected)
        self.assertEqual(self.command('capabilities')[0], 0)
