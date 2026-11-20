from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import cli
from src.techexpert.processes import CommandStopped


class PluginRuntimeTests(unittest.TestCase):
    def run_doctor(self, *arguments):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(io.StringIO()):
            try:
                code = cli.main(list(map(str, arguments)))
            except SystemExit as error:
                code = error.code
        return code, json.loads(output.getvalue()) if output.getvalue() else {}

    def test_explicit_check_reports_loaded_interpreter_without_using_investigation_state(self):
        launcher = str(Path.cwd() / 'installed Python' / 'python3')
        python = str(Path.cwd() / 'installed Python' / 'python')
        payload = json.dumps(dict(version=[3, 14, 0], executable=python)).encode()
        with patch('src.techexpert.state_location.load', side_effect=AssertionError('loaded state')):
            with patch('shutil.which', return_value=launcher), \
                    patch('src.techexpert.plugin_runtime.run_bounded', return_value=(0, payload, b'')) as run:
                code, answer = self.run_doctor('doctor', '--check-plugin')
        self.assertEqual((code, answer['status'], answer['python_version']), (0, 'available', '3.14.0'))
        self.assertEqual((answer['launcher'], answer['python_executable']), (launcher, python))
        (argv,), options = run.call_args
        self.assertEqual(argv[:6], [launcher, '-I', '-B', '-X', 'utf8', '-c'])
        self.assertEqual(options['env']['PYTHON_MANAGER_AUTOMATIC_INSTALL'], '0')
        self.assertLessEqual(options['timeout'], 5)
        self.assertLessEqual(options['max_bytes'], 4096)

    def test_normal_doctor_and_readiness_do_not_start_the_plugin_launcher(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / 'uncreated'
            with patch('shutil.which', return_value=None), \
                    patch('src.techexpert.plugin_runtime.run_bounded') as run:
                self.assertEqual(self.run_doctor('--state-dir', state, 'doctor')[0], 0)
                _, readiness = self.run_doctor('--state-dir', state, 'readiness')
                self.assertIn(readiness['status'], ('needs_harness_confirmation', 'state_storage_blocked'))
                code, missing = self.run_doctor('doctor', '--check-plugin')
            run.assert_not_called()
            self.assertEqual((code, missing['status']), (2, 'launcher_missing'))
            self.assertFalse(state.exists())

    def test_reports_failure_or_unsupported_python_with_bounded_diagnostics(self):
        launcher = str(Path.cwd() / 'bin' / 'python3')
        python310 = json.dumps(dict(version=[3, 10, 5], executable=launcher)).encode()
        runs = [((1, b'raw private bytes', b'raw private bytes'), 'launcher_failed', 'nonzero_exit'),
                ((0, b'raw private bytes', b''), 'launcher_failed', 'invalid_response'),
                ((0, python310, b''), 'unsupported_python', None),
                (CommandStopped('timeout', stdout=b'raw private bytes'), 'launcher_failed', 'timeout')]
        for result, status, reason in runs:
            with self.subTest(status=status, reason=reason), patch('shutil.which', return_value=launcher):
                with patch('src.techexpert.plugin_runtime.run_bounded', side_effect=[result]):
                    code, answer = self.run_doctor('doctor', '--check-plugin')
                self.assertEqual((code, answer['status'], answer.get('reason')), (2, status, reason))
                self.assertNotIn('raw private bytes', json.dumps(answer))
