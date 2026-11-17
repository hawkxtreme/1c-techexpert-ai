import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from src.techexpert.processes import run_bounded


class ProcessBudgetTests(unittest.TestCase):
    def test_output_limit_and_timeout_stop_only_owned_process(self):
        with self.assertRaisesRegex(ValueError,'output_limit'):
            run_bounded([sys.executable,'-c','print("x"*100000)'],max_bytes=1000)
        with self.assertRaisesRegex(ValueError,'timeout'):
            run_bounded([sys.executable,'-c','import time;time.sleep(5)'],timeout=.1)

    def test_literal_argument_and_stdin_do_not_invoke_shell(self):
        code,out,err=run_bounded([sys.executable,'-c','import sys;print(sys.argv[1]);print(sys.stdin.read())','a;$(whoami)'],
                                input_data=b'bounded stdin')
        self.assertEqual(code,0)
        self.assertEqual(err,b'')
        self.assertIn(b'a;$(whoami)',out)
        self.assertIn(b'bounded stdin',out)

    def test_invalid_input_and_cancel_before_launch_never_start_a_process(self):
        with patch('src.techexpert.processes.subprocess.Popen',side_effect=AssertionError('Invalid input launched a process')):
            with self.assertRaises(ValueError):run_bounded([sys.executable],input_data='not bytes')
            with self.assertRaisesRegex(ValueError,'cancelled'):run_bounded([sys.executable],should_stop=lambda:'cancelled')

    def test_explicit_cancel_retains_bounded_partial_output_and_stops_owned_child(self):
        with tempfile.TemporaryDirectory() as temp:
            ready=Path(temp)/'ready'
            source='import sys,time;from pathlib import Path;print("captured-before-cancel",flush=True);Path(sys.argv[1]).write_text("ready");time.sleep(30)'
            with self.assertRaises(ValueError) as caught:
                run_bounded([sys.executable,'-c',source,str(ready)],timeout=10,should_stop=lambda:'cancelled' if ready.exists() else None)
            error=caught.exception
            self.assertEqual(getattr(error,'reason',None),'cancelled')
            self.assertIn(b'captured-before-cancel',error.stdout)
            self.assertTrue(error.process_started)
            self.assertIsNotNone(error.returncode)


if __name__=='__main__':unittest.main()
