import sys
import unittest
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


if __name__=='__main__':unittest.main()
