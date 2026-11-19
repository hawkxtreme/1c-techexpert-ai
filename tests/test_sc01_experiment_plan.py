"""Verify independent starts for the SC-01 experiment."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts import sc01_trial
from scripts.sc01_experiment_report import summarize
from src.techexpert import investigations, knowledge, storage


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests' / 'fixtures' / 'order-load'


class SC01ExperimentPlanTests(unittest.TestCase):
    def test_prepares_independent_starts_from_one_exact_withheld_trial(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            output = parent / 'experiment'
            source = output / 'input-trial'
            before, after = FIXTURES / 'baseline.json', FIXTURES / 'cached.json'
            originals = {path: path.read_bytes() for path in (before, after)}

            def run(command, *args, expected=0):
                result = subprocess.run([sys.executable, '-B', '-X', 'utf8',
                    str(ROOT / 'scripts' / 'sc01_experiment_plan.py'), command, '--output', str(output),
                    *map(str, args)], cwd=parent, capture_output=True, timeout=160)
                self.assertEqual(result.returncode, expected, (result.stdout + result.stderr).decode('utf-8', 'replace'))
                return json.loads(result.stdout)

            ready = run('prepare', '--before', before, '--after', after, '--seed', 17)
            self.assertEqual(ready['status'], 'prepared_unlaunched')
            schedule_path = output / 'schedule.json'
            plan = json.loads(schedule_path.read_bytes())
            summary = summarize(schedule_path)
            self.assertEqual(len(summary['attempts']), 30)
            self.assertTrue(all(row['outcome'] == 'not_recorded' for row in summary['attempts']))
            self.assertEqual(plan['tool_workdir'], 'diagnosis')
            cli = plan['tool_argv']['cli']
            self.assertEqual(cli[-3:], ['techexpert.py', '--state-dir', 'state'])
            self.assertEqual(plan['tool_argv']['direct_mcp'], [*cli, 'mcp-stdio', '--profile', 'direct'])
            self.assertEqual(plan['tool_argv']['code_mode'], [*cli, 'mcp-stdio', '--profile', 'program'])

            slots = sorted(plan['schedule'], key=lambda row: (row['series'], row['repeat'], row['position']))
            self.assertEqual(len({row['trial'] for row in slots}), 30)
            for series in ('first_start', 'prepared_start'):
                order = [tuple(row['method'] for row in slots if row['series'] == series and row['repeat'] == repeat)
                         for repeat in range(1, 6)]
                self.assertEqual(len(set(order)), 5)

            cold = [output / row['trial'] for row in slots if row['series'] == 'first_start']
            warm = [output / row['trial'] for row in slots if row['series'] == 'prepared_start']
            self.assertTrue(all(not (trial / 'diagnosis' / 'state').exists() for trial in cold))
            self.assertTrue(all(not (trial / 'diagnosis' / 'answer.json').exists() for trial in cold + warm))
            prepared = plan['prepared_state']
            first_warm_state = warm[0] / 'diagnosis' / 'state'
            context = investigations.load(first_warm_state, prepared['investigation_id'])
            self.assertEqual(context['revision'], prepared['revision'])
            self.assertEqual(len(context['attachments']), 1)
            case = storage.verified_case(first_warm_state, context['attachments'][0]['target_id'])
            projection = knowledge.load_library(warm[0] / 'diagnosis' / 'knowledge')
            self.assertEqual(case['knowledge_revision'], projection['legacy_digest'])
            self.assertNotEqual(case['knowledge_revision'], storage.knowledge_revision())
            inventory = sc01_trial.inventory(first_warm_state)
            self.assertEqual(inventory, sc01_trial.inventory(warm[-1] / 'diagnosis' / 'state'))
            self.assertEqual({path: path.read_bytes() for path in originals}, originals)
            self.assertEqual(run('check')['verified_attempts'], 30)
            original_schedule = schedule_path.read_bytes()
            run('prepare', '--before', before, '--after', after, '--seed', 17, expected=2)
            self.assertEqual(schedule_path.read_bytes(), original_schedule)

            answer = parent / 'answer.json'
            answer.write_text(json.dumps(dict(status='insufficient_data', cause_hypothesis=None, proposed_change=None,
                evidence=[], limitations=[], next_steps=['Inspect the comparison'])), encoding='utf-8')
            sc01_trial.release(cold[0], answer)
            self.assertEqual(sc01_trial.status(cold[0])['release_status'], 'released')
            self.assertEqual(sc01_trial.status(cold[1])['release_status'], 'withheld')
            self.assertEqual(sc01_trial.status(source)['release_status'], 'withheld')
            self.assertIn('initial state', run('check', expected=2)['error'])
