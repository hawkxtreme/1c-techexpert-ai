"""Finite sample API scopes retained inputs and seals exact private dependencies."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from src.techexpert import artifacts, capabilities, input_intake, mcp_tools, operations, storage
from src.techexpert.input_adapters import import_selected
from src.techexpert.inputs import InputError
from src.techexpert.sample_description import describe
from test_sample_description import measurement
from test_sc01 import SCOPE

ROOT = Path(__file__).resolve().parents[1]


class SampleOperationTests(unittest.TestCase):
    def setUp(self):
        self.assertIn('sample.describe', capabilities.CODE_API, 'Sample description API is not executable')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'state'
        self.source = self.root / 'events.jsonl'
        rows = [dict(kind=kind, timestamp=stamp, scope=SCOPE) for kind, stamp in
            [('started', '2026-11-17T09:00:00Z'), ('finished', '2026-11-17T09:00:02Z')]]
        self.source.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        self.manifest = self.root / 'case.json'
        self.manifest.write_text(json.dumps(dict(schema=1, scenario='SC-01', origin='synthetic', selection=SCOPE,
            sources=[dict(path=str(self.source), format='normalized-events-v1')])), encoding='utf-8')
        case = storage.investigate(self.manifest, self.state)
        self.measurements = self.root / 'measurements.json'
        self.measurements.write_text(json.dumps([measurement('a', 1), measurement('b', 9)]), encoding='utf-8')
        artifact = artifacts.import_apdex(self.state, self.measurements, 3)
        self.args = dict(inputs=[dict(kind='case', id=case['case_id']), dict(kind='artifact', id=artifact['artifact_id'])],
            operation='post', reported_normal_seconds=300)

    def request(self, operation='sample.describe', args=None, key='describe-sample'):
        return dict(schema_version=1, operation_key=key, executor_id='fixture-harness',
            operation=operation, arguments=self.args if args is None else args)

    def change_report(self, ref, edit, name='report'):
        folder = self.state / ('cases' if ref['kind'] == 'case' else 'artifacts') / ref['id']
        path = folder / (name + '.json')
        report = json.loads(path.read_text(encoding='utf-8'))
        edit(report)
        storage.write_json(path, report)
        receipt = json.loads((folder / 'receipt.json').read_text(encoding='utf-8'))
        receipt[name + '_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        storage.write_json(folder / 'receipt.json', receipt)

    def test_managed_sample_replays_without_originals_and_refuses_corrupt_retained_suffix(self):
        request = self.request()
        result = operations.run(self.state, request)
        self.assertEqual(result['status'], 'succeeded', result)
        self.assertEqual(result['data']['statistics']['median'], 2)
        self.assertFalse(result['data']['normal_established'])
        self.assertEqual(len(result['snapshots']), 2)
        self.source.unlink()
        self.manifest.unlink()
        self.measurements.unlink()
        replay = operations.run(self.state, request)
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['data'], result['data'])
        source = self.state / 'artifacts' / self.args['inputs'][1]['id'] / 'sources/s1.bin'
        with source.open('r+b') as stream:
            stream.seek(-2, 2)
            stream.write(b'X')
        with self.assertRaises(InputError):
            operations.result(self.state, result['run_id'])

    def test_scoped_program_requires_every_selected_kind_and_exact_id_before_dispatch(self):
        program = 'sample = api("sample.describe", selected)\nreturn {"n": sample["data"]["statistics"]["count"], "median": sample["data"]["statistics"]["median"]}'
        for grant in (False, True):
            scope = dict(operations=['sample.describe'], cases=[self.args['inputs'][0]['id']],
                artifacts=[self.args['inputs'][1]['id']] if grant else [])
            args = dict(program=program, bindings=dict(selected=self.args), scope=scope)
            result = operations.run(self.state, self.request('code.execute', args, 'sample-scope-' + str(grant)))
            if grant:
                self.assertEqual(result['status'], 'succeeded', result)
                self.assertEqual(result['data']['value'], dict(n=3, median=2))
                self.assertEqual(result['data']['metrics']['calls_started'], 1)
            else:
                self.assertEqual(result['data']['metrics']['calls_started'], 0)
                self.assertEqual(result['data']['diagnostic']['code'], 'scope_denied')

    def test_mcp_publishes_real_types_and_original_thirteen_stay_unchanged(self):
        self.assertEqual(len(capabilities.BASE_API), 13)
        self.assertNotIn('sample.describe', capabilities.BASE_API)
        tool = next(t for t in mcp_tools.tools() if t['name'] == 'techexpert_sample_describe')
        self.assertTrue(tool['annotations']['readOnlyHint'])
        schema = tool['outputSchema']['properties']['data']['anyOf'][0]['properties']
        self.assertEqual(schema['inputs']['type'], 'array')
        self.assertEqual(schema['normal_established']['type'], 'boolean')
        self.assertEqual(schema['statistics']['properties']['median']['type'], ['number', 'null'])
        _, _, request = mcp_tools.prepare(tool['name'], dict(operation_key='sample-mcp', executor_id='fixture', arguments=self.args))
        self.assertEqual(request['operation'], 'sample.describe')
        self.assertEqual(request['arguments']['inputs'], self.args['inputs'])
        bad = dict(self.args, inputs=[dict(self.args['inputs'][0], kind='path')])
        with self.assertRaises(InputError):
            mcp_tools.prepare(tool['name'], dict(operation_key='bad', executor_id='fixture', arguments=bad))

    def test_cli_uses_owned_bounded_controller_for_the_same_api(self):
        path = self.root / 'request.json'
        path.write_text(json.dumps(self.request()), encoding='utf-8')
        process = subprocess.run([sys.executable, '-X', 'utf8', str(ROOT / 'techexpert.py'), '--state-dir', str(self.state),
            'operation-run', str(path)], capture_output=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result['data']['statistics']['count'], 3)
        self.assertTrue(result['kernel_call_id'])

    def test_first_output_rejects_changed_report_or_request_even_with_updated_receipt(self):
        for name in ('report', 'request'):
            with self.subTest(name=name):
                data = describe(self.state, **self.args)
                self.change_report(self.args['inputs'][1], lambda document: document.update(note='changed after calculation'), name=name)
                with self.assertRaises(InputError):
                    operations._snapshots(self.state, 'sample.describe', self.args, data)

    def test_first_output_rejects_omitted_source_or_dependency_binding(self):
        data = describe(self.state, **self.args)
        for key in ('sources', 'receipt_digest'):
            changed = copy.deepcopy(data)
            changed['inputs'][0].pop(key)
            with self.assertRaises(InputError):
                operations._snapshots(self.state, 'sample.describe', self.args, changed)
        changed = copy.deepcopy(data)
        changed['dependencies'].pop()
        with self.assertRaises(InputError):
            operations._snapshots(self.state, 'sample.describe', self.args, changed)

    def test_parent_integrity_is_pinned_without_granting_arbitrary_artifact_reads(self):
        plan = input_intake.inspect(self.state, [dict(path=str(self.measurements), kind='file')])
        artifact = import_selected('apdex.import', dict(measurements=str(self.measurements), target_seconds=3,
            input_plan=plan['artifact_id'], members=['m1']), self.state, self.state)
        selected = dict(inputs=[dict(kind='artifact', id=artifact['artifact_id'])], operation='post')
        data = describe(self.state, **selected)
        self.assertEqual(len(operations._snapshots(self.state, 'sample.describe', selected, data)), 2)
        program = 'sample = api("sample.describe", selected)\nreturn api("artifact.show", {"artifact_id": parent})'
        args = dict(program=program, bindings=dict(selected=selected, parent=plan['artifact_id']),
            scope=dict(operations=['sample.describe', 'artifact.show'], artifacts=[artifact['artifact_id']]))
        result = operations.run(self.state, self.request('code.execute', args, 'sample-parent-scope'))
        self.assertEqual(result['data']['metrics']['calls_started'], 1)
        self.assertEqual(result['data']['diagnostic']['code'], 'scope_denied')
        self.change_report(dict(kind='artifact', id=plan['artifact_id']), lambda doc: doc['result'].update(collection_coverage='changed'))
        with self.assertRaises(InputError):
            operations._snapshots(self.state, 'sample.describe', selected, data)


if __name__ == '__main__':
    unittest.main()
