"""Finite source comparison scopes both resources and seals exact dependencies."""
import hashlib
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from src.techexpert import capabilities, operations, mcp_tools, storage, input_intake, artifacts
from src.techexpert.inputs import InputError
from test_tj_prefix_capture import PROFILE, ROW

ROOT = Path(__file__).resolve().parents[1]


class SourceChangeOperationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'state'
        self.log = self.root / 'source.log'
        self.manifest = self.root / 'source.json'
        refs = []
        for raw in (ROW, ROW * 2):
            self.log.write_bytes(raw)
            self.manifest.write_text(json.dumps(dict(schema=1, scenario='SC-01', origin='provided',
                selection={k: 'reported' for k in ('database', 'node', 'process', 'epoch', 'run')},
                sources=[dict(PROFILE, path=str(self.log), read_mode='tj-prefix-v1')])), encoding='utf-8')
            case = storage.investigate(self.manifest, self.state)
            refs.append(dict(kind='case', id=case['case_id'], source_id='s1'))
        self.arguments = dict(before=refs[0], after=refs[1])

    def request(self, operation, arguments, key='source-compare-test'):
        return dict(schema_version=1, operation=operation, arguments=arguments, operation_key=key, executor_id='fixture-harness')

    def test_managed_compare_replays_without_originals_and_refuses_retained_corruption(self):
        request = self.request('source.compare', self.arguments)
        result = operations.run(self.state, request)
        self.assertEqual(result['status'], 'succeeded', result)
        self.assertEqual(result['data']['observation']['relation'], 'prefix_extended')
        self.assertEqual(len(result['snapshots']), 2)
        self.assertEqual({r['id'] for r in result['snapshots']}, {r['id'] for r in self.arguments.values()})
        self.log.unlink()
        self.manifest.unlink()
        replay = operations.run(self.state, request)
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['data'], result['data'])
        target = storage.case_folder(self.state, self.arguments['after']['id']) / 'sources/s1.bin'
        target.write_bytes(ROW)
        with self.assertRaises(InputError):
            operations.result(self.state, result['run_id'])

    def test_scoped_program_requires_both_selected_resources_before_any_api_call(self):
        program = 'value = api("source.compare", selected)\nreturn {"relation": value["data"]["observation"]["relation"], "bytes": value["data"]["common_prefix_bytes"]}'
        ids = [ref['id'] for ref in self.arguments.values()]
        for count in (1, 2):
            with self.subTest(allowed=count):
                arguments = dict(program=program, bindings=dict(selected=self.arguments),
                    scope=dict(operations=['source.compare'], cases=ids[:count]))
                result = operations.run(self.state, self.request('code.execute', arguments, 'source-program-' + str(count)))
                if count == 1:
                    self.assertEqual(result['data']['metrics']['calls_started'], 0)
                    self.assertEqual(result['data']['diagnostic']['code'], 'scope_denied')
                else:
                    self.assertEqual(result['status'], 'succeeded', result)
                    self.assertEqual(result['data']['value'], dict(relation='prefix_extended', bytes=len(ROW)))
                    self.assertEqual(result['data']['metrics']['calls_started'], 1)

    def test_mcp_is_read_only_uses_real_schema_and_does_not_default_new_capture_fields(self):
        self.assertIn('source.compare', capabilities.CODE_API)
        self.assertNotIn('source.compare', capabilities.BASE_API)
        self.assertEqual(len(capabilities.BASE_API), 13)
        tool = next(item for item in mcp_tools.tools() if item['name'] == 'techexpert_source_compare')
        self.assertTrue(tool['annotations']['readOnlyHint'])
        self.assertFalse(tool['annotations']['destructiveHint'])
        wire = tool['outputSchema']['properties']['data']['anyOf'][0]['properties']
        self.assertEqual(wire['byte_relation']['type'], 'string')
        self.assertEqual(wire['common_prefix_bytes']['type'], 'integer')
        self.assertIn('context_digest', wire['before']['required'])
        _, _, request = mcp_tools.prepare('techexpert_source_compare', dict(operation_key='source-sdk', executor_id='fixture', arguments=self.arguments))
        self.assertEqual(request['arguments'], self.arguments)
        bad = dict(before=dict(self.arguments['before'], kind='directory'), after=self.arguments['after'])
        with self.assertRaises(InputError):
            mcp_tools.prepare('techexpert_source_compare', dict(operation_key='bad', executor_id='fixture', arguments=bad))

    def test_case_and_artifact_grants_are_separate_even_for_the_same_reference_shape(self):
        report = artifacts.save_artifact(self.state, 'provided_bytes', {}, [('row', ROW)], {})
        selected = dict(before=self.arguments['before'], after=dict(kind='artifact', id=report['artifact_id'], source_id='s1'))
        program = 'return api("source.compare", selected)["data"]["byte_relation"]'
        for allowed in (False, True):
            scope = dict(operations=['source.compare'], cases=[selected['before']['id']], artifacts=[report['artifact_id']] if allowed else [])
            arguments = dict(program=program, bindings=dict(selected=selected), scope=scope)
            value = operations.run(self.state, self.request('code.execute', arguments, 'mixed-source-scope-' + str(allowed)))
            if allowed:
                self.assertEqual(value['status'], 'succeeded', value)
                self.assertEqual(value['data']['value'], 'identical')
            else:
                self.assertEqual(value['data']['metrics']['calls_started'], 0)
                self.assertEqual(value['data']['diagnostic']['code'], 'scope_denied')

    def test_catalogue_integrity_dependency_does_not_grant_arbitrary_artifact_reads(self):
        plan = input_intake.inspect(self.state, [dict(path=str(self.log), kind='file')])
        self.manifest.write_text(json.dumps(dict(schema=1, scenario='SC-01', origin='provided',
            selection={k: 'reported' for k in ('database', 'node', 'process', 'epoch', 'run')}, sources=[dict(PROFILE, path='m1')])), encoding='utf-8')
        case = input_intake.analyze(self.state, self.state, self.manifest, plan['artifact_id'])
        ref = dict(kind='case', id=case['case_id'], source_id='s1')
        program = 'value = api("source.compare", selected)\nreturn api("artifact.show", {"artifact_id": value["data"]["dependencies"][1]["id"]})'
        arguments = dict(program=program, bindings=dict(selected=dict(before=ref, after=ref)),
            scope=dict(operations=['source.compare', 'artifact.show'], cases=[case['case_id']]))
        value = operations.run(self.state, self.request('code.execute', arguments, 'parent-is-not-a-grant'))
        self.assertEqual(value['data']['metrics']['calls_started'], 1)
        self.assertEqual(value['data']['diagnostic']['code'], 'scope_denied')

    def test_cli_uses_a_bounded_controller(self):
        path = self.root / 'request.json'
        path.write_text(json.dumps(self.request('source.compare', self.arguments)), encoding='utf-8')
        run = subprocess.run([sys.executable, '-X', 'utf8', str(ROOT / 'techexpert.py'), '--state-dir', str(self.state), 'operation-run', str(path)], capture_output=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        result = json.loads(run.stdout)
        self.assertEqual(result['data']['byte_relation'], 'extended_prefix')
        self.assertTrue(result['kernel_call_id'])

    def test_first_output_refuses_a_changed_input_report_even_with_a_new_valid_receipt(self):
        from src.techexpert.source_changes import compare
        value = compare(self.state, **self.arguments)
        folder = storage.case_folder(self.state, self.arguments['before']['id'])
        report = storage.load_case(self.state, self.arguments['before']['id'])
        report['symptom'] = 'changed after comparison'
        storage.write_json(folder / 'report.json', report)
        receipt = json.loads((folder / 'receipt.json').read_text())
        receipt['report_sha256'] = hashlib.sha256((folder / 'report.json').read_bytes()).hexdigest()
        storage.write_json(folder / 'receipt.json', receipt)
        with self.assertRaises(InputError):
            operations._snapshots(self.state, 'source.compare', self.arguments, value)

    def test_first_output_refuses_a_changed_manifest_with_an_updated_valid_receipt(self):
        from src.techexpert.source_changes import compare
        value = compare(self.state, **self.arguments)
        folder = storage.case_folder(self.state, self.arguments['before']['id'])
        manifest = json.loads((folder / 'manifest.json').read_text())
        manifest['selection']['run'] = 'another-episode'
        storage.write_json(folder / 'manifest.json', manifest)
        receipt = json.loads((folder / 'receipt.json').read_text())
        receipt['manifest_sha256'] = hashlib.sha256((folder / 'manifest.json').read_bytes()).hexdigest()
        storage.write_json(folder / 'receipt.json', receipt)
        with self.assertRaises(InputError):
            operations._snapshots(self.state, 'source.compare', self.arguments, value)

    def test_selected_catalogue_parent_is_pinned_and_checked_before_first_output(self):
        from src.techexpert.source_changes import compare
        plan = input_intake.inspect(self.state, [dict(path=str(self.log), kind='file')])
        self.manifest.write_text(json.dumps(dict(schema=1, scenario='SC-01', origin='provided',
            selection={k: 'reported' for k in ('database', 'node', 'process', 'epoch', 'run')}, sources=[dict(PROFILE, path='m1')])), encoding='utf-8')
        case = input_intake.analyze(self.state, self.state, self.manifest, plan['artifact_id'])
        reference = dict(kind='case', id=case['case_id'], source_id='s1')
        arguments = dict(before=reference, after=reference)
        value = compare(self.state, **arguments)
        pins = operations._snapshots(self.state, 'source.compare', arguments, value)
        self.assertEqual({p['kind'] for p in pins}, {'cases', 'artifacts'})
        missing = copy.deepcopy(value)
        missing['before'].pop('crc32')
        with self.assertRaises(InputError):
            operations._snapshots(self.state, 'source.compare', arguments, missing)
        folder = self.state / 'artifacts' / plan['artifact_id']
        report = json.loads((folder / 'report.json').read_text())
        report['result']['collection_coverage'] = 'changed-after-capture'
        storage.write_json(folder / 'report.json', report)
        receipt = json.loads((folder / 'receipt.json').read_text())
        receipt['report_sha256'] = hashlib.sha256((folder / 'report.json').read_bytes()).hexdigest()
        storage.write_json(folder / 'receipt.json', receipt)
        with self.assertRaises(InputError):
            operations._snapshots(self.state, 'source.compare', arguments, value)


if __name__ == '__main__':
    unittest.main()
