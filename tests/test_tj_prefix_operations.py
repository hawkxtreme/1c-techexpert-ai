"""The native prefix mode reuses existing bounded and scoped diagnostic APIs."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import operations, input_intake, mcp_tools, storage
from src.techexpert.inputs import InputError
from test_tj_prefix_capture import PROFILE, ROW


class TJPrefixOperationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'state'
        self.log = self.root / '26111609.log'
        self.raw = ROW + b'04:06.000000-0,NEW_EVENT,0,Context="unfinished'
        self.log.write_bytes(self.raw)
        self.manifest = self.root / 'provided.json'
        self.document = dict(schema=1, scenario='SC-01', origin='provided',
            selection=dict(database='reported', node='reported', process='reported', epoch='reported', run='reported'),
            sources=[dict(PROFILE, path=str(self.log), read_mode='tj-prefix-v1')])
        self.manifest.write_text(json.dumps(self.document), encoding='utf-8')

    def request(self, operation, arguments, key):
        return dict(schema_version=1, operation=operation, arguments=arguments, operation_key=key, executor_id='fixture-harness')

    def test_managed_capture_replays_without_original_and_refuses_corrupt_retained_tail(self):
        request = self.request('case.analyze', dict(manifest=str(self.manifest)), 'prefix-capture')
        result = operations.run(self.state, request)
        self.assertEqual(result['status'], 'succeeded', result)
        source = result['data']['sources'][0]
        self.assertEqual(source['acquisition']['method'], 'tj-prefix-v1')
        retained = storage.case_folder(self.state, result['data']['case_id']) / 'sources/s1.bin'
        self.assertEqual(retained.read_bytes(), self.raw)
        self.log.unlink()
        self.manifest.unlink()
        replay = operations.run(self.state, request)
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['data'], result['data'])
        retained.write_bytes(self.raw[:-1] + b'X')
        with self.assertRaises(InputError):
            operations.result(self.state, result['run_id'])

    def test_scoped_program_captures_queries_and_replays_the_same_prefix(self):
        program = '''case = api("case.analyze", {"manifest": manifest})
page = api("case.events", {"case_id": case["data"]["case_id"], "limit": 2})
evidence = api("case.evidence", {"case_id": case["data"]["case_id"], "evidence_id": "s1:1"})
return {"records": page["data"]["matched_count"], "method": case["data"]["sources"][0]["acquisition"]["method"], "end": evidence["data"]["byte_end"]}'''
        args = dict(program=program, bindings=dict(manifest=str(self.manifest)),
            scope=dict(operations=['case.analyze', 'case.events', 'case.evidence'], manifests=[str(self.manifest)]))
        request = self.request('code.execute', args, 'prefix-program')
        result = operations.run(self.state, request)
        self.assertEqual(result['status'], 'succeeded', result)
        self.assertEqual(result['data']['value'], dict(records=1, method='tj-prefix-v1', end=len(ROW)))
        self.assertEqual(result['data']['metrics']['calls_started'], 3)
        self.log.unlink()
        self.manifest.unlink()
        replay = operations.run(self.state, request)
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['data']['value'], result['data']['value'])

    def test_explicit_managed_source_check_reports_prefix_without_creating_a_case(self):
        request = self.request('source.check', dict(manifest=str(self.manifest)), 'prefix-check')
        result = operations.run(self.state, request)
        self.assertEqual(result['status'], 'succeeded', result)
        self.assertEqual(result['data']['sources'][0]['acquisition']['method'], 'tj-prefix-v1')
        self.assertFalse((self.state / 'cases').exists())
        self.assertFalse((self.state / 'artifacts').exists())
        self.assertFalse(result['data']['can_establish_absence'])

    def test_catalogue_mode_cannot_mislabel_staged_member_as_live_original(self):
        plan = input_intake.inspect(self.state, [dict(path=str(self.log), kind='file')])
        self.document['sources'][0]['path'] = 'm1'
        self.manifest.write_text(json.dumps(self.document), encoding='utf-8')
        with patch.object(input_intake, 'capture_selected', side_effect=AssertionError('Live mode created a stage')):
            with self.assertRaisesRegex(InputError, 'stable read mode'):
                input_intake.analyze(self.state, self.root / 'output', self.manifest, plan['artifact_id'])
        self.assertFalse((self.root / 'output').exists())

    def test_mcp_still_uses_the_same_manifest_route_without_new_tools_or_defaults(self):
        self.assertEqual(len(mcp_tools.tools()), 42)
        _, _, request = mcp_tools.prepare('techexpert_case_analyze', dict(operation_key='prefix-sdk', executor_id='fixture', arguments=dict(manifest=str(self.manifest))))
        self.assertEqual(request['arguments'], dict(manifest=str(self.manifest.absolute())))


if __name__ == '__main__':
    unittest.main()
