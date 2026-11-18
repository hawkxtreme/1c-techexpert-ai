"""A reviewed update keeps existing packages, private state and interrupted staging."""
import hashlib
import json
from pathlib import Path
import py_compile
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts.package_plugin import build
from src.techexpert.inputs import InputError


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root/'private'
        self.bundle = self.root/'kit.zip'
        build(self.bundle)

    def check(self):
        from src.techexpert.updates import check
        return check(self.state,self.bundle)

    def stage(self,report,sha=None):
        from src.techexpert.updates import stage
        return stage(self.state,report['plan'],expected_sha256=sha or report['plan_sha256'])

    def test_assessment_is_passive_and_stage_requires_exact_approved_plan(self):
        preview=self.check()
        self.assertFalse(self.state.exists())
        with self.assertRaisesRegex(InputError,'plan digest'):
            self.stage(preview,'f'*64)
        self.assertFalse(self.state.exists())
        staged=self.stage(preview)
        self.assertEqual(staged['status'],'staged')
        self.assertTrue(self.stage(preview)['replayed'])
        self.assertFalse((self.state/'updates/.agents/plugins/marketplace.json').exists())

    def test_interrupted_stage_keeps_files_and_refuses_to_publish_or_repeat(self):
        from src.techexpert import updates
        preview=self.check()
        with patch.object(updates,'_unpack',side_effect=OSError('interrupted')):
            with self.assertRaises(OSError):
                self.stage(preview)
        with self.assertRaisesRegex(InputError,'incomplete stage'):
            self.stage(preview)
        self.assertFalse((self.state/'updates/.agents/plugins/marketplace.json').exists())

    def test_activation_refuses_indeterminate_activity_and_unsupported_saved_schema(self):
        from src.techexpert.updates import select_plan,select
        from src.techexpert.update_state import inspect_state
        edition=self.stage(self.check())['release_id']
        profile=self.state/'profiles/current.json'
        profile.parent.mkdir(parents=True)
        profile.write_text(json.dumps(dict(schema_version=999)),encoding='utf-8')
        self.assertEqual(inspect_state(self.state)['schemata']['profiles'],[999])
        with self.assertRaisesRegex(InputError,'saved state schema'):
            select_plan(self.state,edition)
        profile.unlink()
        preview=select_plan(self.state,edition)
        operation=self.state/'operations'/hashlib.sha256(b'incomplete').hexdigest()
        operation.mkdir(parents=True)
        with self.assertRaisesRegex(InputError,'safe point'):
            select(self.state,preview['plan'],expected_sha256=preview['plan_sha256'])
        self.assertFalse((self.state/'updates/.agents/plugins/marketplace.json').exists())

    def test_first_selection_publishes_only_the_checked_local_marketplace_pointer(self):
        from src.techexpert.updates import select_plan,select,selected
        edition=self.stage(self.check())['release_id']
        preview=select_plan(self.state,edition)
        response=select(self.state,preview['plan'],expected_sha256=preview['plan_sha256'])
        self.assertEqual(response['status'],'selected_for_install')
        self.assertEqual(selected(self.state)['release_id'],edition)
        manifest=Path(response['marketplace_root'])/'.agents/plugins/marketplace.json'
        self.assertIn(edition,json.loads(manifest.read_bytes())['plugins'][0]['source']['path'])
        self.assertFalse(response['installation_verified'])
        self.assertTrue(select(self.state,preview['plan'],expected_sha256=preview['plan_sha256'])['replayed'])

    def test_source_export_writer_blocks_selection_only_while_held(self):
        from src.techexpert import operation_state as fs
        from src.techexpert.update_state import inspect_state
        from src.techexpert.updates import select, select_plan

        edition = self.stage(self.check())['release_id']
        preview = select_plan(self.state, edition)
        exports = self.state / 'source-exports'
        marker = exports / 'writer.lock'
        self.assertFalse(exports.exists())
        exports.mkdir()
        with fs.writer(exports):
            self.assertEqual(inspect_state(self.state)['activity'], 'active')
            with self.assertRaisesRegex(InputError, 'safe point'):
                select(self.state, preview['plan'], expected_sha256=preview['plan_sha256'])
        before = marker.read_bytes(), marker.stat().st_mtime_ns
        self.assertEqual(inspect_state(self.state)['activity'], 'idle_observed')
        self.assertEqual((marker.read_bytes(), marker.stat().st_mtime_ns), before)
        self.assertEqual(select(self.state, preview['plan'],
            expected_sha256=preview['plan_sha256'])['status'], 'selected_for_install')

    def test_case_source_registry_is_active_only_during_owned_write(self):
        from src.techexpert import case_retention, operation_state as fs
        from src.techexpert.update_state import inspect_state

        identifier = '1' * 32
        registry = case_retention.registry(self.state, identifier)
        self.assertEqual(inspect_state(self.state)['activity'], 'idle_observed')
        self.assertFalse(registry.exists())
        with fs.writer(fs.private(registry)):
            current = inspect_state(self.state)
            self.assertEqual(current['activity'], 'active')
            self.assertIn(dict(kind='case-sources', id=identifier, status='active'), current['problems'])
        self.assertEqual(inspect_state(self.state)['activity'], 'idle_observed')

    def test_observed_retirement_requires_a_compatible_reader_after_a_completed_write(self):
        from src.techexpert import case_retention, operation_state as fs
        from src.techexpert.release_packages import read_package
        from src.techexpert.update_state import inspect_state, supports

        case_id = '2' * 32
        target = self.state / 'cases' / case_id / 'sources/s1.bin'
        registry = fs.private(case_retention.registry(self.state, case_id) / 's1')
        plan = dict(schema_version=1, kind='case_source_snapshot_v1', case_id=case_id, source_id='s1',
                    policy=None, report_sha256='a'*64, file=dict(path=str(target), identity=dict(bytes=12), sha256='b'*64),
                    impact=dict(investigations=[], comparisons=[]))
        intent = dict(schema_version=1, plan=plan, plan_sha256=fs.digest(plan), admitted_at=fs.stamp())
        fs.write(registry/'intent.json', intent)
        unresolved = inspect_state(self.state)
        self.assertEqual(unresolved['activity'], 'unresolved')
        self.assertEqual(unresolved['schemata']['case-source-retirements'], [1])
        record = dict(schema_version=1, status='removed', intent_sha256=fs.digest(intent),
                      removed_at=fs.stamp(), logical_bytes_removed=12)
        fs.write(registry/'receipt.json', dict(record=record, sha256=fs.digest(record)))
        observed = inspect_state(self.state)
        self.assertEqual(observed['activity'], 'idle_observed')
        package = read_package(self.bundle)
        self.assertFalse(supports(package['metadata'], observed['schemata']))
        self.assertTrue(supports(package['metadata'], observed['schemata'],
                                 case_retirement_schemas=package['case_retirement_schemas']))
        self.assertTrue(self.check()['state_schema_compatible'])

    def test_retired_report_history_requires_a_reader_that_respects_its_receipt(self):
        from src.techexpert import investigation_retention, investigations
        from src.techexpert.release_packages import read_package
        from src.techexpert.update_state import inspect_state, supports

        report = investigations.create(self.state, {'task':'Проверка обновления после очистки отчётов'})
        preview = investigation_retention.preview(self.state, report['investigation_id'])
        result = investigation_retention.apply(self.state, preview['plan'], expected_sha256=preview['plan_sha256'])
        self.assertEqual(result['status'], 'removed')
        observed = inspect_state(self.state)
        self.assertEqual(observed['activity'], 'idle_observed')
        self.assertEqual(observed['schemata']['investigation-report-retirements'], [1])
        package = read_package(self.bundle)
        self.assertFalse(supports(package['metadata'], observed['schemata']))
        self.assertTrue(supports(package['metadata'], observed['schemata'],
                                 report_retirement_schemas=package['report_retirement_schemas']))
        self.assertTrue(self.check()['state_schema_compatible'])

    def test_saved_reference_window_requires_a_reader_that_preserves_the_selection(self):
        from src.techexpert.release_packages import read_package
        from src.techexpert.storage import investigate
        from src.techexpert.tj_reference import plan
        from src.techexpert.update_state import inspect_state, supports

        package = read_package(self.bundle)
        self.assertTrue(supports(package['metadata'], inspect_state(self.state)['schemata']))
        source = self.root / 'outside.log'
        source.write_bytes(b'2026-11-15T09:04:00.000000-1,CALL,0\n')
        manifest = self.root / 'request.json'
        spec = dict(path=str(source), format='1c-tj-text-v1', platform_version='8.3.27.1989',
                    encoding='utf-8', placement='plain', timestamp_format='iso', utc_offset='+00:00',
                    external_window=dict(start='2026-11-15T09:00:00Z', end='2026-11-15T09:05:00Z', max_retained_bytes=4096))
        manifest.write_text(json.dumps(dict(schema=2, origin='provided', sources=[spec])), encoding='utf-8')
        receipt = plan(manifest, self.state)
        investigate(manifest, self.state, reference_sha256=receipt['plan_sha256'])
        source.rename(self.root / 'rotated.log')
        seen = inspect_state(self.state)
        self.assertEqual(seen['schemata']['tj-reference-windows'], [1])
        self.assertFalse(supports(package['metadata'], seen['schemata']))
        self.assertTrue(supports(package['metadata'], seen['schemata'], tj_reference_schemas=package['tj_reference_schemas']))
        self.assertTrue(self.check()['state_schema_compatible'])

    def test_reviewed_context_policy_requires_a_reader_with_policy_support(self):
        from src.techexpert import context_policy, investigations
        from src.techexpert.release_packages import read_package
        from src.techexpert.update_state import inspect_state, supports

        doc = investigations.create(self.state, {'task':'Ограничение выдачи'})
        args = (self.state, doc['investigation_id'], doc['revision'], ['tj'], 4096)
        preview = context_policy.plan(*args)
        package = read_package(self.bundle)
        self.assertTrue(supports(package['metadata'], inspect_state(self.state)['schemata']))
        context_policy.save(*args, preview['plan_sha256'])
        seen = inspect_state(self.state)
        self.assertEqual(seen['schemata']['context-disclosure'], [1])
        self.assertFalse(supports(package['metadata'], seen['schemata']))
        self.assertTrue(supports(package['metadata'], seen['schemata'],
                                 context_disclosure_schemas=package['context_disclosure_schemas']))
        self.assertTrue(self.check()['state_schema_compatible'])

    def test_retained_intake_requires_its_reader_even_before_policy_approval(self):
        from src.techexpert import context_intake, investigations, operations
        from src.techexpert.release_packages import read_package
        from src.techexpert.storage import ROOT
        from src.techexpert.update_state import inspect_state, supports

        doc = investigations.create(self.state, {'task':'Первичный импорт'})
        request = context_intake.prepare(dict(schema_version=1,operation='case.analyze',
            operation_key='reader-check',executor_id='tests',
            arguments=dict(manifest=str(ROOT/'examples/sc01/case.json')),
            context=dict(investigation_id=doc['investigation_id'],expected_revision=1)))
        saved = operations.run(self.state, request)
        self.assertEqual(saved['status'], 'succeeded')
        observed = inspect_state(self.state)
        self.assertEqual(observed['schemata']['context-intake'], [1])
        self.assertEqual(observed['schemata']['context-disclosure'], [])
        package = read_package(self.bundle)
        self.assertFalse(supports(package['metadata'], observed['schemata']))
        self.assertTrue(supports(package['metadata'], observed['schemata'],
                                 context_intake_schemas=package['context_intake_schemas']))
        self.assertTrue(self.check()['state_schema_compatible'])

    def test_retained_context_program_requires_a_reader_with_its_delivery_gate(self):
        from src.techexpert import context_policy, investigations, operations, storage
        from src.techexpert.release_packages import read_package
        from src.techexpert.update_state import inspect_state, supports

        saved_case = storage.investigate(storage.ROOT/'examples/sc01/case.json', self.state)
        first = investigations.create(self.state, {'task': 'Расчёт по согласованным измерениям'})
        iid = first['investigation_id']
        doc = investigations.revise(self.state, iid, dict(attachments=[
            dict(id='A-1', kind='case', target_id=saved_case['case_id'])]), expected_revision=1)
        approval = (self.state, iid, doc['revision'], ['case'], 4096)
        context_policy.save(*approval, context_policy.plan(*approval)['plan_sha256'])
        compatible = dict(context_disclosure_schemas=[1])
        package = read_package(self.bundle)
        self.assertTrue(supports(package['metadata'], inspect_state(self.state)['schemata'], **compatible))

        request = dict(schema_version=1, operation='code.context', operation_key='check-program-reader',
            executor_id='tests', context=dict(investigation_id=iid, expected_revision=doc['revision']),
            arguments=dict(scope=dict(views=[dict(attachment='A-1', kind='case-summary')]),
                program='view = api("context.read", {"attachment": "A-1", "kind": "case-summary"})\nreturn view["status"]'))
        run = operations.run(self.state, request)
        self.assertEqual(run['status'], 'succeeded', run)
        observed = inspect_state(self.state)
        self.assertEqual(observed['activity'], 'idle_observed')
        self.assertEqual(observed['schemata']['context-program'], [2])
        self.assertEqual(observed['schemata']['operations'], [1])
        self.assertFalse(supports(package['metadata'], observed['schemata'], **compatible))
        self.assertTrue(supports(package['metadata'], observed['schemata'], **compatible,
                                 check_history_schemas=package['check_history_schemas'],
                                 context_program_schemas=package['context_program_schemas']))
        self.assertTrue(self.check()['state_schema_compatible'])

    def test_tampered_staged_file_cannot_be_selected(self):
        from src.techexpert.updates import select_plan
        from src.techexpert import operation_state as fs
        staged=self.stage(self.check())
        target=Path(staged['bundle_root'])/'techexpert.py'
        target.write_bytes(b'different')
        receipt=target.parent.parent/'stage.json'
        evidence=fs.read(receipt)
        evidence['record']['files']['techexpert.py']=dict(bytes=9,sha256=hashlib.sha256(b'different').hexdigest())
        fs.write(receipt,dict(record=evidence['record'],sha256=fs.digest(evidence['record'])))
        with self.assertRaisesRegex(InputError,'staged package'):
            select_plan(self.state,staged['release_id'])

    def test_malformed_stage_receipt_reports_an_input_error(self):
        from src.techexpert.updates import select_plan
        staged=self.stage(self.check())
        receipt=Path(staged['bundle_root']).parent/'stage.json'
        receipt.write_bytes(b'[]')
        with self.assertRaisesRegex(InputError,'receipt'):
            select_plan(self.state,staged['release_id'])

    def test_only_bytecode_matching_its_checked_source_can_be_replaced(self):
        from src.techexpert import updates
        data=b'value = "known installation"\n'
        expected={'sample.py':dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())}
        root=self.root/'installed'
        root.mkdir()
        dest=root/'sample.py'
        dest.write_bytes(data)
        cache=Path(py_compile.compile(str(dest),doraise=True))
        updates._verify_tree(root,expected,installed=True)
        payload=bytearray(cache.read_bytes())
        payload[-1] ^= 1
        cache.write_bytes(payload)
        with self.assertRaisesRegex(InputError,'bytecode'):
            updates._verify_tree(root,expected,installed=True)

    def test_interrupted_codex_response_reconciles_by_cache_without_reinstall(self):
        from src.techexpert import update_codex, updates
        from src.techexpert.processes import CommandStopped
        stage=self.stage(self.check())
        profile=self.root/'codex-profile'
        profile.mkdir()
        probe=update_codex.plan_install(self.state,stage['release_id'],profile,maintenance_window=True)
        root=self.state/'updates'
        issued=[]
        registered=[]

        def command(*args):
            issued.append(args)
            if args[:3]==('plugin','marketplace','list'):
                return dict(marketplaces=registered)
            if args[:3]==('plugin','marketplace','add'):
                registered.append(dict(name=updates.MARKETPLACE,root=str(root)))
                return {}
            if args[:2]==('plugin','add'):
                target=profile/'plugins/cache'/updates.MARKETPLACE/'1c-techexpert-ai'/stage['version']
                shutil.copytree(stage['bundle_root'],target)
                (profile/'config.toml').write_text('[plugins."'+updates.SELECTOR+'"]\nenabled = true\n',encoding='utf-8')
                raise CommandStopped('timeout',process_started=True)
            raise AssertionError(args)

        with patch.object(update_codex,'_command',return_value=command):
            with self.assertRaises(CommandStopped):
                update_codex.install(self.state,probe['plan'],expected_sha256=probe['plan_sha256'])
            result=update_codex.install(self.state,probe['plan'],expected_sha256=probe['plan_sha256'])
        self.assertTrue(result['installation_verified'] and result['replayed'])
        self.assertEqual(sum(args[:2]==('plugin','add') for args in issued),1)

    def test_exact_codex_cache_requires_registration(self):
        from src.techexpert import update_codex, updates
        stage=self.stage(self.check())
        profile=self.root/'codex-profile'
        cache=profile/'plugins/cache'/updates.MARKETPLACE/'1c-techexpert-ai'/stage['version']
        shutil.copytree(stage['bundle_root'],cache)
        probe=update_codex.plan_install(self.state,stage['release_id'],profile,maintenance_window=True)
        issued=[]
        def command(*args):
            issued.append(args)
            if args[:3]==('plugin','marketplace','list'):
                return dict(marketplaces=[dict(name=updates.MARKETPLACE,root=str(self.state/'updates'))])
            if args[:2]==('plugin','add'):
                (profile/'config.toml').write_text('[plugins."'+updates.SELECTOR+'"]\nenabled = true\n',encoding='utf-8')
                return dict(pluginId=updates.SELECTOR,version=stage['version'],installedPath=str(cache))
            raise AssertionError(args)
        with patch.object(update_codex,'_command',return_value=command):
            result=update_codex.install(self.state,probe['plan'],expected_sha256=probe['plan_sha256'])
            self.assertTrue(result['installation_verified'])
            self.assertEqual(sum(args[:2]==('plugin','add') for args in issued),1)
            (profile/'config.toml').write_text('',encoding='utf-8')
            with self.assertRaisesRegex(InputError,'outcome is unresolved'):
                update_codex.install(self.state,probe['plan'],expected_sha256=probe['plan_sha256'])
        self.assertEqual(sum(args[:2]==('plugin','add') for args in issued),1)
