"""Offline proposals preserve unrelated bytes; rollback is conditional, never applied."""
from pathlib import Path
import os
import tempfile
import unittest

from src.techexpert import artifacts
from src.techexpert.inputs import InputError
from src.techexpert import logcfg

NS = 'http://v8.1c.ru/v8/tech-log'
BASE = ('\ufeff<?xml version="1.0" encoding="UTF-8"?>\r\n'
        '<config xmlns="'+NS+'">\r\n  <!-- сохранено администратором -->\r\n'
        '  <dump create="false"/>\r\n  <log location="C:\\old" history="24"><event><eq property="name" value="EXCP"/></event></log>\r\n'
        '</config>\r\n').encode('utf-8')


def settings(path=None, **extra):
    return dict(current_file=str(path) if path else None, current_absent=path is None,
        node='client-a', os='windows', mode='file', process='client', platform_version='8.3.27.1989',
        config_path='C:\\1c\\conf\\logcfg.xml', log_location='C:\\tj\\incident', events=['CALL','SCALL','SDBL','EXCP'],
        history_hours=1, duration_seconds=300, max_bytes=16*1024**2, purpose='Проверить задержку операции', **extra)


class LogcfgTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root/'private'
        self.current = self.root/'supplied.xml'
        self.current.write_bytes(BASE)

    def prepare(self, raw=None, **changes):
        if raw is not None: self.current.write_bytes(raw)
        args=settings(self.current); args.update(changes)
        return logcfg.prepare(self.state, **args)

    def read(self, report, name):
        source=next(s for s in report['sources'] if s.get('file_name')==name)
        return artifacts.source_path(artifacts.artifact_folder(self.state,report['artifact_id']),source).read_bytes()

    def rollback(self, proposal, raw):
        self.current.write_bytes(raw)
        return logcfg.rollback_plan(self.state, proposal_id=proposal['artifact_id'], current_file=str(self.current))

    def test_preserves_original_bytes_and_declares_unverified_live_application(self):
        proposal=self.prepare(); result=proposal['result']
        self.assertEqual(result['status'],'ready')
        proposed=self.read(proposal,'logcfg.xml')
        self.assertEqual(proposed.replace(result['inserted_text'].encode('utf-8'),b''),BASE)
        self.assertEqual(self.current.read_bytes(),BASE)
        self.assertEqual(self.read(proposal,'original-logcfg.xml'),BASE)
        self.assertIn(b'<property name="all"/>',proposed)
        self.assertIn(b'format="text"',proposed)
        self.assertEqual(result['validation']['application'],'not_applied')
        self.assertEqual(result['validation']['event_arrival'],'unknown')
        self.assertFalse(result['collection_plan']['limits_enforced_by_xml'])
        self.assertIn('history',result['collection_plan']['retention_note'])
        self.assertEqual(result['collection_plan']['scope'],'all matching events from every process using this configuration')
        self.assertFalse(result['collection_plan']['process_or_infobase_filter_generated'])
        self.assertTrue(self.read(proposal,'change.diff').startswith(b'--- supplied'))

    def test_new_config_requires_reported_absence_and_rolls_back_to_removal_plan(self):
        report=logcfg.prepare(self.state,**settings())
        raw=self.read(report,'logcfg.xml')
        rollback=self.rollback(report,raw)
        self.assertEqual(rollback['result']['action'],'remove_file')
        self.assertNotIn('logcfg.xml',[s['file_name'] for s in rollback['sources']])
        self.assertEqual(self.current.read_bytes(),raw)

    def test_exact_rollback_restores_bom_crlf_and_original_dumps(self):
        report=self.prepare()
        rollback=self.rollback(report,self.read(report,'logcfg.xml'))
        self.assertEqual(rollback['result']['status'],'ready')
        self.assertEqual(self.read(rollback,'logcfg.xml'),BASE)
        self.assertEqual(rollback['result']['parent']['id'],report['artifact_id'])

    def test_later_unrelated_changes_survive_rollback(self):
        report=self.prepare()
        raw=self.read(report,'logcfg.xml').replace(b'create="false"',b'create="true"')
        rollback=self.rollback(report,raw)
        self.assertEqual(self.read(rollback,'logcfg.xml'),BASE.replace(b'create="false"',b'create="true"'))
        self.assertEqual(rollback['result']['rollback_basis'],'unchanged_owned_block')

    def test_modified_missing_or_duplicate_owned_block_conflicts(self):
        report=self.prepare(); raw=self.read(report,'logcfg.xml'); block=report['result']['inserted_text'].encode('utf-8')
        for changed in (raw.replace(b'format="text"',b'format="json"'),raw.replace(block,b'').replace(b'create="false"',b'create="true"'),raw.replace(block,block+block)):
            rollback=self.rollback(report,changed)
            self.assertEqual(rollback['result']['status'],'needs_review')
            self.assertNotIn('logcfg.xml',[s['file_name'] for s in rollback['sources']])

    def test_already_original_is_no_change(self):
        report=self.prepare(); rollback=self.rollback(report,BASE)
        self.assertEqual(rollback['result']['status'],'no_change')

    def test_existing_empty_file_does_not_prove_original_absence(self):
        report=logcfg.prepare(self.state,**settings())
        rollback=self.rollback(report,b'')
        self.assertEqual(rollback['result']['status'],'needs_review')
        self.assertNotEqual(rollback['result'].get('rollback_basis'),'exact_original')

    def test_windows_reserved_device_aliases_are_portably_rejected(self):
        for part in ('COM¹','LPT²','COM³.txt','NUL .txt','CONIN$','CONOUT$.xml'):
            with self.subTest(part=part),self.assertRaises(InputError):self.prepare(log_location='C:\\tj\\'+part)

    def test_retention_cannot_be_shorter_than_the_proposed_observation(self):
        with self.assertRaisesRegex(InputError,'retention'): self.prepare(duration_seconds=86400,history_hours=1)
        report=self.prepare(duration_seconds=86400,history_hours=24)
        self.assertEqual(report['result']['status'],'ready')

    def test_prefixed_and_self_closing_roots_preserve_original_on_exact_rollback(self):
        for raw in (('<t:config xmlns:t="'+NS+'"><t:dump create="false"/></t:config>').encode(),
                    ('<?xml version="1.0"?><config xmlns="'+NS+'" />\n').encode()):
            report=self.prepare(raw)
            self.assertEqual(report['result']['status'],'ready',report)
            rollback=self.rollback(report,self.read(report,'logcfg.xml'))
            self.assertEqual(self.read(rollback,'logcfg.xml'),raw)

    def test_self_closing_root_preserves_later_added_rule(self):
        report=self.prepare(('<config xmlns="'+NS+'"/>').encode())
        raw=self.read(report,'logcfg.xml').replace(b'</config>',b'<dump create="false"/></config>')
        rollback=self.rollback(report,raw)
        self.assertIn(b'<dump create="false"/>',self.read(rollback,'logcfg.xml'))

    def test_existing_same_destination_needs_review_instead_of_double_writer(self):
        report=self.prepare(log_location='c:\\OLD')
        self.assertEqual(report['result']['status'],'needs_review')
        self.assertEqual(report['result']['reason'],'destination_already_configured')

    def test_invalid_unsupported_or_expanding_xml_retains_input_without_ready_file(self):
        for raw in (b'<config>',b'<!DOCTYPE config [<!ENTITY a "x">]><config>&a;</config>',b'<wrong/>',
                    b'<?xml version="1.0" encoding="windows-1251"?><config/>',b'\xff',
                    ('<config xmlns="'+NS+'">'+'<a>'*33+'</a>'*33+'</config>').encode()):
            report=self.prepare(raw)
            self.assertEqual(report['result']['status'],'needs_review')
            self.assertEqual(self.read(report,'original-logcfg.xml'),raw)
            self.assertNotIn('logcfg.xml',[s['file_name'] for s in report['sources']])

    def test_rejects_unbounded_or_inconsistent_plans_without_reading_target_paths(self):
        invalid=[dict(current_absent=True),dict(events=['ALL']),dict(events=[]),dict(events=['CALL','CALL']),
            dict(process='rphost'),dict(duration_seconds=0),dict(max_bytes=0),dict(history_hours=0),
            dict(platform_version='8.3.24.1'),dict(config_path='C:\\ib\\1Cv8.1CD'),dict(log_location='relative'),
            dict(config_path='C:\\conf\\..\\logcfg.xml'),dict(log_location='C:\\tj\\%USERNAME%')]
        for changes in invalid:
            with self.subTest(changes=changes),self.assertRaises(InputError): self.prepare(**changes)

    def test_linux_and_server_paths_are_reported_not_probed(self):
        report=self.prepare(os='linux',mode='server',process='rphost',config_path='/opt/1cv8/x86_64/8.3.27.1989/conf/logcfg.xml',log_location='/var/log/onec/incident')
        self.assertEqual(report['result']['status'],'ready')
        self.assertEqual(report['result']['target']['basis'],'caller_reported')
        self.assertIn('service',report['result']['access']['principal'])

    def test_permission_failure_is_bounded_actionable_error(self):
        from unittest.mock import patch
        with patch.object(logcfg,'read_snapshot',side_effect=PermissionError('denied')):
            with self.assertRaisesRegex(InputError,'read access'): self.prepare()

    def test_attribute_characters_are_escaped_and_round_trip_in_xml(self):
        report=self.prepare(log_location='C:\\tj\\a&b')
        self.assertEqual(report['result']['status'],'ready')
        self.assertIn(b'a&amp;b',self.read(report,'logcfg.xml'))

    def test_diff_separates_changed_lines_without_final_newline(self):
        report=self.prepare(('<config xmlns="'+NS+'"/>').encode())
        diff=self.read(report,'change.diff')
        self.assertNotIn(b'/>+<',diff)
        self.assertIn(b'\n+<',diff)

    def test_too_large_input_is_rejected_before_xml_parsing(self):
        from src.techexpert.logcfg_xml import MAX_BYTES
        with self.assertRaisesRegex(InputError,'byte limit'): self.prepare(b' '*(MAX_BYTES+1))


class LogcfgDiscoveryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.image = self.root / '1cv8' / '8.3.27.1989' / 'bin' / '1cv8.exe'
        self.user = self.root / 'account'
        self.machine = self.root / 'program'
        self.version_conf = self.image.parent / 'conf'
        self.user_conf = self.user / '1C' / '1cv8' / 'conf'
        self.machine_conf = self.machine / '1C' / '1cv8' / 'conf'

    def find(self):
        from src.techexpert.logcfg_discovery import find
        return find(self.image, self.user, self.machine)

    def place(self, directory, name='logcfg.xml', content=BASE):
        target = directory / name
        directory.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def test_logcfg_search_uses_documented_order_and_stops_at_the_first_candidate(self):
        shared = self.root / 'shared'
        redirect = ('ConfLocation=' + str(shared) + '\r\n').encode('utf-8-sig')
        self.place(self.version_conf, 'conf.cfg', redirect)
        paths = [self.place(path) for path in (self.version_conf, self.user_conf, shared, self.machine_conf)]
        for index, tier in enumerate(('version', 'user', 'shared', 'all_users')):
            with self.subTest(tier=tier):
                observed = self.find()
                self.assertEqual(observed['status'], 'found')
                self.assertEqual(observed['tier'], tier)
                self.assertEqual(observed['file'], paths[index])
                self.assertEqual([row['status'] for row in observed['checked']], ['not_found'] * index + ['found'])
                paths[index].unlink()
        self.assertEqual(self.find()['status'], 'config_file_not_found')

    def test_logcfg_search_keeps_unreadable_or_unresolved_higher_precedence(self):
        from unittest.mock import patch
        from src.techexpert import input_files

        lower = self.place(self.machine_conf)
        redirect = self.place(self.version_conf, 'conf.cfg', b'ConfLocation=relative-to-somewhere\n')
        observed = self.find()
        self.assertEqual(observed['status'], 'shared_location_unresolved')
        self.assertNotIn('all_users', [row['tier'] for row in observed['checked']])

        redirect.unlink()
        first = self.place(self.version_conf)
        original = input_files.observe
        def observe(path):
            self.assertNotEqual(path, lower)
            if path == first:
                raise PermissionError('synthetic inaccessible higher priority')
            return original(path)
        with patch.object(input_files, 'observe', side_effect=observe):
            observed = self.find()
        self.assertEqual(observed['status'], 'access_denied')
        self.assertEqual(observed['checked'], [{'tier': 'version', 'status': 'access_denied'}])

    def test_logcfg_search_detects_new_higher_precedence_file_during_read(self):
        from unittest.mock import patch
        from src.techexpert import logcfg_discovery

        lower = self.place(self.user_conf)
        current = dict(image=str(self.image), platform_version='8.3.27.1989', role='thick_client')
        read = logcfg_discovery._read
        def read_then_change(path, *args):
            self.assertEqual(path, lower)
            stored = read(path, *args)
            self.place(self.version_conf)
            return stored
        with patch.object(logcfg_discovery, '_client', return_value=current), \
                patch.object(logcfg_discovery, '_read', side_effect=read_then_change), \
                patch.dict(os.environ, LOCALAPPDATA=str(self.user), ALLUSERSPROFILE=str(self.machine)):
            info, snapshot = logcfg_discovery.observe(1, stop=lambda: False)
        self.assertEqual(info['status'], 'configuration_search_changed')
        self.assertIsNone(snapshot)

    def test_logcfg_search_requires_a_known_installation_root_for_the_shared_default(self):
        from unittest.mock import patch

        expected = self.place(self.root / '1cv8' / 'conf')
        with patch.dict(os.environ, ProgramFiles=str(self.root / 'different-programs')):
            self.assertEqual(self.find()['status'], 'shared_location_unresolved')
        with patch.dict(os.environ, ProgramFiles=str(self.root)):
            observed = self.find()
        self.assertEqual((observed['tier'], observed['file']), ('shared', expected))

    def test_file_lookup_requires_one_observable_client_using_the_exact_file(self):
        from unittest.mock import patch
        from src.techexpert import logcfg_discovery as discovery

        path = self.place(self.root, '1Cv8.1CD', b'disposable file')
        clients = {10: self.image, 20: self.image.with_name('1cv8c.exe'), 30: self.root / 'indexer.exe'}
        def identity(pid):
            return dict(state='running', lifetime=str(pid + 100))
        with patch.object(discovery.fs, 'process_identity', side_effect=identity), \
                patch.object(discovery.windows_native, 'process_image', side_effect=clients.__getitem__), \
                patch.object(discovery.windows_native, 'file_open_processes') as holders:
            holders.return_value = [(10, '110'), (30, '130')]
            first = discovery._file_client(path)
            holders.assert_called_once_with(path)
            self.assertEqual((first['pid'], first['lifetime']), (10, '110'))
            self.assertEqual(first['path'], str(path))
            path.write_bytes(b'ordinary database writes can change its size')
            self.assertEqual(discovery._file_client(path), first)
            for rows, status in (([(10, '110'), (20, '120')], 'client_ambiguous'),
                                 ([(10, '110'), (20, '119')], 'client_observation_unresolved'),
                                 ([(30, '130')], 'client_not_found')):
                with self.subTest(status=status):
                    holders.return_value = rows
                    with self.assertRaisesRegex(discovery.DiscoveryError, status):
                        discovery._file_client(path)

    @unittest.skipUnless(os.name == 'nt', 'Windows file-base process lookup')
    def test_file_lookup_rechecks_the_holder_after_reading_configuration(self):
        from unittest.mock import patch
        from src.techexpert import logcfg_discovery as discovery

        database = self.place(self.root, '1Cv8.1CD', b'disposable file')
        first = dict(pid=10, lifetime='110')
        snapshot = dict(process=dict(process=dict(pid=10, lifetime='110')))
        with patch.object(discovery, '_file_client', side_effect=[first, dict(first, pid=20, lifetime='120')]) as holder, \
                patch.object(discovery, 'observe', return_value=(dict(status='found'), snapshot)):
            info, result = discovery.observe_file(f'File="{self.root}";', stop=lambda: False)
        self.assertEqual([call.args for call in holder.call_args_list], [(database,), (database,)])
        self.assertEqual(info['status'], 'file_client_association_changed')
        self.assertIsNone(result)
