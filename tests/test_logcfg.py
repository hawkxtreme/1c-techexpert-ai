"""Offline proposals preserve unrelated bytes; rollback is conditional, never applied."""
from pathlib import Path
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
