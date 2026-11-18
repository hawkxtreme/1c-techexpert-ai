"""Controlled SQLite fixtures for the observed LGD profile."""
from contextlib import closing
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from zipfile import ZipFile

from src.techexpert import artifacts, input_intake, native_jr
from src.techexpert.inputs import InputError


DATE = datetime(2026, 11, 16, 9, 0)
TICKS = (DATE - datetime(1, 1, 1)).days * 86400 * 10000 + 9 * 3600 * 10000
VERSION = '8.3.27.1989'
SQLITE_PROFILE = '1c-jr-lgd-eventlog-v1'


def write_lgd(path, *, last_time=TICKS+20000):
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript('''
            CREATE TABLE EventLog (
                rowID INTEGER PRIMARY KEY, severity INTEGER, date INTEGER, connectID INTEGER,
                session INTEGER, transactionStatus INTEGER, transactionDate INTEGER, transactionID INTEGER,
                userCode INTEGER, computerCode INTEGER, appCode INTEGER, eventCode INTEGER,
                comment TEXT, metadataCodes TEXT, sessionDataSplitCode INTEGER, dataType INTEGER,
                data TEXT, dataPresentation TEXT, workServerCode INTEGER, primaryPortCode INTEGER,
                secondaryPortCode INTEGER
            );
            CREATE TABLE EventCodes (code INTEGER PRIMARY KEY, name TEXT);
            CREATE TABLE UserCodes (code INTEGER PRIMARY KEY, name TEXT, uuid TEXT);
            CREATE TABLE ComputerCodes (code INTEGER PRIMARY KEY, name TEXT);
            CREATE TABLE AppCodes (code INTEGER PRIMARY KEY, name TEXT);
            CREATE TABLE MetadataCodes (code INTEGER PRIMARY KEY, name TEXT, uuid TEXT);
            CREATE TABLE EventLogMetadata (eventLogID INTEGER, metadataCode INTEGER);
            INSERT INTO EventCodes VALUES (1, 'Test.JobMarker');
            INSERT INTO UserCodes VALUES (1, 'fixture-account', NULL);
            INSERT INTO ComputerCodes VALUES (1, 'fixture-node');
            INSERT INTO AppCodes VALUES (1, 'BackgroundJob');
            INSERT INTO MetadataCodes VALUES (1, 'Document.Order', NULL), (2, 'Document.Invoice', NULL);
            INSERT INTO EventLogMetadata VALUES (30, 1), (30, 1), (30, 2), (90, 1);
        ''')
        query = '''INSERT INTO EventLog (rowID, severity, date, connectID, session, transactionStatus,
                    userCode, computerCode, appCode, eventCode, comment, data) VALUES
                    (?, 1, ?, 12, 42, 3, 1, 1, 1, 1, 'private-test-marker', '{"S","fixture"}')'''
        connection.executemany(query, ((30,TICKS+1),(50,TICKS+2),(90,last_time)))
        connection.commit()


class SQLiteJRTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.input = self.root/'selected'
        self.input.mkdir()
        self.source = self.input/'1Cv8.lgd'
        self.state = self.root/'state'

    def test_saved_sqlite_window_keeps_exact_row_and_avoids_join_duplication(self):
        write_lgd(self.source)
        raw = self.source.read_bytes()
        saved = native_jr.read_journal(self.state,self.input,consistency='provided_snapshot')
        identifier = saved['artifact_id']
        self.assertEqual(saved['kind'],'native-jr')
        self.assertEqual(saved['result']['profile'],SQLITE_PROFILE)
        self.assertEqual(saved['result']['event_count'],3)
        self.assertEqual(saved['result']['status'],'parsed')
        self.assertEqual(saved['sources'][0]['sha256'],sha256(raw).hexdigest())
        self.assertIsNone(saved['result']['writer_version'])
        self.source.rename(self.root/'saved-original.lgd')

        window = dict(start='2026-11-16T12:00:00+03:00',end='2026-11-16T09:00:02Z')
        readback = native_jr.list_events(self.state,identifier,window=window)
        self.assertEqual(readback['profile'],SQLITE_PROFILE)
        self.assertEqual(readback['total_matched'],2)
        self.assertEqual(readback['coverage']['time_basis'],'native_utc_second_precision')
        row, other = readback['records']
        self.assertEqual(row['id'],'s1:r1')
        self.assertEqual(row['sqlite_row_id'],'30')
        self.assertEqual(other['sqlite_row_id'],'50')
        self.assertEqual(row['timestamp'],'2026-11-16T09:00:00+00:00')
        self.assertEqual(row['stored_timestamp_utc'],'2026-11-16T09:00:00.000100+00:00')
        self.assertEqual(row['event'],'Test.JobMarker')
        self.assertEqual(row['user'],'fixture-account')
        self.assertEqual(row['metadata_values'],['Document.Order','Document.Invoice'])
        self.assertIsNone(row['byte_start'])
        self.assertIsNone(row['job_identity'])
        self.assertIsNone(row['database_identity'])
        self.assertNotIn('row_values',row)
        proof = native_jr.read_record(self.state,identifier,row['id'])
        self.assertEqual(proof['text_basis'],'sqlite_row_projection')
        self.assertEqual(proof['source_sha256'],saved['sources'][0]['sha256'])
        self.assertEqual(sha256(proof['text'].encode()).hexdigest(),row['sha256'])
        self.assertEqual(json.loads(proof['text'])['rowID'],30)
        with self.assertRaisesRegex(InputError,'jr.record'):
            artifacts.artifact_evidence(self.state,identifier,'s1')

    def test_missing_time_in_valid_row_is_unknown(self):
        write_lgd(self.source,last_time=None)
        report = native_jr.read_journal(self.state,self.source,consistency='provided_snapshot')
        page = native_jr.list_events(self.state,report['artifact_id'],window=dict(
            start='2026-11-16T09:00:00Z',end='2026-11-16T09:00:01Z'))
        self.assertEqual(report['result']['status'],'partial')
        self.assertEqual(page['coverage']['unplaced_records'],1)
        self.assertFalse(page['coverage']['can_establish_absence'])

    def test_wrong_schema_sidecar_and_ambiguous_directory_fail_before_saved_product(self):
        with closing(sqlite3.connect(self.source)) as wrong:
            wrong.execute('CREATE TABLE arbitrary (name TEXT)')
        with self.assertRaisesRegex(InputError,'LGD schema'):
            native_jr.read_journal(self.state,self.source,consistency='provided_snapshot')
        self.source.unlink()
        write_lgd(self.source)
        with self.assertRaisesRegex(InputError,'LGD.*snapshot'):
            native_jr.read_journal(self.state,self.source)
        with self.assertRaisesRegex(InputError,'LGD.*UTC'):
            native_jr.read_journal(self.state,self.source,consistency='provided_snapshot',utc_offset='+03:00')
        marker = self.input/'1Cv8.lgd-wal'
        marker.touch()
        with self.assertRaisesRegex(InputError,'LGD.*sidecar'):
            native_jr.read_journal(self.state,self.input,consistency='provided_snapshot')
        marker.unlink()
        (self.input/'1Cv8.lgf').touch()
        with self.assertRaisesRegex(InputError,'multiple JR profiles'):
            native_jr.read_journal(self.state,self.input,platform_version=VERSION,consistency='provided_snapshot')
        self.assertFalse(self.state.exists())

    def test_selected_zip_reads_main_member_and_refuses_an_unselected_sidecar(self):
        from src.techexpert.input_adapters import import_selected

        write_lgd(self.source)
        for has_sidecar in (False,True):
            path = self.root/('sidecar.zip' if has_sidecar else 'snapshot.zip')
            with ZipFile(path,'w') as archive:
                archive.write(self.source,'journal/1Cv8.lgd')
                if has_sidecar:
                    archive.writestr('journal/1Cv8.lgd-wal',b'')
            selected = input_intake.inspect(self.state,[dict(kind='zip',path=str(path))])
            member = next(item['id'] for item in selected['result']['members'] if item['relative_path'].endswith('.lgd'))
            request = dict(path=str(path),input_plan=selected['artifact_id'],members=[member],consistency='provided_snapshot')
            output = self.root/('output-sidecar' if has_sidecar else 'output')
            if has_sidecar:
                with self.assertRaisesRegex(InputError,'LGD.*sidecar'):
                    import_selected('jr.import',request,self.state,output)
                self.assertFalse(output.exists())
            else:
                incomplete=dict(request,consistency='unknown')
                with self.assertRaisesRegex(InputError,'LGD.*snapshot'):
                    import_selected('jr.import',incomplete,self.state,output)
                self.assertFalse(output.exists())
                result = import_selected('jr.import',request,self.state,output)
                self.assertEqual(result['result']['profile'],SQLITE_PROFILE)
                self.assertEqual(result['sources'][0]['input_origin']['member'],'journal/1Cv8.lgd')

    def test_rejects_a_wal_header_and_non_table_dictionary(self):
        write_lgd(self.source)
        original = self.source.read_bytes()
        self.source.write_bytes(original[:18]+b'\x02\x02'+original[20:])
        with self.assertRaisesRegex(InputError,'LGD.*WAL'):
            native_jr.read_journal(self.state,self.source,consistency='provided_snapshot')
        self.source.write_bytes(original)
        with closing(sqlite3.connect(self.source)) as connection:
            connection.execute('ALTER TABLE EventCodes RENAME TO OtherCodes')
            connection.execute('CREATE VIEW EventCodes AS SELECT code,name FROM OtherCodes')
        with self.assertRaisesRegex(InputError,'LGD schema'):
            native_jr.read_journal(self.state,self.source,consistency='provided_snapshot')
        self.assertFalse(self.state.exists())

    def test_retained_remote_import_checks_the_pinned_complete_catalogue(self):
        from src.techexpert import remote_intake, remote_transfers

        write_lgd(self.source)
        raw = self.source.read_bytes()
        uri = 'sftp://fixture@example.test:22/snapshot'
        plan = dict(id='1'*32,report_digest='2'*64,receipt_digest='3'*64)
        selected = dict(id='m1',relative_path='journal/1Cv8.lgd',bytes=len(raw),importable=True)
        companion = dict(id='m2',relative_path='journal/1Cv8.lgd-journal',bytes=0,importable=True)
        for label,members,complete,expected in (
                ('sidecar',[selected,companion],True,'LGD.*sidecar'),
                ('incomplete',[selected],False,'LGD.*complete.*catalogue'),
                ('clean',[selected,dict(companion,relative_path='elsewhere/1Cv8.lgd-journal')],True,None)):
            with self.subTest(label=label):
                catalogue = artifacts.save_artifact(self.state,'remote_catalog',{},[],dict(schema_version=1,
                    profile=remote_transfers.CATALOG,transfer_status='completed',plan=plan,source_id='logs',
                    listing_complete=complete,truncated=not complete,excluded=[],members=members))
                capture = artifacts.save_artifact(self.state,'remote_capture',{},[(uri+'/'+selected['relative_path'],raw)],
                    dict(schema_version=1,profile=remote_intake.PROFILE,capture_complete=True,plan=plan,source_id='logs',
                    catalogue=remote_transfers.dependency(self.state,catalogue),roots=[dict(kind='sftp',path=uri)],
                    members=[dict(selected,root=0,source_id='s1',sha256=sha256(raw).hexdigest())],file_count=1,expanded_bytes=len(raw)))
                output = self.root/label
                arguments = (self.state,output,capture['artifact_id'],'jr',dict(members=['m1'],consistency='provided_snapshot'))
                if expected:
                    with self.assertRaisesRegex(InputError,expected):
                        remote_intake.parse(*arguments)
                    self.assertFalse(output.exists())
                else:
                    result = remote_intake.parse(*arguments)
                    self.assertEqual(result['result']['profile'],SQLITE_PROFILE)
                    self.assertEqual(result['sources'][0]['input_origin']['member'],selected['relative_path'])

    def test_protected_context_requires_policy_and_exposes_only_typed_row_reference(self):
        from src.techexpert import context_disclosure, context_policy, investigations, update_state

        write_lgd(self.source)
        report = native_jr.read_journal(self.state,self.source,consistency='provided_snapshot')
        created = investigations.create(self.state,dict(task='fixture JR question'))
        iid = created['investigation_id']
        attached = investigations.revise(self.state,iid,dict(attachments=[dict(id='A-jr',kind='artifact',
            target_id=report['artifact_id'])]),expected_revision=1)
        request = dict(investigation_id=iid,revision=attached['revision'],kind='jr-events',attachment='A-jr',limit=1)
        blocked = context_disclosure.read(self.state,request)
        self.assertEqual(blocked['stop_reason'],'context_policy_required')
        approval = context_policy.plan(self.state,iid,2,['jr'],8192)
        context_policy.save(self.state,iid,2,['jr'],8192,approval['plan_sha256'])
        result = context_disclosure.read(self.state,request)
        view = result['data']['records'][0]
        self.assertEqual(view['evidence']['sqlite_row_id'],'30')
        self.assertEqual(view['evidence']['evidence_kind'],'sqlite_row_projection')
        self.assertIsNone(view['evidence']['byte_start'])
        self.assertNotIn('private-test-marker',json.dumps(result))
        self.assertNotIn('fixture-account',json.dumps(result))
        self.assertEqual(update_state.inspect_state(self.state)['schemata']['jr-lgd'],[1])
