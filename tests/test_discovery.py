"""Discovery reads selected descriptions, never the databases they describe."""
import hashlib
import importlib
from copy import deepcopy
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert.inputs import InputError

ENTRY='11111111-1111-1111-1111-111111111111'


class StarterDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.api=importlib.import_module('src.techexpert.discovery')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name);self.path=self.folder/'ibases.v8i'

    def write(self,name='Main',connection='Srvr="app";Ref="main";',entry=ENTRY,path=None):
        path=self.path if path is None else path
        path.write_text('['+name+']\nConnect='+connection+'\nID='+entry+'\n',encoding='utf-8-sig')
        return self.api.inspect_starter(path)

    def test_registration_is_scoped_by_list_and_entry_id_and_survives_rename(self):
        first=self.write();identity=first['bases'][0]['id'];registration=first['registrations'][identity][0]
        self.assertEqual(registration['entry_id'],ENTRY);self.assertEqual(registration['source_path'],str(self.path.absolute()))
        self.assertEqual(registration['source_sha256'],hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertNotIn('infobase_id',registration)
        renamed=self.write(name='Renamed');self.assertEqual(renamed['bases'][0]['id'],identity)
        other=self.write(path=self.folder/'shared.v8i');self.assertNotEqual(other['bases'][0]['id'],identity)

    def test_quote_sensitive_parameters_are_preserved_and_credentials_not_returned(self):
        result=self.write(connection='Srvr="app";Ref="orders;main";Usr="reader";Pwd="private-synthetic-secret";')
        base=result['bases'][0];self.assertEqual(base['mode'],'server')
        self.assertEqual(self.api.connection_parameters(base['connection']),{'srvr':'app','ref':'orders;main'})
        self.assertNotIn('reader',str(result));self.assertNotIn('private-synthetic-secret',str(result))

    def test_mixed_or_duplicate_storage_parameters_fail_without_returning_source_text(self):
        for connection in ('File="local";Srvr="app";Ref="db";Pwd="private-synthetic-secret";',
                           'Srvr="app";Srvr="other";Ref="db";', 'File="a";WS="https://example.invalid/ib";'):
            with self.subTest(connection=connection),self.assertRaises(InputError) as caught:self.write(connection=connection)
            self.assertNotIn('private-synthetic-secret',str(caught.exception))

    def test_web_publication_does_not_invent_storage_mode_or_keep_query_credentials(self):
        result=self.write(connection='WS="https://user:private-synthetic-secret@[2001:db8::1]:8443/ib?token=hidden#fragment";')
        base=result['bases'][0];self.assertEqual(base['mode'],'unknown')
        self.assertEqual(base['connection'],'https://[2001:db8::1]:8443/ib')
        self.assertNotIn('private-synthetic-secret',str(result));self.assertNotIn('token=',str(result))

    def test_unc_file_remains_file_and_inspection_follows_no_shared_list(self):
        self.path.write_text('[Network]\nConnect=File="\\\\files.invalid\\bases\\main";\nID='+ENTRY+'\n[Shared]\nCommonInfoBases=\\\\other.invalid\\lists\\shared.v8i\n',encoding='utf-8')
        read=self.api.read_snapshot
        with patch.object(self.api,'read_snapshot',wraps=read) as reader:
            result=self.api.inspect_starter(self.path)
        self.assertEqual(reader.call_count,1);self.assertEqual(result['bases'][0]['mode'],'file')
        self.assertFalse(result['connections_opened']);self.assertNotIn('other.invalid',str(result))

    def test_duplicate_entry_ids_are_ambiguous_instead_of_collapsing_two_rows(self):
        self.path.write_text('[A]\nConnect=File="a";\nID='+ENTRY+'\n[B]\nConnect=File="b";\nID='+ENTRY+'\n',encoding='utf-8')
        with self.assertRaisesRegex(InputError,'ambiguous|duplicate'):self.api.inspect_starter(self.path)

    def test_invalid_connection_and_duplicate_configuration_errors_hide_source_lines(self):
        for connection in ('File="unclosed;Pwd=private-synthetic-secret;', 'File="a";not a parameter private-synthetic-secret'):
            with self.subTest(connection=connection),self.assertRaises(InputError) as caught:self.write(connection=connection)
            self.assertNotIn('private-synthetic-secret',str(caught.exception))

    def test_legacy_entrypoint_remains_a_list_with_only_its_existing_fields(self):
        self.write()
        from src.techexpert.profiles import read_starter
        result=read_starter(self.path)
        self.assertEqual(set(result[0]),{'id','name','mode','connection'})

    def test_imported_registration_survives_composition_and_save_without_becoming_cluster_uuid(self):
        from src.techexpert.profile_resources import compose_profile,effective_profile
        from src.techexpert.profiles import save_profile,load_profile
        discovered=self.write();flat=dict(schema_version=1,name='Imported',bases=discovered['bases'],sources=[])
        with patch.object(self.api,'read_snapshot',side_effect=AssertionError('Composition read a source')):
            result=compose_profile(None,flat,base_registrations=discovered['registrations'])['profile']
        base=result['bases'][0];self.assertEqual(base['registrations'][0]['entry_id'],ENTRY)
        self.assertEqual(base['reported_identity'],'');self.assertIsNone(base['cluster_id'])
        self.assertEqual(base['mode_origin'],dict(basis='reported',origin='starter_srvr_ref'))
        saved=save_profile(self.folder/'state',result,expected_revision=0)
        self.assertEqual(load_profile(self.folder/'state'),saved)
        self.assertEqual(effective_profile(saved)['bases'][0]['connection'],discovered['bases'][0]['connection'])

    def test_user_override_preserves_registration_but_revises_the_origin(self):
        from src.techexpert.profile_resources import compose_profile,effective_profile
        discovered=self.write(connection='File="D:\\file-ib";')
        flat=dict(schema_version=1,name='Imported',bases=discovered['bases'],sources=[])
        original=compose_profile(None,flat,base_registrations=discovered['registrations'])['profile'];before=deepcopy(original)
        edited=effective_profile(original);edited['bases'][0].update(mode='server',connection='Srvr=other;Ref=copy')
        changed=compose_profile(original,edited)['profile'];base=changed['bases'][0]
        self.assertEqual(base['registrations'],original['bases'][0]['registrations'])
        self.assertEqual(base['mode_origin'],dict(basis='reported',origin='user_override'))
        self.assertEqual(original,before)

    def test_registration_extension_does_not_add_fields_to_old_schema2_profiles(self):
        from src.techexpert.profile_resources import upgrade_profile,validate
        profile=upgrade_profile(dict(schema_version=1,name='Old',bases=[dict(id='old',name='Main',mode='file',connection='D:/old')],sources=[]))
        self.assertNotIn('registrations',validate(profile)['bases'][0])

    def test_saved_registration_cannot_claim_observed_ownership_or_embed_credentials(self):
        from src.techexpert.profile_resources import compose_profile,validate
        discovered=self.write();flat=dict(schema_version=1,name='Imported',bases=discovered['bases'],sources=[])
        profile=compose_profile(None,flat,base_registrations=discovered['registrations'])['profile']
        for field,value in (('basis','observed'),('connection','Srvr=app;Ref=main;Pwd=private-secret')):
            modified=deepcopy(profile);modified['bases'][0]['registrations'][0][field]=value
            with self.subTest(field=field),self.assertRaises(InputError):validate(modified)

    def test_public_incident_preview_masks_old_registration_values_after_override(self):
        from src.techexpert.profile_resources import compose_profile,effective_profile
        from src.techexpert.profiles import save_profile
        from src.techexpert.investigations import create
        from src.techexpert.incident_drafts import prepare
        found=self.write(name='PRIVATE_OLD_ENTRY_NAME',connection='Srvr="private-original.invalid";Ref="PRIVATE_OLD_REF";')
        flat=dict(schema_version=1,name='Environment',bases=found['bases'],sources=[])
        original=compose_profile(None,flat,base_registrations=found['registrations'])['profile']
        edited=effective_profile(original);edited['bases'][0].update(name='Current',connection='Srvr=replacement.invalid;Ref=changed')
        changed=compose_profile(original,edited)['profile'];record=changed['bases'][0]['registrations'][0]
        private=[record['source_path'],record['entry_id'],record['entry_name'],record['source_sha256'],'private-original.invalid','PRIVATE_OLD_REF']
        state=self.folder/'private-state';save_profile(state,changed,expected_revision=0)
        doc=create(state,dict(task='Проверка '+ ' '.join(private)));preview=prepare(state,doc['investigation_id'])
        for value in private:self.assertNotIn(value,preview['body'])

    def test_refreshed_list_does_not_silently_replace_provenance_of_unchanged_settings(self):
        from src.techexpert.profile_resources import compose_profile,effective_profile
        first=self.write();flat=dict(schema_version=1,name='Imported',bases=first['bases'],sources=[])
        original=compose_profile(None,flat,base_registrations=first['registrations'])['profile']
        newer=self.write(connection='Srvr="new-app";Ref="new-db";')
        unchanged=compose_profile(original,effective_profile(original),base_registrations=newer['registrations'])['profile']
        self.assertEqual(unchanged['bases'][0]['registrations'],original['bases'][0]['registrations'])
        accepted=effective_profile(original);accepted['bases'][0]['connection']=newer['bases'][0]['connection']
        updated=compose_profile(original,accepted,base_registrations=newer['registrations'])['profile']
        self.assertEqual(updated['bases'][0]['registrations'],newer['registrations'][flat['bases'][0]['id']])

    def test_starter_inspect_cli_returns_private_configuration_without_creating_state(self):
        self.write(connection='Srvr="app";Ref="main";Pwd="private-synthetic-secret";')
        state=self.folder/'no-state'
        r=subprocess.run([sys.executable,'-X','utf8',str(Path(__file__).resolve().parents[1]/'techexpert.py'),'--state-dir',str(state),'starter-inspect',str(self.path)],capture_output=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stderr.decode('utf-8','replace'));result=json.loads(r.stdout)
        self.assertFalse(result['connections_opened']);self.assertNotIn('private-synthetic-secret',r.stdout.decode('utf-8'));self.assertFalse(state.exists())
