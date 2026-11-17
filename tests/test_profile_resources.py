"""Reusable configured resources, immutable profiles, no runtime ownership inference."""
import copy
import importlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


def graph():
    return dict(schema_version=2,name='Общие ресурсы',
        nodes=[dict(id='app',name='app-alias'),dict(id='db',name='db-alias')],
        connections=[dict(id='application',name='Сервер 1С',kind='onec',address='app.internal',settings=dict(method='direct')),
            dict(id='sql',name='Общая СУБД',kind='sql',address='db.internal',credential_ref='private-pgpass',settings=dict(engine='postgresql',port=5432,user='readonly')),
            dict(id='ras',name='RAS',kind='rac',address='ras.internal:1545',settings={}),
            dict(id='metrics',name='Метрики',kind='os',address='db.internal',settings=dict(transport='ssh',port=22))],
        clusters=[dict(id='cluster',name='Кластер',node_ids=['app'],ras_connection_id='ras',reported_identity='cluster-reported')],
        dbms_instances=[dict(id='postgres',name='PostgreSQL',node_id='db',connection_id='sql')],
        bases=[dict(id=bid,name='Одинаковое имя',mode='server',connection_method='direct',connection_id='application',
            connection_parameters=dict(ref=ref),cluster_id='cluster') for bid,ref in [('a','main'),('b','copy')]],
        database_bindings=[dict(id='db-'+bid,base_id=bid,instance_id='postgres',name=name,permission_scope='statistics_readonly') for bid,name in [('a','main_sql'),('b','copy_sql')]],
        sources=[dict(id='sql-'+bid,type='sql',base_ids=[bid],path='',dbms_instance_id='postgres',database_ids=['db-'+bid],settings={}) for bid in ('a','b')]+
            [dict(id='os',type='os',base_ids=['a','b'],path='',node_id='db',connection_id='metrics',settings=dict(duration_seconds=300,interval_seconds=1,role='sql')),
             dict(id='tj',type='tj',base_ids=['a','b'],path='//app/logs',node_id='app',cluster_id='cluster',settings={})])


class ProfileResourceTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.profile_resources'),'Shared profile resources are not implemented')
        self.api=importlib.import_module('src.techexpert.profile_resources')

    def test_shared_connection_is_stored_once_and_resolves_each_database_separately(self):
        from src.techexpert.profiles import validate_profile
        value=validate_profile(graph());view=self.api.effective_profile(value)
        self.assertEqual(value['schema_version'],2)
        self.assertTrue(all('host' not in source for source in value['sources']))
        self.assertTrue(all('connection' not in base for base in value['bases']))
        self.assertEqual(json.dumps(value).count('private-pgpass'),1)
        self.assertEqual([b['connection'] for b in view['bases']],['Srvr=app.internal;Ref=main','Srvr=app.internal;Ref=copy'])
        sql=[s for s in view['sources'] if s['type']=='sql']
        self.assertEqual([s['host'] for s in sql],['db.internal','db.internal'])
        self.assertEqual([s['settings']['databases'] for s in sql],[{'a':'main_sql'},{'b':'copy_sql'}])
        self.assertEqual([s['settings']['credential_ref'] for s in sql],['private-pgpass']*2)
        self.assertEqual(value['bases'][0]['mode_origin']['basis'],'reported')
        self.assertEqual(value['bases'][0]['applicability'],dict(start=None,end=None))

    def test_shared_edits_report_transitive_affected_sources_and_bases(self):
        old=graph();new=copy.deepcopy(old);new['connections'][1]['address']='replacement.internal'
        impact=self.api.resource_impact(old,new)
        self.assertEqual(impact['affected_base_ids'],['a','b'])
        self.assertEqual(impact['affected_source_ids'],['sql-a','sql-b'])
        self.assertEqual(impact['changed_resources'][0]['id'],'sql')
        self.assertFalse(impact['connected']);self.assertFalse(impact['applied'])
        new=copy.deepcopy(old);new['nodes'][0]['name']='changed-app-alias'
        impact=self.api.resource_impact(old,new)
        self.assertEqual(impact['affected_base_ids'],['a','b']);self.assertIn('tj',impact['affected_source_ids'])
        new=copy.deepcopy(old);new['database_bindings'][0]['permission_scope']='different_reported_scope'
        impact=self.api.resource_impact(old,new)
        self.assertEqual(impact['affected_base_ids'],['a']);self.assertEqual(impact['affected_source_ids'],['sql-a'])
        new=copy.deepcopy(old);new['connections'][3]['address']='different-monitor-node'
        impact=self.api.resource_impact(old,new)
        self.assertEqual(impact['affected_source_ids'],['os']);self.assertEqual(impact['affected_base_ids'],['a','b'])

    def test_editor_edits_shared_endpoint_once_and_clears_outdated_claims(self):
        from src.techexpert.profiles import validate_profile
        old=validate_profile(graph());old['dbms_instances'][0]['reported_identity']='old-instance-claim';old['nodes'][1]['reported_identity']='old-node-claim'
        view=self.api.effective_profile(old)
        result=self.api.compose_profile(old,view,connection_edits={'sql':dict(address='replacement.internal')})
        saved=result['profile'];resolved=self.api.effective_profile(saved)
        self.assertEqual([s['host'] for s in resolved['sources'] if s['type']=='sql'],['replacement.internal']*2)
        self.assertEqual(saved['dbms_instances'][0]['reported_identity'],'')
        self.assertEqual(saved['nodes'][1]['reported_identity'],'')
        self.assertTrue(all(d['permission_scope']=='not_checked' for d in saved['database_bindings']))
        self.assertEqual(result['impact']['affected_base_ids'],['a','b'])
        self.assertEqual(old['connections'][1]['address'],'db.internal')
        self.assertEqual(old['dbms_instances'][0]['reported_identity'],'old-instance-claim')

    def test_editor_preserves_metadata_and_explicit_separation_of_equal_addresses(self):
        from src.techexpert.profiles import validate_profile
        old=validate_profile(graph());old['bases'][0]['applicability']=dict(start='2026-11-01T00:00:00Z',end=None)
        old['nodes'][0]['reported_identity']='reported-app'
        view=self.api.effective_profile(old)
        result=self.api.compose_profile(old,view)
        self.assertEqual(result['profile'],old)
        detached=self.api.compose_profile(old,view,connection_bindings={'sql-b':None})['profile']
        lookup={r['id']:r for r in detached['dbms_instances']};sources={s['id']:s for s in detached['sources']}
        self.assertNotEqual(lookup[sources['sql-a']['dbms_instance_id']]['connection_id'],lookup[sources['sql-b']['dbms_instance_id']]['connection_id'])
        again=self.api.compose_profile(detached,self.api.effective_profile(detached))['profile']
        self.assertEqual(again,detached)

    def test_editor_never_silently_overwrites_a_single_card_change_in_a_shared_group(self):
        from src.techexpert.profiles import validate_profile
        old=validate_profile(graph());view=self.api.effective_profile(old)
        view['sources'][0]['host']='other-endpoint'
        with self.assertRaisesRegex(ValueError,'shared|connection'):self.api.compose_profile(old,view)
        detached=self.api.compose_profile(old,view,connection_bindings={'sql-a':None})['profile']
        hosts={s['id']:s['host'] for s in self.api.effective_profile(detached)['sources']}
        self.assertEqual(hosts['sql-a'],'other-endpoint');self.assertEqual(hosts['sql-b'],'db.internal')
        for choices in ([],False,{'tj':'sql'}):
            with self.subTest(choices=choices),self.assertRaises(ValueError):self.api.compose_profile(old,self.api.effective_profile(old),connection_bindings=choices)

    def test_reattaching_a_separate_connection_uses_the_selected_instance_node(self):
        from src.techexpert.profiles import validate_profile
        old=validate_profile(graph());view=self.api.effective_profile(old);view['sources'][1]['host']='separate-host'
        detached=self.api.compose_profile(old,view,connection_bindings={'sql-b':None})['profile']
        restored=self.api.compose_profile(detached,self.api.effective_profile(detached),connection_bindings={'sql-b':'sql'})['profile']
        source=next(s for s in restored['sources'] if s['id']=='sql-b')
        self.assertEqual(source['dbms_instance_id'],'postgres');self.assertEqual(source['node_id'],'db')
        impact=self.api.resource_impact(detached,restored)
        self.assertEqual(impact['affected_base_ids'],['b']);self.assertEqual(impact['affected_source_ids'],['sql-b'])
        self.assertTrue(impact['changed_associations'])

    def test_editor_discards_only_abandoned_new_resources_and_keeps_saved_unused_ones(self):
        from src.techexpert.profiles import validate_profile
        old=validate_profile(graph());old['connections'].append(dict(id='retained-unused',name='Saved for later',kind='rac',address='future:1545',credential_ref='',settings={}))
        view=self.api.effective_profile(old);view['sources'][1]['host']='temporary-host'
        detached=self.api.compose_profile(old,view,connection_bindings={'sql-b':None})['profile']
        restored=self.api.compose_profile(detached,self.api.effective_profile(detached),connection_bindings={'sql-b':'sql'})['profile']
        cleaned=self.api.retain_editor_resources(restored,old)
        self.assertTrue(any(c['id']=='retained-unused' for c in cleaned['connections']))
        self.assertFalse(any(c['address']=='temporary-host' for c in cleaned['connections']))
        self.assertFalse(any(n['name']=='temporary-host' for n in cleaned['nodes']))

    def test_conversion_is_explicit_pure_and_groups_only_identical_configured_connections(self):
        from src.techexpert.profiles import validate_profile
        legacy=dict(schema_version=1,name='Legacy',bases=[dict(id=bid,name=bid,mode='server',connection='Srvr=app.internal;Ref='+bid) for bid in ('a','b')],
            sources=[dict(id='sql-'+bid,type='sql',path='',host='db.internal',base_ids=[bid],settings=dict(database=bid,credential_ref='one-reference')) for bid in ('a','b')])
        old=copy.deepcopy(legacy);new=self.api.upgrade_profile(legacy)
        self.assertEqual(legacy,old);self.assertEqual(new['schema_version'],2)
        self.assertEqual(len(new['dbms_instances']),1)
        self.assertEqual(len([c for c in new['connections'] if c['kind']=='sql']),1)
        resolved=self.api.effective_profile(new)['sources']
        self.assertEqual([s['host'] for s in resolved],['db.internal']*2)
        self.assertEqual([s['settings']['databases'] for s in resolved],[{'a':'a'},{'b':'b'}])
        self.assertEqual([s['settings']['credential_ref'] for s in resolved],['one-reference']*2)
        legacy['sources'][1]['settings']['credential_ref']='different-reference'
        self.assertEqual(len(self.api.upgrade_profile(legacy)['dbms_instances']),2)
        # Legacy material is not upgraded by read/validation/projection.
        pinned=dict(validate_profile(old),revision=19)
        self.assertEqual(self.api.effective_profile(pinned),pinned)

    def test_web_and_file_mode_method_origin_and_period_remain_independent(self):
        value=dict(schema_version=1,name='Modes',bases=[dict(id='file',name='Share',mode='file',connection='//storage/share/IB'),dict(id='web',name='Web',mode='unknown',connection='https://public.example.test/base')],sources=[])
        result=self.api.upgrade_profile(value);bases={b['id']:b for b in result['bases']}
        self.assertEqual(bases['file']['mode'],'file');self.assertEqual(bases['file']['connection_method'],'direct')
        self.assertEqual(bases['web']['mode'],'unknown');self.assertEqual(bases['web']['connection_method'],'web')
        self.assertEqual(bases['web']['mode_origin']['basis'],'unknown')
        result['bases'][0]['applicability']=dict(start='2026-11-01T00:00:00+03:00',end=None)
        from src.techexpert.profiles import validate_profile
        self.assertEqual(validate_profile(result)['bases'][0]['applicability']['end'],None)

    def test_quoted_direct_and_ras_imports_preserve_their_distinct_meanings(self):
        value=dict(schema_version=1,name='Imported',bases=[
            dict(id='f',name='file',mode='file',connection='File="D:/Test IB";'),
            dict(id='s',name='server',mode='server',connection='Srvr="host";Ref="main";'),
            dict(id='r',name='ras',mode='server',connection='RAS=ras:1545;Cluster=cluster-id;IB=infobase-id')],sources=[])
        result=self.api.upgrade_profile(value);view=self.api.effective_profile(result)
        self.assertEqual([b['connection_method'] for b in result['bases']],['direct','direct','unknown'])
        self.assertEqual([b['connection'] for b in view['bases']],['D:/Test IB','Srvr=host;Ref=main',value['bases'][2]['connection']])
        self.assertIsNone(result['bases'][2]['connection_id'])

    def test_cli_upgrade_projection_and_impact_are_explicit_without_saving(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);before=root/'before.json';after=root/'after.json'
            before.write_text(json.dumps(graph()),encoding='utf-8');changed=graph();changed['connections'][1]['address']='replacement';after.write_text(json.dumps(changed),encoding='utf-8')
            project=Path(__file__).resolve().parents[1]
            def cli(*args):
                r=subprocess.run([sys.executable,'-X','utf8',str(project/'techexpert.py'),'--state-dir',str(root/'state'),*args],capture_output=True,timeout=15)
                self.assertEqual(r.returncode,0,r.stderr.decode('utf-8','replace')+r.stdout.decode('utf-8','replace'));return json.loads(r.stdout)
            self.assertEqual(cli('profile-upgrade',str(before))['schema_version'],2)
            self.assertEqual(cli('profile-resolve',str(before))['view']['sources'][0]['host'],'db.internal')
            self.assertEqual(cli('profile-impact',str(before),str(after))['affected_base_ids'],['a','b'])
            self.assertFalse((root/'state').exists())
            from src.techexpert.profiles import save_profile
            save_profile(root/'state',graph(),expected_revision=0)
            self.assertEqual(cli('profile','--resolved')['view']['sources'][0]['settings']['databases'],{'a':'main_sql'})

    def test_public_incident_preview_masks_graph_aliases_and_access_references(self):
        from src.techexpert.profiles import save_profile
        from src.techexpert.investigations import create
        from src.techexpert.incident_drafts import prepare
        aliases=('PRIVATE_NODE_ALIAS','PRIVATE_SQL_ENDPOINT','PRIVATE_CONNECTOR_REF','PRIVATE_CLUSTER_ID')
        value=graph();value['nodes'][0]['name']=aliases[0];value['connections'][1]['address']=aliases[1];value['connections'][1]['credential_ref']=aliases[2];value['clusters'][0]['reported_identity']=aliases[3]
        with tempfile.TemporaryDirectory() as tmp:
            save_profile(tmp,value,expected_revision=0);doc=create(tmp,dict(task='Наблюдение '+ ' '.join(aliases)))
            preview=prepare(tmp,doc['investigation_id'])
            for alias in aliases:self.assertNotIn(alias,preview['body'])

    def test_public_preview_masks_known_infobase_claims_without_source_bindings(self):
        from src.techexpert.profiles import save_profile
        from src.techexpert.investigations import create
        from src.techexpert.incident_drafts import prepare
        aliases=('PRIVATE_REPORTED_IB_ID','PRIVATE_IB_REF','PRIVATE_UNUSED_SQL_DB','PRIVATE_CLUSTER_ALIAS','PRIVATE_INSTANCE_ALIAS','PRIVATE_CONNECTION_ALIAS')
        value=graph();value['bases'][0]['reported_identity']=aliases[0];value['bases'][0]['connection_parameters']['ref']=aliases[1]
        value['database_bindings'].append(dict(id='unused-db',base_id='a',instance_id='postgres',name=aliases[2]))
        value['clusters'][0]['name']=aliases[3];value['dbms_instances'][0]['name']=aliases[4];value['connections'][1]['name']=aliases[5]
        with tempfile.TemporaryDirectory() as tmp:
            save_profile(tmp,value,expected_revision=0);doc=create(tmp,dict(task='Наблюдение '+ ' '.join(aliases)))
            preview=prepare(tmp,doc['investigation_id'])
            for alias in aliases:self.assertNotIn(alias,preview['body'])

    def test_legacy_preflight_fills_os_defaults_without_mutating_the_document(self):
        from src.techexpert.profiles import check_profile
        value=dict(schema_version=1,name='Legacy OS',bases=[dict(id='a',name='File',mode='file',connection='//file.invalid/main')],
            sources=[dict(id='os',type='os',path='',host='',base_ids=['a'],settings={})])
        before=copy.deepcopy(value)
        self.assertEqual(check_profile(value)['sources'][0]['status'],'local_collector_available')
        self.assertEqual(value,before)

    def test_invalid_graphs_do_not_reach_save(self):
        from src.techexpert.profiles import validate_profile
        changes=[lambda p:p['sources'][0].update(dbms_instance_id='absent'),
            lambda p:p['connections'][1].update(kind='rac'),lambda p:p['bases'][0].update(mode='file'),
            lambda p:p['bases'][0].update(connection_method='web'),
            lambda p:p['bases'][0].update(mode_origin=dict(basis='observed',origin='caller_claim')),
            lambda p:p['bases'][0].update(applicability=dict(start='2026-11-01T00:00:00',end=None)),
            lambda p:p['database_bindings'][0].update(base_id='absent'),
            lambda p:p['sources'][0].update(database_ids=['db-b']),
            lambda p:p['connections'][1].update(address='postgresql://user:secret@host/db'),
            lambda p:p['connections'][1]['settings'].update(password='secret'),
            lambda p:p['sources'][0]['settings'].update(user='duplicated-common-setting')]
        for change in changes:
            value=graph();change(value)
            with self.subTest(change=changes.index(change)),self.assertRaises(ValueError):validate_profile(value)

    def test_validation_upgrade_resolution_and_preflight_have_no_external_io(self):
        from src.techexpert.profiles import validate_profile,check_profile
        with patch.object(Path,'is_dir',side_effect=AssertionError('No metadata access')),patch('subprocess.run',side_effect=AssertionError('No process')):
            value=validate_profile(graph());self.api.effective_profile(value)
            self.assertFalse(check_profile(value)['connected'])

    def test_save_pins_old_investigation_and_rejects_silent_schema_downgrade(self):
        from src.techexpert.profiles import save_profile,load_profile
        from src.techexpert.investigations import create,load
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);old=save_profile(root,graph(),expected_revision=0)
            doc=create(root,dict(task='Проверка общей СУБД'));old_raw=(root/'profiles/1.json').read_bytes()
            changed=copy.deepcopy(old);changed['connections'][1]['address']='new.internal';save_profile(root,changed,expected_revision=1)
            self.assertEqual(load(root,doc['investigation_id'])['profile_snapshot'],old)
            self.assertEqual((root/'profiles/1.json').read_bytes(),old_raw)
            legacy=self.api.effective_profile(old)
            with self.assertRaisesRegex(ValueError,'schema|downgrade|верси'):save_profile(root,legacy,expected_revision=2)
            self.assertEqual(load_profile(root)['revision'],2)

    def test_source_passport_uses_configured_graph_but_pins_original_profile_hash(self):
        from src.techexpert.profiles import validate_profile
        from src.techexpert.source_code import snapshot_source
        from src.techexpert.source_passports import normalize_bindings,digest
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);code=root/'code';code.mkdir();(code/'Module.bsl').write_text('Возврат 1;',encoding='utf-8')
            report=snapshot_source(root/'state',str(code));value=graph()
            value['sources'].append(dict(id='code',type='source',path=str(code),node_id='app',base_ids=['a'],settings={}))
            value['nodes'][0]['reported_identity']='USER_NODE_ID';value['bases'][0]['reported_identity']='USER_IB_ID'
            profile=dict(validate_profile(value),revision=7)
            result=normalize_bindings(profile,[dict(id='A-1',kind='artifact',target_id=report['artifact_id'])],{'A-1':report},[dict(id='S-1',attachment='A-1',profile_source_id='code')])[0]['passport']
            fact=result['facts']['base_alias'];self.assertEqual(fact['basis'],'reported')
            self.assertEqual(fact['claims'][0]['proof']['profile_sha256'],digest(profile))
            self.assertEqual(result['facts']['node_alias']['value'],'app-alias')
            self.assertEqual(result['facts']['node_identity']['basis'],'reported');self.assertEqual(result['facts']['node_identity']['value'],'USER_NODE_ID')
            self.assertEqual(result['facts']['infobase_identity']['basis'],'reported');self.assertEqual(result['facts']['infobase_identity']['value'],'USER_IB_ID')
            self.assertEqual(result['facts']['cluster_identity']['basis'],'reported')
            self.assertEqual(result['access_scope']['configured_resource_refs']['node_id'],'app')
            raw=dict(value,revision=8)
            direct=normalize_bindings(raw,[dict(id='A-1',kind='artifact',target_id=report['artifact_id'])],{'A-1':report},[dict(id='S-1',attachment='A-1',profile_source_id='code')])[0]['passport']
            self.assertEqual(direct['facts']['node_identity']['claims'][0]['proof']['profile_sha256'],digest(raw))
            self.assertNotIn('mode_origin',raw['bases'][0])
