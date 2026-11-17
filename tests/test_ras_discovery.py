"""A selected RAS scope supplies configuration candidates, not data access."""
import unittest
from copy import deepcopy
from unittest.mock import patch

from src.techexpert import discovery,rac
from src.techexpert.inputs import InputError

C='11111111-1111-1111-1111-111111111111'
IB='22222222-2222-2222-2222-222222222222'
NODE='33333333-3333-3333-3333-333333333333'
OTHER='44444444-4444-4444-4444-444444444444'


class RasDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.calls=[];self.denied=set();self.real=rac.RacClient
        self.texts=dict(clusters='cluster : '+C+'\nname : Cluster\nhost : app.invalid\nport : 1541\n\ncluster : '+OTHER+'\nhost : other.invalid\nport : 2541\n',
            infobases='infobase : '+IB+'\nname : orders\ndescr : not SQL metadata\n',
            servers='server : '+NODE+'\nagent-host : node.invalid\nagent-port : 1540\n',
            infobase_info='infobase : '+IB+'\nname : orders\ndbms : PostgreSQL\ndb-server : db.invalid\ndb-name : orders_sql\ndb-pwd : private-secret\n')
        def client(*args,**kwargs):
            value=self.real(*args,**kwargs)
            def execute(operation,cluster=None,**options):
                self.calls.append((operation,cluster,options));self.assertLessEqual(options.get('timeout_seconds',23),23)
                if operation in self.denied:raise InputError('private inaccessible response')
                return self.texts[operation]
            value.execute=execute;return value
        self.patcher=patch.object(rac,'RacClient',side_effect=client);self.patcher.start();self.addCleanup(self.patcher.stop)

    def test_common_resources_are_returned_once_and_only_for_the_selected_cluster(self):
        result=discovery.inspect_ras('management.invalid:1545',cluster=C)
        self.assertEqual(len(result['bases']),1);base=result['bases'][0]
        self.assertEqual(base['mode'],'server');self.assertEqual(discovery.connection_parameters(base['connection']),dict(srvr='app.invalid:1541',ref='orders'))
        self.assertEqual(len(result['resources']['clusters']),1);self.assertEqual(len(result['resources']['nodes']),1)
        self.assertEqual(result['resources']['nodes'][0]['name'],'node.invalid')
        self.assertEqual(result['registrations'][base['id']][0]['infobase_id'],IB)
        self.assertNotIn('other.invalid',str(result['resources']))
        self.assertEqual({op for op,_,_ in self.calls},{'clusters','infobases','servers'})
        self.assertTrue(all(cluster in (None,C) for _,cluster,_ in self.calls));self.assertFalse(result['sql_connected'])

    def test_unavailable_node_list_does_not_discard_available_infobases_or_mean_no_nodes(self):
        self.denied.add('servers');result=discovery.inspect_ras('management.invalid:1545',cluster=C)
        self.assertEqual(len(result['bases']),1);self.assertEqual(result['availability']['nodes'],'unavailable')
        self.assertIsNone(result['node_observations']);self.assertEqual(result['resources']['nodes'],[])

    def test_unknown_application_host_is_not_guessed_from_the_ras_endpoint(self):
        self.denied.add('clusters');result=discovery.inspect_ras('management.invalid:1545',cluster=C)
        base=result['bases'][0];self.assertEqual(base['connection'],'RAS=management.invalid:1545;Cluster='+C+';IB='+IB)
        self.assertEqual(result['availability']['cluster_properties'],'unavailable')
        self.assertFalse(result['registrations'][base['id']][0]['cluster_host'])
        from src.techexpert.profile_resources import compose_profile
        proposed=compose_profile(None,dict(schema_version=1,name='RAS',bases=result['bases'],sources=[]),base_registrations=result['registrations'],discovery_resources=result['resources'])['profile']
        bound=next(c for c in proposed['clusters'] if c['id']==proposed['bases'][0]['cluster_id'])
        self.assertEqual(len(bound['node_ids']),1)

    def test_cluster_enumeration_does_not_read_other_cluster_or_infobase_properties(self):
        result=discovery.inspect_ras('management.invalid:1545')
        self.assertEqual(len(result['clusters']),2);self.assertEqual(result['bases'],[])
        self.assertEqual([op for op,_,_ in self.calls],['clusters'])

    def test_info_reads_only_the_selected_uuid_and_never_returns_access_secrets(self):
        result=discovery.inspect_ras('management.invalid:1545',cluster=C,infobase=IB)
        self.assertEqual([op for op,_,_ in self.calls],['infobase_info'])
        self.assertEqual(self.calls[0][2]['infobase'],IB)
        self.assertEqual(result['properties']['db-name'],'orders_sql');self.assertNotIn('private-secret',str(result))
        self.assertFalse(result['sql_connected'])

    def test_namespace_changes_do_not_reuse_one_candidate_id(self):
        local=discovery.inspect_ras('localhost:1545',cluster=C)
        container=discovery.inspect_ras('localhost:1545',cluster=C,docker_container='other-namespace')
        self.assertNotEqual(local['bases'][0]['id'],container['bases'][0]['id'])

    def test_selected_info_suggests_sql_only_for_its_current_scoped_registration(self):
        from src.techexpert.profile_resources import compose_profile,effective_profile
        found=discovery.inspect_ras('management.invalid:1545',cluster=C)
        flat=dict(schema_version=1,name='RAS',bases=found['bases'],sources=[])
        initial=compose_profile(None,flat,base_registrations=found['registrations'],discovery_resources=found['resources'])['profile']
        info=discovery.inspect_ras('management.invalid:1545',cluster=C,infobase=IB)
        result=compose_profile(initial,effective_profile(initial),base_registrations=info['registrations'],discovery_resources=info['resources'])
        suggestion=result['source_suggestions'][0]
        self.assertEqual(suggestion['host'],'db.invalid');self.assertEqual(suggestion['settings']['databases'],{found['bases'][0]['id']:'orders_sql'})
        self.assertFalse(suggestion['connected']);self.assertEqual(result['profile']['sources'],[])
        self.assertEqual(result['profile']['bases'][0]['connection_method'],'direct')
        rid=next(c['id'] for c in result['profile']['connections'] if c['kind']=='rac')
        changed=compose_profile(result['profile'],effective_profile(result['profile']),connection_edits={rid:dict(address='new.invalid:1545')})
        self.assertEqual(changed['source_suggestions'],[])

    def test_composite_db_server_does_not_guess_a_port_or_host(self):
        from src.techexpert.profile_resources import compose_profile,effective_profile
        self.texts['infobase_info']=self.texts['infobase_info'].replace('db.invalid','db.invalid port=6543')
        info=discovery.inspect_ras('management.invalid:1545',cluster=C,infobase=IB)
        flat=dict(schema_version=1,name='RAS',bases=info['bases'],sources=[])
        result=compose_profile(None,flat,base_registrations=info['registrations'],discovery_resources=info['resources'])
        self.assertEqual(result['source_suggestions'],[])

    def test_suggestion_does_not_replace_existing_sql_configuration(self):
        from src.techexpert.profile_resources import compose_profile,effective_profile
        info=discovery.inspect_ras('management.invalid:1545',cluster=C,infobase=IB)
        bid=info['bases'][0]['id']
        flat=dict(schema_version=1,name='RAS',bases=info['bases'],sources=[dict(id='sql',type='sql',host='user-selected.invalid',path='',base_ids=[bid],settings=dict(engine='postgresql',databases={bid:'user_sql'},credential_ref='existing-private-ref'))])
        result=compose_profile(None,flat,base_registrations=info['registrations'],discovery_resources=info['resources'])
        sql=effective_profile(result['profile'])['sources'][0]
        self.assertEqual(sql['host'],'user-selected.invalid');self.assertEqual(sql['settings']['databases'],{bid:'user_sql'})
        self.assertEqual(sql['settings']['credential_ref'],'existing-private-ref');self.assertEqual(result['source_suggestions'][0]['host'],'db.invalid')

    def test_new_locator_uses_its_selected_docker_rac_scope(self):
        from src.techexpert.profile_resources import compose_profile
        info=discovery.inspect_ras('localhost:1545',cluster=C,infobase=IB,docker_container='selected-rac-container')
        flat=dict(schema_version=1,name='RAS',bases=info['bases'],sources=[])
        result=compose_profile(None,flat,base_registrations=info['registrations'],discovery_resources=info['resources'])
        base=result['profile']['bases'][0];cluster=next(c for c in result['profile']['clusters'] if c['id']==base['cluster_id'])
        connection=next(c for c in result['profile']['connections'] if c['id']==cluster['ras_connection_id'])
        self.assertEqual(connection['settings']['docker_container'],'selected-rac-container')
        self.assertEqual(base['mode_origin']['origin'],'ras_selected_infobase_info')
        self.assertEqual(result['source_suggestions'][0]['namespace'],'selected-rac-container')

    def test_public_incident_preview_masks_retained_ras_metadata_after_override(self):
        import tempfile
        from src.techexpert.profile_resources import compose_profile,effective_profile
        from src.techexpert.profiles import save_profile
        from src.techexpert.investigations import create
        from src.techexpert.incident_drafts import prepare
        info=discovery.inspect_ras('management.invalid:1545',cluster=C,infobase=IB)
        flat=dict(schema_version=1,name='RAS',bases=info['bases'],sources=[])
        original=compose_profile(None,flat,base_registrations=info['registrations'],discovery_resources=info['resources'])['profile']
        view=effective_profile(original);view['bases'][0]['connection']='Srvr=replacement.invalid;Ref=new'
        changed=compose_profile(original,view)['profile'];record=changed['bases'][0]['registrations'][0]
        private=[record['snapshot_sha256'],record['ras_connection_sha256'],record['infobase_id'],record['cluster_id'],'orders_sql','db.invalid']
        with tempfile.TemporaryDirectory() as tmp:
            save_profile(tmp,changed,expected_revision=0);doc=create(tmp,dict(task='Check '+' '.join(private)))
            public=prepare(tmp,doc['investigation_id'])
            for value in private:self.assertNotIn(value,public['body'])


    def test_discovered_shared_resources_reach_proposed_profile_without_io(self):
        from src.techexpert.profile_resources import compose_profile
        found=discovery.inspect_ras('management.invalid:1545',cluster=C)
        flat=dict(schema_version=1,name='RAS',bases=found['bases'],sources=[])
        with patch('subprocess.Popen',side_effect=AssertionError('Composition started a process')):
            profile=compose_profile(None,flat,base_registrations=found['registrations'],discovery_resources=found['resources'])['profile']
        base=profile['bases'][0];self.assertEqual(base['reported_identity'],IB)
        cluster=next(c for c in profile['clusters'] if c['id']==base['cluster_id'])
        self.assertEqual(cluster['reported_identity'],C);self.assertEqual(len(cluster['node_ids']),1)
        self.assertEqual(base['mode_origin'],dict(basis='reported',origin='ras_cluster_list'))

    def test_repeated_discovery_preserves_user_aliases_and_connection_credentials(self):
        from src.techexpert.profile_resources import compose_profile,effective_profile
        found=discovery.inspect_ras('management.invalid:1545',cluster=C);flat=dict(schema_version=1,name='RAS',bases=found['bases'],sources=[])
        original=compose_profile(None,flat,base_registrations=found['registrations'],discovery_resources=found['resources'])['profile']
        original['nodes'][0]['name']='UserAlias';next(c for c in original['connections'] if c['kind']=='rac')['credential_ref']='existing-reference'
        before=deepcopy(original)
        result=compose_profile(original,effective_profile(original),base_registrations=found['registrations'],discovery_resources=found['resources'])['profile']
        self.assertEqual(result['nodes'][0]['name'],'UserAlias')
        self.assertEqual(next(c for c in result['connections'] if c['kind']=='rac')['credential_ref'],'existing-reference')
        self.assertEqual(original,before)

    def test_changed_ras_endpoint_does_not_restore_an_old_registration_identity(self):
        from src.techexpert.profile_resources import compose_profile,effective_profile
        found=discovery.inspect_ras('management.invalid:1545',cluster=C);flat=dict(schema_version=1,name='RAS',bases=found['bases'],sources=[])
        original=compose_profile(None,flat,base_registrations=found['registrations'],discovery_resources=found['resources'])['profile']
        rid=next(c['id'] for c in original['connections'] if c['kind']=='rac')
        result=compose_profile(original,effective_profile(original),connection_edits={rid:dict(address='replacement.invalid:1545')})['profile']
        self.assertEqual(result['bases'][0]['reported_identity'],'')
        self.assertEqual(next(c for c in result['clusters'] if c['id']==result['bases'][0]['cluster_id'])['reported_identity'],'')

    def test_a_ras_reference_cannot_promote_a_file_registration_to_server_identity(self):
        from src.techexpert.profile_resources import compose_profile
        found=discovery.inspect_ras('management.invalid:1545',cluster=C)
        flat=dict(schema_version=1,name='File',bases=[dict(id='file',name='orders',mode='file',connection='D:/file')],sources=[])
        refs={'file':next(iter(found['registrations'].values()))}
        result=compose_profile(None,flat,base_registrations=refs,discovery_resources=found['resources'])['profile']
        self.assertEqual(result['bases'][0]['mode'],'file');self.assertEqual(result['bases'][0]['reported_identity'],'');self.assertIsNone(result['bases'][0]['cluster_id'])
