"""Configuration candidates require explicit choice and retain source scopes."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from src.techexpert import registrations as api
from src.techexpert.profile_resources import upgrade_profile
from src.techexpert.inputs import InputError

C='11111111-1111-1111-1111-111111111111'
IB='22222222-2222-2222-2222-222222222222'

def profile(a='Srvr=app;Ref=orders',b='Srvr=app:1541;Ref=orders'):
    return upgrade_profile(dict(schema_version=1,name='Candidates',bases=[dict(id=bid,name='Same name',mode='server',connection=conn) for bid,conn in [('a',a),('b',b)]],sources=[]))

def ras_claim(value,bid,namespace=None):
    rid='rac-'+bid;cid='cluster-'+bid
    value['connections'].append(dict(id=rid,kind='rac',name='RAS',address='management:1545',credential_ref='',settings=dict(executable='rac',**(dict(docker_container=namespace) if namespace else {}))))
    value['clusters'].append(dict(id=cid,name='Cluster',node_ids=[],ras_connection_id=rid,reported_identity=C))
    base=next(b for b in value['bases'] if b['id']==bid);base.update(cluster_id=cid,reported_identity=IB)


class RegistrationMatchTests(unittest.TestCase):
    def test_names_alone_never_form_a_match(self):
        value=profile(b='Srvr=other;Ref=orders')
        self.assertEqual(api.candidate_matches(value)['groups'],[])

    def test_explicit_application_parameters_form_a_candidate_without_identity_attestation(self):
        value=profile();before=deepcopy(value)
        with patch('subprocess.Popen',side_effect=AssertionError('Matching launched a process')),patch('socket.getaddrinfo',side_effect=AssertionError('Matching used DNS')):
            result=api.candidate_matches(value)
        self.assertEqual(result['automatic_merges'],0);self.assertFalse(result['runtime_identity_proven'])
        self.assertEqual(result['groups'][0]['base_ids'],['a','b']);self.assertEqual(result['groups'][0]['status'],'candidate')
        self.assertEqual(value,before)

    def test_starter_entry_id_equal_to_a_ras_uuid_does_not_link_different_parameters(self):
        value=profile(b='Srvr=other;Ref=orders');ras_claim(value,'b')
        value['bases'][0]['registrations']=[dict(kind='starter',source_path='D:/ibases.v8i',source_sha256='0'*64,entry_id=IB,entry_name='Same name',mode='server',connection='Srvr=app;Ref=orders',captured_at='2026-11-17T10:00:00Z')]
        self.assertEqual(api.candidate_matches(value)['groups'],[])

    def test_equal_localhost_parameters_in_distinct_docker_namespaces_are_ambiguous(self):
        value=profile(a='Srvr=localhost;Ref=orders',b='Srvr=localhost:1541;Ref=orders');ras_claim(value,'a','container-a');ras_claim(value,'b','container-b')
        group=api.candidate_matches(value)['groups'][0]
        self.assertEqual(group['status'],'ambiguous')
        with self.assertRaises(InputError):api.merge_profile_bases(value,'a',['b'])

    def test_confirmed_merge_remaps_only_new_profile_and_keeps_reported_identity(self):
        value=profile();ras_claim(value,'b')
        value['sources']=[dict(id='tj',type='tj',path='//logs.invalid',node_id=None,cluster_id=None,connection_id=None,dbms_instance_id=None,database_ids=[],base_ids=['a','b'],settings={},status='not_checked')]
        before=deepcopy(value)
        merged=api.merge_profile_bases(value,'a',['b'])
        self.assertEqual([b['id'] for b in merged['bases']],['a']);self.assertEqual(merged['sources'][0]['base_ids'],['a'])
        self.assertEqual(merged['bases'][0]['reported_identity'],IB)
        self.assertEqual(merged['bases'][0]['mode_origin']['basis'],'reported');self.assertEqual(value,before)

    def test_conflicting_per_infobase_sql_mappings_cannot_be_silently_merged(self):
        from test_profile_resources import graph
        value=graph();value['bases'][1]['connection_parameters']['ref']=value['bases'][0]['connection_parameters']['ref']
        with self.assertRaisesRegex(InputError,'SQL|database|mapping'):api.merge_profile_bases(value,'a',['b'])

    def test_separate_choice_is_persisted_only_for_the_same_configuration(self):
        value=profile();group=api.candidate_matches(value)['groups'][0]
        value['registration_decisions']={group['id']:'separate'}
        self.assertEqual(api.candidate_matches(value)['groups'][0]['status'],'separate')
        changed=deepcopy(value)
        for connection in changed['connections']:
            if connection['kind']=='onec':connection['address']='replacement'
        newer=api.candidate_matches(changed)['groups'][0]
        self.assertNotEqual(newer['id'],group['id']);self.assertEqual(newer['status'],'candidate')
        merged=api.merge_profile_bases(value,'a',['b'])
        self.assertNotIn(group['id'],merged.get('registration_decisions',{}))
