"""Shared configured SSH access is separate from journal format and IB mode."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.techexpert import profile_resources as resources,profiles
from src.techexpert.inputs import InputError


def graph():
    return dict(schema_version=2,name='Файлы и общие узлы',
        nodes=[dict(id='linux',name='Узел журналов')],
        connections=[dict(id='ssh',name='Общий Linux',kind='ssh',address='reader@logs.invalid',settings=dict(port=2222,
            known_hosts_file=str(Path('/not-probed/known_hosts').absolute()),identity_file=str(Path('/not-probed/private-key').absolute())))],
        bases=[dict(id='a',name='Файловая база',mode='file'),dict(id='b',name='Серверная база',mode='server')],
        sources=[dict(id='tj',type='tj',path='/var/log/onec/tj',base_ids=['a','b'],node_id='linux',connection_id='ssh',settings=dict(platform_version='8.3.27.1989')),
            dict(id='jr',type='jr',path='/var/log/onec/jr-a',base_ids=['a'],node_id='linux',connection_id='ssh',settings=dict(platform_version='8.3.27.1989')),
            dict(id='os',type='os',path='',base_ids=['a','b'],node_id='linux',connection_id='ssh',settings=dict(duration_seconds=300,interval_seconds=1,role='storage'))])


class ProfileSshTests(unittest.TestCase):
    def test_one_ssh_connection_resolves_journals_and_os_with_independent_paths(self):
        clean=profiles.validate_profile(graph());view=resources.effective_profile(clean)
        self.assertEqual(len(clean['connections']),1)
        self.assertEqual([s['connection_id'] for s in clean['sources']],['ssh']*3)
        self.assertEqual([s['path'] for s in view['sources']],['/var/log/onec/tj','/var/log/onec/jr-a',''])
        self.assertEqual([s['host'] for s in view['sources']],['reader@logs.invalid']*3)
        self.assertEqual([s['settings']['transport'] for s in view['sources']],['sftp','sftp','ssh'])
        self.assertEqual([s['settings']['port'] for s in view['sources']],[2222]*3)
        self.assertEqual(view['bases'][0]['mode'],'file')
        self.assertNotIn('known_hosts_file',clean['sources'][0]['settings'])
        self.assertEqual(json.dumps(clean).count('private-key'),1)

    def test_profile_save_load_and_preflight_never_read_keys_trust_or_remote_files(self):
        with tempfile.TemporaryDirectory() as tmp,patch('src.techexpert.input_files.read',side_effect=AssertionError('configured source was probed')),patch('src.techexpert.ssh_sftp.subprocess.Popen',side_effect=AssertionError('SSH launched')):
            state=Path(tmp)/'state';saved=profiles.save_profile(state,graph(),expected_revision=0)
            self.assertEqual(profiles.load_profile(state),saved)
            checked=profiles.check_profile(saved)
            self.assertFalse(checked['connected']);self.assertFalse(checked['collection_started'])
            self.assertEqual([s['status'] for s in checked['sources']],['remote_prerequisites_not_checked']*3)
            self.assertFalse((state/'artifacts').exists())

    def test_legacy_projection_upgrade_keeps_ssh_access_and_file_mode(self):
        original=profiles.validate_profile(graph());view=resources.effective_profile(original)
        roundtrip=resources.effective_profile(resources.upgrade_profile(view))
        self.assertEqual(roundtrip,view)
        self.assertEqual(roundtrip['bases'][0]['mode'],'file')
        self.assertEqual(resources.editor_context(original)['connection_bindings'],dict(tj='ssh',jr='ssh',os='ssh'))

    def test_shared_edit_affects_all_three_sources_and_preserves_old_snapshot(self):
        old=profiles.validate_profile(graph());before=deepcopy(old)
        result=resources.compose_profile(old,resources.effective_profile(old),connection_edits=dict(ssh=dict(address='reader@replacement.invalid')))
        self.assertEqual(result['impact']['affected_source_ids'],['jr','os','tj'])
        self.assertEqual(result['impact']['affected_base_ids'],['a','b'])
        self.assertEqual([s['host'] for s in resources.effective_profile(result['profile'])['sources']],['reader@replacement.invalid']*3)
        self.assertEqual(old,before)

    def test_journal_can_switch_to_separate_local_access_without_changing_other_sources(self):
        old=profiles.validate_profile(graph());view=resources.effective_profile(old)
        tj=view['sources'][0];tj['host']='';tj['path']=str(Path('/local/tj').absolute());tj['settings']={'platform_version':'8.3.27.1989'}
        changed=resources.compose_profile(old,view,connection_bindings=dict(tj=None))['profile']
        self.assertIsNone(changed['sources'][0]['connection_id'])
        self.assertEqual([s['connection_id'] for s in changed['sources'][1:]],['ssh','ssh'])
        self.assertNotIn('transport',resources.effective_profile(changed)['sources'][0]['settings'])
        self.assertEqual(changed['bases'][0]['mode'],'file')

    def test_invalid_ssh_roots_access_and_source_types_are_rejected_offline(self):
        for root in ('relative/path','/logs/../private','//logs/root','C:/logs'):
            with self.subTest(root=root):
                value=graph();value['sources'][0]['path']=root
                with self.assertRaises(InputError):profiles.validate_profile(value)
        for field,value in [('address','-ProxyCommand=bad'),('known_hosts_file','bad%path'),('port',True)]:
            with self.subTest(field=field):
                doc=graph()
                if field=='address':doc['connections'][0]['address']=value
                else:doc['connections'][0]['settings'][field]=value
                with self.assertRaises(InputError):profiles.validate_profile(doc)
        value=graph();value['sources'][0]['type']='source';value['sources'][0]['settings']={}
        with self.assertRaises(InputError):profiles.validate_profile(value)
        value=graph();value['sources'][0]['settings']['port']=22
        with self.assertRaises(InputError):profiles.validate_profile(value)

    def test_projected_common_edit_preserves_node_alias_and_clears_old_identity(self):
        old=profiles.validate_profile(graph());old['nodes'][0]['reported_identity']='previous-node-claim'
        changed=deepcopy(old);changed['connections'][0]['address']='reader@replacement.invalid'
        changed['connections'][0]['settings']['known_hosts_file']=str(Path('/changed/known_hosts').absolute())
        view=resources.effective_profile(changed)
        result=resources.compose_profile(old,view,connection_edits=dict(ssh=dict(address=changed['connections'][0]['address'],settings=changed['connections'][0]['settings'])))['profile']
        self.assertEqual([s['node_id'] for s in result['sources']],['linux']*3)
        self.assertEqual(len(result['nodes']),1);self.assertEqual(result['nodes'][0]['name'],'Узел журналов')
        self.assertEqual(result['nodes'][0]['reported_identity'],'')
        self.assertEqual(old['nodes'][0]['reported_identity'],'previous-node-claim')

    def test_explicit_separate_ssh_choice_is_not_coalesced_and_optional_key_can_clear(self):
        old=profiles.validate_profile(graph());view=resources.effective_profile(old)
        separate=resources.compose_profile(old,view,connection_bindings=dict(tj=None))['profile']
        self.assertNotEqual(separate['sources'][0]['connection_id'],separate['sources'][1]['connection_id'])
        self.assertEqual(sum(c['kind']=='ssh' for c in separate['connections']),2)
        cleared=resources.compose_profile(old,view,connection_edits=dict(ssh=dict(settings=dict(identity_file=''))))['profile']
        self.assertNotIn('identity_file',cleared['connections'][0]['settings'])

    def test_custom_os_python_survives_journal_roundtrip_and_shared_edits(self):
        for kind in ('ssh','os'):
            with self.subTest(connection_kind=kind):
                configured=graph();connection=configured['connections'][0];connection['kind']=kind
                connection['settings']['python']='/opt/onec-python/bin/python3'
                if kind=='os':connection['settings']['transport']='ssh'
                old=profiles.validate_profile(configured);view=resources.effective_profile(old)
                self.assertNotIn('python',view['sources'][0]['settings'])
                unchanged=resources.compose_profile(old,view)['profile']
                self.assertEqual(unchanged['connections'][0]['settings']['python'],'/opt/onec-python/bin/python3')
                changed=resources.compose_profile(old,view,connection_edits=dict(ssh=dict(address='reader@replacement.invalid',settings=dict(python='/opt/new-python/bin/python3'))))['profile']
                self.assertEqual(changed['connections'][0]['settings']['python'],'/opt/new-python/bin/python3')
                self.assertEqual(resources.effective_profile(changed)['sources'][2]['settings']['python'],'/opt/new-python/bin/python3')

    def test_ssh_port_change_clears_previous_node_identity_but_keeps_alias_and_old_profile(self):
        old=profiles.validate_profile(graph());old['nodes'][0]['reported_identity']='node-at-old-port';before=deepcopy(old)
        result=resources.compose_profile(old,resources.effective_profile(old),connection_edits=dict(ssh=dict(settings=dict(port=2200))))['profile']
        self.assertEqual(result['nodes'][0]['reported_identity'],'')
        self.assertEqual(result['nodes'][0]['id'],'linux');self.assertEqual(result['nodes'][0]['name'],'Узел журналов')
        self.assertEqual([s['node_id'] for s in result['sources']],['linux']*3)
        self.assertEqual(old,before)


if __name__=='__main__':unittest.main()
