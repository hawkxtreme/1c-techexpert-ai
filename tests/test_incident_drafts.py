import importlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
import hashlib
import subprocess
import sys

PUBLIC_URL='https://www.postgresql.org/docs/17/monitoring-stats.html'

class IncidentDraftTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.incident_drafts'),'reviewable local incident drafts are missing')
        self.api=importlib.import_module('src.techexpert.incident_drafts')

    def investigation(self,state,source_origin=None):
        from src.techexpert.profiles import save_profile
        from src.techexpert.artifacts import save_artifact
        from src.techexpert.investigations import create,revise
        save_profile(state,dict(schema_version=1,name='Private Environment',bases=[dict(id='a',name='PrivateOrders',mode='file',connection='C:/PrivateCompany/Base')],
            sources=[dict(id='os-a',type='os',path='',host='private-node.local',base_ids=['a'])]))
        payload=dict(count=200)
        if source_origin is not None:payload['origin']=source_origin
        artifact=save_artifact(state,'test',{},[('private-observation.txt',b'private raw source')],payload)
        created=create(state,dict(task='PrivateOrders тормозит на private-node.local',template_id='TPL-02',time_mode='past',scale='background'))
        return revise(state,created['investigation_id'],dict(attachments=[dict(id='A-1',kind='artifact',target_id=artifact['artifact_id'])],
            evidence=[dict(id='E-1',attachment='A-1',record='s1')],
            facts=[dict(id='F-1',text='Повторы в PrivateOrders на private-node.local',evidence=['E-1'],measurement=dict(attachment='A-1',pointer='/result/count'))],
            assessment=dict(summary='private-node.local PrivateOrders analyst@example.test 192.0.2.44 C:\\PrivateCompany\\Base 12345678-1234-4234-8234-123456789012 password=synthetic-secret Bearer synthetic-token',
                cause_state='insufficient_data',evidence=['E-1'],limitations=['Проверить свободный текст отдельно'],recommendations=[],
                references=[dict(url=PUBLIC_URL,purpose='Проверка статистики',applicability='PostgreSQL')]),
            open_questions=['```sql\nSELECT * FROM private_business WHERE customer=\'private literal\';\n``` https://internal.local/?token=synthetic-url-secret']),expected_revision=1)

    def test_preview_redacts_known_identifiers_and_secrets_but_keeps_public_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state)
            preview=self.api.prepare(state,inv['investigation_id'])
            serialized=json.dumps(preview,ensure_ascii=False)
            for secret in ('PrivateOrders','private-node.local','analyst@example.test','192.0.2.44','PrivateCompany','12345678-1234-4234-8234-123456789012','synthetic-secret','synthetic-token','synthetic-url-secret','private_business','private literal'):
                self.assertNotIn(secret,serialized)
            self.assertIn(PUBLIC_URL,preview['body'])
            self.assertTrue(preview['requires_human_review'])
            self.assertTrue(preview['redactions'])
            self.assertNotIn('mapping',preview)
            same=self.api.prepare(state,inv['investigation_id'])
            self.assertEqual(same['draft_id'],preview['draft_id'])
            self.assertEqual(same['preview_sha256'],preview['preview_sha256'])

    def test_edit_changes_preview_hash_and_stale_export_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state);first=self.api.prepare(state,inv['investigation_id'])
            second=self.api.edit(state,first['draft_id'],title=first['title'],body=first['body']+'\nДополнение о private-node.local',expected_sha256=first['preview_sha256'])
            self.assertNotEqual(second['preview_sha256'],first['preview_sha256'])
            self.assertNotIn('private-node.local',second['body'])
            self.assertEqual(self.api.prepare(state,inv['investigation_id'])['draft_id'],first['draft_id'])
            destination=state/'public.zip'
            with self.assertRaisesRegex(ValueError,'preview'):self.api.export(state,first['draft_id'],destination,expected_sha256=first['preview_sha256'])
            self.assertFalse(destination.exists())
            receipt=self.api.export(state,second['draft_id'],destination,expected_sha256=second['preview_sha256'])
            self.assertFalse(receipt['published'])
            with zipfile.ZipFile(destination) as archive:
                self.assertEqual(set(archive.namelist()),{'issue.md','report.json','manifest.json'})
                content=b'\n'.join(archive.read(name) for name in archive.namelist()).decode('utf-8')
                self.assertNotIn('private-node.local',content)
                self.assertNotIn('private raw source',content)
                self.assertNotIn('mapping',content)
                self.assertNotIn(inv['investigation_id'],content)
            with self.assertRaises(FileExistsError):self.api.export(state,second['draft_id'],destination,expected_sha256=second['preview_sha256'])

    def test_send_plan_has_only_previewed_payload_and_does_not_publish(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state);preview=self.api.prepare(state,inv['investigation_id'])
            action=self.api.send_plan(state,preview['draft_id'],'owner/repository',expected_sha256=preview['preview_sha256'])
            self.assertEqual(action['title'],preview['title']);self.assertEqual(action['body'],preview['body'])
            self.assertEqual(action['attachments'],[])
            self.assertTrue(action['requires_explicit_user_send'])
            self.assertFalse(action['published'])
            other=self.api.send_plan(state,preview['draft_id'],'owner/other',expected_sha256=preview['preview_sha256'])
            self.assertNotEqual(action.get('action_sha256'),other.get('action_sha256'))
            for repo in ('https://github.com/owner/repository','owner/repository/other','owner;cmd/repo'):
                with self.assertRaises(ValueError):self.api.send_plan(state,preview['draft_id'],repo,expected_sha256=preview['preview_sha256'])

    def test_harness_readback_receipt_must_match_the_preview_and_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state);preview=self.api.prepare(state,inv['investigation_id'])
            action=self.api.send_plan(state,preview['draft_id'],'owner/repository',expected_sha256=preview['preview_sha256'])
            record=getattr(self.api,'record_submission',None);self.assertIsNotNone(record,'a verified-shape harness receipt is missing')
            response=dict(url='https://github.com/owner/repository/issues/1',title=preview['title'],body=preview['body'])
            for wrong in (dict(response,body=response['body']+'unreviewed text'),dict(response,url='https://github.com/owner/other/issues/1')):
                with self.assertRaises(ValueError):record(state,preview['draft_id'],'owner/repository',wrong,expected_sha256=preview['preview_sha256'],expected_action_sha256=action['action_sha256'])
            result=record(state,preview['draft_id'],'owner/repository',response,expected_sha256=preview['preview_sha256'],expected_action_sha256=action['action_sha256'])
            self.assertEqual(result['url'],response['url'])
            self.assertEqual(record(state,preview['draft_id'],'owner/repository',response,expected_sha256=preview['preview_sha256'],expected_action_sha256=action['action_sha256']),result)

    def test_source_corruption_refuses_a_prepared_draft(self):
        from src.techexpert.artifacts import artifact_folder
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state);preview=self.api.prepare(state,inv['investigation_id'])
            target=inv['attachments'][0]['target_id'];(artifact_folder(state,target)/'sources/s1.bin').write_bytes(b'corrupted')
            with self.assertRaises(ValueError):self.api.preview(state,preview['draft_id'])

    def test_lost_private_correspondence_is_not_reported_as_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state);prepared=self.api.prepare(state,inv['investigation_id'])
            table=state/'incident-private'/(inv['investigation_id']+'.json')
            table.write_text('{}',encoding='utf-8')
            with self.assertRaises(ValueError):self.api.preview(state,prepared['draft_id'])

    def test_unknown_ipv6_hosts_and_private_reference_urls_are_not_made_public(self):
        from src.techexpert.investigations import revise
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state)
            inv=revise(state,inv['investigation_id'],dict(open_questions=['Проверить other-node.internal и 2001:db8::7']),expected_revision=2)
            for url in ('https://192.168.1.2/manual','https://[::1]/manual','https://localhost./manual'):
                with self.subTest(url=url),self.assertRaises(ValueError):self.api.prepare(state,inv['investigation_id'],public_urls=[url])
            prepared=self.api.prepare(state,inv['investigation_id'])
            self.assertNotIn('other-node.internal',prepared['body'])
            self.assertNotIn('2001:db8::7',prepared['body'])
            for path in (state/'incident-private').glob('*.json'):
                data=path.read_text(encoding='utf-8')
                self.assertNotIn('synthetic-secret',data);self.assertNotIn('synthetic-token',data)

    def test_selected_excerpt_has_its_own_hash_and_can_be_excluded_after_preview(self):
        from src.techexpert.artifacts import artifact_folder
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state)
            first=self.api.prepare(state,inv['investigation_id'],evidence_ids=['E-1'])
            excerpt=next(f for f in first['files'] if f['path'].startswith('evidence/'))
            public_id=Path(excerpt['path']).stem
            self.assertEqual(hashlib.sha256(excerpt['text'].encode()).hexdigest(),excerpt['sha256'])
            self.assertIn('private raw source',first['body'])
            self.assertIn('private raw source',self.api.send_plan(state,first['draft_id'],'owner/repository',expected_sha256=first['preview_sha256'])['body'])
            removed=self.api.edit(state,first['draft_id'],title=first['title'],body=first['body'],exclude_evidence_ids=[public_id],expected_sha256=first['preview_sha256'])
            self.assertFalse(any(f['path'].startswith('evidence/') for f in removed['files']))
            self.assertNotIn('private raw source',removed['body'])
            self.assertNotEqual(first['preview_sha256'],removed['preview_sha256'])

    def test_full_local_preview_is_escaped_and_its_integrity_is_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state);prepared=self.api.prepare(state,inv['investigation_id'])
            path=prepared.get('local_preview_path')
            self.assertIsNotNone(path,'a complete human-readable local preview is required')
            text=Path(path).read_text(encoding='utf-8')
            self.assertIn(prepared['preview_sha256'],text)
            self.assertNotIn('<script',text.lower())
            self.assertNotIn('src="http',text)
            Path(path).write_text('tampered preview',encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'preview'):self.api.preview(state,prepared['draft_id'])

    def test_encoded_credential_urls_and_russian_secret_labels_are_removed(self):
        from src.techexpert.investigations import revise
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state)
            for value in ('https://example.test/doc?%74oken=synthetic','https://example.test/doc?api_key=synthetic'):
                with self.subTest(url=value),self.assertRaises(ValueError):self.api.prepare(state,inv['investigation_id'],public_urls=[value])
            assessment=dict(inv['assessment']);assessment['summary']='Пароль=русский-секрет токен=второй-секрет имя@пример.рф'
            updated=revise(state,inv['investigation_id'],dict(assessment=assessment),expected_revision=2)
            prepared=self.api.prepare(state,updated['investigation_id'])
            for value in ('русский-секрет','второй-секрет','имя@пример.рф'):self.assertNotIn(value,prepared['body'])

    def test_cli_prepares_previews_and_exports_without_a_network_publisher(self):
        repo=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state)
            def run(*args):
                result=subprocess.run([sys.executable,'-X','utf8',str(repo/'techexpert.py'),'--state-dir',str(state),*args],capture_output=True,timeout=15)
                self.assertEqual(result.returncode,0,result.stderr.decode('utf-8',errors='replace')+result.stdout.decode('utf-8',errors='replace'))
                return json.loads(result.stdout)
            draft=run('incident-draft',inv['investigation_id'],'--summary')
            self.assertNotIn('body',draft)
            self.assertTrue(Path(draft['local_preview_path']).exists())
            preview=run('incident-preview',draft['draft_id'])
            self.assertEqual(preview['preview_sha256'],draft['preview_sha256'])
            plan=run('incident-send-plan',draft['draft_id'],'--repository','owner/repository','--expected-sha256',draft['preview_sha256'])
            self.assertFalse(plan['published'])
            exported=run('incident-export',draft['draft_id'],str(state/'case.zip'),'--expected-sha256',draft['preview_sha256'])
            self.assertTrue(Path(exported['path']).exists())

    def test_free_form_origin_metadata_is_not_copied_into_the_public_report(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state,source_origin='private-origin-with-commercial-name')
            prepared=self.api.prepare(state,inv['investigation_id'])
            self.assertNotIn('private-origin-with-commercial-name',json.dumps(prepared))

    def test_export_does_not_add_actual_timestamps_or_source_file_attributes(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state);prepared=self.api.prepare(state,inv['investigation_id'])
            output=state/'reviewed.zip';self.api.export(state,prepared['draft_id'],output,expected_sha256=prepared['preview_sha256'])
            with zipfile.ZipFile(output) as archive:
                for member in archive.infolist():self.assertEqual(member.date_time,(1980,1,1,0,0,0))

    def test_binary_control_characters_in_an_excerpt_require_a_text_preparation_step(self):
        from src.techexpert.artifacts import save_artifact
        from src.techexpert.investigations import revise
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state)
            raw=save_artifact(state,'test',{},[('binary',b'opaque\x00content')],{})
            inv=revise(state,inv['investigation_id'],dict(attachments=inv['attachments']+[dict(id='A-2',kind='artifact',target_id=raw['artifact_id'])],
                evidence=inv['evidence']+[dict(id='E-2',attachment='A-2',record='s1')]),expected_revision=2)
            with self.assertRaisesRegex(ValueError,'text'):self.api.prepare(state,inv['investigation_id'],evidence_ids=['E-2'])

    def test_encoded_source_snapshot_requires_a_separate_prepared_text_excerpt(self):
        from src.techexpert.source_code import snapshot_source
        from src.techexpert.investigations import revise
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state);source=state/'source';source.mkdir()
            (source/'Module.bsl').write_text('SecretBusiness = "private code";',encoding='utf-8')
            raw=snapshot_source(state,source)
            inv=revise(state,inv['investigation_id'],dict(attachments=inv['attachments']+[dict(id='A-2',kind='artifact',target_id=raw['artifact_id'])],
                evidence=inv['evidence']+[dict(id='E-2',attachment='A-2',record='s1')]),expected_revision=2)
            with self.assertRaisesRegex(ValueError,'prepared text'):self.api.prepare(state,inv['investigation_id'],evidence_ids=['E-2'])

    def test_identifiers_from_tool_reports_are_pseudonymized_even_without_profile_entries(self):
        from src.techexpert.artifacts import save_artifact
        from src.techexpert.investigations import revise
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state)
            raw=save_artifact(state,'postgresql',{},[('response.json',b'{"database":"CommercePrivate"}')],
                dict(database='CommercePrivate',connection_scope=dict(host='NODESECRET',user='LoginPrivate'),rows=[dict(usename='AnotherLogin')]))
            inv=revise(state,inv['investigation_id'],dict(attachments=inv['attachments']+[dict(id='A-2',kind='artifact',target_id=raw['artifact_id'])],
                open_questions=['CommercePrivate on NODESECRET under LoginPrivate and AnotherLogin']),expected_revision=2)
            prepared=self.api.prepare(state,inv['investigation_id'])
            for value in ('CommercePrivate','NODESECRET','LoginPrivate','AnotherLogin'):self.assertNotIn(value,prepared['body'])

    def test_recommendations_keep_conditions_risk_and_rollback_in_the_proposal(self):
        from src.techexpert.investigations import revise
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state);assessment=dict(inv['assessment'])
            assessment['recommendations']=[dict(id='R-1',kind='lab_change',basis=['E-1'],goal='Изменить в лаборатории',
                prerequisites='Только при неизменяемом каталоге',expected_effect='Сократить повторы',verification='Сравнить документы',
                limitations='Не проверено в рабочей базе',risk='Риск устаревшего значения',rollback='Вернуть исходный обработчик')]
            inv=revise(state,inv['investigation_id'],dict(assessment=assessment),expected_revision=2)
            prepared=self.api.prepare(state,inv['investigation_id'])
            for key in ('prerequisites','expected_effect','risk','rollback'):self.assertIn(assessment['recommendations'][0][key],prepared['body'])

    def test_corrupted_submission_receipt_is_not_exposed_as_a_previous_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state);prepared=self.api.prepare(state,inv['investigation_id'])
            action=self.api.send_plan(state,prepared['draft_id'],'owner/repository',expected_sha256=prepared['preview_sha256'])
            self.api.record_submission(state,prepared['draft_id'],'owner/repository',dict(url='https://github.com/owner/repository/issues/1',title=action['title'],body=action['body']),
                expected_sha256=prepared['preview_sha256'],expected_action_sha256=action['action_sha256'])
            path=state/'incident-drafts'/prepared['draft_id']/'submissions'/(action['action_sha256']+'.json')
            receipt=json.loads(path.read_text());receipt['unexpected']='private value';path.write_text(json.dumps(receipt),encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'submission'):self.api.send_plan(state,prepared['draft_id'],'owner/repository',expected_sha256=prepared['preview_sha256'])

    def test_quoted_json_secret_fields_are_removed_including_nested_and_escaped_values(self):
        from src.techexpert.artifacts import save_artifact
        from src.techexpert.investigations import revise
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state)
            secrets={'password':'SYNTHETIC-JSON-SECRET','api_key':'SYNTHETIC-KEY','пароль':'СЕКРЕТ-ИЗ-JSON','token':'SYNTHETIC-ESCAPED-"-TAIL'}
            data=json.dumps({'nested':secrets},ensure_ascii=False).encode()
            artifact=save_artifact(state,'test',{},[('observation.json',data)],{})
            inv=revise(state,inv['investigation_id'],dict(attachments=inv['attachments']+[dict(id='A-2',kind='artifact',target_id=artifact['artifact_id'])],
                evidence=inv['evidence']+[dict(id='E-2',attachment='A-2',record='s1')]),expected_revision=2)
            view=self.api.prepare(state,inv['investigation_id'],evidence_ids=['E-2'])
            serialized=json.dumps(view,ensure_ascii=False)
            for value in (*secrets.values(),'SYNTHETIC-ESCAPED','TAIL'):
                self.assertNotIn(value,serialized)
                self.assertNotIn(value,(state/'incident-private'/(inv['investigation_id']+'.json')).read_text(encoding='utf-8'))

    def test_public_evidence_names_do_not_expose_arbitrary_local_identifiers(self):
        from src.techexpert.investigations import revise
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state)
            inv=revise(state,inv['investigation_id'],dict(evidence=inv['evidence']+[dict(id='E-PrivateOrders',attachment='A-1',record='s1')]),expected_revision=2)
            first=self.api.prepare(state,inv['investigation_id'],evidence_ids=['E-PrivateOrders'])
            self.assertNotIn('PrivateOrders',json.dumps(first,ensure_ascii=False))
            file=next(f for f in first['files'] if f['path'].startswith('evidence/'))
            another=self.api.prepare(state,inv['investigation_id'],evidence_ids=['E-PrivateOrders'],include_versions=True)
            self.assertEqual(file['path'],next(f for f in another['files'] if f['path'].startswith('evidence/'))['path'])

    def test_local_evidence_identifiers_in_free_text_use_the_same_public_alias(self):
        from src.techexpert.investigations import revise
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state);local_id='E-CommerceSecret'
            inv=revise(state,inv['investigation_id'],dict(evidence=inv['evidence']+[dict(id=local_id,attachment='A-1',record='s1')],
                open_questions=['Нужно проверить '+local_id]),expected_revision=2)
            view=self.api.prepare(state,inv['investigation_id'],evidence_ids=[local_id])
            self.assertFalse(local_id in json.dumps(view),'local evidence identifier leaked into the preview')
            public_id=Path(next(f['path'] for f in view['files'] if f['path'].startswith('evidence/'))).stem
            self.assertGreaterEqual(view['body'].count(public_id),2)

    def test_encoded_json_secret_keys_and_nonstring_values_are_removed_before_text_cleanup(self):
        from src.techexpert.artifacts import save_artifact
        from src.techexpert.investigations import revise
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state)
            artifact=save_artifact(state,'test',{},[('observation.json',b'{"\\u0070assword":{"part":"PRIVATE-VALUE"},"nested":[{"token":["PRIVATE-TOKEN"]}]}')],{})
            inv=revise(state,inv['investigation_id'],dict(attachments=inv['attachments']+[dict(id='A-2',kind='artifact',target_id=artifact['artifact_id'])],
                evidence=inv['evidence']+[dict(id='E-2',attachment='A-2',record='s1')]),expected_revision=2)
            view=self.api.prepare(state,inv['investigation_id'],evidence_ids=['E-2'])
            self.assertNotIn('PRIVATE-VALUE',json.dumps(view));self.assertNotIn('PRIVATE-TOKEN',json.dumps(view))

    def test_old_cleanup_policy_draft_requires_new_preparation_before_export(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state);view=self.api.prepare(state,inv['investigation_id'])
            folder=state/'incident-drafts'/view['draft_id']/'revisions'/'000001'
            source=json.loads((folder/'source.json').read_text(encoding='utf-8'));source['sanitizer_version']=0
            raw=json.dumps(source).encode();(folder/'source.json').write_bytes(raw)
            receipt=json.loads((folder/'receipt.json').read_text(encoding='utf-8'));receipt['source_sha256']=hashlib.sha256(raw).hexdigest()
            (folder/'receipt.json').write_text(json.dumps(receipt),encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'policy changed'):self.api.export(state,view['draft_id'],state/'old.zip',expected_sha256=view['preview_sha256'])
            self.assertFalse((state/'old.zip').exists())

    def test_json_decoding_must_not_introduce_hidden_direction_controls_into_the_preview(self):
        from src.techexpert.artifacts import save_artifact
        from src.techexpert.investigations import revise
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.investigation(state)
            artifact=save_artifact(state,'test',{},[('observation.json',b'{"password":"private","note":"\\u202e"}')],{})
            inv=revise(state,inv['investigation_id'],dict(attachments=inv['attachments']+[dict(id='A-2',kind='artifact',target_id=artifact['artifact_id'])],
                evidence=inv['evidence']+[dict(id='E-2',attachment='A-2',record='s1')]),expected_revision=2)
            with self.assertRaisesRegex(ValueError,'control'):self.api.prepare(state,inv['investigation_id'],evidence_ids=['E-2'])

    def jr_investigation(self,state):
        from src.techexpert.native_jr import read_journal
        from src.techexpert.investigations import revise
        inv=self.investigation(state);journal=state/'jr';journal.mkdir()
        header='1CV8LOG(ver 2.0)\n12345678-1234-4234-8234-123456789012\n'
        (journal/'1Cv8.lgf').write_text(header+'{1,"OperatorPetrov",1},\n{2,"PERSONAL-COMPUTER-01",1},\n{3,"Client",1},\n{4,"_$Job$_.Start",1},\n',encoding='utf-8')
        (journal/'20261116000000.lgp').write_text(header+'{20261116090000,N,0,1,1,1,1,1,I,"OperatorPetrov PERSONAL-COMPUTER-01",0,{},0,0,0,0,1,0,0},\n',encoding='utf-8')
        artifact=read_journal(state,journal,platform_version='8.3.27.1989',utc_offset='+03:00')
        self.assertEqual(artifact['result']['event_count'],1)
        inv=revise(state,inv['investigation_id'],dict(attachments=inv['attachments']+[dict(id='A-2',kind='artifact',target_id=artifact['artifact_id'])],
            evidence=inv['evidence']+[dict(id='E-2',attachment='A-2',record='s1'),dict(id='E-3',attachment='A-2',record='s2:r1')]),expected_revision=2)
        return inv

    def test_whole_serialized_jr_dictionary_is_not_a_prepared_public_excerpt(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.jr_investigation(state)
            with self.assertRaisesRegex(ValueError,'prepared text'):self.api.prepare(state,inv['investigation_id'],evidence_ids=['E-2'])

    def test_native_jr_record_requires_prepared_text_instead_of_exporting_serialized_values(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);inv=self.jr_investigation(state)
            with self.assertRaisesRegex(ValueError,'prepared text'):self.api.prepare(state,inv['investigation_id'],evidence_ids=['E-3'])

    def test_duplicate_or_truncated_json_never_falls_back_to_uncleaned_text(self):
        from src.techexpert.artifacts import save_artifact
        from src.techexpert.investigations import revise
        samples=[b'{"\\u0070assword":"SECRET1","\\u0070assword":"SECRET2"}',
                 b'{"\\u0070assword":"SECRET1","padding":"'+b'x'*9000+b'"}']
        for data in samples:
            with self.subTest(bytes=len(data)),tempfile.TemporaryDirectory() as temp:
                state=Path(temp);inv=self.investigation(state)
                artifact=save_artifact(state,'test',{},[('observation.json',data)],{})
                inv=revise(state,inv['investigation_id'],dict(attachments=inv['attachments']+[dict(id='A-2',kind='artifact',target_id=artifact['artifact_id'])],
                    evidence=inv['evidence']+[dict(id='E-2',attachment='A-2',record='s1')]),expected_revision=2)
                with self.assertRaisesRegex(ValueError,'JSON|prepared'):self.api.prepare(state,inv['investigation_id'],evidence_ids=['E-2'])

if __name__=='__main__':unittest.main()
