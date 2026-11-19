import copy
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import tempfile
import os
import subprocess
import sys
import zipfile
import unittest
from unittest.mock import patch

from src.techexpert import knowledge


class KnowledgeLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.knowledge_review'),
                             'Knowledge-use snapshots and reuse review are missing')
        self.api=importlib.import_module('src.techexpert.knowledge_review')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.library=self.root/'knowledge';self.library.mkdir();self.state=self.root/'state'
        def source(sid):
            return dict(id=sid,url='https://example.test/'+sid,publisher='Synthetic fixture author',checked_at='2026-11-16',
                storage='url_only',lifecycle=dict(state='active'),link=dict(state='not_checked'),
                rights=dict(status='link_only',basis='Only independently authored fixture notes and URL are stored.'))
        def card(cid,sid,depends=()):
            path=cid+'.md';(self.library/path).write_text('Own synthetic slow-job note '+cid+'\n',encoding='utf-8')
            return dict(id=cid,title='Slow job '+cid,type='method',status='reviewed',author='Fixture',date='2026-11-16',revision=1,
                applicability='Synthetic controlled scope',signs=['slow'],steps=['measure'],evidence_basis='Synthetic test only',
                sources=[sid],related=['C'] if cid=='A' else [],depends_on=list(depends),path=path,lifecycle=dict(state='active'))
        self.doc=dict(schema_version=2,revision='fixture-1',sources=[source('S1'),source('S2')],
            cards=[card('A','S1',['B']),card('B','S1'),card('C','S2')],open_conflicts=[])
        self.save()

    def save(self):
        (self.library/'index.json').write_text(json.dumps(self.doc,ensure_ascii=False,indent=2),encoding='utf-8')

    def pin(self,*ids):return self.api.pin_use(self.state,list(ids),root=self.library)

    def test_schema2_is_ready_and_defaults_do_not_claim_source_or_expert_verification(self):
        library=knowledge.load_library(self.library)
        self.assertEqual(library['revision'],'fixture-1')
        self.assertEqual(library['sources']['S1']['link']['state'],'not_checked')
        found=knowledge.search('slow',root=self.library)
        self.assertEqual(len(found['matches']),3)
        self.assertFalse(found['matches'][0]['diagnosis_for_current_case_established'])

    def test_event_claims_bind_exact_revision_and_retained_source_provenance(self):
        a = self.doc['cards'][0]
        a.update(type='tj_event', event_types=['SDBL'], claims=[
            dict(id='observed-model-call', status='documented', text='Own fixture statement.',
                 applicability='Synthetic test scope', sources=['S1'])])
        self.save()
        actual = knowledge.load_library(self.library)['digest']
        pinned = self.api.pin_use(self.state, ['A'], root=self.library, expected_knowledge_digest=actual)
        self.assertEqual(pinned['result']['cards'][0]['card']['claims'], a['claims'])
        self.assertEqual(self.api.checked_snapshot(pinned)['result']['library_digest'], actual)
        forged = copy.deepcopy(pinned)
        card = forged['result']['cards'][0]
        card['card']['claims'][0]['sources'] = ['S2']
        card['metadata_sha256'] = knowledge.digest(card['card'])
        with self.assertRaisesRegex(ValueError, 'claim source'):
            self.api.checked_snapshot(forged)

        a['claims'][0]['text'] = 'Changed independently authored statement.'
        self.save()
        with self.assertRaisesRegex(ValueError, 'revision changed'):
            self.api.pin_use(self.state, ['A'], root=self.library, expected_knowledge_digest=actual)
        review = self.api.review_use(self.state, pinned['artifact_id'], root=self.library)
        self.assertIn('card_metadata_changed', {reason['code'] for reason in review['cards'][0]['reasons']})

        for changes in ({'event_types':['SDBL','sdbl']}, {'event_types':[]},
                        {'claims':[dict(a['claims'][0], sources=['S2'])]},
                        {'lifecycle':dict(state='withdrawn',reason='Fixture withdrawal'),'path':None}):
            with self.subTest(changes=changes):
                self.doc['cards'][0] = dict(a, **changes)
                self.save()
                with self.assertRaises(ValueError):
                    knowledge.load_library(self.library)

    def test_explicit_dependencies_are_not_the_related_navigation_graph(self):
        self.doc['sources'][0]['lifecycle']=dict(state='withdrawn',reason='Synthetic source withdrawal')
        self.save();found=knowledge.search('slow',root=self.library)
        by_id={m['id']:m for m in found['matches']}
        self.assertTrue(by_id['A']['review_required']);self.assertTrue(by_id['B']['review_required'])
        self.assertFalse(by_id['C']['review_required'])

    def test_search_applies_constraints_of_explicit_dependencies(self):
        self.doc['cards'][1]['applicability_constraints'] = dict(database_mode=['server'])
        self.save()
        found = knowledge.search('slow', environment=dict(database_mode='file'), root=self.library)
        self.assertEqual([row['id'] for row in found['matches']], ['C'])
        excluded = {row['id']: row for row in found['excluded_matches']}
        self.assertEqual(set(excluded), {'A', 'B'})
        self.assertEqual(excluded['A']['reasons'][0]['card'], 'B')
        self.assertEqual(excluded['A']['applicability_check']['status'], 'outside_recorded_scope')

    def test_withdrawn_tombstone_has_no_body_and_is_not_offered_by_search(self):
        self.doc['cards'][1].update(path=None,lifecycle=dict(state='withdrawn',reason='Synthetic rights request'))
        self.save()
        with patch('subprocess.run',side_effect=AssertionError('knowledge caused a process launch')):
            found=knowledge.search('slow',root=self.library)
        self.assertNotIn('B',[m['id'] for m in found['matches']])
        self.assertTrue(next(m for m in found['matches'] if m['id']=='A')['review_required'])
        self.assertNotIn('B.md',knowledge.package_members(self.library))
        with self.assertRaises(ValueError):self.pin('B')

    def test_explicit_conflict_keeps_both_positions_open(self):
        self.doc['open_conflicts']=[dict(id='X1',cards=['A','C'],summary='Synthetic incompatible positions; not adjudicated.')]
        self.save();found=knowledge.search('slow',root=self.library)
        selected={m['id']:m for m in found['matches']}
        self.assertTrue(selected['A']['review_required']);self.assertTrue(selected['C']['review_required'])
        self.assertEqual(selected['A']['open_conflicts'][0]['cards'],['A','C'])
        self.assertFalse(selected['A']['technical_truth_judged'])
        page = knowledge.search('A', limit=1, root=self.library)
        self.assertEqual([row['id'] for row in page['matches']], ['A'])
        versions = {position['id']: position for position in page['conflicts'][0]['positions']}
        self.assertEqual(set(versions), {'A','C'})
        self.assertEqual(versions['A']['revision'],1)

    def test_link_unavailability_is_not_technical_falsehood(self):
        self.doc['sources'][0]['link']=dict(state='unavailable',checked_at='2026-11-16',reason='Synthetic offline observation')
        self.save();found=knowledge.search('slow',root=self.library)
        a=next(m for m in found['matches'] if m['id']=='A')
        self.assertFalse(a['review_required']);self.assertTrue(a['link_warnings'])

    def test_source_check_date_alone_does_not_change_technical_basis(self):
        pinned=self.pin('A');self.doc['sources'][0]['checked_at']='2026-11-17';self.save()
        result=self.api.review_use(self.state,pinned['artifact_id'],root=self.library)
        self.assertFalse(result['cards'][0]['review_required'])

    def test_reserved_computed_metadata_and_unsafe_conditions_link_are_rejected(self):
        self.doc['cards'][0]['body']='Untrusted computed override';self.save()
        with self.assertRaises(ValueError):knowledge.load_library(self.library)
        self.doc['cards'][0].pop('body');self.doc['sources'][0]['rights']['conditions_url']='javascript:bad';self.save()
        with self.assertRaises(ValueError):knowledge.load_library(self.library)

    def test_dependency_cycles_and_unknown_references_are_rejected(self):
        self.doc['cards'][1]['depends_on']=['A'];self.save()
        with self.assertRaises(ValueError):knowledge.load_library(self.library)
        self.doc['cards'][1]['depends_on']=['missing'];self.save()
        with self.assertRaises(ValueError):knowledge.load_library(self.library)

    def test_linked_catalogue_root_and_ancestor_are_rejected_before_content_read(self):
        from src.techexpert.inputs import InputError
        target=self.root/'outside';target.mkdir();(target/'nested').mkdir()
        marker=target/'nested/index.json';marker.write_bytes(b'must not be read through a link')
        before=marker.read_bytes()
        script=self.root/'junction.ps1'
        script.write_text("param([string]$LeafPath,[string]$TargetPath)\n$ErrorActionPreference='Stop'\nNew-Item -ItemType Junction -Path $LeafPath -Target $TargetPath -ErrorAction Stop | Out-Null\n",encoding='utf-8-sig')
        for name,destination,nested in [('root-link',target/'nested',False),('parent-link',target,True)]:
            with self.subTest(name=name):
                leaf=self.root/name
                if os.name=='nt':
                    run=subprocess.run(['C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(script),str(leaf),str(destination)],capture_output=True,timeout=15)
                    self.assertEqual(run.returncode,0,run.stderr)
                else:os.symlink(destination,leaf,target_is_directory=True)
                try:
                    with patch.object(knowledge,'read_snapshot',side_effect=AssertionError('linked catalogue bytes opened')):
                        with self.assertRaises(InputError):knowledge.load_library(leaf/'nested' if nested else leaf)
                finally:
                    if os.name=='nt':os.rmdir(leaf)
                    else:leaf.unlink()
                self.assertEqual(marker.read_bytes(),before)

    def test_unknown_lifecycle_state_and_original_storage_are_rejected(self):
        self.doc['sources'][0]['lifecycle']=dict(state='automatically_verified');self.save()
        with self.assertRaises(ValueError):knowledge.load_library(self.library)
        self.doc['sources'][0]['lifecycle']=dict(state='active');self.doc['sources'][0]['storage']='full_article';self.save()
        with self.assertRaises(ValueError):knowledge.load_library(self.library)

    def test_usage_snapshot_survives_changes_and_marks_only_dependent_requested_cards(self):
        pinned=self.pin('A','C')
        (self.library/'B.md').write_text('Changed independently authored fixture note\n',encoding='utf-8')
        self.doc['revision']='fixture-2';self.save()
        result=self.api.review_use(self.state,pinned['artifact_id'],root=self.library)
        cards={c['id']:c for c in result['cards']}
        self.assertTrue(cards['A']['review_required']);self.assertFalse(cards['C']['review_required'])
        self.assertFalse(result['technical_truth_judged'])
        folder=self.state/'artifacts'/pinned['artifact_id']
        self.assertTrue((folder/'sources/s1.bin').read_bytes().startswith(b'Own synthetic'))

    def test_card_metadata_change_and_new_platform_need_review_not_automatic_rejection(self):
        self.doc['cards'][0]['applicability_constraints']=dict(platform_version=['8.3.27.1989']);self.save()
        pinned=self.pin('A')
        result=self.api.review_use(self.state,pinned['artifact_id'],root=self.library,environment=dict(platform_version='8.3.28.1'))
        self.assertTrue(result['cards'][0]['review_required'])
        self.assertIn('outside_recorded_applicability',[r['code'] for r in result['cards'][0]['reasons']])
        self.assertFalse(result['technical_truth_judged'])

    def test_crlf_only_change_does_not_invalidate_a_card(self):
        pinned=self.pin('A')
        path=self.library/'A.md';path.write_bytes(path.read_bytes().replace(b'\r\n',b'\n').replace(b'\n',b'\r\n'))
        result=self.api.review_use(self.state,pinned['artifact_id'],root=self.library)
        self.assertFalse(result['cards'][0]['review_required'])

    def test_changed_unrelated_card_does_not_invalidate_used_card(self):
        pinned=self.pin('A');(self.library/'C.md').write_text('Unrelated change',encoding='utf-8')
        self.doc['revision']='fixture-2';self.save()
        result=self.api.review_use(self.state,pinned['artifact_id'],root=self.library)
        self.assertFalse(result['cards'][0]['review_required'])

    def test_missing_or_withdrawn_dependency_retains_snapshot_and_requests_review(self):
        pinned=self.pin('A')
        self.doc['cards'][1].update(path=None,lifecycle=dict(state='withdrawn',reason='Synthetic withdrawal'));self.save()
        result=self.api.review_use(self.state,pinned['artifact_id'],root=self.library)
        self.assertTrue(result['cards'][0]['review_required'])
        self.doc['cards'][0]['depends_on']=[];self.doc['cards'].pop(1);self.save()
        result=self.api.review_use(self.state,pinned['artifact_id'],root=self.library)
        self.assertTrue(result['cards'][0]['review_required'])

    def test_snapshot_corruption_is_not_replaced_from_current_card(self):
        pinned=self.pin('A');path=self.state/'artifacts'/pinned['artifact_id']/'sources/s1.bin';path.write_bytes(b'changed')
        with self.assertRaises(ValueError):self.api.review_use(self.state,pinned['artifact_id'],root=self.library)

    def test_snapshot_card_identity_cannot_disagree_with_its_hashed_metadata(self):
        pinned=self.pin('A');folder=self.state/'artifacts'/pinned['artifact_id'];path=folder/'report.json'
        report=json.loads(path.read_text(encoding='utf-8'));entry=report['result']['cards'][0]
        entry['card']['id']='C';entry['metadata_sha256']=knowledge.digest(entry['card'])
        data=json.dumps(report).encode('utf-8');path.write_bytes(data)
        receipt=json.loads((folder/'receipt.json').read_text(encoding='utf-8'));receipt['report_sha256']=hashlib.sha256(data).hexdigest()
        (folder/'receipt.json').write_text(json.dumps(receipt),encoding='utf-8')
        with self.assertRaises(ValueError):self.api.review_use(self.state,pinned['artifact_id'],root=self.library)

    def test_broken_current_library_is_separate_from_saved_snapshot_integrity(self):
        pinned=self.pin('A');(self.library/'index.json').write_text('{broken',encoding='utf-8')
        result=self.api.review_use(self.state,pinned['artifact_id'],root=self.library)
        self.assertEqual(result['status'],'current_library_unavailable')
        self.assertTrue(result['saved_snapshot_integrity_verified'])

    def test_investigation_recommendations_follow_exact_knowledge_evidence(self):
        from src.techexpert.investigations import create,revise,load
        pinned=self.pin('A','C')
        first=create(self.state,dict(task='SC01 synthetic knowledge use',template_id='TPL-02',time_mode='past',scale='background'))
        sources={c['id']:c['source_id'] for c in pinned['result']['cards']}
        patch_doc=dict(attachments=[dict(id='A-KB',kind='artifact',target_id=pinned['artifact_id'])],
            evidence=[dict(id='E-A',attachment='A-KB',record=sources['A']),dict(id='E-C',attachment='A-KB',record=sources['C'])],
            hypotheses=[dict(id='H-1',text='Synthetic hypothesis using A',status='proposed',evidence=['E-A'])],
            assessment=dict(summary='Synthetic saved interpretation',cause_state='insufficient_data',evidence=[],limitations=['Synthetic fixture'],references=[],
                recommendations=[dict(id='R-1',kind='diagnostic',basis=['E-A'],goal='Measure A',prerequisites='Fixture only',expected_effect='Evidence',verification='Compare',limitations='Not a diagnosis'),
                    dict(id='R-2',kind='diagnostic',basis=['E-C'],goal='Measure C',prerequisites='Fixture only',expected_effect='Evidence',verification='Compare',limitations='Not a diagnosis'),
                    dict(id='R-3',kind='diagnostic',basis=['H-1'],goal='Check hypothesis',prerequisites='Fixture only',expected_effect='Evidence',verification='Compare',limitations='Not a diagnosis')]))
        doc=revise(self.state,first['investigation_id'],patch_doc,expected_revision=1)
        folder=self.state/'investigations'/doc['investigation_id'];paths=[folder/'head.json',folder/'revisions/000002/report.json',folder/'revisions/000002/report.md']
        before={str(p):p.read_bytes() for p in paths}
        self.doc['sources'][0]['lifecycle']=dict(state='withdrawn',reason='Synthetic changed basis');self.save()
        result=self.api.review_investigation(self.state,doc,root=self.library)
        self.assertEqual(result['recommendations_requiring_review'],['R-1','R-3'])
        self.assertEqual({str(p):p.read_bytes() for p in paths},before)
        self.assertEqual(load(self.state,doc['investigation_id']),doc)

    def test_changed_attachment_warns_even_before_recommendations_are_written(self):
        from src.techexpert.investigations import create,revise
        pinned=self.pin('A')
        doc=create(self.state,dict(task='SC01 pending interpretation',template_id='TPL-02',time_mode='past',scale='background'))
        doc=revise(self.state,doc['investigation_id'],dict(attachments=[dict(id='A-KB',kind='artifact',target_id=pinned['artifact_id'])]),expected_revision=1)
        self.doc['cards'][1].update(path=None,lifecycle=dict(state='withdrawn',reason='Synthetic withdrawn basis'));self.save()
        result=self.api.review_investigation(self.state,doc,root=self.library)
        self.assertEqual(result['status'],'review_required')
        self.assertEqual(result['recommendations_requiring_review'],[])
        self.assertFalse(result['stored_assessment_changed'])

    def test_one_tracked_recommendation_does_not_hide_an_untracked_basis(self):
        from src.techexpert.investigations import create,revise
        from src.techexpert.artifacts import save_artifact
        pinned=self.pin('A')
        observed=save_artifact(self.state,'observation',{},[('fixture.txt',b'Own synthetic observation')],{})
        with patch('src.techexpert.investigations.knowledge_revision',return_value=knowledge.load_library(self.library)['legacy_digest']):
            doc=create(self.state,dict(task='SC01 mixed recommendation basis',template_id='TPL-02',time_mode='past',scale='background'))
        doc=revise(self.state,doc['investigation_id'],dict(
            attachments=[dict(id='A-KB',kind='artifact',target_id=pinned['artifact_id']),dict(id='A-OBS',kind='artifact',target_id=observed['artifact_id'])],
            evidence=[dict(id='E-KB',attachment='A-KB',record='s1'),dict(id='E-OBS',attachment='A-OBS',record='s1')],
            assessment=dict(summary='Synthetic only',cause_state='insufficient_data',evidence=[],limitations=['Fixture'],references=[],
                recommendations=[dict(id=rid,kind='diagnostic',basis=[basis],goal='Measure',prerequisites='Fixture',expected_effect='Evidence',verification='Compare',limitations='Fixture')
                    for rid,basis in [('R-1','E-KB'),('R-2','E-OBS')]])),expected_revision=1)
        self.assertEqual(self.api.review_investigation(self.state,doc,root=self.library)['status'],'unchanged')
        self.doc['sources'][1]['lifecycle']=dict(state='withdrawn',reason='Synthetic unrelated source withdrawal');self.save()
        result=self.api.review_investigation(self.state,doc,root=self.library)
        self.assertEqual(result['status'],'review_required')
        self.assertEqual(result['recommendations_requiring_review'],[])
        self.assertEqual(result['untracked_recommendation_ids'],['R-2'])
        self.assertEqual(result['legacy_warning']['code'],'knowledge_revision_changed_usage_untracked')
        self.assertEqual(result['usages'][0]['review']['status'],'unchanged')

    def test_cli_pins_reviews_and_reads_bounded_card_without_model_or_network(self):
        from src.techexpert.storage import ROOT
        cid=knowledge.load_library()['cards'][0]['id']
        command=[sys.executable,'-X','utf8',str(ROOT/'techexpert.py'),'--state-dir',str(self.state)]
        def cli(*args):
            run=subprocess.run(command+list(args),cwd=self.root,capture_output=True,timeout=15)
            self.assertEqual(run.returncode,0,run.stderr.decode('utf-8',errors='replace'))
            return json.loads(run.stdout)
        card=cli('knowledge-card',cid,'--limit','20')
        self.assertLessEqual(len(card['body']),20);self.assertTrue(card['body_truncated'])
        usage=cli('knowledge-use',cid)
        self.assertEqual(usage['kind'],'knowledge_use')
        review=cli('knowledge-review',usage['artifact_id'],'--kind','artifact')
        self.assertEqual(review['status'],'unchanged')

    def test_private_knowledge_snapshot_is_not_a_public_incident_excerpt(self):
        from src.techexpert.investigations import create,revise
        from src.techexpert.incident_drafts import prepare
        pinned=self.pin('A')
        doc=create(self.state,dict(task='SC01 proposal fixture',template_id='TPL-02',time_mode='past',scale='background'))
        doc=revise(self.state,doc['investigation_id'],dict(attachments=[dict(id='A-KB',kind='artifact',target_id=pinned['artifact_id'])],
            evidence=[dict(id='E-KB',attachment='A-KB',record='s1')]),expected_revision=1)
        with self.assertRaises(ValueError):prepare(self.state,doc['investigation_id'],evidence_ids=['E-KB'])

    def test_withdrawn_body_is_excluded_from_portable_members_and_inventory(self):
        from scripts import package_plugin
        from src.techexpert.storage import ROOT
        archive=self.root/'original.zip';package_plugin.build(archive)
        unpacked=self.root/'unpacked'
        with zipfile.ZipFile(archive) as stream:stream.extractall(unpacked)
        index=unpacked/'knowledge/index.json';doc=json.loads(index.read_text(encoding='utf-8'))
        card=doc['cards'][0];withdrawn_path=card['path'];card.update(path=None,lifecycle=dict(state='withdrawn',reason='Disposable synthetic package test'))
        index.write_text(json.dumps(doc),encoding='utf-8')
        run=subprocess.run([sys.executable,'-X','utf8',str(unpacked/'scripts/generate_bundle_manifest.py'),'--write'],cwd=self.root,capture_output=True,timeout=15)
        self.assertEqual(run.returncode,0,run.stderr.decode('utf-8',errors='replace'))
        output=self.root/'withdrawn.zip'
        with patch.object(package_plugin,'ROOT',unpacked):package_plugin.build(output)
        with zipfile.ZipFile(output) as stream:
            self.assertTrue('knowledge/'+withdrawn_path not in stream.namelist(),'withdrawn body leaked into portable package')
            inventory=json.loads(stream.read('src/techexpert/assets/bundle-manifest.json'))
            self.assertNotIn('knowledge/'+withdrawn_path,inventory['members'])


if __name__=='__main__':unittest.main()
