import importlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import urlsplit


class KnowledgeTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.knowledge'), 'versioned knowledge catalogue is missing')
        self.api=importlib.import_module('src.techexpert.knowledge')

    def test_bundled_catalogue_is_ready_offline_and_links_have_provenance(self):
        library=self.api.load_library()
        self.assertGreaterEqual(len(library['cards']),12)
        self.assertTrue(library['revision'])
        ids={c['id'] for c in library['cards']}
        for card in library['cards']:
            self.assertLessEqual(set(card['related']),ids)
            self.assertIn(card['status'],('draft','reviewed','validated_in_lab','deprecated'))
            self.assertTrue(card['applicability'])
        result=self.api.search('очередь дисков')
        self.assertIn('KB-OS-DISK',[m['id'] for m in result['matches']])
        self.assertTrue(all(m['sources'] for m in self.api.search('индекс')['matches']))

    def test_sc01_search_uses_word_forms_and_explains_retrieval(self):
        from src.techexpert.capabilities import normalize_request

        result = self.api.search('Фоновым заданиям загрузки заказов требуется по 45 минут вместо пяти',
            environment=dict(database_mode='file', platform_version='8.3.27.1989'), excerpt_chars=0)
        candidates = {item['id']: item for item in result['matches']}
        self.assertIn('PLAYBOOK-SLOW-JOB', candidates)
        case = candidates['SC01-ORDER-LOAD']
        self.assertEqual(case['applicability_check']['status'], 'matches_reported_environment')
        self.assertTrue(any(match['basis'] == 'word_form' for match in case['matching']))
        self.assertEqual(case['excerpt'], '')
        self.assertFalse(case['diagnosis_for_current_case_established'])
        self.assertTrue(case['sources'])
        self.assertEqual(self.api.search('SDB')['matches'], [])
        self.assertEqual(self.api.search('SC01-ORDER-LOAD', environment=dict(database_mode='file'))['matches'][0]
                         ['applicability_check']['status'], 'environment_unknown')
        legacy = normalize_request(dict(schema_version=1, operation_key='previous-search', executor_id='test',
                            operation='knowledge.search', arguments=dict(query='очередь')))
        self.assertEqual(legacy['arguments'], dict(query='очередь', limit=5))

    def test_sc01_search_reports_observed_events_and_skips_server_only_cards(self):
        result = self.api.search('Замедление фонового задания PostgreSQL pg_stat_activity',
            events=['SDBL'], environment=dict(database_mode='file'), limit=1)
        self.assertTrue(result['matches'])
        skipped = {item['id']: item for item in result['excluded_matches']}
        self.assertEqual(skipped['KB-PG-VISIBILITY']['applicability_check']['status'], 'outside_recorded_scope')
        self.assertNotIn('excerpt', skipped['KB-PG-VISIBILITY'])
        self.assertTrue(any(m['kind'] == 'event' and m['term'] == 'SDBL' for m in result['matches'][0]['matching']))
        offset = result['next_offset']
        self.assertIsInstance(offset, int)
        second = self.api.search('Замедление фонового задания PostgreSQL pg_stat_activity',
            events=['SDBL'], environment=dict(database_mode='file'), limit=1, offset=offset,
            expected_knowledge_digest=result['knowledge_digest'])
        self.assertNotEqual(result['matches'][0]['id'], second['matches'][0]['id'])
        with self.assertRaisesRegex(ValueError, 'revision'):
            self.api.search('замедление', offset=1, expected_knowledge_digest='0'*64)

    def test_tj_event_cards_use_declared_events_and_link_their_claims(self):
        environment = dict(database_mode='file', platform_version='8.3.27.1989')
        result = self.api.search('Границы фонового задания и SDBL', events=['sesn'],
                                 environment=environment, card_type='tj_event', excerpt_chars=0)
        self.assertEqual([row['id'] for row in result['matches']], ['KB-TJ-SESN'])
        selected = result['matches'][0]
        self.assertEqual(selected['event_types'], ['SESN'])
        self.assertIn(dict(kind='event', term='SESN', field='event_types', basis='declared'), selected['matching'])
        self.assertEqual(selected['applicability_check']['status'], 'matches_reported_environment')
        self.assertTrue(selected['hypothesis_only'])
        self.assertFalse(selected['diagnosis_for_current_case_established'])
        card = self.api.get_card(selected['id'], expected_knowledge_digest=result['knowledge_digest'])
        self.assertEqual(card['knowledge_digest'], result['knowledge_digest'])
        self.assertEqual(card['status'], 'draft')
        sources = {item['id']:item for item in card['sources_metadata']}
        supporting = [source for row in card['claims'] if row['status']=='documented' for source in row['sources']]
        self.assertTrue(supporting)
        self.assertTrue(all(sources[source]['storage']=='url_only' and urlsplit(sources[source]['url']).fragment
                            for source in supporting))
        with self.assertRaisesRegex(ValueError, 'revision changed'):
            self.api.get_card(selected['id'], expected_knowledge_digest='0'*64)

    def test_changed_catalogue_revision_includes_metadata_and_invalid_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'card.md').write_text('original note',encoding='utf-8')
            document=dict(schema_version=1,revision='1',sources=[],cards=[dict(id='C',title='Card',path='../outside.md',
                status='reviewed',type='method',author='A',date='2026-11-16',revision=1,applicability='scope',
                related=[],sources=[],signs=[],steps=[],evidence_basis='authored methodology')])
            (root/'index.json').write_text(json.dumps(document),encoding='utf-8')
            with self.assertRaises(ValueError):self.api.load_library(root)


if __name__=='__main__':unittest.main()
