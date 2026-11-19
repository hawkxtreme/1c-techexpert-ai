"""Local editorial projects consume exact incident previews and retain their history."""
import copy
import importlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from src.techexpert import incident_drafts, investigations, knowledge
from src.techexpert.inputs import InputError


SOURCE = '1c-tj-event-functions'
ACTIONS = ('read','automated_retrieval','local_storage','adaptation','external_model_transfer','publication')


class KnowledgeProposalTests(unittest.TestCase):
    def setUp(self):
        self.api = importlib.import_module('src.techexpert.knowledge_proposals')
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.state = self.folder/'state'
        self.book = self.folder/'knowledge'
        shutil.copytree(knowledge.ROOT/'knowledge',self.book)
        task = investigations.create(self.state,dict(task='Задание загрузки заказов стало выполняться дольше.'))
        note = dict(summary='InternalFixtureMemo should remain in this investigation.', cause_state='insufficient_data',
                    evidence=[], limitations=['Нужен отдельный замер.'], recommendations=[], references=[])
        doc = investigations.revise(self.state,task['investigation_id'],dict(assessment=note),expected_revision=1)
        self.preview = incident_drafts.prepare(self.state,doc['investigation_id'])
        self.request = dict(schema_version=1,draft_id=self.preview['draft_id'],
            expected_preview_sha256=self.preview['preview_sha256'],expected_knowledge_digest=knowledge.load_library(self.book)['digest'],
            author='Fixture maintainer',applicability='Сохранённый ТЖ файловой ИБ.',
            environment=dict(database_mode='file',platform_version='8.3.27.1989'),
            result='Сеанс требует сопоставления с запуском.', related=['KB-TJ-SESN'],
            claims=[dict(id='session',status='documented',text='Событие Finish описывает завершение сеанса.',
                         applicability='SESN платформы 8.3.27.',sources=[SOURCE]),
                    dict(id='wait',status='hypothesis',text='Часть задержки могла приходиться на ожидание.',
                         applicability='Исследуемый запуск.',sources=[])],
            checks=[dict(claim_id='session',procedure='Сверить событие с описанием Func.',expected='Получена отметка сеанса.'),
                    dict(claim_id='wait',procedure='Сопоставить постановку и начало по данным запуска.',expected='Видна длительность ожидания.')])

    def prepare(self, request=None):
        return self.api.prepare(self.state,self.request if request is None else request,root=self.book)

    def review(self):
        return dict(schema_version=1,reviewer='Fixture editor',verdict='accepted',
            claims=[dict(id='session',outcome='supported',result='Смысл Finish сверили в разделе Func.'),
                    dict(id='wait',outcome='hypothesis',result='Нужны отдельные отметки ожидания.')],
            anonymization=dict(status='checked',basis='Проверили текст учебной карточки.'),
            rights=[dict(source_id=SOURCE,basis='В карточке собственный текст и ссылка на справочник.',
                         actions=dict.fromkeys(ACTIONS,'not_requested') | dict(read='allowed',adaptation='allowed',publication='link_only'))])

    def test_preview_to_draft_replays_and_keeps_superseded_revisions(self):
        first = self.prepare()
        self.assertEqual(first['card']['status'],'draft')
        self.assertEqual(first['source_preview']['preview_sha256'], self.preview['preview_sha256'])
        self.assertEqual(first['card']['applicability_constraints']['database_mode'],['file'])
        self.assertIn('#the-property-values-of-func',first['body'])
        self.assertNotIn('InternalFixtureMemo',json.dumps(first,ensure_ascii=False))
        self.assertNotIn('local_preview_path',first['source_preview'])
        self.assertFalse(first['catalogue_updated'])
        self.assertIsNone(first['editorial_review'])
        self.assertTrue(self.prepare()['replayed'])

        changed = dict(self.request,result='Сохранены отдельно границы сеанса.')
        with self.assertRaisesRegex(InputError,'already exists'):
            self.prepare(changed)
        changed['expected_proposal_sha256'] = first['proposal_sha256']
        second = self.prepare(changed)
        self.assertEqual(second['proposal_id'],first['proposal_id'])
        self.assertEqual(second['revision'],2)
        self.assertEqual(self.prepare(changed)['proposal_sha256'],second['proposal_sha256'])
        saved = self.api.show(self.state,first['proposal_id'],revision=1)
        self.assertEqual(saved['proposal_sha256'],first['proposal_sha256'])
        self.assertEqual(saved['card'],first['card'])
        stale = dict(changed,result='Другой результат.')
        with self.assertRaisesRegex(InputError,'revision changed'):
            self.prepare(stale)
        self.assertEqual(len(list((self.state/'knowledge-proposals').glob('*.json'))),1)

    def test_stale_or_invalid_evidence_refused_before_any_proposal(self):
        with self.assertRaisesRegex(InputError,'preview changed'):
            self.prepare(dict(self.request,expected_preview_sha256='0'*64))
        with self.assertRaisesRegex(InputError,'knowledge revision changed'):
            self.prepare(dict(self.request,expected_knowledge_digest='0'*64))
        with self.assertRaisesRegex(InputError,'expected knowledge digest'):
            self.prepare(dict(self.request,expected_knowledge_digest=None))
        with self.assertRaisesRegex(InputError,'must not be blank'):
            self.prepare(dict(self.request,author=' \n '))
        bad = copy.deepcopy(self.request)
        bad['claims'][0]['sources'] = ['unregistered-source']
        with self.assertRaisesRegex(InputError,'source'):
            self.prepare(bad)
        bad = copy.deepcopy(self.request)
        bad['checks'][0]['evidence_ids'] = ['E-PRIVATE']
        with self.assertRaisesRegex(InputError,'evidence'):
            self.prepare(bad)
        self.assertFalse(list((self.state/'knowledge-proposals').glob('*.json')))

    def test_review_records_exact_named_decision_and_separate_source_rights(self):
        proposal = self.prepare()
        pid, sha = proposal['proposal_id'],proposal['proposal_sha256']
        review = self.review()
        with self.assertRaisesRegex(InputError,'must not be blank'):
            self.api.record_review(self.state,pid,dict(review,reviewer=' '),expected_sha256=sha,root=self.book)
        incomplete = copy.deepcopy(review)
        incomplete['rights'][0]['actions'].pop('external_model_transfer')
        with self.assertRaisesRegex(InputError,'rights'):
            self.api.record_review(self.state,pid,incomplete,expected_sha256=sha,root=self.book)
        denied = copy.deepcopy(review)
        denied['rights'][0]['actions']['publication'] = 'needs_clarification'
        with self.assertRaisesRegex(InputError,'rights'):
            self.api.record_review(self.state,pid,denied,expected_sha256=sha,root=self.book)
        broader = copy.deepcopy(review)
        broader['rights'][0]['actions']['publication'] = 'allowed'
        with self.assertRaisesRegex(InputError,'rights'):
            self.api.record_review(self.state,pid,broader,expected_sha256=sha,root=self.book)

        index = self.book/'index.json'
        previous = index.read_bytes()
        document = json.loads(previous)
        source = next(item for item in document['sources'] if item['id']==SOURCE)
        source['rights']['status'] = 'excluded'
        index.write_text(json.dumps(document,ensure_ascii=False),encoding='utf-8')
        with self.assertRaisesRegex(InputError,'source changed'):
            self.api.record_review(self.state,pid,review,expected_sha256=sha,root=self.book)
        index.write_bytes(previous)

        accepted = self.api.record_review(self.state,pid,review,expected_sha256=sha,root=self.book)
        self.assertEqual(accepted['editorial_review']['verdict'],'accepted')
        self.assertEqual(accepted['editorial_review']['proposal_sha256'],sha)
        self.assertEqual(accepted['card']['status'],'draft')
        self.assertFalse(accepted['catalogue_updated'])
        self.assertEqual(index.read_bytes(),previous)
        self.assertTrue(self.api.record_review(self.state,pid,review,expected_sha256=sha,root=self.book)['replayed'])
        self.assertIsNone(next((c for c in knowledge.load_library(self.book)['cards'] if c['id']==accepted['card']['id']),None))
