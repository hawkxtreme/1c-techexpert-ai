from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from src.techexpert import incident_drafts, investigations, knowledge_review, storage, update_state
from src.techexpert.inputs import InputError


DOC_URL = 'https://1c-dn.com/glossary/file_mode/'
DISCUSSION_URL = 'https://t.me/example_forum/18'
OLD_REFERENCE = dict(url=DOC_URL, purpose='Описание режима', applicability='Файловая база')


class ReportReferencesTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.state = Path(temp.name)
        first = investigations.create(self.state, dict(task='Проверить задержку операции'))
        self.iid = first['investigation_id']
        case = storage.investigate(storage.ROOT / 'examples/sc01/case.json', self.state)
        self.card = knowledge_review.pin_use(self.state, ['SC01-ORDER-LOAD'])
        self.patch = dict(
            attachments=[dict(id='A-local', kind='case', target_id=case['case_id']),
                         dict(id='A-card', kind='artifact', target_id=self.card['artifact_id'])],
            evidence=[dict(id='E-local', attachment='A-local', record='s1:2'),
                      dict(id='E-card', attachment='A-card', record='s1')],
            hypotheses=[dict(id='H-1', text='Проверяемый механизм', status='supported', evidence=['E-local']),
                        dict(id='H-2', text='Предположение из опыта другого случая', status='proposed', evidence=['E-card'])],
            assessment=dict(summary='Есть данные о долгом выполнении', cause_state='hypothesis', hypothesis_id='H-1',
                mechanism='Сопоставить события с операцией', evidence=['E-local'], limitations=['Синтетический образец'],
                recommendations=[dict(id='R-1', kind='diagnostic', basis=['H-1', 'E-card'],
                    goal='Сравнить два запуска', prerequisites='Получить замеры', expected_effect='Получить сопоставимые тайминги',
                    verification='Проверить эффект по замерам', limitations='Файловая база')], references=[]))

    def save(self, references):
        patch = deepcopy(self.patch)
        patch['assessment']['references'] = references
        return investigations.revise(self.state, self.iid, patch, expected_revision=1)

    def document(self, *targets):
        return dict(OLD_REFERENCE, kind='documentation', targets=list(targets), version='8.3.27.1989')

    def discussion(self, hypothesis='H-1', url=DISCUSSION_URL):
        return dict(kind='discussion', targets=[hypothesis], url=url, purpose='Идея проверки',
                    applicability='Обстоятельства требуют сверки', version=None)

    def knowledge(self, target='R-1', evidence='E-card'):
        return dict(kind='knowledge_card', targets=[target], evidence=evidence, purpose='Похожий случай',
                    applicability='Методика сравнения запусков')

    def test_saved_references_are_rendered_with_their_support_and_exact_card(self):
        result = self.save([self.document('assessment', 'R-1'), self.discussion(), self.knowledge(), OLD_REFERENCE])
        self.assertEqual(investigations.load(self.state, self.iid), result)
        docs, discussion, knowledge, old = result['assessment']['references']
        self.assertEqual(docs['targets'], ['assessment', 'R-1'])
        self.assertEqual(discussion['checks'], [dict(hypothesis='H-1', status='supported',
            harness_status='supported', incident_evidence=['E-local'])])
        card = knowledge['pinned_card']
        self.assertEqual((card['id'], card['revision'], card['artifact_id'], card['source_id']),
                         ('SC01-ORDER-LOAD', 1, self.card['artifact_id'], 's1'))
        saved_urls = [row['url'] for row in self.card['result']['cards'][0]['sources_metadata']]
        self.assertEqual([row['url'] for row in card['sources']], saved_urls)
        self.assertEqual(old, OLD_REFERENCE)
        folder = investigations.revision_folder(self.state, self.iid, 2)
        self.assertEqual((folder / card['local_link']).resolve().read_bytes(),
                         (self.state / 'artifacts' / self.card['artifact_id'] / 'sources/s1.bin').read_bytes())
        markdown = (folder / 'report.md').read_text(encoding='utf-8')
        hypothesis = markdown.split('## Гипотезы и противоречия', 1)[1].split('## Доказательства', 1)[0]
        recommendation = markdown.split('### R-1', 1)[1].split('## Ограничения', 1)[0]
        self.assertIn(DISCUSSION_URL, hypothesis)
        self.assertIn('E-local', hypothesis)
        self.assertIn(card['local_link'], recommendation)
        self.assertIn(DOC_URL, recommendation)
        self.assertEqual(update_state.inspect_state(self.state)['schemata']['report-references'], [1])

    def test_old_flat_links_still_read_without_admitting_the_extended_format(self):
        result = self.save([OLD_REFERENCE])
        self.assertEqual(result['assessment']['references'], [OLD_REFERENCE])
        self.assertEqual(investigations.load(self.state, self.iid), result)
        self.assertEqual(update_state.inspect_state(self.state)['schemata']['report-references'], [])

    def test_discussion_with_only_knowledge_evidence_stays_unverified(self):
        self.patch['hypotheses'][1]['status'] = 'supported'
        result = self.save([self.discussion('H-2')])
        state = result['assessment']['references'][0]['checks'][0]
        self.assertEqual(state['status'], 'insufficient_data')
        self.assertEqual(state['harness_status'], 'supported')
        self.assertEqual(state['incident_evidence'], [])

    def test_discussion_citations_preserve_exact_message_locators_inside_topics(self):
        urls = ['https://t.me/example_forum/17/18?single', 'https://t.me/c/1000001/17/18?comment=19',
                'https://t.me/c/1000001/18?thread=17', 'https://t.me/s/example_forum/18']
        result = self.save([self.discussion(url=url) for url in urls])
        self.assertEqual([item['url'] for item in result['assessment']['references']], urls)

    def test_invalid_targets_and_unbound_or_imprecise_references_leave_revision_unchanged(self):
        invalid = [self.document('R-lost'), self.discussion('R-1'), self.discussion(url='https://t.me/example_forum'),
                   self.discussion(url='https://t.me/c/1000001'), self.discussion(url='https://t.me/joinchat/111111111'),
                   self.document('R-1', 'R-1'), self.knowledge('H-1'), self.knowledge(evidence='E-local'),
                   self.document('assessment') | {'url': 'https://someone@docs.example/reference'}]
        for reference in invalid:
            with self.subTest(reference=reference), self.assertRaises(InputError):
                self.save([reference])
        self.assertEqual(investigations.load(self.state, self.iid)['revision'], 1)

    def test_confirmed_cause_with_discussion_needs_linked_measurements(self):
        self.patch['hypotheses'][0]['evidence'] = ['E-card']
        self.patch['assessment'].update(cause_state='confirmed', verification='Текст проверки', alternatives=['Другая причина'])
        with self.assertRaisesRegex(InputError, 'incident evidence'):
            self.save([self.discussion()])
        self.assertEqual(investigations.load(self.state, self.iid)['revision'], 1)

    def test_incident_draft_keeps_private_reference_details_out_of_default_preview(self):
        self.save([self.document('R-1'), self.discussion(), self.knowledge()])
        draft = incident_drafts.prepare(self.state, self.iid)
        body = draft['body']
        self.assertIn('Описание режима', body)
        self.assertNotIn(DISCUSSION_URL, body)
        self.assertNotIn('Похожий случай', body)
        self.assertNotIn(self.card['artifact_id'], body)
