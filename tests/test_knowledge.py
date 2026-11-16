import importlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


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

    def test_changed_catalogue_revision_includes_metadata_and_invalid_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'card.md').write_text('original note',encoding='utf-8')
            document=dict(schema_version=1,revision='1',sources=[],cards=[dict(id='C',title='Card',path='../outside.md',
                status='reviewed',type='method',author='A',date='2026-11-16',revision=1,applicability='scope',
                related=[],sources=[],signs=[],steps=[],evidence_basis='authored methodology')])
            (root/'index.json').write_text(json.dumps(document),encoding='utf-8')
            with self.assertRaises(ValueError):self.api.load_library(root)


if __name__=='__main__':unittest.main()
