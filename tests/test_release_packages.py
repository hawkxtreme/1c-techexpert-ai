"""Update input is a bounded product package with a checked inventory."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile

from scripts.package_plugin import build
from src.techexpert.inputs import InputError
from src.techexpert.readiness import MANIFEST


class ReleasePackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.release = self.root / 'valid.zip'
        build(self.release)

    def changed(self, change):
        target = self.root / 'modified.zip'
        with ZipFile(self.release) as source:
            parts = {name: source.read(name) for name in source.namelist()}
        change(parts)
        with ZipFile(target, 'w') as output:
            for name, body in parts.items():
                output.writestr(name, body)
        return target

    def test_verifies_whole_package_and_all_shipped_bytes_without_installing(self):
        from src.techexpert.release_packages import read_package
        release = read_package(self.release)
        self.assertEqual(release['path'],str(self.release))
        self.assertEqual(release['identity']['sha256'], hashlib.sha256(self.release.read_bytes()).hexdigest())
        self.assertEqual(release['metadata']['version'], json.loads(release['files']['plugin.json'])['version'])
        self.assertEqual(set(self.root.iterdir()), {self.release})

    def test_unexpected_package_entry_is_rejected_even_when_inventory_is_intact(self):
        from src.techexpert.release_packages import read_package
        altered = self.changed(lambda parts: parts.update({'unrecognized-package-content.dat': b'sample'}))
        with self.assertRaisesRegex(InputError, 'package member'):
            read_package(altered)

    def test_integrity_failure_is_distinct_from_all_members_present(self):
        from src.techexpert.release_packages import read_package
        altered = self.changed(lambda parts: parts.update({'skills/setup-and-access/SKILL.md': b'edited'}))
        with self.assertRaisesRegex(InputError, 'digest'):
            read_package(altered)

    def test_rehashed_bundle_still_requires_known_local_plugin_entrypoint(self):
        from src.techexpert.release_packages import read_package
        def runtime(parts):
            configuration=json.loads(parts['.mcp.json'])
            configuration['mcpServers']['techexpert']['command']='another-runner'
            parts['.mcp.json']=json.dumps(configuration).encode()
            inventory=json.loads(parts[MANIFEST])
            inventory['members']['.mcp.json']=hashlib.sha256(parts['.mcp.json']).hexdigest()
            parts[MANIFEST]=json.dumps(inventory).encode()
        with self.assertRaisesRegex(InputError,'MCP configuration'):
            read_package(self.changed(runtime))

    def test_reports_runtime_and_knowledge_edits_separately(self):
        from src.techexpert.release_packages import read_package, compare_packages
        def knowledge_revision(parts):
            name = 'knowledge/index.json'
            book = json.loads(parts[name])
            book['revision'] = 'updated-test-knowledge'
            parts[name] = json.dumps(book).encode()
            inventory = json.loads(parts[MANIFEST])
            inventory['members'][name] = hashlib.sha256(parts[name]).hexdigest()
            parts[MANIFEST] = json.dumps(inventory).encode()
        candidate = read_package(self.changed(knowledge_revision))
        report = compare_packages(read_package(self.release), candidate)
        self.assertEqual(report['kind'], 'knowledge_only')
        self.assertEqual(report['components']['knowledge']['changed'], ['knowledge/index.json'])
        self.assertEqual(report['components']['runtime']['changed'], [])
