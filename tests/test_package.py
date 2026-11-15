import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PackageTests(unittest.TestCase):
    def test_portable_package_runs_from_other_directory_without_private_files(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            package = folder / 'plugin.zip'
            build = subprocess.run([sys.executable, str(ROOT / 'scripts/package_plugin.py'), str(package)],
                                   cwd=folder, capture_output=True, text=True, encoding='utf-8', timeout=20)
            self.assertEqual(build.returncode, 0, build.stderr)
            with zipfile.ZipFile(package) as archive:
                names = archive.namelist()
                self.assertIn('.codex-plugin/plugin.json', names)
                self.assertIn('skills/techexpert/SKILL.md', names)
                self.assertFalse(any('.local/' in name or '__pycache__/' in name or name.startswith('.git/') for name in names))
                archive.extractall(folder / 'unpacked')
            run = subprocess.run([sys.executable, str(folder / 'unpacked/techexpert.py'), '--state-dir', str(folder / 'state'), 'demo'],
                                 cwd=folder, capture_output=True, text=True, encoding='utf-8', timeout=20)
            self.assertEqual(run.returncode, 0, run.stderr)
            report = json.loads(run.stdout)
            self.assertEqual(report['durations_seconds']['execution'], 2460)
            self.assertTrue((folder / 'unpacked/src/techexpert/assets/init.html').is_file())


if __name__ == '__main__':
    unittest.main()
