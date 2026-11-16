import json
import hashlib
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
            # Native input remains outside the installed package, as in a real deployment.
            log=folder/'external-tj.txt'
            log.write_bytes((ROOT/'tests/fixtures/native-tj/plain-iso.txt').read_bytes())
            manifest=json.loads((ROOT/'examples/sc01/case.json').read_text(encoding='utf-8'))
            manifest['origin']='provided'
            manifest['sources']=[dict(path=str(log),format='1c-tj-text-v1',platform_version='8.3.27.1989',
                encoding='utf-8',placement='plain',timestamp_format='iso',utc_offset='+03:00')]
            case=folder/'native.json'
            case.write_text(json.dumps(manifest),encoding='utf-8')
            native=subprocess.run([sys.executable,str(folder/'unpacked/techexpert.py'),'--state-dir',
                str(folder/'state'),'analyze',str(case)],cwd=folder,capture_output=True,
                text=True,encoding='utf-8',timeout=20)
            self.assertEqual(native.returncode,0,native.stdout+native.stderr)
            native_report=json.loads(native.stdout)
            self.assertEqual(native_report['native_observations']['event_count'],2)
            self.assertIsNone(native_report['durations_seconds']['execution'])
            # Controlled real fixture and the verified probe sources also travel
            # with the bundle; neither needs this checkout or the platform to read.
            packaged=folder/'unpacked'
            receipt=json.loads((packaged/'examples/sc01/lifecycle-probe/verification.json').read_text(encoding='utf-8'))
            for name, digest in receipt['configuration_source_sha256'].items():
                member=packaged/'examples/sc01/lifecycle-probe'/name
                self.assertEqual(hashlib.sha256(member.read_bytes()).hexdigest(),digest)
            linked=subprocess.run([sys.executable,str(packaged/'techexpert.py'),'--state-dir',str(folder/'state'),
                'analyze',str(packaged/'tests/fixtures/job-lifecycle/completed.json')],cwd=folder,
                capture_output=True,encoding='utf-8',timeout=20)
            self.assertEqual(linked.returncode,0,linked.stdout+linked.stderr)
            linked_report=json.loads(linked.stdout)
            self.assertEqual(linked_report['job_correlation']['native_link']['status'],'established')
            self.assertEqual(linked_report['job_correlation']['native_link']['linked_count'],4)
            self.assertEqual(linked_report['durations_seconds'],dict(queue=None,execution=2,total=None))


if __name__ == '__main__':
    unittest.main()
