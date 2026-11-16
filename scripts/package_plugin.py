"""Create an unpublished portable local pilot bundle from an explicit allowlist."""
import hashlib
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build(output):
    output = Path(output).resolve()
    files = [ROOT / 'techexpert.py', ROOT / 'README.md', ROOT / 'AGENTS.md', ROOT / '.codex-plugin/plugin.json',
             ROOT / 'scripts/sc01_blind.py', ROOT / 'scripts/generate_bundle_manifest.py', ROOT / 'evaluations/sc01-codex-skill.md',
             ROOT / 'evaluations/local-adapters-0.5.0.md',ROOT / 'evaluations/investigations-0.7.0.md',
             ROOT / 'evaluations/incident-drafts-0.8.0.md',ROOT / 'evaluations/source-export-0.9.0.md',ROOT / 'evaluations/first-run-0.10.0.md',
             ROOT / 'evaluations/source-coverage-0.11.0.md']
    files.extend(ROOT/'infrastructure/lab'/name for name in ('README.md','Dockerfile.onec','Dockerfile.postgres',
                 'onec-entrypoint.sh','postgres-entrypoint.sh','compose.yaml','pgpro-key.asc'))
    # Only these reviewed, nonprivate capture excerpts are shipped as test data.
    files.extend(ROOT / 'tests/fixtures/native-tj' / name
                 for name in ('passport.json', 'folders-minute.txt', 'plain-iso.txt'))
    files.extend(ROOT / 'tests/fixtures/native-jr' / name
                 for name in ('passport.json','1Cv8.lgf','20261116000000.lgp'))
    files.extend(ROOT / 'tests/fixtures/job-lifecycle' / name for name in (
        'README.md', 'passport.json', 'native.txt', 'completed.json', 'failed.json',
        'completed-controller.json', 'completed-worker-enter.json', 'completed-worker-exit.json',
        'failed-controller.json', 'failed-worker-enter.json'))
    files.extend(p for p in (ROOT / 'examples/sc01/lifecycle-probe').rglob('*')
                 if p.is_file() and p.suffix in ('.bsl', '.xml'))
    files.extend(ROOT / 'tests/fixtures/order-load' / name for name in (
        'README.md','passport.json','orders.csv',
        'baseline.json','baseline-native.txt','baseline-controller.json','baseline-worker-enter.json',
        'baseline-worker-exit.json','baseline-http.json','baseline-capture.json',
        'cached.json','cached-native.txt','cached-controller.json','cached-worker-enter.json',
        'cached-worker-exit.json','cached-http.json','cached-capture.json'))
    files.extend(p for p in (ROOT / 'examples/sc01/order-load-probe').rglob('*')
                 if p.is_file() and p.suffix in ('.bsl','.xml','.csv'))
    for directory in ('src/techexpert', 'skills', 'knowledge', 'examples/sc01', '.agents/skills'):
        files.extend(p for p in (ROOT / directory).rglob('*')
                     if p.is_file() and '__pycache__' not in p.parts and p.suffix in ('.py','.md','.html','.json','.jsonl','.yaml'))
    for path in files:
        if not path.is_file() or path.is_symlink():
            raise ValueError(f'missing or linked package member: {path}')
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(set(files)):
            archive.write(path, path.relative_to(ROOT).as_posix())
    return dict(path=str(output), bytes=output.stat().st_size, sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
                published=False, compatibility='local-pilot-only')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python scripts/package_plugin.py <new-output.zip>')
    print(json.dumps(build(sys.argv[1]), ensure_ascii=True))
