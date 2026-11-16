"""Create an unpublished portable local pilot bundle from an explicit allowlist."""
import hashlib
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build(output):
    output = Path(output).resolve()
    files = [ROOT / 'techexpert.py', ROOT / 'README.md', ROOT / 'AGENTS.md', ROOT / '.codex-plugin/plugin.json']
    # Only these reviewed, nonprivate capture excerpts are shipped as test data.
    files.extend(ROOT / 'tests/fixtures/native-tj' / name
                 for name in ('passport.json', 'folders-minute.txt', 'plain-iso.txt'))
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
