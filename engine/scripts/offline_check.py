#!/usr/bin/env python3
"""Offline patch check for Vanta patches (no full Chromium checkout needed).

For every file a Vanta patch touches, this fetches the pristine file from the
Chromium source at the version in engine/VERSION (chromium.googlesource.com),
applies, in series order, every ungoogled-chromium and ungoogled-chromium-windows
hunk for that file, then applies the Vanta series with GNU patch using the same
options as ungoogled's utils/patches.py (-p1 --ignore-whitespace --forward).

Usage:
  offline_check.py --ucw <ungoogled-chromium-windows checkout> [--work DIR] [--keep]

It is a fast developer check. The authoritative check is CI stage S1, which
applies everything to the full source tarball.
"""
import argparse
import base64
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ENGINE = Path(__file__).resolve().parent.parent
GITILES = 'https://chromium.googlesource.com/chromium/src/+/refs/tags/{ver}/{path}?format=TEXT'
MIRROR = 'https://raw.githubusercontent.com/chromium/chromium/{ver}/{path}'


def parse_series(series: Path):
    out = []
    for line in series.read_text(encoding='utf-8').splitlines():
        line = line.split('#', 1)[0].strip()
        if line:
            out.append(series.parent / line)
    return out


def split_patch(text: str):
    """Yield (target_path, chunk_text) for each file section of a unified diff."""
    lines = text.splitlines(keepends=True)
    starts = [i for i in range(len(lines) - 1)
              if lines[i].startswith('--- ') and lines[i + 1].startswith('+++ ')]
    for n, s in enumerate(starts):
        e = starts[n + 1] if n + 1 < len(starts) else len(lines)
        # drop trailing "diff --git"/"index" header lines that belong to the next section
        chunk = lines[s:e]
        while chunk and not (chunk[-1].startswith((' ', '+', '-', '@', '\\')) or chunk[-1] in ('\n',)):
            chunk.pop()
        target = lines[s + 1][4:].split('\t')[0].strip()
        if target.startswith('b/'):
            target = target[2:]
        src = lines[s][4:].split('\t')[0].strip()
        yield target, src, ''.join(chunk)


def fetch(ver: str, path: str, dest: Path) -> bool:
    # Gitiles answers 503 to urllib's default User-Agent at times; the GitHub
    # mirror (same tag, raw bytes) is the fallback.
    sources = ((GITILES.format(ver=ver, path=path), True),
               (MIRROR.format(ver=ver, path=path), False))
    data = None
    for url, b64 in sources:
        req = urllib.request.Request(url, headers={'User-Agent': 'curl/8.5.0'})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read()
            data = base64.b64decode(raw) if b64 else raw
            break
        except Exception as exc:  # 404 for files that are new
            print(f'  fetch {path}: {exc}', file=sys.stderr)
    if data is None:
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return True


def run_patch(tree: Path, chunk: str, label: str, dry: bool = False) -> bool:
    cmd = ['patch', '-p1', '--ignore-whitespace', '--forward', '--no-backup-if-mismatch',
           '-d', str(tree)]
    if dry:
        cmd.append('--dry-run')
    r = subprocess.run(cmd, input=chunk, text=True, capture_output=True)
    ok = r.returncode == 0
    print(f'  {"ok " if ok else "FAIL"} {label}')
    if not ok:
        print(r.stdout + r.stderr)
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ucw', required=True, type=Path)
    ap.add_argument('--work', type=Path)
    ap.add_argument('--keep', action='store_true')
    a = ap.parse_args()
    ver = (ENGINE / 'VERSION').read_text().strip()
    work = a.work or Path(tempfile.mkdtemp(prefix='vanta-offline-'))
    tree = work / 'src'
    if tree.exists():
        shutil.rmtree(tree)
    tree.mkdir(parents=True)

    upstream = parse_series(a.ucw / 'ungoogled-chromium' / 'patches' / 'series') + \
        parse_series(a.ucw / 'patches' / 'series')
    vanta = parse_series(ENGINE / 'patches' / 'series')

    # target -> True if the first Vanta patch touching it creates it. A later
    # patch may edit a file an earlier Vanta patch created (0003 edits 0002's
    # chrome/browser/vanta/*); such files are not upstream, so not fetched.
    touched = {}
    for p in vanta:
        for target, src, _ in split_patch(p.read_text(encoding='utf-8')):
            touched.setdefault(target, src == '/dev/null')
    print(f'Chromium {ver}; Vanta patches touch {len(touched)} files')
    for target, is_new in sorted(touched.items()):
        if not is_new and not fetch(ver, target, tree / target):
            print(f'missing upstream file {target}')
            return 1

    names = set(touched)
    print('Upstream (ungoogled + windows) hunks on those files:')
    for p in upstream:
        for target, _, chunk in split_patch(p.read_text(encoding='utf-8')):
            if target in names and not run_patch(tree, chunk, f'{p.name} -> {target}'):
                return 1
    print('Vanta series:')
    for p in vanta:
        if not run_patch(tree, p.read_text(encoding='utf-8'), p.name):
            return 1
    print(f'OFFLINE CHECK PASSED (tree: {tree})')
    if not a.keep and not a.work:
        shutil.rmtree(work)
    return 0


if __name__ == '__main__':
    sys.exit(main())
