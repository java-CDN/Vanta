#!/usr/bin/env python3
"""Stage a packaged Vanta engine for the desktop installer.

Input: the folder engine/scripts/package_engine.py writes (the "vanta-engine-win64"
artifact of engine-s3.yml): vanta-engine-win64.zip and SHA256SUMS, whose lines are

    <sha256>  vanta-engine-win64.zip
    <sha256>  vanta-engine-win64/vanta-chromium.exe

Steps (any problem stops with exit code 1 and nothing usable left behind):
  1. the zip's SHA-256 must match its SHA256SUMS line;
  2. every zip entry must sit under vanta-engine-win64/ (no absolute paths, no "..",
     no links); it is extracted into --to without that top folder;
  3. the extracted vanta-chromium.exe must match its SHA256SUMS line;
  4. --to/SHA256SUMS = the original lines, then one line per other extracted file
     (same "vanta-engine-win64/<path>" form), which the app checks at start;
  5. --to/VERSION = --version-file (engine/VERSION of this checkout);
  6. --tauri-config: a config overlay for `tauri build --config` that ships --to as the
     app's engine/ resource folder.

  stage_engine.py --from <dir> --to apps/desktop/src-tauri/engine-bundle \\
      --version-file engine/VERSION --tauri-config apps/desktop/src-tauri/tauri.engine.json
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath

TOP = 'vanta-engine-win64'
ZIP = f'{TOP}.zip'
EXE = 'vanta-chromium.exe'
SUMS = 'SHA256SUMS'
LINE = re.compile(r'^([0-9a-fA-F]{64}) [ *](.+)$')


class StageError(Exception):
    pass


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def safe_rel(name: str) -> bool:
    p = PurePosixPath(name)
    return (bool(name) and '\\' not in name and not p.is_absolute()
            and all(part not in ('', '.', '..') for part in p.parts)
            and ':' not in p.parts[0])


def read_sums(path: Path) -> dict:
    if not path.is_file():
        raise StageError(f'{path} not found')
    sums = {}
    for n, raw in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if not raw.strip():
            continue
        m = LINE.match(raw.rstrip('\r'))
        if not m or not safe_rel(m.group(2)):
            raise StageError(f'{SUMS} line {n} is not "<sha256>  <relative path>"')
        sums[m.group(2)] = m.group(1).lower()
    for need in (ZIP, f'{TOP}/{EXE}'):
        if need not in sums:
            raise StageError(f'{SUMS} has no line for {need}')
    return sums


def extract(zpath: Path, dest: Path) -> list:
    """Extract TOP/* into dest; return the relative paths of the files written."""
    written = []
    with zipfile.ZipFile(zpath) as z:
        for info in z.infolist():
            name = info.filename
            if not safe_rel(name.rstrip('/')) or not (name == f'{TOP}/' or name.startswith(f'{TOP}/')):
                raise StageError(f'zip entry outside {TOP}/: {name!r}')
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise StageError(f'zip entry is a link: {name!r}')
            rel = name[len(TOP) + 1:]
            if not rel or info.is_dir():
                continue
            out = dest.joinpath(*PurePosixPath(rel).parts)
            out.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, out.open('wb') as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            written.append(rel)
    return written


def stage(src: Path, dest: Path, version_file: Path, tauri_config: Path = None) -> int:
    sums = read_sums(src / SUMS)
    zpath = src / ZIP
    if not zpath.is_file():
        raise StageError(f'{zpath} not found')
    got = sha256(zpath)
    if got != sums[ZIP]:
        raise StageError(f'{ZIP} does not match {SUMS} (got {got}, expected {sums[ZIP]})')
    version = version_file.read_text(encoding='utf-8').strip()
    if not re.fullmatch(r'\d+\.\d+\.\d+\.\d+', version):
        raise StageError(f'{version_file} is not a version: {version!r}')

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    try:
        files = extract(zpath, dest)
        if EXE not in files:
            raise StageError(f'{ZIP} has no {TOP}/{EXE}')
        exe_sha = sha256(dest / EXE)
        if exe_sha != sums[f'{TOP}/{EXE}']:
            raise StageError(f'{EXE} does not match {SUMS}')
        if (dest / SUMS).exists() or (dest / 'VERSION').exists():
            raise StageError(f'{ZIP} must not contain {SUMS} or VERSION')
        lines = (src / SUMS).read_text(encoding='utf-8').splitlines()
        lines = [l.rstrip('\r') for l in lines if l.strip()]
        for rel in sorted(files):
            if rel != EXE:
                lines.append(f'{sha256(dest.joinpath(*PurePosixPath(rel).parts))}  {TOP}/{rel}')
        (dest / SUMS).write_text('\n'.join(lines) + '\n', encoding='utf-8', newline='\n')
        (dest / 'VERSION').write_text(version + '\n', encoding='utf-8', newline='\n')
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise

    if tauri_config is not None:
        rel = Path(os.path.relpath(dest.resolve(), tauri_config.resolve().parent)).as_posix()
        overlay = {'bundle': {'resources': {f'{rel}/': 'engine/'}}}
        tauri_config.write_text(json.dumps(overlay, indent=2) + '\n', encoding='utf-8')
    print(f'staged engine {version}: {len(files)} files in {dest} (zip {got})')
    return len(files)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--from', dest='src', type=Path, required=True)
    ap.add_argument('--to', dest='dest', type=Path, required=True)
    ap.add_argument('--version-file', type=Path, required=True)
    ap.add_argument('--tauri-config', type=Path)
    a = ap.parse_args(argv)
    try:
        stage(a.src, a.dest, a.version_file, a.tauri_config)
    except (StageError, zipfile.BadZipFile, OSError) as e:
        print(f'stage_engine: {e}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
