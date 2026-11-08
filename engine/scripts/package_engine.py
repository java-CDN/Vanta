#!/usr/bin/env python3
"""Package a built Vanta engine: vanta-engine-win64.zip + SHA-256.

Same file selection as ungoogled-chromium-windows package.py: the
chrome/tools/build/win/FILES.cfg entries for official 64-bit builds, read with
ungoogled-chromium's utils/filescfg.py, without the installer pieces and
without .pdb files. The zip's top folder is vanta-engine-win64/.

  package_engine.py --ucw <ucw checkout> --src <build/src> --dest <dir>
"""
import argparse
import hashlib
import os
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parent.parent
NAME = 'vanta-engine-win64'
EXCLUDED = {'mini_installer.exe', 'mini_installer_exe_version.rc', 'setup.exe',
            'chrome.packed.7z'}
REQUIRED = ('vanta-chromium.exe', 'chrome.dll', 'chrome_elf.dll', 'resources.pak',
            'icudtl.dat', 'locales/en-US.pak')


def sha256(path: Path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--ucw', type=Path, required=True)
    ap.add_argument('--src', type=Path, required=True)
    ap.add_argument('--dest', type=Path, required=True)
    a = ap.parse_args()
    sys.path.insert(0, str(a.ucw / 'ungoogled-chromium' / 'utils'))
    import filescfg  # noqa: E402

    out = a.src / 'out' / 'Default'
    files = list(filescfg.filescfg_generator(a.src / 'chrome' / 'tools' / 'build' / 'win' /
                                             'FILES.cfg', out, '64bit',
                                             {Path(p) for p in EXCLUDED}))
    names = {f.as_posix() for f in files}
    missing = [r for r in REQUIRED if r not in names]
    if missing:
        raise SystemExit(f'packaging: required files missing from FILES.cfg selection: {missing}')
    a.dest.mkdir(parents=True, exist_ok=True)
    zpath = a.dest / f'{NAME}.zip'
    if zpath.exists():
        zpath.unlink()
    filescfg.create_archive(iter(files), tuple(), out, zpath)
    digest = sha256(zpath)
    exe_digest = sha256(out / 'vanta-chromium.exe')
    version = (ENGINE / 'VERSION').read_text().strip()
    sums = (f'{digest}  {zpath.name}\n'
            f'{exe_digest}  {NAME}/vanta-chromium.exe\n')
    (a.dest / 'SHA256SUMS').write_text(sums)
    print(f'{zpath} ({zpath.stat().st_size} bytes, {len(files)} files), engine {version}')
    print(sums, end='')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as f:
            f.write(f'### Vanta engine {version} packaged\n\n```\n{sums}```\n')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as f:
            f.write(f'zip_sha256={digest}\nexe_sha256={exe_digest}\n')


if __name__ == '__main__':
    main()
