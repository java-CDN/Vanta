#!/usr/bin/env python3
"""Clone ungoogled-chromium-windows (+ its ungoogled-chromium submodule) at the
pins in engine/upstream.lock and verify every SHA. Works on Linux and Windows.

  fetch_upstream.py <dest>          clone into <dest> (or verify if it exists)
  fetch_upstream.py --verify <dest> only verify an existing checkout
"""
import argparse
import subprocess
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parent.parent


def lock():
    out = {}
    for line in (ENGINE / 'upstream.lock').read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            k, v = line.split('=', 1)
            out[k.strip()] = v.strip()
    return out


def git(*args, cwd=None, capture=False):
    r = subprocess.run(['git', *args], cwd=cwd, check=True, text=True,
                       capture_output=capture)
    return r.stdout.strip() if capture else None


def verify(dest: Path, pins):
    errors = []
    version = (ENGINE / 'VERSION').read_text().strip()
    if pins['chromium_version'] != version:
        errors.append(f"upstream.lock chromium_version {pins['chromium_version']} != VERSION {version}")
    if not pins['ucw_tag'].startswith(version + '-'):
        errors.append(f"ucw_tag {pins['ucw_tag']} is not for {version}")
    head = git('rev-parse', 'HEAD', cwd=dest, capture=True)
    if head != pins['ucw_commit']:
        errors.append(f"ungoogled-chromium-windows HEAD {head} != {pins['ucw_commit']}")
    sub = git('rev-parse', 'HEAD', cwd=dest / 'ungoogled-chromium', capture=True)
    if sub != pins['ungoogled_commit']:
        errors.append(f"ungoogled-chromium HEAD {sub} != {pins['ungoogled_commit']}")
    pinned = git('ls-tree', 'HEAD', 'ungoogled-chromium', cwd=dest, capture=True).split()[2]
    if pinned != pins['ungoogled_commit']:
        errors.append(f"submodule pin {pinned} != {pins['ungoogled_commit']}")
    uc_v = (dest / 'ungoogled-chromium' / 'chromium_version.txt').read_text().strip()
    if uc_v != version:
        errors.append(f'ungoogled chromium_version.txt {uc_v} != VERSION {version}')
    if errors:
        for e in errors:
            print('PIN MISMATCH: ' + e, file=sys.stderr)
        sys.exit(1)
    print(f"upstream pins ok: ucw {pins['ucw_tag']}@{head[:12]}, "
          f"ungoogled-chromium@{sub[:12]}, chromium {version}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dest', type=Path)
    ap.add_argument('--verify', action='store_true')
    a = ap.parse_args()
    pins = lock()
    if not a.verify and not a.dest.exists():
        git('-c', 'advice.detachedHead=false', 'clone', '--depth', '1', '--branch',
            pins['ucw_tag'], '--recurse-submodules', '--shallow-submodules',
            pins['ucw_repo'], str(a.dest))
    verify(a.dest, pins)


if __name__ == '__main__':
    main()
