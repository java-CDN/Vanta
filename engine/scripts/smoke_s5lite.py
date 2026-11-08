#!/usr/bin/env python3
"""S5-lite smoke test of a packaged Vanta engine (Windows, runs in CI S3).

Checks the G1 contract of patch 0002 on the real binary:
  1. version resource: ProductName "Vanta", ProductVersion == engine/VERSION
  2. no --vanta-config            -> browser starts and keeps running
  3. bad signature                -> exit 86
  4. --vanta-pubkey missing       -> exit 86
  5. signed, engine version wrong -> exit 87
  6. signed, engine version right -> browser starts and keeps running

The Ed25519 key is generated here for this run only and never written to the
repository. The config format is the one 0002 reads and vanta-fingerprint
writes: {"payload": "<persona JSON>", "signature": "<base64 Ed25519 over the
payload bytes>"}, with --vanta-pubkey=<base64 32-byte public key>.

  smoke_s5lite.py --exe <dir>\\vanta-chromium.exe [--work DIR] [--alive 20]
"""
import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ENGINE = Path(__file__).resolve().parent.parent


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def signed_config(key, engine, path: Path, tamper=False):
    payload = json.dumps({'engine': engine, 'vanta_smoke': True, 'persona_id': 'smoke'},
                         separators=(',', ':'))
    sig = key.sign(payload.encode())
    if tamper:
        sig = bytes([sig[0] ^ 0x01]) + sig[1:]
    path.write_text(json.dumps({'payload': payload, 'signature': b64(sig)}), encoding='utf-8')
    return path


def kill_tree(proc):
    subprocess.run(['taskkill', '/T', '/F', '/PID', str(proc.pid)], capture_output=True)
    try:
        proc.wait(30)
    except subprocess.TimeoutExpired:
        pass


class Smoke:

    def __init__(self, exe: Path, work: Path, alive: int):
        self.exe, self.work, self.alive = exe, work, alive
        self.results = []
        self.n = 0

    def launch(self, extra):
        self.n += 1
        udd = self.work / f'profile-{self.n}'
        if udd.exists():
            shutil.rmtree(udd, ignore_errors=True)
        cmd = [str(self.exe), f'--user-data-dir={udd}', '--no-first-run',
               '--no-default-browser-check', '--disable-gpu', '--enable-logging=stderr',
               '--v=0', *extra, 'about:blank']
        logf = (self.work / f'run-{self.n}.log').open('w', encoding='utf-8', errors='replace')
        print('> ' + ' '.join(cmd), flush=True)
        return subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT), udd, logf

    def expect_exit(self, name, extra, code, timeout=90):
        proc, _, logf = self.launch(extra)
        try:
            rc = proc.wait(timeout)
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            rc = 'still running'
        logf.close()
        ok = rc == code
        self.record(name, ok, f'exit {rc} (want {code})')

    def expect_running(self, name, extra):
        proc, udd, logf = self.launch(extra)
        time.sleep(self.alive)
        rc = proc.poll()
        local_state = (udd / 'Local State').exists() or (udd / 'Default').exists()
        if rc is None:
            kill_tree(proc)
        logf.close()
        ok = rc is None and local_state
        self.record(name, ok, f'running after {self.alive}s: {rc is None} (exit {rc}); '
                    f'profile written: {local_state}')

    def record(self, name, ok, detail):
        self.results.append((name, ok, detail))
        print(f'[{"PASS" if ok else "FAIL"}] {name}: {detail}', flush=True)
        if not ok:
            log = self.work / f'run-{self.n}.log'
            if log.exists():
                print('::group::browser log ' + name, flush=True)
                print(log.read_text(encoding='utf-8', errors='replace')[-6000:], flush=True)
                print('::endgroup::', flush=True)


def version_resource(exe: Path):
    ps = (f"$v=(Get-Item '{exe}').VersionInfo; "
          "Write-Output ($v.ProductName + '|' + $v.ProductVersion + '|' + $v.OriginalFilename)")
    out = subprocess.run(['powershell', '-NoProfile', '-Command', ps], capture_output=True,
                         text=True).stdout.strip()
    return out.split('|')


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--exe', type=Path, required=True)
    ap.add_argument('--work', type=Path)
    ap.add_argument('--alive', type=int, default=20)
    a = ap.parse_args()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    work = a.work or Path(tempfile.mkdtemp(prefix='vanta-smoke-'))
    work.mkdir(parents=True, exist_ok=True)
    version = (ENGINE / 'VERSION').read_text().strip()
    major, minor, build, patch = (int(x) for x in version.split('.'))
    good = {'major': major, 'minor': minor, 'build': build, 'patch': patch}
    wrong = dict(good, major=major - 1)

    key = Ed25519PrivateKey.generate()  # this run only; never stored
    pub = key.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)
    pub_arg = f'--vanta-pubkey={b64(pub)}'

    s = Smoke(a.exe.resolve(), work, a.alive)
    name, ver, orig = (version_resource(a.exe) + ['', '', ''])[:3]
    s.record('version resource', name == 'Vanta' and ver == version and
             orig == 'vanta-chromium.exe',
             f'ProductName={name!r} ProductVersion={ver!r} OriginalFilename={orig!r}')
    s.expect_running('no --vanta-config: starts', [])
    s.expect_exit('bad signature -> 86',
                  [f'--vanta-config={signed_config(key, good, work / "bad.json", True)}',
                   pub_arg], 86)
    s.expect_exit('missing --vanta-pubkey -> 86',
                  [f'--vanta-config={signed_config(key, good, work / "nokey.json")}'], 86)
    s.expect_exit('engine version mismatch -> 87',
                  [f'--vanta-config={signed_config(key, wrong, work / "old.json")}', pub_arg],
                  87)
    s.expect_running('valid signed config: starts',
                     [f'--vanta-config={signed_config(key, good, work / "good.json")}', pub_arg])

    failed = [r for r in s.results if not r[1]]
    lines = ['| check | result | detail |', '|---|---|---|']
    lines += [f'| {n} | {"PASS" if ok else "FAIL"} | {d} |' for n, ok, d in s.results]
    table = '\n'.join(lines)
    print(table)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as f:
            f.write(f'### S5-lite smoke ({version})\n\n{table}\n')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
