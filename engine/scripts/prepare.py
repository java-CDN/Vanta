#!/usr/bin/env python3
"""Prepare a Vanta engine source tree (Master Plan v3, section 5).

Layers, in order:
  1. Chromium source tarball (the "-lite" tarball ungoogled-chromium uses),
     downloaded and hash-checked with ungoogled-chromium's utils/downloads.py
  2. ungoogled-chromium patches            (<ucw>/ungoogled-chromium/patches/series)
  3. ungoogled-chromium-windows patches    (<ucw>/patches/series)
  4. Vanta patches                         (engine/patches/series)
then domain substitution, exactly as ungoogled-chromium-windows build.py does
with --tarball. Steps are selectable so CI stages and a local PC share one script:

  S1 (ubuntu):   --steps source,prune,patch,domsub
  S2 (windows):  --steps source,windeps,prune,patch,domsub,rust,args,gngen
  S3 (windows):  the S2 steps + bindgen in stage 1; later stages and resumed
                 runs: --steps resync,args,gngen --no-gn-check
  local build:   build.ps1 runs all of the above, then ninja

`patch` keeps a copy of every file the Vanta series touches as it was before
the Vanta patches (after the upstream patches) in <src>/.vanta_state/. `resync`
uses it to swap an already built tree over to the current engine/patches
without a fresh source tree: it restores those files, applies the current
Vanta series, redoes domain substitution on them, and puts the old timestamps
back on every file whose content did not change, so ninja rebuilds only what
the patch change affects.

This script never runs ninja.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parent.parent
ALL_STEPS = ('source', 'windeps', 'prune', 'patch', 'domsub', 'resync', 'rust', 'args', 'gngen',
             'bindgen')
STATE_DIR = '.vanta_state'  # inside src, so CI stage archives carry it

# `gn check` scope. The whole graph cannot pass: the -lite tarball has no test
# sources (v8/test/unittests, ...) and some upstream test targets have include
# errors after ungoogled's patches. Everything Vanta adds must pass (fatal);
# the large upstream browser targets are checked too, but only reported, so an
# upstream include issue there cannot block the Vanta pipeline.
GN_CHECK_TARGETS = (
    '//chrome/browser/vanta/*',
    '//chrome:chrome_initial',
)
GN_CHECK_ADVISORY = (
    '//chrome:chrome_dll',
    '//chrome/browser:browser',
)


def log(msg):
    print(f'[vanta-prepare] {msg}', flush=True)


def read_flags(path: Path):
    """Parse a flags file of `name=value` lines (comments and blanks ignored)."""
    out = []
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            raise SystemExit(f'{path}: not a flag line: {raw!r}')
        k, v = line.split('=', 1)
        out.append((k.strip(), v.strip()))
    return out


def vanta_series():
    d = ENGINE / 'patches'
    out = []
    for line in (d / 'series').read_text(encoding='utf-8').splitlines():
        line = line.split('#', 1)[0].strip()
        if line:
            out.append((d / line).resolve())
    return out


def vanta_series_hash():
    h = hashlib.sha256()
    for p in vanta_series():
        h.update(p.name.encode() + b'\0' + p.read_bytes() + b'\0')
    return h.hexdigest()


def patch_targets(patch: Path):
    """Files a unified diff touches -> True if it creates them (--- /dev/null)."""
    out = {}
    old = None
    for line in patch.read_text(encoding='utf-8').splitlines():
        if line.startswith('--- '):
            old = line[4:].split('\t')[0].strip()
        elif line.startswith('+++ ') and old is not None:
            new = line[4:].split('\t')[0].strip()
            rel = new[2:] if new.startswith('b/') else new
            if rel == '/dev/null':
                rel = old[2:] if old.startswith('a/') else old
            out.setdefault(rel, old == '/dev/null')
            old = None
    return out


def vanta_targets():
    out = {}
    for p in vanta_series():
        for rel, created in patch_targets(p).items():
            out.setdefault(rel, created)
    return out


def read_lock():
    out = {}
    for line in (ENGINE / 'upstream.lock').read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            k, v = line.split('=', 1)
            out[k.strip()] = v.strip()
    return out


def _file_sha256(path: Path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def _sha(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def merge_flags(*groups):
    """Later groups win; order of first appearance is kept."""
    merged = {}
    for group in groups:
        for k, v in group:
            merged[k] = v
    return merged


class Ctx:

    def __init__(self, a):
        self.ucw = a.ucw.resolve()
        self.uc = self.ucw / 'ungoogled-chromium'
        self.build = (a.build or (self.ucw / 'build')).resolve()
        self.src = self.build / 'src'
        self.cache = self.build / 'download_cache'
        self.delete_archives = a.delete_archives
        self.progress = not a.no_progress
        self.check = a.gn_check
        self.windeps_only = [c for c in (a.windeps_only or '').split(',') if c]
        sys.path.insert(0, str(self.uc / 'utils'))
        import downloads, domain_substitution, prune_binaries, patches, _common  # noqa: E402
        self.downloads = downloads
        self.domsub = domain_substitution
        self.prune = prune_binaries
        self.patches = patches
        self.common = _common
        self.is_win = sys.platform == 'win32'
        self.extractors = {
            _common.ExtractorEnum.SEVENZIP: _common.USE_REGISTRY,
            _common.ExtractorEnum.WINRAR: _common.USE_REGISTRY,
            _common.ExtractorEnum.TAR: 'tar',
        }

    # ---------------------------------------------------------------- helpers
    def _fetch(self, ini: Path, unpack_to: Path, components=None, pinned_sha256=None):
        info = self.downloads.DownloadInfo([ini])
        self.cache.mkdir(parents=True, exist_ok=True)
        self.downloads.retrieve_downloads(info, self.cache, components, self.progress, False)
        try:
            self.downloads.check_downloads(info, self.cache, components)
        except self.downloads.HashMismatchError as exc:
            raise SystemExit(f'checksum mismatch: {exc}')
        log(f'hashes ok for {ini}')
        for name, want in (pinned_sha256 or {}).items():
            props = dict(info.properties_iter())[name]
            got = _file_sha256(self.cache / props.download_filename)
            if got != want:
                raise SystemExit(f'{name}: SHA-256 {got} != upstream.lock {want}')
            log(f'{name}: SHA-256 matches upstream.lock ({got})')
        for name, props in info.properties_iter():
            if components and name not in components:
                continue
            if props.has_hash_url():
                hashes = self.cache / props.hashes['hash_url'][1]
                log(f'{hashes.name}:\n' + hashes.read_text(encoding='utf-8'))
        for name, props in info.properties_iter():  # tar's extractor needs the parent dir
            if not components or name in components:
                (unpack_to / props.output_path).parent.mkdir(parents=True, exist_ok=True)
        self.downloads.unpack_downloads(info, self.cache, components, unpack_to, self.extractors)
        if self.delete_archives:
            for name, props in info.properties_iter():
                if components and name not in components:
                    continue
                p = self.cache / props.download_filename
                if p.exists():
                    p.unlink()
                    log(f'deleted archive {p.name}')

    def _patch_bin(self):
        if self.is_win:
            return self.src / 'third_party' / 'git' / 'usr' / 'bin' / 'patch.exe'
        return None

    def _vcvars(self):
        vswhere = os.path.expandvars(
            r'%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe')
        out = subprocess.run([vswhere, '-products', '*', '-prerelease', '-latest', '-property',
                              'installationPath'], check=True, capture_output=True,
                             text=True).stdout.strip()
        p = Path(out, 'VC/Auxiliary/Build/vcvars64.bat')
        if not p.exists():
            raise SystemExit(f'vcvars64.bat not found under {out}')
        return p

    def _run_vc(self, *args):
        """Same as build.py _run_build_process: vcvars64 + DEPOT_TOOLS_WIN_TOOLCHAIN=0."""
        cmd = [f'call "{self._vcvars()}" >nul', 'set DEPOT_TOOLS_WIN_TOOLCHAIN=0',
               ' '.join(f'"{a}"' for a in args), 'exit %ERRORLEVEL%\n']
        log('vc> ' + ' '.join(map(str, args)))
        r = subprocess.run(('cmd.exe', '/k'), input='\n'.join(cmd), text=True, cwd=self.src)
        if r.returncode != 0:
            raise SystemExit(f'command failed ({r.returncode}): {args}')

    # ------------------------------------------------------------------ steps
    def verify_version(self):
        engine_v = (ENGINE / 'VERSION').read_text().strip()
        uc_v = (self.uc / 'chromium_version.txt').read_text().strip()
        if engine_v != uc_v:
            raise SystemExit(f'engine/VERSION {engine_v} != ungoogled chromium_version.txt {uc_v}')
        chrome_version = self.src / 'chrome' / 'VERSION'
        if chrome_version.exists():
            parts = dict(l.split('=', 1) for l in chrome_version.read_text().split())
            tree_v = '{MAJOR}.{MINOR}.{BUILD}.{PATCH}'.format(**parts)
            if tree_v != engine_v:
                raise SystemExit(f'chrome/VERSION {tree_v} != engine/VERSION {engine_v}')
        log(f'version lock ok: {engine_v}')

    def step_source(self):
        self.verify_version()
        if (self.src / 'BUILD.gn').exists():
            log('source tree already unpacked; skipping')
            return
        self.src.mkdir(parents=True, exist_ok=True)
        lock = read_lock()
        self._fetch(self.uc / 'downloads.ini', self.src,
                    pinned_sha256={'chromium': lock['chromium_tarball_sha256']})
        self.verify_version()

    def step_windeps(self):
        # build.py empties these two before unpacking the Windows downloads.
        for comp, rel in (('directx-headers', 'third_party/microsoft_dxheaders/src'),
                          ('esbuild', 'third_party/devtools-frontend/src/third_party/esbuild')):
            if self.windeps_only and comp not in self.windeps_only:
                continue
            d = self.src / rel
            if d.exists():
                shutil.rmtree(d)
                d.mkdir()
        if self.windeps_only:
            log(f'windeps limited to: {self.windeps_only}')
        self._fetch(self.ucw / 'downloads.ini', self.src, self.windeps_only or None)

    def step_prune(self):
        lst = (self.uc / 'pruning.list').read_text(encoding='utf-8').splitlines()
        bad = self.prune.prune_files(self.src, lst)
        if bad:
            raise SystemExit(f'files could not be pruned: {bad[:20]}')
        log(f'pruned ({len(lst)} entries)')

    def step_patch(self):
        bin_ = self._patch_bin()
        for name, d in (('ungoogled-chromium', self.uc / 'patches'),
                        ('ungoogled-chromium-windows', self.ucw / 'patches')):
            series = list(self.patches.generate_patches_from_series(d, resolve=True))
            log(f'applying {len(series)} {name} patches')
            self.patches.apply_patches(series, self.src, patch_bin_path=bin_)
        self._snapshot(vanta_targets(), fresh=True)
        self._apply_vanta(bin_)
        log('all patches applied')

    # ------------------------------------------------- vanta pre-patch state
    def _state(self):
        return self.src / STATE_DIR

    def _load_manifest(self):
        f = self._state() / 'manifest.json'
        return json.loads(f.read_text(encoding='utf-8')) if f.exists() else None

    def _snapshot(self, targets, fresh=False):
        """Keep the pre-Vanta content of each target not yet in the manifest."""
        state = self._state()
        if fresh and state.exists():
            shutil.rmtree(state)
        man = self._load_manifest() or {'files': {}, 'series_sha256': None}
        for rel in sorted(targets):
            if rel in man['files']:
                continue
            src = self.src / rel
            exists = src.is_file()
            man['files'][rel] = {'existed': exists}
            if exists:
                dst = state / 'pre' / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
        state.mkdir(parents=True, exist_ok=True)
        (state / 'manifest.json').write_text(json.dumps(man, indent=1), encoding='utf-8')
        return man

    def _apply_vanta(self, bin_):
        series = vanta_series()
        log(f'applying {len(series)} vanta patches')
        self.patches.apply_patches(series, self.src, patch_bin_path=bin_)
        for f in ('chrome/browser/vanta/launch_config.cc', 'chrome/browser/vanta/BUILD.gn'):
            if not (self.src / f).exists():
                raise SystemExit(f'vanta file missing after patching: {f}')
        man = self._load_manifest()
        man['series_sha256'] = vanta_series_hash()
        (self._state() / 'manifest.json').write_text(json.dumps(man, indent=1), encoding='utf-8')

    def step_resync(self):
        """Swap a built tree over to the current Vanta series (see module doc)."""
        man = self._load_manifest()
        if man is None:
            raise SystemExit(f'{self._state()} missing: tree was not prepared by this script')
        want = vanta_series_hash()
        if man.get('series_sha256') == want:
            log('resync: vanta series unchanged; nothing to do')
            return
        # Files the new series touches that the old one did not are still
        # pristine (post domain substitution, which is idempotent): snapshot them.
        man = self._snapshot(vanta_targets())
        before = {}
        for rel in man['files']:
            p = self.src / rel
            if p.is_file():
                before[rel] = (_sha(p), p.stat().st_atime_ns, p.stat().st_mtime_ns)
        for rel, info in man['files'].items():  # back to the pre-Vanta tree
            p = self.src / rel
            if info['existed']:
                shutil.copyfile(self._state() / 'pre' / rel, p)
            elif p.exists():
                p.unlink()
        self._apply_vanta(self._patch_bin())
        domsub_list = set((self.uc / 'domain_substitution.list').read_text().splitlines())
        regex = self.domsub.DomainRegexList(self.uc / 'domain_regex.list').regex_pairs
        changed = []
        for rel in man['files']:
            p = self.src / rel
            if not p.is_file():
                if rel in before:
                    changed.append(rel + ' (removed)')
                continue
            if rel in domsub_list:
                self.domsub._substitute_path(p, regex)  # pylint: disable=protected-access
            old = before.get(rel)
            if old and old[0] == _sha(p):
                os.utime(p, ns=(old[1], old[2]))  # unchanged: keep ninja's view
            else:
                changed.append(rel)
        log('resync: changed files: ' + (', '.join(changed) or 'none'))

    def step_domsub(self):
        self.domsub.apply_substitution(self.uc / 'domain_regex.list',
                                       self.uc / 'domain_substitution.list', self.src, None)
        log('domain substitution done')

    def step_rust(self):
        # Mirrors build.py: assemble third_party/rust-toolchain from the downloads.
        dst = self.src / 'third_party' / 'rust-toolchain'
        host64 = sys.maxsize > 2**32
        src64 = self.src / 'third_party' / 'rust-toolchain-x64'
        for rust_src in (src64, self.src / 'third_party' / 'rust-toolchain-x86',
                         self.src / 'third_party' / 'rust-toolchain-arm'):
            for sub in ('bin', 'lib'):
                if sub == 'bin' and host64 != (rust_src == src64):
                    continue
                (dst / sub).mkdir(parents=True, exist_ok=True)
                for item in rust_src.glob(f'*/{sub}/*'):
                    target = dst / sub / item.name
                    if item.is_dir():
                        shutil.copytree(item, target, dirs_exist_ok=True)
                    else:
                        shutil.copy2(item, target)
        with open(dst / 'INSTALLED_VERSION', 'w') as f:
            subprocess.run([str(src64 / 'rustc' / 'bin' / 'rustc.exe'), '--version'], stdout=f,
                           check=True)
        log('rust toolchain assembled: ' + (dst / 'INSTALLED_VERSION').read_text().strip())

    def args_gn(self) -> str:
        """ungoogled flags.gn + flags.windows.gn (+ build.py tarball/libclang additions)
        + engine/flags.vanta.gn, later files winning."""
        uc = read_flags(self.uc / 'flags.gn')
        win = read_flags(self.ucw / 'flags.windows.gn')
        extra = [('chrome_pgo_phase', '0')]  # build.py --tarball
        spec = importlib.util.find_spec('clang')
        if spec is not None and spec.submodule_search_locations:
            libclang = (self.src / 'third_party' / 'llvm-build' / 'Release+Asserts' / 'bin' /
                        'libclang.dll').resolve().as_posix()
            bindings = Path(list(spec.submodule_search_locations)[0]).parent.resolve().as_posix()
            extra += [('v8_metagen_libclang_so', f'"{libclang}"'),
                      ('v8_metagen_libclang_bindings_dir', f'"{bindings}"')]
        elif self.is_win:
            raise SystemExit('Python clang bindings not found: pip install clang==21.1.7')
        else:
            log('note: python clang bindings absent; v8_metagen_* omitted (non-Windows preview)')
        vanta = read_flags(ENGINE / 'flags.vanta.gn')
        merged = merge_flags(uc, win, extra, vanta)
        lines = ['# Generated by engine/scripts/prepare.py: ungoogled flags.gn + flags.windows.gn',
                 '# + build.py tarball settings + engine/flags.vanta.gn (later wins).']
        lines += [f'{k}={v}' for k, v in merged.items()]
        return '\n'.join(lines) + '\n'

    def step_args(self):
        out = self.src / 'out' / 'Default'
        out.mkdir(parents=True, exist_ok=True)
        text = self.args_gn()
        args = out / 'args.gn'
        if args.exists() and args.read_text(encoding='utf-8') == text:
            log('out/Default/args.gn unchanged')  # keep its timestamp: no gn re-run
            return
        args.write_text(text, encoding='utf-8')
        log('out/Default/args.gn:\n' + text)

    def step_gngen(self):
        gn = self.src / 'out' / 'Default' / 'gn.exe'
        if not gn.exists():
            self._run_vc(sys.executable, 'tools\\gn\\bootstrap\\bootstrap.py', '-o',
                         'out\\Default\\gn.exe', '--skip-generate-buildfiles')
        self._run_vc('out\\Default\\gn.exe', 'gen', 'out\\Default', '--fail-on-unused-args')
        log('gn gen ok')
        if self.check:
            # gn check takes one label pattern per call.
            for t in GN_CHECK_TARGETS:
                self._run_vc('out\\Default\\gn.exe', 'check', 'out\\Default', t)
                log('gn check ok: ' + t)
            for t in GN_CHECK_ADVISORY:
                try:
                    self._run_vc('out\\Default\\gn.exe', 'check', 'out\\Default', t)
                    log('gn check (advisory) ok: ' + t)
                except SystemExit as exc:
                    log(f'WARNING gn check (advisory, upstream target {t}) failed: {exc}')

    def step_bindgen(self):
        # Same as build.py: bindgen is built from source before ninja.
        if (self.src / 'third_party' / 'rust-toolchain' / 'bin' / 'bindgen.exe').exists():
            log('bindgen already built')
            return
        self._run_vc(sys.executable, 'tools\\rust\\build_bindgen.py', '--skip-test')
        log('bindgen built')


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--ucw', type=Path, required=True,
                    help='ungoogled-chromium-windows checkout (with its submodule)')
    ap.add_argument('--build', type=Path, help='build dir (default <ucw>/build)')
    ap.add_argument('--steps', default=','.join(ALL_STEPS),
                    help=f'comma list from {",".join(ALL_STEPS)}')
    ap.add_argument('--delete-archives', action='store_true',
                    help='delete each downloaded archive after unpacking (CI disk)')
    ap.add_argument('--no-progress', action='store_true')
    ap.add_argument('--windeps-only', metavar='A,B',
                    help='only these ungoogled-chromium-windows downloads.ini sections '
                         '(S1 on Linux needs just "typescript", which a windows patch edits)')
    ap.add_argument('--no-gn-check', dest='gn_check', action='store_false')
    ap.add_argument('--print-args', action='store_true', help='print merged args.gn and exit')
    a = ap.parse_args()
    ctx = Ctx(a)
    if a.print_args:
        print(ctx.args_gn())
        return 0
    steps = [s.strip() for s in a.steps.split(',') if s.strip()]
    for s in steps:
        if s not in ALL_STEPS:
            raise SystemExit(f'unknown step {s}')
    for s in ALL_STEPS:  # always canonical order
        if s in steps:
            log(f'=== step {s} ===')
            getattr(ctx, f'step_{s}')()
    return 0


if __name__ == '__main__':
    sys.exit(main())
