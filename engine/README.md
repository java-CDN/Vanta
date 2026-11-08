# Vanta engine

The browser engine Vanta launches: `vanta-chromium.exe`, built from Chromium with
ungoogled-chromium, ungoogled-chromium-windows and Vanta's own patches
(Master Plan v3, sections 5–6). Windows x64 only.

It lives in this repository (monorepo) instead of a fork of
ungoogled-chromium-windows: upstream is cloned at a pinned tag in CI and on your
PC, and only Vanta's files are kept here.

## Layers

1. Chromium source: the official `chromium-<version>-lite.tar.xz` tarball,
   checked against its published `.hashes` file by ungoogled-chromium's
   `utils/downloads.py`
2. ungoogled-chromium patches (`ungoogled-chromium/patches/series`)
3. ungoogled-chromium-windows patches (`patches/series`), its `downloads.ini`
   toolchain (LLVM, ninja, git, node, rust, …), and `flags.windows.gn`
4. Vanta patches: `engine/patches/vanta/NNNN-*.patch`, listed in order in
   `engine/patches/series`

Then pruning and domain substitution, the same as ungoogled-chromium-windows
`build.py --tarball`. Vanta patches go on after the Windows patches and before
domain substitution.

## Files

| File | What it is |
|---|---|
| `VERSION` | The Chromium version, `156.0.8078.79`. The only place it is written (R5). CI fails if `upstream.lock`, ungoogled's `chromium_version.txt` or the tarball's `chrome/VERSION` disagree. |
| `upstream.lock` | Repository URLs, tags and commit SHAs of every upstream layer. CI checks them. |
| `flags.vanta.gn` | GN args added after ungoogled `flags.gn` + `flags.windows.gn`. A flag set here wins. |
| `patches/series`, `patches/vanta/*.patch` | Vanta patches (unified diffs, `a/` `b/` paths, applied with `patch -p1 --ignore-whitespace --forward`, the same options as ungoogled's `utils/patches.py`). |
| `scripts/fetch_upstream.py` | Clones ungoogled-chromium-windows + its submodule at the lock and checks the SHAs. |
| `scripts/prepare.py` | Every step up to and including `gn gen` + `gn check`: `source, windeps, prune, patch, domsub, rust, args, gngen`, plus `resync` (swap a built tree to the current Vanta series) and `bindgen` for S3. It never runs ninja. |
| `scripts/offline_check.py` | Quick check for developers: pulls only the files the Vanta patches touch from chromium.googlesource.com, applies the upstream hunks for them, then the Vanta series. |
| `scripts/ci_ninja.py` | S3: runs ninja until a stage deadline (`-k 0`, vcvars64), `--canary` compiles the Vanta-touched objects first, writes `finished`/`failures`/edge counts. |
| `scripts/package_engine.py` | S3: `vanta-engine-win64.zip` + SHA-256 from `FILES.cfg` (no installer, no `.pdb`). |
| `scripts/smoke_s5lite.py` | S3: S5-lite smoke of the packaged exe (version resource, no config, 86, 87, valid signed config). |
| `scripts/gen_s3_workflow.py` | Generates `.github/workflows/engine-s3.yml`. |
| `scripts/build.ps1` | Full local build on your own Windows PC (R8). |

### Pinned upstream

| Layer | Tag | Commit |
|---|---|---|
| Chromium | `156.0.8078.79` | `a21ce95c24ce3964416f09ae1862f53f319eb4d0` |
| ungoogled-chromium-windows | `156.0.8078.79-1.1` | `8492884eb30fdd9417ea7816aa92def805c97c74` |
| ungoogled-chromium (submodule pin) | `156.0.8078.79-1` | `28a211ab4ab6b83d919966a4f58a6df23cf4fb29` |

## GN flags (`flags.vanta.gn`)

Release build (`is_official_build`, no debug or component build, `symbol_level=0`).
D5: `proprietary_codecs=false` and `ffmpeg_branding="Chromium"`. Because
`flags.windows.gn` turns codecs on, `enable_mse_mpeg2ts_stream_parser` is also
set to false, since Chromium asserts that it needs proprietary codecs. No
Widevine. `use_unofficial_version_number=false` keeps the version equal to
`VERSION`. The file has no NaCl flag: NaCl is gone from Chromium 156, and
`gn gen --fail-on-unused-args` would reject it.

## Patch groups

| Group | Status | What |
|---|---|---|
| **G1** | this phase | `0001` branding + exe name, `0002` signed launch config + version lock |
| G2 | P3 | navigator, User-Agent, UA-CH, Sec-CH-UA |
| G3 | P3 | screen, hardwareConcurrency, deviceMemory, maxTouchPoints |
| G4 | P3 | Canvas 2D, WebGL, WebGPU (Real/Noise/Block) |
| G5 | P3 | AudioContext / OfflineAudioContext noise |
| G6 | P3 | fonts, ClientRects / text metrics |
| G7 | P3 | timezone, locale, Accept-Language, geolocation, speech voices, media devices |
| G8 | P3 | WebRTC non-proxied UDP off, QUIC/IPv6/LAN gates, background networking off |

### G1 `0001-vanta-branding-and-exe-name.patch`

- `chrome/BUILD.gn`: on Windows `chrome_initial` writes `vanta-chromium.exe`,
  on top of ungoogled-windows' `windows-disable-reorder-fix-linking.patch`.
  The DLL is still `chrome.dll`, and the ninja target is still `chrome`.
- `chrome/common/chrome_constants.cc`: the browser and helper executable
  names/paths on Windows are `vanta-chromium.exe`, so relaunches and child
  processes find the right binary.
- `chrome/app/chrome_exe.ver`: `ORIGINAL_FILENAME=vanta-chromium.exe`.
- `chrome/tools/build/win/FILES.cfg`: packages `vanta-chromium.exe` (+ `.pdb`).
- `chrome/app/theme/chromium/BRANDING`, `chrome/app/chromium_strings.grd`
  (`IDS_PRODUCT_NAME`, `IDS_SHORT_PRODUCT_NAME`): product name "Vanta".
- `chrome/install_static/chromium_install_modes.h`: `kProductPathName` and
  `base_app_name`/`base_app_id` are "Vanta". The default user data dir becomes
  `%LOCALAPPDATA%\Vanta\User Data`, so it never collides with a real Chromium.
  The launcher passes `--user-data-dir` per profile anyway.
- Web-exposed brand strings do not change. Under Chromium branding, UA-CH does not
  read the product name (`components/embedder_support/user_agent_utils.cc`).
  G2 sets the brands.
- `chrome/installer/mini_installer/BUILD.gn` + `chrome.release`: the archive
  input is `vanta-chromium.exe`. Without this, `gn gen` fails with "Input to
  target not generated by a dependency" (S2 run 42380226685).
- Not covered: the Chromium installer at runtime. `setup.exe` still expects
  `chrome.exe`, and Vanta ships its own installer (section 7). Build only
  `chrome` (and `chromedriver` if needed), not `mini_installer`.

### G1 `0002-vanta-signed-launch-config.patch`

New `chrome/browser/vanta/` (`launch_config.{h,cc}`, `BUILD.gn`, `DEPS`), a
dependency in `//chrome/browser:browser`, and one call in
`ChromeMainDelegate::BasicStartupComplete()` (`chrome/app/chrome_main_delegate.cc`).
That is the earliest browser-process callback. It runs before the process
singleton, the profile, de-elevation and isolated-browser relaunch. It only runs
in the browser process (`--type` absent) and is not compiled into the separate
renderer binary.

Switches:

- `--vanta-config=<path>`: a JSON file in the exact form of `vanta-fingerprint`'s
  `SignedConfig` (`serde_json::to_string(&signed)`):
  `{"payload":"<persona JSON>","signature":"<base64 Ed25519 signature>"}`
- `--vanta-pubkey=<base64>`: the launcher's 32-byte Ed25519 public key
  (standard base64 with padding)

Verification uses BoringSSL `ED25519_verify` over the exact UTF-8 bytes of
`payload`, just as `config.rs::verify_for_engine` checks it, plus
`base::JSONReader` (RFC mode):

| Condition | Exit |
|---|---|
| no `--vanta-config` | starts normally (plain engine) |
| file unreadable or larger than 1 MiB, not JSON, `payload`/`signature` missing | 86 |
| signature not 64 bytes, pubkey missing or not 32 bytes, signature invalid | 86 |
| payload not a JSON object, or `engine.{major,minor,build,patch}` missing | 86 |
| `engine` ≠ this engine's `version_info::GetVersion()` (= `VERSION`) | 87 |

The codes match `vanta-types::exit_codes` (`BAD_CONFIG_SIGNATURE = 86`,
`VERSION_MISMATCH = 87`). Chrome's own result codes stop at 43. The verified
persona is kept in memory for later groups (`vanta::GetVerifiedPersona()`).
There is no spoofing, no CDP and no telemetry.

## CI stages (fast-fail pipeline, R7)

| Stage | Workflow | Runner | What |
|---|---|---|---|
| **S1** | `.github/workflows/engine-s1.yml` | ubuntu-latest | Pin check, offline check, then the real tarball: download, verify, unpack (archive deleted), prune, apply all three patch layers, domain substitution. No compile. Runs on pushes touching `engine/**` or `engine-*.yml`. |
| **S2** | `.github/workflows/engine-s2.yml` | windows-latest | After S1 succeeds on main (`workflow_run`) or by hand: SDK 10.0.28000.0, Windows downloads, the full `prepare.py` flow, `gn` bootstrap, `gn gen --fail-on-unused-args` over the whole graph, then `gn check` on `//chrome/browser/vanta/*` and `//chrome:chrome_initial` (fatal) and on `//chrome:chrome_dll` and `//chrome/browser:browser` (reported only). The full-graph check cannot pass, because the -lite tarball has no test sources (`v8/test/unittests`, …) and some upstream test targets have include errors once ungoogled's patches are applied. Builds on `D:` because `C:` runs out of space. No ninja. |
| **S3** | `.github/workflows/engine-s3.yml` | windows-2022 | By hand (`workflow_dispatch`): chained full build of `chrome` in up to 10 stages that resume from the `build-state` artifact, with a canary compile of the Vanta-touched files first; then `vanta-engine-win64.zip` and the S5-lite smoke (86/87/valid config) on the same runner. See `docs/engine-build.md`. |
| S5 | *not yet* | windows | Full smoke test (S3 already runs S5-lite): exe starts; bad signature gives 86, wrong version gives 87; fingerprint = config; proxy-only traffic; kill switch. |
| S6 | *not yet* | windows | SHA-256, minisign, optional Authenticode, GitHub Release. |

Rule: S3 is only dispatched once S1 and S2 pass. No release unless S5 passes.

## Local build (your PC)

```powershell
powershell -ExecutionPolicy Bypass -File engine\scripts\build.ps1 -Work D:\vanta-build
# prepare + gn gen only:
powershell -ExecutionPolicy Bypass -File engine\scripts\build.ps1 -Work D:\vanta-build -PrepareOnly
```

Requirements: Visual Studio 2022+ (Desktop C++), Windows SDK 10.0.28000.0,
Python 3.12, Git, 7-Zip, about 120 GB of free disk. Output:
`<Work>\ungoogled-chromium-windows\build\src\out\Default\vanta-chromium.exe`.

Quick patch check without a Chromium tree (Linux or macOS, needs GNU patch):

```bash
python3 engine/scripts/fetch_upstream.py /tmp/ucw
python3 engine/scripts/offline_check.py --ucw /tmp/ucw
```

## Adding or updating a patch

1. `python3 engine/scripts/offline_check.py --ucw /tmp/ucw --work /tmp/v --keep`
   leaves the touched files with all patches applied in `/tmp/v/src`.
2. Edit, then write a unified diff with `a/` and `b/` paths into
   `engine/patches/vanta/NNNN-name.patch` and add it to `engine/patches/series`.
   New files use `--- /dev/null`.
3. Push. S1 must pass before S2 runs.

To bump Chromium, change `VERSION`, every pin in `upstream.lock` and the
expected values in this README together. S1 refuses any mismatch.
