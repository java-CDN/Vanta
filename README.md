# Vanta

Vanta is a local-only, multi-profile privacy browser for **Windows 10/11 (x64)**. Every
profile is an isolated browser identity built from a real Windows device record and checked
against 30 consistency rules before it is allowed to launch.

- **Engine:** [ungoogled-chromium-windows](https://github.com/ungoogled-software/ungoogled-chromium-windows)
  156.0.8078.79-1.1 plus Vanta patches, built on GitHub Actions. All spoofing happens in the
  engine's C++; there is no JavaScript injection.
- **Version lock:** the Chrome version a persona reports (User-Agent, UA Client Hints) is bound
  to the installed engine at every launch. It is never stored per profile and cannot drift
  (rule C030, engine exit code 87).
- **Local-only:** no telemetry, no account, no cloud sync, no teams, no API/MCP server.
  `scripts/no-telemetry.sh` enforces the no-telemetry rule in CI.
- **Personas are Windows 10 / Windows 11 only.** Other operating systems are rejected when a
  device record, a stored profile or a search query names them.

## Features (Master Plan v3)

| ID  | Feature             | What it does |
|-----|---------------------|--------------|
| F01 | Profile Manager     | All profiles in one table: folders, tags, saved searches (`tag:shop os:win11 health:<80`), new profile form, bulk Launch / Stop / Move / Health check / Delete. |
| F02 | Fingerprint Studio  | View and edit a profile's device identity (browser & OS, hardware, graphics, fonts, media, language, location); rules C001–C030 run live and a failing rule blocks launch. |
| F03 | Health Check        | Local test lab: 56 checks in 8 areas with a 0–100 score and fix hints, run entirely on your PC through Vanta's own reflector. |
| F04 | Proxy Hub           | Bulk import of HTTP and SOCKS5 proxies from any provider, 8-step check (connect, auth, exit IP/ASN, country/city, DNS, UDP, speed, blacklist); passwords live in the vault. |
| F05 | Network Guard       | Kill switch, WebRTC proxy-only, DNS-over-HTTPS, QUIC off when the proxy has no UDP, IPv6 and LAN blocked; a profile does not open unless every guard is on. |
| F06 | Vault Lock          | Everything encrypted under a master password (Argon2id → per-profile XChaCha20-Poly1305 keys), Windows Hello unlock, auto-lock on idle, sleep or Windows lock. |
| F07 | Geo Auto-Match      | Timezone and location follow the proxy exit IP via an offline GeoIP database; a country change pauses launch and asks (rule C018). |
| F08 | Activity Log        | Encrypted, hash-chained, local-only log of launches, blocked leaks, edits and vault events, kept 90 days. |
| —   | Settings            | Performance switches, disk, vault settings; shows the installed engine version. |

The full plan (rules R1–R13, feature details, screens) is in
[`docs/Vanta-Master-Plan-v3.pdf`](docs/Vanta-Master-Plan-v3.pdf).

## Clickable prototype

[`docs/prototype/index.html`](docs/prototype/index.html) is a single self-contained HTML file
(no network requests). Download it and open it in any modern browser. It shows every screen of
the app with demo data; the demo password is anything non-empty except `wrong`.

## Repository layout

| Path | Contents |
|------|----------|
| `crates/vanta-types` | Shared types: `EngineVersion`, `ProfileId`, `OsKind` (Windows 10/11), exit codes 86/87/88. |
| `crates/vanta-vault` | Vault Lock (F06) and the activity-log key (F08). |
| `crates/vanta-store` | SQLite + FTS5 profile database and search language (F01). |
| `crates/vanta-fingerprint` | Real Windows device records, UA / UA-CH from the engine version, rules C001–C030, Ed25519-signed launch config (F02, F07). |
| `engine/` | The engine (`vanta-chromium.exe`): pinned upstream, Vanta Chromium patches, GN flags, build scripts. See `engine/README.md`. |
| `.github/workflows/engine-s1.yml`, `engine-s2.yml` | Engine CI stages S1 (patches apply, ubuntu) and S2 (`gn gen --check`, windows). |
| `scripts/check.sh` | All local quality gates. |
| `scripts/no-telemetry.sh` | Fails on references to analytics/telemetry endpoints or SDKs. |
| `docs/` | Master Plan v3 (PDF) and the clickable prototype. |

## Consistency rules

`crates/vanta-fingerprint/src/rules.rs` defines exactly 30 rules. A **Fail** blocks launch; a
**Note** is informational.

| Rule | Check |
|------|-------|
| C001 | UA carries the frozen Windows token `Windows NT 10.0; Win64; x64` |
| C002 | `navigator.platform` is `Win32` |
| C003 | UA-CH `platform` is `Windows` |
| C004 | WebGL renderer uses the ANGLE Direct3D backend (D3D11, or D3D9 on old drivers) |
| C005 | Hardware GPU, no software renderer (SwiftShader, llvmpipe, Basic Render Driver) |
| C006 | WebGL vendor `Google Inc. (<Vendor>)` matches the renderer's GPU maker |
| C007 | WebGPU vendor matches the GPU |
| C008 | Available screen area fits inside the screen |
| C009 | Screen size plausible for a desktop (landscape, 1024×600 to 7680 wide) |
| C010 | Device pixel ratio is a Windows scaling step: 1, 1.25, 1.5, 1.75, 2 |
| C011 | Color depth is 24 |
| C012 | Core Windows fonts present (Arial, Segoe UI, Times New Roman, Tahoma, Verdana, Consolas) |
| C013 | No fonts from another OS, and no Windows 11-only fonts (Segoe UI Variable, Segoe Fluent Icons) on Windows 10 |
| C014 | CPU core count is a real desktop value |
| C015 | `deviceMemory` is a Chrome bucket (≤ 8) |
| C016 | `maxTouchPoints` is 0, or 10 on touch screens |
| C017 | Desktop flags consistent: mobile=false, empty model, form factor Desktop |
| C018 | Timezone matches the exit-IP country (Note until a location is known) |
| C019 | Locale equals the first entry of `navigator.languages` |
| C020 | `Accept-Language` matches `navigator.languages` |
| C021 | UA-CH `platformVersion` fits the release: Windows 10 = 1–10, Windows 11 = 13+ (three-part form) |
| C022 | Architecture `x86` or `arm`, bitness 64, WOW64 off (matches `Win64; x64`) |
| C023 | Media device counts plausible |
| C024 | WebRTC policy is `disable_non_proxied_udp` (proxy only) |
| C025 | Note: rarity of the device record (from its weight) |
| C026 | Noise surfaces (canvas, audio) have stable non-zero seeds |
| C027 | ANGLE Direct3D renderer string well-formed: vendor tag, `(0x…)` device id, shader model |
| C028 | GPU family matches CPU architecture: Qualcomm Adreno ⇔ `arm`, all others ⇔ `x86` |
| C029 | Real Windows taskbar gap: full available width, 24–80 px less available height |
| C030 | Version lock: UA and UA-CH version equal the installed engine |

## Develop

Requires the stable Rust toolchain (see `rust-toolchain.toml`). The crates build and test on
Windows directly; on Linux, install `gcc-mingw-w64-x86-64` and the `x86_64-pc-windows-gnu`
target for the Windows cross-check.

```sh
bash scripts/check.sh   # fmt, clippy -D warnings, tests, Windows target check, no-telemetry
```

CI (`.github/workflows/ci.yml`) runs fmt, clippy and the tests on `windows-latest`, and the
no-telemetry scan on `ubuntu-latest`, for every push and pull request to `main`.

## License

No license has been chosen yet. All rights reserved by the authors until one is added.
