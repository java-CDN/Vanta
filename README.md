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
- **Local-only:** no telemetry, no account, no cloud sync, no teams, no API/MCP server. The
  app's own network use is proxy checks (the Proxy Hub's IP-information, speed-test and blocklist lookups only through the proxy being checked), DNS-over-HTTPS and, during a health run, one IP echo
  endpoint (see [Health Check](#health-check)).
  `scripts/no-telemetry.sh` enforces the no-telemetry rule in CI.
- **Personas are Windows 10 / Windows 11 only.** Other operating systems are rejected when a
  device record, a stored profile or a search query names them.
- **No manual User-Agent.** The UA is always the engine's own reduced Chrome 156 Windows UA
  (`Mozilla/5.0 (Windows NT 10.0; Win64; x64) … Chrome/156.0.0.0 Safari/537.36`). Profiles
  differ by UA-CH `platformVersion`, GPU, screen, noise seeds and timezone.

## Features (Master Plan v3.1)

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

The full plan (rules R1–R14, feature details, screens, current status) is in
[`docs/Vanta-Master-Plan-v3.1.pdf`](docs/Vanta-Master-Plan-v3.1.pdf).

## Clickable prototype

[`docs/prototype/index.html`](docs/prototype/index.html) is a single self-contained HTML file
(no network requests). Download it and open it in any modern browser. It shows every screen of
the app with demo data; the demo password is anything non-empty except `wrong`.

## Repository layout

| Path | Contents |
|------|----------|
| `crates/vanta-types` | Shared types: `EngineVersion`, `ProfileId`, `OsKind` (Windows 10/11), `ProfileStatus`, exit codes 86/87/88, `VantaError`. |
| `crates/vanta-vault` | Vault Lock (F06), the activity-log key (F08) and sealed vault secrets (proxy passwords, launcher signing key, log head) bound to their reference. |
| `crates/vanta-store` | SQLite + FTS5 profile database and search language (F01); Proxy Hub table that keeps only a vault reference for each password (schema 2, legacy inline proxy lines migrated at unlock), the provider preset an entry's username is built from (schema 3) and its last extended check (schema 4); sealed-secret blobs; last health summary per profile. |
| `crates/vanta-fingerprint` | Real Windows device records, UA / UA-CH from the engine version, rules C001–C030, Ed25519-signed launch config (F02, F07). |
| `crates/vanta-proxy` | Proxy Hub (F04): import grammar (`host:port`, `host:port:user:pass`, `user:pass@host:port`, `scheme://…` for http/https/socks5), username presets for Bright Data, SOAX, Geonode, DataImpulse, Webshare and Thordata with a sticky session per profile or per Proxy Hub entry (grammars from the providers' public docs, not verified with live accounts), one-proxy-one-profile warning, offline launch gate, SOCKS5 UDP ASSOCIATE probe; extended Proxy Hub check strictly through the proxy under test (exit IP with ASN / organisation / country from a configurable JSON endpoint, default `https://ipinfo.io/json`; optional speed test capped at 2 MB / 20 s, default Cloudflare's `__down`; UDP ASSOCIATE support; DNS blocklists Spamhaus ZEN, SpamCop, DroneBL and PSBL over DoH through the proxy, each validated with its RFC 5782 test entries so a refusing public resolver reads `unknown`, never a guess). Network Guard (F05): tokio relay on `127.0.0.1:<ephemeral>` with SOCKS5/HTTP(S) upstreams, DoH (Cloudflare/Google/Quad9 or custom, sent through the proxy), IPv6/LAN/UDP blocked, fail-closed kill switch (5 s heartbeat), IP echo for health runs (exit IP through the proxy, own IP compared only), and a client check: on Windows only processes in the profile's engine Job Object may use its relay (owning PID via `GetExtendedTcpTable`). TLS is rustls + ring. |
| `crates/vanta-log` | Activity Log (F08): append-only, SHA-256 hash chain, XChaCha20-Poly1305 at rest under the vault's log key, 90-day retention with an anchor so the pruned chain still verifies, filters by kind/profile/time. |
| `crates/vanta-launcher` | Launch gate (proxy online, guard armed, rules passed, health ≥ 60 and fresh), engine command line (no CDP), typed exit codes 86/87/88, process status from the real child process, Windows Job Object kill-on-close. The engine starts `CREATE_SUSPENDED`, is assigned to the profile's job, then resumed (`spawn_in_job`), so every child it spawns is in the job. One job per profile doubles as the relay's client authorizer (`JobAuthorizer`, `IsProcessInJob`). |
| `crates/vanta-core` | Orchestration and the Tauri-facing API (`VantaApp`, serde DTOs): launch flow (vault → persona bound to the engine → per-launch relay with Job-Object-only clients → gate incl. last health report → Ed25519-signed launch config in the 0002 format → suspended start in the job), status watcher, relay events and launches into the activity log with the log head sealed in the vault and verified at unlock, health runs, profile/proxy CRUD, lock/unlock. After 3 failed launches of a profile in a row (gate block, exit 86/87, engine ended within its 3 s start-up window) the next attempt needs an explicit confirmation in the UI (`confirm_required`); a successful launch resets the count. |
| `apps/desktop` | The desktop app (Tauri 2): `src-tauri/` (crate `vanta-desktop`, binary `vanta.exe`) wraps `VantaApp` in IPC commands and pushes status, activity-log and lock events; `ui/` is the React + TypeScript interface ported from the approved prototype, with one typed backend interface (`ui/src/api/`: `backend.ts` types the calls, `tauri.ts` maps them to commands), a mock backend for browser development, vitest unit tests and a headless smoke test. See [Desktop app](#desktop-app). |
| `crates/vanta-health` | Health Check (F03), local-only: HTTPS reflector on `127.0.0.1` (rustls + ring, self-signed rcgen certificate) that parses the raw TLS ClientHello (JA4), the HTTP/2 client start (SETTINGS order, WINDOW_UPDATE, pseudo-header order) and HTTP/1.1 header order; STUN Binding responder (WebRTC leaks); DNS leak hook on the relay's resolver; static probe page (no CDP, no external fetch); 56 checks H01–H56 in 8 areas with a weighted 0–100 score. |
| `engine/` | The engine (`vanta-chromium.exe`): pinned upstream, Vanta Chromium patches, GN flags, build scripts. See `engine/README.md`. |
| `.github/workflows/engine-s1.yml`, `engine-s2.yml` | Engine CI stages S1 (patches apply, ubuntu) and S2 (`gn gen --check`, windows). |
| `scripts/check.sh` | All local quality gates. |
| `scripts/stage_engine.py` | Checks a packaged engine (`vanta-engine-win64.zip` + `SHA256SUMS`) and stages it for the installer (see [Desktop app](#desktop-app)); tests in `scripts/test_stage_engine.py`. |
| `scripts/no-telemetry.sh` | Fails on references to analytics/telemetry endpoints or SDKs. |
| `docs/` | Master Plan v3.1 (PDF) and the clickable prototype. |

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

## Network Guard

Every profile's engine talks only to its own local relay (`--proxy-server=socks5://127.0.0.1:<port>`).
The relay opens the upstream tunnel before it accepts a single client byte, resolves names over
DNS-over-HTTPS through the proxy (never the system resolver), refuses IPv6, LAN and UDP
(non-proxied UDP), and cuts every connection the moment the upstream proxy fails. It never
falls back to a direct connection. The kill switch and the WebRTC rule
(`disable_non_proxied_udp`) have no "off" value in the types, so no profile can disable them.

Chromium cannot authenticate to a SOCKS5 proxy, so the relay checks the client instead: for
every accepted connection it looks up the PID owning the client end (`GetExtendedTcpTable`,
`TCP_TABLE_OWNER_PID_ALL`) and accepts it only if that process is in the profile's Job Object
(`IsProcessInJob`), which every process the engine spawns inherits. Any other local process is
cut before a byte is read and logged as a blocked event. The kill-switch heartbeat runs every
5 s (configurable): each heartbeat is a fresh login at the proxy provider, and 1 s heartbeats
(86,400 logins per profile per day) run into provider rate limits. Live traffic is still cut
inside 1 s, because a failed tunnel or a dropped upstream trips the switch at once.

## Health Check

`crates/vanta-health` runs entirely on the PC. For one run it starts:

- an HTTPS reflector at `https://vanta-health.localhost:<port>/` (Chrome maps `*.localhost` to
  loopback and bypasses the proxy for it; the engine trusts exactly this run's key through
  `--ignore-certificate-errors-spki-list`). It reads the ClientHello before TLS (JA4), the
  HTTP/1.1 header order of the navigation, and, on a second `h2`-only port, the HTTP/2
  SETTINGS / WINDOW_UPDATE / pseudo-header order;
- a STUN responder on `127.0.0.1/udp`, used as the page's ICE server: with proxy-only WebRTC
  and a proxy without UDP, no Binding Request may arrive;
- a DNS leak test: unique `*.leak.vanta.invalid` names the page requests through the relay;
  every one must show up at the relay's DoH resolver.

Before the engine starts, the run measures the network inputs of H01–H10 and H17–H22 with a
plain-text **IP echo** endpoint (`https://api.ipify.org/` by default; Settings › Privacy,
any `https://` URL that answers with the IP only):

- the **exit IP**, asked twice through the profile's upstream proxy with the relay's own
  tunnel code (the proxy resolves the echo host; nothing is resolved locally). The two
  answers also test the sticky session (H07);
- the PC's **own public IP**, asked once over a direct connection (echo host resolved over
  DoH, never the system resolver), plus its local address on the default route (no packet
  sent). These are only compared with the exit IP and the page's WebRTC candidates; they are
  never stored, logged or returned to the UI. The echo service sees both requests.

If the echo cannot be reached, the exit IP stays unknown and H01 fails with a hint.

The probe page collects navigator, UA-CH, screen, WebGL/WebGPU, canvas/audio/ClientRects
stability, fonts, voices, codecs, worker and iframe values, WebRTC candidates and automation
traces, and POSTs them back as JSON. The 56 checks are pure functions of that report, the
captures, the persona and the Network Guard state. Score: 100 minus weighted penalties
(critical 15/5, warn 8/3, info 3/1 for fail/warn); any critical Fail caps the score at 40;
below 60 the launch is blocked. The TLS and HTTP/2 references are measured values for Chrome
156 on Windows (`t13d1517h2_8daaf6152771_cb7bf5808d99`,
`1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`) and must be re-calibrated against the
Vanta engine build.

| ID | Key | Area | Severity | Check |
|----|-----|------|----------|-------|
| H01 | `net.exit` | Network & IP | critical | Exit IP matches the assigned proxy |
| H02 | `net.direct` | Network & IP | critical | No direct-IP leak |
| H03 | `net.asn` | Network & IP | info | Exit ASN is a residential / ISP network |
| H04 | `net.black` | Network & IP | info | Exit IP not on public blacklists |
| H05 | `net.geo` | Network & IP | critical | Exit country = profile timezone & locale |
| H06 | `net.reach` | Network & IP | critical | Proxy reachable at launch |
| H07 | `net.sticky` | Network & IP | info | Sticky session keeps the same exit IP |
| H08 | `net.ipv6` | Network & IP | warn | IPv6 path blocked |
| H09 | `net.hdr` | Network & IP | warn | No proxy-revealing headers |
| H10 | `net.lan` | Network & IP | warn | Local network not reachable from pages |
| H11 | `tls.ja4` | TLS / HTTP2 / QUIC | warn | TLS ClientHello JA4 = Chrome reference |
| H12 | `tls.alpn` | TLS / HTTP2 / QUIC | warn | ALPN offers h2, http/1.1 |
| H13 | `tls.h2set` | TLS / HTTP2 / QUIC | warn | HTTP/2 SETTINGS frame = Chrome |
| H14 | `tls.pseudo` | TLS / HTTP2 / QUIC | warn | HTTP/2 pseudo-header order = Chrome |
| H15 | `tls.hdr` | TLS / HTTP2 / QUIC | warn | Request header order = Chrome |
| H16 | `tls.quic` | TLS / HTTP2 / QUIC | warn | QUIC handled correctly for this proxy |
| H17 | `rtc.pub` | WebRTC & DNS | critical | WebRTC public candidate = exit IP |
| H18 | `rtc.host` | WebRTC & DNS | critical | No host (local IP) candidate exposed |
| H19 | `rtc.mdns` | WebRTC & DNS | info | mDNS candidates behave like Chrome |
| H20 | `dns.doh` | WebRTC & DNS | critical | DNS goes through DoH via the relay |
| H21 | `dns.leak` | WebRTC & DNS | critical | No DNS query outside DoH |
| H22 | `rtc.stun` | WebRTC & DNS | warn | STUN traffic goes through the proxy |
| H23 | `nav.ua` | Navigator & UA-CH | critical | User-Agent version = engine |
| H24 | `nav.brands` | Navigator & UA-CH | warn | Sec-CH-UA brand list is valid |
| H25 | `nav.pv` | Navigator & UA-CH | warn | UA-CH platform & platformVersion match the OS |
| H26 | `nav.platform` | Navigator & UA-CH | warn | navigator.platform = Win32 |
| H27 | `nav.cores` | Navigator & UA-CH | warn | hardwareConcurrency plausible for the device |
| H28 | `nav.mem` | Navigator & UA-CH | warn | deviceMemory ≤ 8 and = record |
| H29 | `nav.lang` | Navigator & UA-CH | warn | navigator.languages = Accept-Language |
| H30 | `nav.worker` | Navigator & UA-CH | warn | Web Worker sees the same navigator |
| H31 | `nav.iframe` | Navigator & UA-CH | warn | iframes see the same navigator |
| H32 | `gfx.pair` | Graphics | warn | WebGL vendor matches renderer |
| H33 | `gfx.d3d` | Graphics | warn | Renderer is a Windows D3D ANGLE string |
| H34 | `gfx.params` | Graphics | info | WebGL parameters match the device |
| H35 | `gfx.ext` | Graphics | info | WebGL extension list matches real devices |
| H36 | `gfx.canvas` | Graphics | warn | Canvas render stable across 3 reads |
| H37 | `gfx.webgpu` | Graphics | warn | WebGPU adapter info = WebGL vendor |
| H38 | `gfx.screen` | Graphics | warn | Screen & available size plausible |
| H39 | `gfx.dpr` | Graphics | warn | devicePixelRatio consistent with screen |
| H40 | `aud.ctx` | Audio & media | warn | AudioContext output stable per profile |
| H41 | `aud.dev` | Audio & media | warn | Media device counts plausible |
| H42 | `aud.voices` | Audio & media | info | Speech voices match Windows |
| H43 | `aud.codec` | Audio & media | info | Codec support = Chrome on Windows |
| H44 | `fnt.list` | Fonts & layout | warn | Font list is the record's Windows set |
| H45 | `fnt.os` | Fonts & layout | warn | Fonts match the Windows version |
| H46 | `fnt.rects` | Fonts & layout | warn | ClientRects stable across reads |
| H47 | `fnt.emoji` | Fonts & layout | info | Emoji font is Segoe UI Emoji |
| H48 | `fnt.metrics` | Fonts & layout | warn | Text metrics equal in page and worker |
| H49 | `aut.webdriver` | Automation flags | critical | navigator.webdriver is false |
| H50 | `aut.cdp` | Automation flags | critical | No DevTools protocol traces |
| H51 | `aut.headless` | Automation flags | warn | No headless tokens in UA or window |
| H52 | `aut.chrome` | Automation flags | warn | window.chrome object present |
| H53 | `aut.perm` | Automation flags | warn | Permissions API consistent |
| H54 | `aut.plugins` | Automation flags | info | plugins & mimeTypes = Chrome PDF viewer |
| H55 | `aut.ext` | Automation flags | warn | No automation globals or extensions |
| H56 | `aut.notif` | Automation flags | info | Notification.permission = default |


## Desktop app

`apps/desktop` is the Vanta window: a Tauri 2 shell (`src-tauri/`) over `vanta-core::VantaApp`
and a React + TypeScript UI (`ui/`, Vite, no UI framework beyond React) ported from the
approved clickable prototype.

**Screens** (hash routes): Unlock / Create vault (recovery key shown once, recovery-key
unlock) · Profiles (`#/profiles`: folders, saved searches, search language
`tag: os: status: health: proxy: folder:` and `OR` run by the SQLite/FTS5 store, filters,
sort, virtualized table for 10k+ profiles, live status, launch/stop, bulk launch/stop/move/
health/delete, details drawer, edit, duplicate) · New Profile (`#/new`: seed-picked real
device record with live preview of the exact persona that will be saved, regenerate seed,
proxy with one-proxy-one-profile warning, locale, DoH provider, pre-save rule check) ·
Fingerprint Studio (`#/fingerprints`: read-only identity in 7 tabs, rules C001–C030,
Regenerate; the User-Agent and Chrome version are fixed by design, rule C030) · Health Check
(`#/health`: run, 0–100 score, 56 checks by 8 areas with explanations, score history,
report export) · Proxy Hub (`#/proxies`: import with preview, one proxy with a provider
username preset — provider, country, city, session length, live preview of the final
username, New session — edit with the password kept in, replaced in or removed from the
vault, quick test, full check — exit IP / ASN / country, UDP, blacklists — and speed test on
request, test all, assign with shared-proxy warning, delete) with the Geo Auto-Match tab (`#/geo`) · Network Guard
(`#/network`: guards that cannot be turned off, per-profile DoH provider, traffic path,
DNS/WebRTC leak test, blocked today) · Vault Lock (Ctrl+L, Lock now, idle auto-lock enforced
by the shell, change master password in Settings › Security & vault with the current password or, if it
was lost, the recovery key; only the password wrap changes, so the recovery key, sealed
secrets and the activity log stay as they are) · Activity Log
(`#/activity`: paged, filtered by kind/profile/date, chain status from the unlock check,
CSV export with a warning) · Settings (`#/settings/<section>`: general, security & vault,
engine path, data, appearance, privacy with the health-check IP echo URL, about).

**Shell.** Commands are thin wrappers over `VantaApp` (blocking work and the async launch /
health / proxy-test calls run on the blocking pool); every command must be listed in
`src-tauri/build.rs`, which turns it into an `allow-…` permission, and
`capabilities/default.json` grants the main window exactly those plus event listen/unlisten
(no fs, shell, http, opener or updater plugin). Strict CSP (`'self'` only, no remote
content), no telemetry, devtools only in debug builds, single instance, window title
"Vanta". Background loops push engine status changes (1 s), new activity-log entries (2 s)
and the idle auto-lock (the UI reports activity; the timer runs in Rust). Closing the window
with running profiles asks first; quitting closes every profile's Job Object, which ends its
engine. Data lives in `%LOCALAPPDATA%\Vanta`; `settings.json` there holds the UI settings,
the health-check IP echo URL and an optional engine path override.

**Engine.** The app uses, in this order: the path set in Settings › Engine (read at
start-up), the engine shipped with the installer (`engine\` next to `vanta.exe`), or
`%LOCALAPPDATA%\Programs\Vanta\engine\vanta-chromium.exe`, with the `VERSION` file next
to it. Until an engine is there, launches and health runs fail with a clear error and
everything else works.

The installer bundles an engine only when one is supplied: run CI (`ci.yml`) manually with
`engine_run_id` = an `engine-s3.yml` run id. Its `vanta-engine-win64` artifact (the output
of `engine/scripts/package_engine.py`: `vanta-engine-win64.zip` + `SHA256SUMS`) goes
through `scripts/stage_engine.py`, which checks the zip and `vanta-chromium.exe` against
`SHA256SUMS`, extracts it, adds a `SHA256SUMS` line for every other file, writes `VERSION`
(from `engine/VERSION` of the checkout, so use an engine built from the same version) and a
`tauri build --config` overlay that ships it as `engine\`. At every start the app checks
each file listed in that `SHA256SUMS` in the background (Settings › Engine › Integrity);
until the check passes, or if a file is missing or differs, launches and health runs are
refused with a clear error ("reinstall Vanta"). An engine folder without `SHA256SUMS` is not
checked and behaves as before. Locally:

```sh
python scripts/stage_engine.py --from <folder with the zip and SHA256SUMS> \
  --to apps/desktop/src-tauri/engine-bundle --version-file engine/VERSION \
  --tauri-config apps/desktop/src-tauri/tauri.engine.json
cd apps/desktop && npm run tauri build -- --bundles nsis --config src-tauri/tauri.engine.json
```

### Run it

```sh
cd apps/desktop
npm ci
npm run dev:mock          # UI in a browser at http://127.0.0.1:1420 with demo data (?unlocked=1, ?fresh=1, ?profiles=10000)
npm run tauri dev         # the real app (Windows; WebView2)
npm run tauri build -- --bundles nsis   # unsigned NSIS installer in target/release/bundle/nsis
```

Tests: `npm test` (tsc + vitest: API mapping, search language, health catalog vs
`vanta-health`, mock backend, import parser), `npm run build && npm run size` (bundle budget
300 KB gzip), `npm run build:mock && npm run smoke` (headless Chromium over the mock build;
set `CHROME_PATH` if Chrome/Chromium is not in a standard place).

**Memory (R6).** The manager is `vanta.exe` plus the WebView2 processes Windows runs for its
window; WebView2 memory sits outside the manager process. The < 80 MB idle target has to be
measured on real Windows (Task Manager, the app's process group), not in CI.

## Develop

Requires the stable Rust toolchain (see `rust-toolchain.toml`). The crates build and test on
Windows directly; on a non-Windows host, install `gcc-mingw-w64-x86-64` and the `x86_64-pc-windows-gnu`
target for the Windows cross-check.

```sh
bash scripts/check.sh   # fmt, clippy -D warnings, tests, Windows target check, no-telemetry, desktop UI gates
```

`check.sh` leaves the Tauri crate (`vanta-desktop`) out of the Rust gates: it links WebView2
on Windows and webkit2gtk elsewhere. The desktop UI gates (vitest, builds, bundle budget,
smoke) run when `npm` is available.

CI (`.github/workflows/ci.yml`) runs fmt, clippy and the tests on `windows-latest`, the
desktop job (vitest, bundle budget, smoke over the mock build, clippy for `vanta-desktop`,
`tauri build` → unsigned NSIS installer uploaded as the `vanta-desktop-nsis` artifact, kept
7 days) on `windows-latest`, and the no-telemetry scan on `ubuntu-latest`, for every push and
pull request to `main`.

## License

No license has been chosen yet. All rights reserved by the authors until one is added.
