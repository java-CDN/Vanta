# Vanta persona interface (engine patch 0003)

The contract between the launcher (Rust, `vanta-fingerprint`) and every engine
patch group G2–G8. Source of truth in C++: `components/vanta/persona.h`, added by
`engine/patches/vanta/0003-persona-plumbing.patch`. Changing a field here is an
interface change: update the patch, this file and the Rust contract test
(`vanta-fingerprint` `config::tests::launch_payload_matches_engine_persona_contract`)
together.

## How a persona reaches each process

1. The launcher signs a payload (`LaunchPayload`: the persona's fields at the top
   level, `accept_language`, `vanta_launch`) and starts the engine with
   `--vanta-config=<file> --vanta-pubkey=<key>` (patch 0002).
2. Browser process, `ChromeMainDelegate::BasicStartupComplete`: 0002 verifies
   signature (else exit 86) and engine version (else 87); 0003 then calls
   `vanta::InitializeBrowserPersona(payload)`. Missing/invalid persona field, or
   an encoded persona over 16 KiB → exit 86. This runs before any other thread or
   child exists.
3. `ChromeContentBrowserClient::AppendExtraCommandLineSwitches` calls
   `vanta::AppendPersonaSwitch()`, so every child content launches (renderer,
   GPU, utility: network service, audio, storage, …) gets
   `--vanta-persona=<base64url, no padding, of the canonical persona JSON>`.
4. Child processes parse that switch lazily on the first `vanta::GetPersona()`.
   No switch → `nullptr`. Malformed switch → `CHECK` (crash: running on with the
   host's real values would be a leak). The browser process never reads
   `--vanta-persona`, so it cannot bypass the signature.

## API (`namespace vanta`, GN `//components/vanta`, deps `//base` only)

| Symbol | Meaning |
|---|---|
| `const Persona* GetPersona()` | This process's persona; `nullptr` = no persona, behave exactly like Chromium. Thread-safe, stable pointer, never changes during the process. |
| `SurfaceMode {kReal, kNoise, kBlock}` | `canvas`, `webgl_image`, `audio` modes. |
| `WindowsRelease {kWindows10, kWindows11}` | `os`. |
| `kPersonaSwitch` = `"vanta-persona"` | Child switch name. |
| `InitializeBrowserPersona`, `AppendPersonaSwitch` | Browser only (0002/0003 call sites). |
| `PersonaFromDict`, `ParsePersonaJson`, `SerializePersona`, `EncodePersonaSwitchValue`, `DecodePersonaSwitchValue`, `ReadPersonaSwitch` | Pure helpers (tests). |

Consumers add `//components/vanta` to their GN deps and `+components/vanta/persona.h`
to DEPS. Blink reads it only through its adapter
`third_party/blink/renderer/platform/vanta/vanta_persona.{h,cc}` (added by 0004).

## Fields

`Persona` member ← signed payload key. All required unless noted; unknown
payload keys (`engine`, `seed`, `device_id`, `vanta_launch`, …) are ignored.

| Group | C++ field | JSON key | Type / rule |
|---|---|---|---|
| — | `schema` | `schema` | int, must be 1 |
| — | `os` | `os` | `"windows10"` \| `"windows11"` |
| G2 | `user_agent` | `user_agent` | string; the engine's own reduced Chrome UA computed by the launcher from `engine` (R14: never a manual override) |
| G2 | `brand` | `brand` | string, e.g. `"Google Chrome"` |
| G2 | `platform` | `platform` | `navigator.platform`, `"Win32"` |
| G2 | `ua_ch.brands` / `.full_version_list` | `ua_ch.brands` / `ua_ch.full_version_list` | list of `[brand, version]` string pairs (brands non-empty) |
| G2 | `ua_ch.platform`, `.platform_version`, `.architecture`, `.bitness`, `.model` | `ua_ch.*` | strings (`"Windows"`, e.g. `"19.0.0"`, `"x86"`, `"64"`, `""`) |
| G2 | `ua_ch.mobile`, `.wow64` | `ua_ch.*` | bool (`mobile` false) |
| G2 | `ua_ch.form_factors` | `ua_ch.form_factors` | string list |
| G3 | `hardware_concurrency` | `hardware_concurrency` | int 1–1024 |
| G3 | `device_memory_gb` | `device_memory` | number 0.125–4096 (GiB, unrounded; G3 applies Chrome's rounding) |
| G3 | `max_touch_points` | `max_touch_points` | int 0–256 |
| G3 | `screen.width/height/avail_width/avail_height/color_depth` | `screen.*` | int (CSS px; avail ≤ full) |
| G3 | `screen.device_pixel_ratio` | `device_pixel_ratio` (top level) | number 0.1–16 |
| G4 | `webgl.vendor`, `webgl.renderer` | `gpu.vendor`, `gpu.renderer` | UNMASKED_VENDOR/RENDERER_WEBGL strings (ANGLE D3D11) |
| G4 | `webgpu.vendor`, `webgpu.architecture` | `gpu.webgpu_vendor`, `gpu.webgpu_arch` | GPUAdapterInfo strings |
| G4/G5 | `canvas_mode`, `webgl_image_mode`, `audio_mode` | `canvas`, `webgl_image`, `audio` | `"real"` \| `"noise"` \| `"block"` |
| G4–G6 | `seeds.canvas`, `.audio`, `.webgl`, `.font`, `.client_rects` | `canvas_seed`, `audio_seed`, `webgl_seed`, `font_seed`, `clientrects_seed` | uint64, **decimal string** in JSON (base::JSONReader would round a u64 number), non-zero |
| G6 | `fonts` | `fonts` | non-empty string list (allowed families) |
| G7 | `timezone` | `geo.timezone` | IANA zone; empty when `geo` is null |
| G7 | `locale` | `locale` | BCP 47 tag, e.g. `"de-DE"` |
| G7 | `languages` | `languages` | string list (`navigator.languages`) |
| G7 | `accept_language` | `accept_language` | header value, precomputed by the launcher (`Persona::accept_language()`) |
| G7 | `geolocation` (optional) | `geo` (object or null) | `country` (ISO alpha-2), `latitude` [-90,90], `longitude` [-180,180], `accuracy_m` ≥ 0 |
| G7 | `media_devices.audio_input/audio_output/video_input` | `media_devices.audioinput/audiooutput/videoinput` | int ≥ 0 |
| G8 | `webrtc_policy` | `webrtc_policy` | must be `"disable_non_proxied_udp"` |

Strings are capped at 2048 bytes, lists at 4096 entries; the whole encoded
switch at 16 KiB (`kMaxPersonaSwitchValueLength`).

## Rules for G2–G8 patches

- Read only through `vanta::GetPersona()` (Blink: through the platform adapter).
  A `nullptr` persona means unchanged Chromium behaviour.
- Spoof in engine C++ only; no JavaScript injection (R10). Windows 10/11 x64 only.
- Never derive randomness in the engine: use the matching seed; mix with one
  shared function so every process/realm gives equal values.
- `timezone` empty (no `geo`) is G7's decision; it must not fall back to a
  value that contradicts the exit IP silently.
