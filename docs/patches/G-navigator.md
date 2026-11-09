# Patch group G-navigator: 0007–0010

Chromium 156.0.8078.79 patches in `engine/patches/vanta/`. They stack on
`0003-persona-plumbing` (team/engine-persona: `components/vanta/persona.h`,
`vanta::GetPersona()`) and `0004–0006` (team/engine-graphics: the Blink
adapter `third_party/blink/renderer/platform/vanta/vanta_persona.{h,cc}`).
Series order: 0001 … 0006, then 0007, 0008, 0009, 0010.

Rules kept: Windows 10/11 personas only; all spoofing in engine C++ (no JS
injection, R10); every change is gated on `GetPersona() != nullptr`, so an
engine started without `--vanta-config` is plain Chromium. The User-Agent
string and UA-CH brands/full version list stay the engine's own reduced
Chrome 156 Windows values (R14): `Persona::user_agent` and `ua_ch.brands` are
not applied.

Blink code reads the persona only through the adapter
(`blink::vanta_surfaces::GetPersonaSurfaces()`); these patches add fields to
`PersonaSurfaces` instead of including `components/vanta` again. Code outside
the Blink renderer (browser, `blink/common`, `ui/display`, `content`) calls
`vanta::GetPersona()` directly.

## 0007 navigator + UA-CH

| Surface | Persona field | Where |
|---|---|---|
| `navigator.hardwareConcurrency` (window + all workers) | `hardware_concurrency` | `core/frame/navigator_concurrent_hardware.cc` via adapter field `hardware_concurrency` |
| `navigator.deviceMemory`, `Sec-CH-Device-Memory` | `device_memory_gb` | `blink/common/device_memory/approximated_device_memory.cc`; snapped to a power of two in [2, 32] (Chrome 156 desktop limits) |
| UA-CH `platformVersion` (JS + `Sec-CH-UA-Platform-Version`) | `ua_ch.platform_version` | `components/embedder_support/user_agent_utils.cc` (`GetPlatformVersion`) |
| `navigator.languages`, `Accept-Language` | `languages` | `chrome/browser/renderer_preferences_util.cc` + `chrome/browser/net/profile_network_context_service.cc`, one list for both |
| `navigator.platform` | `platform` ("Win32") | no change: Chromium on Windows already reports "Win32" |

Win10 personas carry `"10.0.0"`, Win11 `"13.0.0"` or later; the launcher
decides, the engine passes it through.

## 0008 screen

- `ui/display/display_util.cc` (`DisplayToScreenInfo`): `rect` = persona
  width × height, `available_rect` = avail size at the same origin, `depth` =
  `color_depth` (24 or 30 only), `is_extended = false`. All `screen.*`, the
  `device-*`/`color` media queries and Window Management read this.
- `ui/display/display.cc`: persona `screen.device_pixel_ratio` (1.0–5.0) is
  the forced device scale factor in every process, so `devicePixelRatio`,
  resolution media queries and layout agree.
- `chrome/browser/ui/window_sizer/window_sizer.cc`: new windows are clamped to
  the persona's available area (un-maximized when the real work area is
  larger), so `outerWidth/outerHeight <= availWidth/availHeight`.

## 0009 time zone

`core/timezone/timezone_controller.cc`: `TimeZoneController::Init()` makes
the persona's IANA zone (adapter field `timezone`) the process-wide ICU
default before any isolate or worker exists, so `Date` and `Intl` agree in
windows and dedicated/shared/service workers. Host time zone change
notifications are then ignored. An empty zone (persona without `geo`) keeps
the host zone; an unknown zone logs and keeps the host zone.

## 0010 fonts + WebRTC

- `components/vanta/font_allowlist.h` (header-only, added to the
  `//components/vanta` sources): allowed = persona `fonts` ∪ a small Windows
  baseline (Arial, Comic Sans MS, Consolas, Courier New, Impact, Segoe UI,
  Segoe UI Emoji, Segoe UI Symbol, Times New Roman), case-insensitive.
- Blink: `platform/fonts/font_cache.cc` refuses name matches (CSS
  `font-family`, `local()`, `document.fonts.check`, canvas) whose real family
  is not allowed, through the adapter's `IsFontFamilyAllowed()`. System
  fallback is not filtered, so text in any script still renders.
- `content/browser/font_access/font_enumeration_cache.cc`:
  `queryLocalFonts()` lists only allowed families.
- WebRTC (`chrome/browser/renderer_preferences_util.cc`): with a persona the
  policy is forced to `disable_non_proxied_udp` (no host, mDNS or local
  candidates; only proxied) and per-URL policy / local-IP allow-lists are
  cleared, so prefs, extensions and policies cannot loosen it.

## Build wiring

New GN deps on `//components/vanta`: `third_party/blink/common`,
`components/embedder_support:user_agent`, `chrome/browser/net:impl`,
`ui/display`, `chrome/browser/ui/window_sizer:impl`, `content/browser`.
DEPS: `+components/vanta/persona.h` (blink/common, embedder_support,
ui/display), `+components/vanta/font_allowlist.h` (content/browser,
platform/vanta).

## Verify

`python engine/scripts/offline_check.py --ucw <ucw>` with 0003–0006 in the
series before these (the version of offline_check.py on team/engine-persona,
which handles patches editing files an earlier Vanta patch created). Passed
2026-11-09 with `patch -F0`.

## Known gaps / risks

- Forced DSF also scales the browser UI when the host DPI differs.
- Physical-pixel APIs not covered here: `matchMedia` on real monitor size is
  consistent, but `window.screenX/screenY` still use the real desktop origin.
- Font filter does not change font metrics (font_seed / clientrects_seed are
  for a later patch).
- `Intl` default *locale* is not changed here (only time zone and
  languages); that belongs to the locale patch (G7).
- DevTools time zone emulation can still override the persona zone.
