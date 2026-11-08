# Engine patches: graphics and audio (0004–0006)

Patch groups G4 (Canvas 2D, WebGL) and G5 (Web Audio) of Master Plan v3.1.
All three live in `engine/patches/vanta/` and run after `0003-persona-plumbing`
(team/engine-persona) in `engine/patches/series`. Context is Chromium
156.0.8078.79 **after** the ungoogled-chromium and ungoogled-chromium-windows
patches (two of the touched files already carry ungoogled/bromite hunks), and
every hunk applies with `patch --fuzz=0` and no offset.

Rules they keep: all of it is C++ in Blink, no script injection (R10); values
come from the persona's real-device record and noise is seeded per profile
(R11); Windows 10/11 personas only, so the WebGL rules assume ANGLE Direct3D 11;
no telemetry. **Without a persona (`vanta::GetPersona() == nullptr`) every
code path below returns before changing anything: plain Chromium behaviour.**

## Shared piece: the Blink persona adapter (added by 0004)

`third_party/blink/renderer/platform/vanta/vanta_persona.{h,cc}` is the only
file that includes `components/vanta/persona.h`. It reads the persona once per
process (thread-safe static) into `blink::vanta_surfaces::PersonaSurfaces`:

| Field | From the persona | Used by |
|---|---|---|
| `gpu_vendor`, `gpu_renderer` | `webgl.vendor`, `webgl.renderer` (the device record's `gpu`) | 0004 |
| `gpu_d3d11_fl11` | renderer starts with `ANGLE (` and contains `Direct3D11 vs_5_0 ps_5_0` | 0004 |
| `gpu_nvidia` | renderer starts with `ANGLE (NVIDIA,` | 0004 |
| `canvas_noise_seed` | `seeds.canvas` when the canvas mode is Noise, else 0 | 0005 |
| `audio_noise_seed` | `seeds.audio` when the audio mode is Noise, else 0 | 0006 |

`Mix64` (SplitMix64 finalizer) is the single mixing function, so equal inputs
give equal noise in every process, realm and thread (page, iframe, worker).

GN: `//components/vanta` is a dep of `//third_party/blink/renderer/platform`
(`platform/BUILD.gn`); the new sources are listed in the same `platform`
component. `platform/vanta/DEPS` allows `+components/vanta/persona.h`. Core and
modules reach the adapter through their existing dependency on platform.

Field names follow the brief for `components/vanta/persona.h` (`webgl.vendor`,
`webgl.renderer`, `seeds.canvas`, `seeds.audio`); the mode fields
(`canvas_mode`, `audio_mode`, `vanta::SurfaceMode::kNoise`) are assumed until
`docs/persona-interface.md` lands. Only `vanta_persona.cc` has to change if they
differ.

## 0004-webgl.patch

**Where**

- `modules/webgl/webgl_rendering_context_base.cc`
  - `getParameter`: `UNMASKED_VENDOR_WEBGL` / `UNMASKED_RENDERER_WEBGL` return
    the persona strings (still only once `WEBGL_debug_renderer_info` is
    enabled; checked before ungoogled's `SpoofWebGLInfo` flag, so the persona
    wins).
  - `getParameter`: for a D3D11 FL11 persona, a pre-switch hook
    (`VantaFixedParameter`) answers the limits ANGLE's D3D11 backend fixes from
    the feature level (ANGLE `renderer11_utils.cpp` at Chromium 156's ANGLE
    revision 127e783d): `MAX_TEXTURE_SIZE`, `MAX_CUBE_MAP_TEXTURE_SIZE`,
    `MAX_RENDERBUFFER_SIZE` 16384; `MAX_VIEWPORT_DIMS` [32767, 32767];
    `MAX_VERTEX_ATTRIBS`, `MAX_TEXTURE_IMAGE_UNITS`,
    `MAX_VERTEX_TEXTURE_IMAGE_UNITS` 16; `MAX_COMBINED_TEXTURE_IMAGE_UNITS` 32;
    `MAX_VARYING_VECTORS` 30; `MAX_FRAGMENT_UNIFORM_VECTORS` 1024;
    `MAX_VERTEX_UNIFORM_VECTORS` **4095 on NVIDIA, 4096 otherwise** (ANGLE's
    `skipVSConstantRegisterZero` workaround is NVIDIA-only);
    `ALIASED_LINE_WIDTH_RANGE` [1, 1]; `ALIASED_POINT_SIZE_RANGE` [1, 1024].
  - `getShaderPrecisionFormat`: D3D11 values, every float `(127, 127, 23)`,
    every int `(31, 30, 0)`, lowp and mediump included (ANGLE `setIEEEFloat`,
    `setTwosComplementInt(32)`).
  - `ExtensionSupportedAndAllowed`: a D3D11 persona never offers
    `WEBGL_compressed_texture_astc`, `_etc`, `_etc1`, `_pvrtc` (absent on
    D3D11). This one check serves both `getSupportedExtensions()` and
    `getExtension()`, so the two always agree.
- `modules/webgl/webgl2_rendering_context_base.cc`: `MAX_VERTEX_UNIFORM_COMPONENTS`
  and `MAX_COMBINED_VERTEX_UNIFORM_COMPONENTS` (ANGLE derives both from the
  vertex uniform vectors × 4) are shifted by 4 × (persona vectors − host
  vectors), so WebGL 2 agrees with the WebGL 1 limit.
- New: `platform/vanta/{DEPS,vanta_persona.h,vanta_persona.cc}`;
  `platform/BUILD.gn` (2 sources, `//components/vanta` dep).

**Why.** On Windows every GPU from about 2012 on reports the same ANGLE D3D11
block, so the device record's `gpu.vendor`/`gpu.renderer` decide everything
except the NVIDIA uniform register. Rewriting only the renderer string while
the limits come from a host of another vendor is off by exactly one
(MAX_VERTEX_UNIFORM_VECTORS), which detectors read. Reporting the block from
the persona also keeps a VM/SwiftShader host from leaking its own limits,
precisions or ASTC/ETC support. The device records carry no limits, so they
are derived from the record's renderer string (backend + vendor), which is
what real hardware does.

**Health checks.** H32 `gfx.pair` (vendor/renderer = record), H33 `gfx.d3d`
(ANGLE Direct3D string from the record), H34 `gfx.params` (MAX_TEXTURE_SIZE
16384), H35 `gfx.ext` (baseline present; can only remove extensions, never add
ones the host lacks).

## 0005-canvas-noise.patch

**Where**

- New `platform/vanta/canvas_noise.{h,cc}` (+ 2 sources in `platform/BUILD.gn`).
- `modules/canvas/canvas2d/base_rendering_context_2d.cc`, `getImageDataInternal`:
  after a successful read, noise the ImageData pixmap with its canvas origin
  `(sx, sy)`. Covers `CanvasRenderingContext2D` and
  `OffscreenCanvasRenderingContext2D` (same base class, page and worker).
- `core/html/canvas/html_canvas_element.cc`: `ToDataURLInternal` (toDataURL)
  and `toBlob` replace the snapshot by a noised raster copy, 2D contexts only.
- `core/offscreencanvas/offscreen_canvas.cc`: `convertToBlob`, 2D contexts only.

**Rule.** Only fully opaque pixels whose colour, ignoring the lowest bit,
differs from every 4-neighbour inside the read area (antialiased edges of
text, arcs, emoji). One seeded bit from `(seed, canvas x, canvas y, colour)`
becomes the lowest bit of R, G and B, except channels at 0 or 255.

**Why this shape.**

- Deterministic and idempotent: every decision reads colour bits the noise
  never changes, so 3 reads are identical, `getImageData → putImageData →
  getImageData` is unchanged, and noise never accumulates.
- Invisible: at most ±1 on one channel value, only on edge pixels.
- Exits agree: the same function runs on getImageData (unpremultiplied) and on
  the encoder copy (premultiplied); opaque pixels are the same in both.
- Spec invariants hold: transparent and translucent pixels are untouched
  (alpha-zero reads black), grey stays grey, solid fills, rectangle edges and
  1px lines read back exact, saturated channels stay exact.
- The canvas's own bitmap is never modified (the encoder path works on a copy;
  getImageData on its own ImageData buffer).

**Health checks.** H36 `gfx.canvas` (canvas render stable across 3 reads);
gives each profile its own, stable canvas hash.

## 0006-audio-noise.patch

**Where**

- New `platform/vanta/audio_noise.{h,cc}` (+ 2 sources in `platform/BUILD.gn`).
- `modules/webaudio/offline_audio_context.cc`, `FireCompletionEvent`: each
  channel of the rendered buffer is noised once, before the `complete` event
  and the `startRendering()` promise hand it to script. `getChannelData()` and
  `copyFromChannel()` then both read the same, stable data.
- `modules/webaudio/analyser_node.cc`: `getFloatFrequencyData` and
  `getFloatTimeDomainData` noise what they wrote.

**Rule.** Each sample keeps sign, exponent and top 20 mantissa bits; the
lowest 3 bits (≤ 7 ulp, < 1e-6 relative) come from `(seed, stream, index, kept
bits)`. Zero/silence, ±Infinity (silent bins in dB), NaN and "round" floats
(low 8 mantissa bits zero: constant sources, gains) stay exact. Idempotent.

**Why at render completion and not in the getters.** Noising inside
`getChannelData()`/`copyFromChannel()` would either change data on every read
(fails stability) or also touch buffers that script filled itself
(`createBuffer` + `copyToChannel` then read back would differ: a direct tell).
Rendering output is the only audio that is a fingerprint, and it is noised
exactly once.

**Health checks.** H40 `aud.ctx` (AudioContext output identical across reads,
different per profile).

## Not covered here (follow-ups)

- WebGL image readback (`readPixels`, WebGL `toDataURL`): persona
  `webgl_image` mode and `seeds.webgl`, not part of this task.
- Block mode for canvas/audio (H36/H40 expect empty data then).
- WebGPU adapter info (H37) and screen/DPR (H38/H39, G3); H41–H43 (media
  devices, speech voices, codecs) belong to G7 and the D5 GN flags.
- AnalyserNode byte data (`getByte*Data`) and realtime ScriptProcessor /
  AudioWorklet input are left exact.

## Risks

- **Interface**: written against the brief's `persona.h` names; the mode fields
  are assumptions until `docs/persona-interface.md` exists (one file to adapt).
  `GetPersona()` must work in the renderer process and be thread-safe.
- **Limits above the host**: on a host that is not D3D11 FL11 (VM, SwiftShader,
  remote desktop), the reported limits can exceed what the context really
  supports; a page that allocates a 16384 texture there gets a GL error.
- **Canvas coverage**: a canvas with no opaque antialiased pixels (text only on
  a transparent background) keeps its real hash. A getImageData sub-rectangle
  can differ from the full read on its own border pixels (neighbours outside
  the rectangle are not seen).
- **Extensions**: only removal; an extension D3D11 has but the host lacks
  cannot be added.
- Not compiled yet: S1/S2 check application and `gn gen`; the first compile is
  S3's canary (Vanta-touched `.cc` files first).
