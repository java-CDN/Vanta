//! Consistency rules C001–C030 (F02). A `Fail` blocks launch; a `Note` is shown only.
//! Personas are Windows 10/11 desktops only (R1). C018 = timezone vs exit country (F07),
//! C025 = rarity note, C030 = version lock to the installed engine (R5).

use crate::device::GpuFamily;
use crate::persona::{Persona, SurfaceMode};
use crate::ua::WINDOWS_UA_TOKEN;
use serde::Serialize;
use vanta_types::{EngineVersion, OsKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Level {
    Pass,
    Note,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleResult {
    pub id: &'static str,
    pub level: Level,
    pub message: String,
}

pub const RULE_COUNT: usize = 30;

fn r(id: &'static str, ok: bool, pass: &str, fail: String) -> RuleResult {
    RuleResult {
        id,
        level: if ok { Level::Pass } else { Level::Fail },
        message: if ok { pass.to_string() } else { fail },
    }
}

fn note(id: &'static str, msg: impl Into<String>) -> RuleResult {
    RuleResult {
        id,
        level: Level::Note,
        message: msg.into(),
    }
}

/// GPU maker named by a WebGL vendor / renderer / WebGPU vendor string.
fn gpu_brand(s: &str) -> Option<&'static str> {
    GpuFamily::from_gpu_string(s).map(GpuFamily::as_str)
}

/// Software rasterizers: a real Windows desktop never reports these.
const SOFTWARE_RENDERERS: &[&str] = &["SwiftShader", "llvmpipe", "Microsoft Basic Render Driver"];

/// Chrome on Windows renders WebGL through ANGLE on Direct3D. The unmasked renderer is
/// `ANGLE (<Vendor>, <Device> (0x<8 hex>) Direct3D11 vs_5_0 ps_5_0, D3D11)` (or the
/// Direct3D9Ex / vs_3_0 ps_3_0 / D3D9 variant on very old drivers).
fn d3d_backend(renderer: &str) -> Option<&'static str> {
    if renderer.ends_with(", D3D11)") && renderer.contains(" Direct3D11 ") {
        Some("D3D11")
    } else if renderer.ends_with(", D3D9)") && renderer.contains(" Direct3D9") {
        Some("D3D9")
    } else {
        None
    }
}

/// Checks the exact shape of an ANGLE Direct3D renderer string and that its vendor tag
/// equals the one inside the WebGL vendor string `Google Inc. (<Vendor>)`.
fn angle_d3d_format_ok(vendor: &str, renderer: &str) -> bool {
    let Some(tag) = vendor
        .strip_prefix("Google Inc. (")
        .and_then(|v| v.strip_suffix(')'))
    else {
        return false;
    };
    let Some(rest) = renderer
        .strip_prefix("ANGLE (")
        .and_then(|r| r.strip_prefix(tag))
        .and_then(|r| r.strip_prefix(", "))
    else {
        return false;
    };
    let tail = match d3d_backend(renderer) {
        Some("D3D11") => " Direct3D11 vs_5_0 ps_5_0, D3D11)",
        Some(_) => " Direct3D9Ex vs_3_0 ps_3_0, D3D9)",
        None => return false,
    };
    let Some(device) = rest.strip_suffix(tail) else {
        return false;
    };
    // "<Device name> (0x0000A7A0)"
    let Some((name, id)) = device.rsplit_once(" (0x") else {
        return false;
    };
    let Some(hex) = id.strip_suffix(')') else {
        return false;
    };
    !name.trim().is_empty() && hex.len() == 8 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// Fonts every Windows 10/11 install ships with.
const WINDOWS_CORE_FONTS: &[&str] = &[
    "Arial",
    "Segoe UI",
    "Times New Roman",
    "Tahoma",
    "Verdana",
    "Consolas",
];

/// Fonts that only ship with Windows 11; on a Windows 10 persona they are a contradiction.
const WINDOWS11_ONLY_FONTS: &[&str] = &["Segoe UI Variable", "Segoe Fluent Icons"];

/// Fonts that are bundled with other desktop systems and never with Windows.
const NON_WINDOWS_FONTS: &[&str] = &[
    "Helvetica Neue",
    "Menlo",
    "Monaco",
    "Geneva",
    "Lucida Grande",
    "Apple Color Emoji",
    "DejaVu Sans",
    "Liberation Sans",
    "Cantarell",
    "Noto Color Emoji",
];

/// Windows display-scaling steps offered in Settings (100–200 %).
const WINDOWS_DPR: [f64; 5] = [1.0, 1.25, 1.5, 1.75, 2.0];

/// IANA zones that are plausible for an exit country (the Geo Auto-Match table, so a
/// matched persona always passes C018). Unknown country -> cannot verify.
pub fn timezones_for(country: &str) -> Option<Vec<&'static str>> {
    crate::geo::timezones_for(country)
}

/// Run every rule against a persona and the installed engine version.
pub fn check(p: &Persona, installed_engine: EngineVersion) -> Vec<RuleResult> {
    let fam = p.os.family();
    let mut out = Vec::with_capacity(RULE_COUNT);

    // --- Browser & OS identity -------------------------------------------------
    out.push(r(
        "C001",
        p.user_agent.contains(WINDOWS_UA_TOKEN),
        "UA carries the frozen Windows token",
        format!("UA does not contain '{WINDOWS_UA_TOKEN}'"),
    ));
    out.push(r(
        "C002",
        p.platform == "Win32",
        "navigator.platform is Win32",
        format!("platform '{}' is not Win32", p.platform),
    ));
    out.push(r(
        "C003",
        p.ua_ch.platform == fam,
        "UA-CH platform is Windows",
        format!("UA-CH platform '{}' != {fam}", p.ua_ch.platform),
    ));

    // --- Graphics ----------------------------------------------------------------
    let software = SOFTWARE_RENDERERS
        .iter()
        .any(|t| p.gpu.renderer.contains(t));
    out.push(r(
        "C004",
        software || d3d_backend(&p.gpu.renderer).is_some(),
        "GPU string uses the Direct3D (ANGLE) backend",
        format!("GPU '{}' is not a Direct3D renderer string", p.gpu.renderer),
    ));
    out.push(r(
        "C005",
        !software,
        "Hardware GPU (no software renderer)",
        "software renderer (SwiftShader/llvmpipe/Basic Render Driver) reveals a VM or headless run"
            .into(),
    ));
    let vb = gpu_brand(&p.gpu.vendor);
    let rb = gpu_brand(&p.gpu.renderer);
    out.push(r(
        "C006",
        p.gpu.vendor.starts_with("Google Inc. (") && vb.is_some() && vb == rb,
        "WebGL vendor matches renderer",
        format!("vendor '{}' does not match renderer", p.gpu.vendor),
    ));
    let wb = gpu_brand(&p.gpu.webgpu_vendor);
    out.push(r(
        "C007",
        wb.is_none() || rb.is_none() || wb == rb,
        "WebGPU vendor matches GPU",
        format!("WebGPU vendor '{}' != GPU", p.gpu.webgpu_vendor),
    ));

    // --- Screen ------------------------------------------------------------------
    let s = p.screen;
    out.push(r(
        "C008",
        s.avail_width <= s.width && s.avail_height <= s.height,
        "Available screen fits inside screen",
        "available area larger than screen".into(),
    ));
    out.push(r(
        "C009",
        s.width >= 1024 && s.height >= 600 && s.width <= 7680 && s.width > s.height,
        "Screen size plausible",
        format!("screen {}x{} implausible for a desktop", s.width, s.height),
    ));
    let dpr = p.device_pixel_ratio;
    out.push(r(
        "C010",
        WINDOWS_DPR.contains(&dpr),
        "Device pixel ratio is a Windows scaling step (1–2)",
        format!("DPR {dpr} is not a Windows scaling step (1, 1.25, 1.5, 1.75, 2)"),
    ));
    out.push(r(
        "C011",
        s.color_depth == 24,
        "Color depth 24",
        format!(
            "color depth {} (Chrome on Windows reports 24)",
            s.color_depth
        ),
    ));

    // --- Fonts -------------------------------------------------------------------
    let has = |f: &str| p.fonts.iter().any(|x| x == f);
    let missing: Vec<&str> = WINDOWS_CORE_FONTS
        .iter()
        .copied()
        .filter(|f| !has(f))
        .collect();
    out.push(r(
        "C012",
        missing.is_empty(),
        "Core Windows fonts present (Segoe UI, Arial, ...)",
        format!("missing Windows fonts: {}", missing.join(", ")),
    ));
    let mut foreign: Vec<&str> = NON_WINDOWS_FONTS
        .iter()
        .copied()
        .filter(|f| has(f))
        .collect();
    if p.os == OsKind::Windows10 {
        foreign.extend(WINDOWS11_ONLY_FONTS.iter().copied().filter(|f| has(f)));
    }
    out.push(r(
        "C013",
        foreign.is_empty(),
        "No fonts from another OS or a newer Windows release",
        format!("fonts not shipped with {:?}: {}", p.os, foreign.join(", ")),
    ));

    // --- Hardware ----------------------------------------------------------------
    // Logical processors of real desktop/laptop CPUs (18 and 22: e.g. Core Ultra
    // 5 125H / 7 155H).
    const CORES: [u32; 14] = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 28, 32];
    out.push(r(
        "C014",
        CORES.contains(&p.hardware_concurrency),
        "CPU core count real",
        format!("{} cores is not a real desktop CPU", p.hardware_concurrency),
    ));
    const MEM: [f64; 6] = [0.25, 0.5, 1.0, 2.0, 4.0, 8.0];
    out.push(r(
        "C015",
        MEM.contains(&p.device_memory),
        "deviceMemory is a Chrome bucket",
        format!(
            "deviceMemory {} (Chrome reports at most 8)",
            p.device_memory
        ),
    ));
    out.push(r(
        "C016",
        p.max_touch_points == 0 || p.max_touch_points == 10,
        "Touch points fit a Windows device (0, or 10 on touch screens)",
        format!("maxTouchPoints {} on {fam}", p.max_touch_points),
    ));
    let desktop_ok = !p.ua_ch.mobile
        && !p.user_agent.contains(" Mobile ")
        && p.ua_ch.model.is_empty()
        && p.ua_ch.form_factors == ["Desktop"];
    out.push(r(
        "C017",
        desktop_ok,
        "Desktop flags consistent (mobile=false, no model, form factor Desktop)",
        "UA-CH mobile/model/form factor do not describe a desktop".into(),
    ));

    // --- Location & language -----------------------------------------------------
    out.push(match &p.geo {
        None => note("C018", "no exit-IP location yet; timezone not verified"),
        Some(g) => match timezones_for(&g.country) {
            Some(z) => r(
                "C018",
                z.contains(&g.timezone.as_str()),
                "Timezone matches exit IP country",
                format!(
                    "timezone {} does not fit exit country {}",
                    g.timezone, g.country
                ),
            ),
            None => note(
                "C018",
                format!("country {} not in table; timezone not verified", g.country),
            ),
        },
    });
    out.push(r(
        "C019",
        !p.locale.is_empty() && p.languages.first() == Some(&p.locale),
        "Locale = first language",
        "languages[0] must equal locale".into(),
    ));
    let al = p.accept_language();
    let al_ok = al.split(',').next() == Some(p.locale.as_str())
        && al.split(',').count() == p.languages.len();
    out.push(r(
        "C020",
        al_ok,
        "Accept-Language matches navigator.languages",
        format!("Accept-Language '{al}' inconsistent"),
    ));

    // --- UA Client Hints details -------------------------------------------------
    let pv: Vec<Option<u32>> = p
        .ua_ch
        .platform_version
        .split('.')
        .map(|x| x.parse().ok())
        .collect();
    let pv_major = match pv.as_slice() {
        [Some(m), Some(_), Some(_)] => Some(*m),
        _ => None,
    };
    let c021 = match (p.os, pv_major) {
        (OsKind::Windows11, Some(m)) => m >= 13,
        (OsKind::Windows10, Some(m)) => (1..=10).contains(&m),
        (_, None) => false,
    };
    out.push(r(
        "C021",
        c021,
        "UA-CH platformVersion fits the Windows release (10: 1–10, 11: 13+)",
        format!(
            "platformVersion {} wrong for {:?}",
            p.ua_ch.platform_version, p.os
        ),
    ));
    let arch_ok = ["x86", "arm"].contains(&p.ua_ch.architecture.as_str())
        && p.ua_ch.bitness == "64"
        && !p.ua_ch.wow64;
    out.push(r(
        "C022",
        arch_ok,
        "Architecture x86/arm, bitness 64, no WOW64 (matches 'Win64; x64')",
        format!(
            "architecture '{}' bitness '{}' wow64 {}",
            p.ua_ch.architecture, p.ua_ch.bitness, p.ua_ch.wow64
        ),
    ));

    // --- Media, network, noise -----------------------------------------------------
    let m = p.media_devices;
    out.push(r(
        "C023",
        m.audioinput <= 4 && m.audiooutput <= 6 && m.videoinput <= 4,
        "Media device counts plausible",
        format!("media devices {m:?}"),
    ));
    out.push(r(
        "C024",
        p.webrtc_policy == "disable_non_proxied_udp",
        "WebRTC uses the proxy only",
        format!("WebRTC policy '{}' can leak the real IP", p.webrtc_policy),
    ));
    out.push(note(
        "C025",
        "rarity of this device is shown from the device DB weight",
    ));
    let seeds_ok = (p.canvas != SurfaceMode::Noise || p.canvas_seed != 0)
        && (p.audio != SurfaceMode::Noise || p.audio_seed != 0);
    out.push(r(
        "C026",
        seeds_ok,
        "Noise surfaces have stable seeds",
        "noise mode without a seed would change on every read".into(),
    ));

    // --- Cross-checks ------------------------------------------------------------
    out.push(r(
        "C027",
        software || angle_d3d_format_ok(&p.gpu.vendor, &p.gpu.renderer),
        "ANGLE Direct3D renderer string well-formed (vendor tag, 0x device id, shader model)",
        format!(
            "renderer '{}' is not a well-formed ANGLE Direct3D string for vendor '{}'",
            p.gpu.renderer, p.gpu.vendor
        ),
    ));
    let arm_gpu = rb == Some("qualcomm");
    out.push(r(
        "C028",
        arm_gpu == (p.ua_ch.architecture == "arm"),
        "GPU family matches CPU architecture (Adreno <-> arm, others <-> x86)",
        format!(
            "GPU '{}' with architecture '{}' is impossible",
            p.gpu.renderer, p.ua_ch.architecture
        ),
    ));
    let bar = s.height.saturating_sub(s.avail_height);
    out.push(r(
        "C029",
        s.avail_width == s.width && (24..=80).contains(&bar),
        "Windows taskbar gap is real",
        format!(
            "screen {}x{} with available {}x{} has no real taskbar",
            s.width, s.height, s.avail_width, s.avail_height
        ),
    ));

    // --- R5 version lock ---------------------------------------------------------
    let major_ok = p
        .user_agent
        .contains(&format!("Chrome/{}.0.0.0", installed_engine.major));
    let full_ok = p
        .ua_ch
        .full_version_list
        .iter()
        .any(|(b, v)| b == "Chromium" && *v == installed_engine.to_string());
    out.push(r(
        "C030",
        p.engine == installed_engine && major_ok && full_ok,
        "UA / UA-CH version = installed engine",
        format!(
            "persona says Chrome {} but the installed engine is {installed_engine}",
            p.engine
        ),
    ));
    debug_assert_eq!(out.len(), RULE_COUNT);
    out
}

/// Native-family gate (launch only, outside C001–C030): canvas, WebGL and WebGPU render
/// on the host GPU, so a persona that claims another GPU maker than the host's would show
/// one maker in its strings and another in its pixels and limits. `host` = the family of
/// the host's default adapter (DXGI adapter 0, the one ANGLE uses); `None` when it could
/// not be detected (non-Windows developer host, software adapter), which cannot be
/// verified and does not block.
pub fn host_gpu_gate(p: &Persona, host: Option<GpuFamily>) -> RuleResult {
    let claimed = p.gpu.family();
    match host {
        None => note(
            "G001",
            "host GPU vendor unknown; persona GPU family not verified against the host",
        ),
        Some(h) => r(
            "G001",
            claimed == Some(h),
            "Persona GPU vendor = host GPU vendor",
            format!(
                "persona GPU '{}' is not a {} GPU like this PC's; canvas/WebGL would render \
                 on the host GPU. Regenerate the fingerprint.",
                p.gpu.renderer,
                h.as_str()
            ),
        ),
    }
}

pub fn failures(results: &[RuleResult]) -> Vec<&RuleResult> {
    results.iter().filter(|r| r.level == Level::Fail).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::builtin;
    use crate::persona::Geo;
    const V: EngineVersion = EngineVersion::new(156, 0, 8078, 79);

    #[test]
    fn every_builtin_record_passes() {
        for d in builtin() {
            let p = Persona::from_device(&d, V, 1, "en-US").unwrap();
            let res = check(&p, V);
            assert_eq!(res.len(), RULE_COUNT);
            let f = failures(&res);
            assert!(f.is_empty(), "{}: {:?}", d.id, f);
        }
    }

    fn win() -> Persona {
        let db = builtin();
        Persona::from_device(
            db.iter().find(|d| d.id == "win11-irisxe-1536").unwrap(),
            V,
            1,
            "de-DE",
        )
        .unwrap()
    }

    fn fails(p: &Persona) -> Vec<&'static str> {
        failures(&check(p, V)).iter().map(|r| r.id).collect()
    }

    #[test]
    fn host_gpu_gate_blocks_foreign_family() {
        let p = win();
        let fam = p.gpu.family().expect("builtin GPU has a family");
        assert_eq!(host_gpu_gate(&p, Some(fam)).level, Level::Pass);
        assert_eq!(host_gpu_gate(&p, None).level, Level::Note);
        for other in [GpuFamily::Nvidia, GpuFamily::Amd, GpuFamily::Intel] {
            if other != fam {
                assert_eq!(host_gpu_gate(&p, Some(other)).level, Level::Fail);
            }
        }
        assert_eq!(GpuFamily::from_pci_vendor(0x10DE), Some(GpuFamily::Nvidia));
        assert_eq!(GpuFamily::from_pci_vendor(0x1002), Some(GpuFamily::Amd));
        assert_eq!(GpuFamily::from_pci_vendor(0x8086), Some(GpuFamily::Intel));
        assert_eq!(GpuFamily::from_pci_vendor(0x1414), None);
    }

    #[test]
    fn version_mismatch_fails_c030() {
        let p = win();
        let ids: Vec<_> = failures(&check(&p, EngineVersion::new(156, 0, 8078, 82)))
            .iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(ids, ["C030"]);
        let mut q = win();
        q.bind_engine(EngineVersion::new(158, 0, 8127, 18));
        assert!(
            fails(&q).contains(&"C030"),
            "persona newer than engine must fail"
        );
    }

    #[test]
    fn foreign_gpu_strings_rejected() {
        // Rejection test: renderer strings from non-Windows backends must fail.
        for renderer in [
            "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)",
            "ANGLE (Intel, Mesa Intel(R) UHD Graphics 630 (CFL GT2), OpenGL 4.6)",
        ] {
            let mut p = win();
            p.gpu.renderer = renderer.into();
            let f = fails(&p);
            assert!(
                f.contains(&"C004") && f.contains(&"C027"),
                "{renderer}: {f:?}"
            );
        }
    }

    #[test]
    fn malformed_d3d_renderer_fails_c027() {
        let mut p = win();
        // Missing PCI device id.
        p.gpu.renderer =
            "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)".into();
        assert_eq!(fails(&p), ["C027"]);
        // Vendor tag differs from the WebGL vendor string.
        let mut q = win();
        q.gpu.renderer =
            "ANGLE (Intel Corporation, Intel(R) Iris(R) Xe Graphics (0x0000A7A0) Direct3D11 vs_5_0 ps_5_0, D3D11)"
                .into();
        assert_eq!(fails(&q), ["C027"]);
    }

    #[test]
    fn d3d9_variant_accepted() {
        let mut p = win();
        p.gpu.renderer =
            "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x0000A7A0) Direct3D9Ex vs_3_0 ps_3_0, D3D9)"
                .into();
        assert!(fails(&p).is_empty());
    }

    fn arm64() -> Persona {
        let mut p = win();
        p.gpu.vendor = "Google Inc. (Qualcomm)".into();
        p.gpu.renderer =
            "ANGLE (Qualcomm, Qualcomm(R) Adreno(TM) X1-85 GPU (0x36334330) Direct3D11 vs_5_0 ps_5_0, D3D11)"
                .into();
        p.gpu.webgpu_vendor = "qualcomm".into();
        p.ua_ch.architecture = "arm".into();
        p
    }

    #[test]
    fn adreno_needs_arm_and_arm_needs_adreno() {
        let mut p = arm64();
        assert!(fails(&p).is_empty(), "{:?}", fails(&p));
        p.ua_ch.architecture = "x86".into();
        assert_eq!(fails(&p), ["C028"]);
        let mut q = win();
        q.ua_ch.architecture = "arm".into();
        assert_eq!(fails(&q), ["C028"]);
    }

    #[test]
    fn wow64_or_32bit_fails_c022() {
        let mut p = win();
        p.ua_ch.wow64 = true;
        assert_eq!(fails(&p), ["C022"]);
        let mut q = win();
        q.ua_ch.bitness = "32".into();
        assert_eq!(fails(&q), ["C022"]);
    }

    #[test]
    fn dpr_must_be_windows_scaling_step() {
        let mut p = win();
        p.device_pixel_ratio = 1.1;
        assert_eq!(fails(&p), ["C010"]);
        p.device_pixel_ratio = 1.75;
        assert!(fails(&p).is_empty());
    }

    #[test]
    fn color_depth_30_fails() {
        let mut p = win();
        p.screen.color_depth = 30;
        assert_eq!(fails(&p), ["C011"]);
    }

    #[test]
    fn non_windows_platform_strings_rejected() {
        let mut p = win();
        p.platform = "MacIntel".into();
        assert_eq!(fails(&p), ["C002"]);
        let mut q = win();
        q.ua_ch.platform = "Linux".into();
        assert_eq!(fails(&q), ["C003"]);
        let mut u = win();
        u.user_agent = u
            .user_agent
            .replace("Windows NT 10.0; Win64; x64", "X11; Linux x86_64");
        assert_eq!(fails(&u), ["C001"]);
    }

    #[test]
    fn missing_segoe_ui_fails_c012() {
        let mut p = win();
        p.fonts.retain(|f| f != "Segoe UI");
        assert_eq!(fails(&p), ["C012"]);
    }

    #[test]
    fn windows11_fonts_on_windows10_fail() {
        let db = builtin();
        let mut p = Persona::from_device(
            db.iter().find(|d| d.id == "win10-rtx3060-1080p").unwrap(),
            V,
            1,
            "en-US",
        )
        .unwrap();
        p.fonts.push("Segoe UI Variable".into());
        assert_eq!(fails(&p), ["C013"]);
        let mut q = win();
        q.fonts.push("Segoe UI Variable".into());
        assert!(fails(&q).is_empty(), "Windows 11 ships Segoe UI Variable");
    }

    #[test]
    fn swiftshader_fails() {
        let mut p = win();
        p.gpu.renderer =
            "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)"
                .into();
        assert!(fails(&p).contains(&"C005"));
    }

    #[test]
    fn memory_16_fails() {
        let mut p = win();
        p.device_memory = 16.0;
        assert_eq!(fails(&p), ["C015"]);
    }

    #[test]
    fn mac_font_on_windows_fails() {
        let mut p = win();
        p.fonts.push("Menlo".into());
        assert_eq!(fails(&p), ["C013"]);
    }

    #[test]
    fn win11_needs_platform_13_plus() {
        let mut p = win();
        p.ua_ch.platform_version = "10.0.0".into();
        assert_eq!(fails(&p), ["C021"]);
        p.ua_ch.platform_version = "15".into();
        assert_eq!(fails(&p), ["C021"], "platformVersion must have three parts");
        p.os = OsKind::Windows10;
        p.ua_ch.platform_version = "15.0.0".into();
        assert_eq!(fails(&p), ["C021"], "Windows 10 cannot report 13+");
    }

    #[test]
    fn mobile_flags_rejected() {
        let mut p = win();
        p.ua_ch.mobile = true;
        assert_eq!(fails(&p), ["C017"]);
        let mut q = win();
        q.max_touch_points = 5;
        assert_eq!(fails(&q), ["C016"]);
    }

    #[test]
    fn windows_screen_without_taskbar_fails() {
        let mut p = win();
        p.screen.avail_height = p.screen.height;
        assert_eq!(fails(&p), ["C029"]);
    }

    #[test]
    fn timezone_vs_exit_country() {
        let mut p = win();
        p.apply_geo(
            Geo {
                country: "DE".into(),
                timezone: "Europe/Berlin".into(),
                latitude: 50.1,
                longitude: 8.7,
                accuracy_m: 2000,
            },
            None,
        );
        assert!(fails(&p).is_empty());
        p.apply_geo(
            Geo {
                country: "NL".into(),
                timezone: "Europe/Berlin".into(),
                latitude: 52.4,
                longitude: 4.9,
                accuracy_m: 2000,
            },
            None,
        );
        assert_eq!(fails(&p), ["C018"]);
    }

    #[test]
    fn webrtc_policy_enforced() {
        let mut p = win();
        p.webrtc_policy = "default".into();
        assert_eq!(fails(&p), ["C024"]);
    }

    #[test]
    fn rule_ids_unique_ordered_and_complete() {
        let res = check(&win(), V);
        let ids: Vec<_> = res.iter().map(|r| r.id).collect();
        let expected: Vec<String> = (1..=30).map(|i| format!("C{i:03}")).collect();
        assert_eq!(ids, expected);
    }
}
