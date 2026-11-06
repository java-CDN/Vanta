//! Consistency rules C001–C031 (F02). A `Fail` blocks launch; a `Note` is shown only.

use crate::persona::{Persona, SurfaceMode};
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

pub const RULE_COUNT: usize = 31;

fn r(id: &'static str, ok: bool, pass: &str, fail: String) -> RuleResult {
    RuleResult {
        id,
        level: if ok { Level::Pass } else { Level::Fail },
        message: if ok { pass.to_string() } else { fail },
    }
}

fn gpu_os(renderer: &str) -> Option<&'static [&'static str]> {
    const T: &[(&str, &[&str])] = &[
        ("SwiftShader", &[]),
        ("llvmpipe", &[]),
        ("Direct3D", &["Windows"]),
        ("D3D11", &["Windows"]),
        ("Metal Renderer", &["macOS"]),
        ("Mesa", &["Linux"]),
        ("OpenGL 4", &["Linux"]),
        ("Adreno", &["Android"]),
        ("Mali", &["Android"]),
        ("PowerVR", &["Android"]),
        ("Xclipse", &["Android"]),
    ];
    T.iter()
        .find(|(t, _)| renderer.contains(t))
        .map(|(_, o)| *o)
}

fn gpu_brand(s: &str) -> Option<&'static str> {
    let l = s.to_lowercase();
    for (k, v) in [
        ("nvidia", "nvidia"),
        ("amd", "amd"),
        ("radeon", "amd"),
        ("intel", "intel"),
        ("apple", "apple"),
        ("adreno", "qualcomm"),
        ("qualcomm", "qualcomm"),
        ("mali", "arm"),
        ("arm", "arm"),
    ] {
        if l.contains(k) {
            return Some(v);
        }
    }
    None
}

const BASE_FONTS: &[(&str, &[&str])] = &[
    (
        "Windows",
        &[
            "Arial",
            "Segoe UI",
            "Times New Roman",
            "Tahoma",
            "Verdana",
            "Consolas",
        ],
    ),
    ("macOS", &["Helvetica", "Helvetica Neue", "Menlo", "Times"]),
    ("Linux", &["DejaVu Sans"]),
    ("Android", &["Roboto"]),
];
const EXCLUSIVE_FONTS: &[(&str, &[&str])] = &[
    (
        "Windows",
        &[
            "Segoe UI",
            "Segoe UI Emoji",
            "Segoe UI Symbol",
            "MS Gothic",
            "Marlett",
        ],
    ),
    (
        "macOS",
        &[
            "Helvetica Neue",
            "Menlo",
            "Apple Color Emoji",
            "Geneva",
            "Lucida Grande",
        ],
    ),
    ("Linux", &["DejaVu Sans", "Ubuntu", "Cantarell"]),
    ("Android", &["Roboto", "Droid Sans Mono", "Cutive Mono"]),
];

/// IANA zones that are plausible for an exit country. Unknown country -> cannot verify.
pub fn timezones_for(country: &str) -> Option<&'static [&'static str]> {
    const T: &[(&str, &[&str])] = &[
        ("DE", &["Europe/Berlin"]),
        ("NL", &["Europe/Amsterdam"]),
        ("FR", &["Europe/Paris"]),
        ("GB", &["Europe/London"]),
        ("IE", &["Europe/Dublin"]),
        ("ES", &["Europe/Madrid", "Atlantic/Canary"]),
        ("IT", &["Europe/Rome"]),
        ("PL", &["Europe/Warsaw"]),
        ("SE", &["Europe/Stockholm"]),
        ("CH", &["Europe/Zurich"]),
        ("AT", &["Europe/Vienna"]),
        ("BE", &["Europe/Brussels"]),
        (
            "PT",
            &["Europe/Lisbon", "Atlantic/Azores", "Atlantic/Madeira"],
        ),
        ("JP", &["Asia/Tokyo"]),
        ("IN", &["Asia/Kolkata", "Asia/Calcutta"]),
        ("BD", &["Asia/Dhaka"]),
        ("SG", &["Asia/Singapore"]),
        ("AE", &["Asia/Dubai"]),
        ("TR", &["Europe/Istanbul"]),
        ("KR", &["Asia/Seoul"]),
        (
            "US",
            &[
                "America/New_York",
                "America/Chicago",
                "America/Denver",
                "America/Phoenix",
                "America/Los_Angeles",
                "America/Anchorage",
                "Pacific/Honolulu",
                "America/Detroit",
                "America/Indiana/Indianapolis",
                "America/Boise",
            ],
        ),
        (
            "CA",
            &[
                "America/Toronto",
                "America/Vancouver",
                "America/Edmonton",
                "America/Winnipeg",
                "America/Halifax",
                "America/St_Johns",
                "America/Regina",
                "America/Montreal",
            ],
        ),
        (
            "AU",
            &[
                "Australia/Sydney",
                "Australia/Melbourne",
                "Australia/Brisbane",
                "Australia/Perth",
                "Australia/Adelaide",
                "Australia/Hobart",
                "Australia/Darwin",
            ],
        ),
        (
            "BR",
            &[
                "America/Sao_Paulo",
                "America/Manaus",
                "America/Fortaleza",
                "America/Recife",
                "America/Bahia",
                "America/Belem",
            ],
        ),
        (
            "MX",
            &[
                "America/Mexico_City",
                "America/Monterrey",
                "America/Tijuana",
                "America/Cancun",
                "America/Merida",
                "America/Chihuahua",
            ],
        ),
    ];
    T.iter()
        .find(|(c, _)| c.eq_ignore_ascii_case(country))
        .map(|(_, z)| *z)
}

fn win_platform_major(p: &Persona) -> Option<u32> {
    p.ua_ch.platform_version.split('.').next()?.parse().ok()
}

/// Run every rule against a persona and the installed engine version.
pub fn check(p: &Persona, installed_engine: EngineVersion) -> Vec<RuleResult> {
    let fam = p.os.family();
    let mobile = p.os.is_mobile();
    let mut out = Vec::with_capacity(RULE_COUNT);

    let ua_token = match p.os {
        OsKind::Windows10 | OsKind::Windows11 => "Windows NT 10.0; Win64; x64",
        OsKind::MacOs => "Macintosh; Intel Mac OS X 10_15_7",
        OsKind::Linux => "X11; Linux x86_64",
        OsKind::Android => "Linux; Android 10; K",
    };
    out.push(r(
        "C001",
        p.user_agent.contains(ua_token),
        "UA OS token matches OS",
        format!("UA does not contain '{ua_token}'"),
    ));

    let plat_ok = match p.os {
        OsKind::Windows10 | OsKind::Windows11 => p.platform == "Win32",
        OsKind::MacOs => p.platform == "MacIntel",
        OsKind::Linux => p.platform.starts_with("Linux x86_64") || p.platform == "Linux aarch64",
        OsKind::Android => {
            ["Linux armv8l", "Linux aarch64", "Linux armv81"].contains(&p.platform.as_str())
        }
    };
    out.push(r(
        "C002",
        plat_ok,
        "navigator.platform fits OS",
        format!("platform '{}' is wrong for {fam}", p.platform),
    ));
    out.push(r(
        "C003",
        p.ua_ch.platform == fam,
        "UA-CH platform matches OS",
        format!("UA-CH platform '{}' != {fam}", p.ua_ch.platform),
    ));

    let g = gpu_os(&p.gpu.renderer);
    out.push(r(
        "C004",
        g.is_none_or(|o| o.contains(&fam)),
        "GPU string fits OS",
        format!("GPU '{}' is not a {fam} GPU string", p.gpu.renderer),
    ));
    out.push(r(
        "C005",
        g.is_none_or(|o| !o.is_empty()),
        "Hardware GPU (no software renderer)",
        "software renderer (SwiftShader/llvmpipe) reveals a VM or headless run".into(),
    ));

    let vb = gpu_brand(&p.gpu.vendor);
    let rb = gpu_brand(&p.gpu.renderer);
    let c006 = if mobile {
        true
    } else {
        p.gpu.vendor.starts_with("Google Inc. (") && vb.is_some() && vb == rb
    };
    out.push(r(
        "C006",
        c006,
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

    let s = p.screen;
    out.push(r(
        "C008",
        s.avail_width <= s.width && s.avail_height <= s.height,
        "Available screen fits inside screen",
        "available area larger than screen".into(),
    ));
    let size_ok = if mobile {
        (320..=1280).contains(&s.width) && s.height > s.width
    } else {
        s.width >= 1024 && s.height >= 600 && s.width <= 7680
    };
    out.push(r(
        "C009",
        size_ok,
        "Screen size plausible",
        format!("screen {}x{} implausible", s.width, s.height),
    ));
    let dpr = p.device_pixel_ratio;
    let dpr_ok = match p.os {
        OsKind::Windows10 | OsKind::Windows11 => {
            [1.0, 1.25, 1.5, 1.75, 2.0, 2.25, 2.5, 3.0].contains(&dpr)
        }
        OsKind::MacOs => dpr == 1.0 || dpr == 2.0,
        OsKind::Linux => [1.0, 1.25, 1.5, 2.0].contains(&dpr),
        OsKind::Android => (1.5..=4.0).contains(&dpr),
    };
    out.push(r(
        "C010",
        dpr_ok,
        "Device pixel ratio fits OS",
        format!("DPR {dpr} not used on {fam}"),
    ));
    out.push(r(
        "C011",
        s.color_depth == 24 || (s.color_depth == 30 && p.os == OsKind::MacOs),
        "Color depth plausible",
        format!("color depth {}", s.color_depth),
    ));

    let base = BASE_FONTS
        .iter()
        .find(|(f, _)| *f == fam)
        .map(|x| x.1)
        .unwrap_or(&[]);
    let missing: Vec<&str> = base
        .iter()
        .copied()
        .filter(|f| !p.fonts.iter().any(|x| x == f))
        .collect();
    out.push(r(
        "C012",
        missing.is_empty(),
        "Core OS fonts present",
        format!("missing {fam} fonts: {}", missing.join(", ")),
    ));
    let foreign: Vec<String> = EXCLUSIVE_FONTS
        .iter()
        .filter(|(f, _)| *f != fam)
        .flat_map(|(_, fs)| fs.iter())
        .filter(|f| p.fonts.iter().any(|x| x == *f) && !base.contains(f))
        .map(|f| f.to_string())
        .collect();
    out.push(r(
        "C013",
        foreign.is_empty(),
        "No fonts from another OS",
        format!("foreign fonts: {}", foreign.join(", ")),
    ));

    const CORES: [u32; 13] = [2, 4, 6, 8, 9, 10, 12, 14, 16, 20, 24, 28, 32];
    out.push(r(
        "C014",
        CORES.contains(&p.hardware_concurrency),
        "CPU core count real",
        format!("{} cores is not a real CPU", p.hardware_concurrency),
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
    let touch_ok = if mobile {
        p.max_touch_points >= 1
    } else {
        p.max_touch_points == 0
            || (matches!(p.os, OsKind::Windows10 | OsKind::Windows11) && p.max_touch_points == 10)
    };
    out.push(r(
        "C016",
        touch_ok,
        "Touch points fit device",
        format!("maxTouchPoints {}", p.max_touch_points),
    ));
    out.push(r(
        "C017",
        p.ua_ch.mobile == mobile && p.user_agent.contains(" Mobile ") == mobile,
        "Mobile flag consistent",
        "UA-CH mobile / UA Mobile token mismatch".into(),
    ));

    out.push(match &p.geo {
        None => RuleResult {
            id: "C018",
            level: Level::Note,
            message: "no exit-IP location yet; timezone not verified".into(),
        },
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
            None => RuleResult {
                id: "C018",
                level: Level::Note,
                message: format!("country {} not in table; timezone not verified", g.country),
            },
        },
    });
    out.push(r(
        "C019",
        !p.locale.is_empty() && p.languages.first() == Some(&p.locale),
        "Locale = first language",
        "languages[0] must equal locale".into(),
    ));
    let al = p.accept_language();
    let al_ok = al.split(',').next().map(|x| x == p.locale).unwrap_or(false)
        && al.split(',').count() == p.languages.len();
    out.push(r(
        "C020",
        al_ok,
        "Accept-Language matches navigator.languages",
        format!("Accept-Language '{al}' inconsistent"),
    ));

    let c021 = match (p.os, win_platform_major(p)) {
        (OsKind::Windows11, Some(m)) => m >= 13,
        (OsKind::Windows10, Some(m)) => (1..=10).contains(&m),
        (OsKind::Windows10 | OsKind::Windows11, None) => false,
        _ => true,
    };
    out.push(r(
        "C021",
        c021,
        "UA-CH platformVersion fits Windows release",
        format!(
            "platformVersion {} wrong for {:?}",
            p.ua_ch.platform_version, p.os
        ),
    ));
    let arch_ok = if mobile {
        p.ua_ch.architecture.is_empty() || p.ua_ch.architecture == "arm"
    } else {
        ["x86", "arm"].contains(&p.ua_ch.architecture.as_str()) && p.ua_ch.bitness == "64"
    };
    out.push(r(
        "C022",
        arch_ok,
        "Architecture / bitness valid",
        format!(
            "architecture '{}' bitness '{}'",
            p.ua_ch.architecture, p.ua_ch.bitness
        ),
    ));
    out.push(r(
        "C023",
        mobile != p.ua_ch.model.is_empty(),
        "Device model present only on mobile",
        "UA-CH model must be set on Android and empty on desktop".into(),
    ));
    let ff_ok = if mobile {
        p.ua_ch
            .form_factors
            .iter()
            .any(|f| f == "Mobile" || f == "Tablet")
    } else {
        p.ua_ch.form_factors == ["Desktop"]
    };
    out.push(r(
        "C024",
        ff_ok,
        "Form factor consistent",
        format!("form factors {:?}", p.ua_ch.form_factors),
    ));
    let m = p.media_devices;
    let media_ok = m.audioinput <= 4
        && m.audiooutput <= 6
        && m.videoinput <= 4
        && (!mobile || m.videoinput >= 1);
    out.push(r(
        "C025",
        media_ok,
        "Media device counts plausible",
        format!("media devices {m:?}"),
    ));
    out.push(r(
        "C026",
        p.webrtc_policy == "disable_non_proxied_udp",
        "WebRTC uses the proxy only",
        format!("WebRTC policy '{}' can leak the real IP", p.webrtc_policy),
    ));
    out.push(RuleResult {
        id: "C027",
        level: Level::Note,
        message: "rarity is measured against the device DB (shown in Linkability Radar)".into(),
    });
    let seeds_ok = (p.canvas != SurfaceMode::Noise || p.canvas_seed != 0)
        && (p.audio != SurfaceMode::Noise || p.audio_seed != 0);
    out.push(r(
        "C028",
        seeds_ok,
        "Noise surfaces have stable seeds",
        "noise mode without a seed would change on every read".into(),
    ));
    out.push(r(
        "C029",
        p.os != OsKind::MacOs || p.user_agent.contains("Intel Mac OS X 10_15_7"),
        "macOS UA uses the frozen 10_15_7 token",
        "macOS UA must use the frozen Intel Mac OS X 10_15_7 token".into(),
    ));
    out.push(r(
        "C030",
        p.os != OsKind::Android || p.user_agent.contains("Android 10; K"),
        "Android UA is the reduced form",
        "Android UA must be the reduced 'Android 10; K' form".into(),
    ));

    let major_ok = p
        .user_agent
        .contains(&format!("Chrome/{}.0.0.0", installed_engine.major));
    let full_ok = p
        .ua_ch
        .full_version_list
        .iter()
        .any(|(b, v)| b == "Chromium" && *v == installed_engine.to_string());
    out.push(r(
        "C031",
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
    fn version_mismatch_fails_c031() {
        let p = win();
        let ids: Vec<_> = failures(&check(&p, EngineVersion::new(156, 0, 8078, 82)))
            .iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(ids, ["C031"]);
        let mut q = win();
        q.age_to(EngineVersion::new(158, 0, 8127, 18));
        assert!(
            fails(&q).contains(&"C031"),
            "persona newer than engine must fail"
        );
    }

    #[test]
    fn mac_gpu_on_windows_fails() {
        let mut p = win();
        p.gpu.renderer =
            "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)".into();
        let f = fails(&p);
        assert!(f.contains(&"C004") && f.contains(&"C006"));
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
        assert_eq!(fails(&p), ["C026"]);
    }

    #[test]
    fn rule_ids_unique_and_complete() {
        let res = check(&win(), V);
        let mut ids: Vec<_> = res.iter().map(|r| r.id).collect();
        ids.dedup();
        assert_eq!(ids.len(), 31);
        assert_eq!(ids.first(), Some(&"C001"));
        assert_eq!(ids.last(), Some(&"C031"));
    }
}
