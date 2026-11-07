//! The 56 health checks (H01–H56) in the prototype's 8 areas. Each check is a pure
//! function of [`HealthInput`]; nothing here touches the network or the clock.

use crate::input::{AsnKind, HealthInput};
use crate::probe::{ProbeReport, RealmValues, FOREIGN_FONTS};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use vanta_fingerprint::rules::{self, timezones_for, Level};
use vanta_fingerprint::SurfaceMode;
use vanta_types::OsKind;

/// The 8 areas of the Health Check screen (design/prototype `HC`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Area {
    NetworkIp,
    TlsHttp2Quic,
    WebRtcDns,
    NavigatorUaCh,
    Graphics,
    AudioMedia,
    FontsLayout,
    Automation,
}

impl Area {
    pub const ALL: [Area; 8] = [
        Area::NetworkIp,
        Area::TlsHttp2Quic,
        Area::WebRtcDns,
        Area::NavigatorUaCh,
        Area::Graphics,
        Area::AudioMedia,
        Area::FontsLayout,
        Area::Automation,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Area::NetworkIp => "Network & IP",
            Area::TlsHttp2Quic => "TLS / HTTP2 / QUIC",
            Area::WebRtcDns => "WebRTC & DNS",
            Area::NavigatorUaCh => "Navigator & UA-CH",
            Area::Graphics => "Graphics (Canvas/WebGL/WebGPU)",
            Area::AudioMedia => "Audio & media",
            Area::FontsLayout => "Fonts & layout",
            Area::Automation => "Automation flags",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// A Fail caps the score at 40 (launch blocked).
    Critical,
    Warn,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Pass,
    Warn,
    Fail,
}

/// Definition of one check.
pub struct CheckDef {
    /// `H01`–`H56`.
    pub id: &'static str,
    /// Prototype key, e.g. `net.exit`.
    pub key: &'static str,
    pub area: Area,
    pub severity: Severity,
    pub title: &'static str,
    pub run: fn(&HealthInput) -> (Outcome, String),
}

/// Result of one check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    pub id: &'static str,
    pub key: &'static str,
    pub area: Area,
    pub severity: Severity,
    pub title: &'static str,
    pub outcome: Outcome,
    pub message: String,
}

type R = (Outcome, String);

fn pass(m: impl Into<String>) -> R {
    (Outcome::Pass, m.into())
}
fn warn(m: impl Into<String>) -> R {
    (Outcome::Warn, m.into())
}
fn fail(m: impl Into<String>) -> R {
    (Outcome::Fail, m.into())
}
fn ok_or(ok: bool, p: &str, f: String) -> R {
    if ok {
        pass(p)
    } else {
        fail(f)
    }
}

const NO_PROBE: &str = "The probe page did not report back, so this could not be checked.";

macro_rules! probe {
    ($i:expr) => {
        match $i.probe.as_ref() {
            Some(p) => p,
            None => return fail(NO_PROBE),
        }
    };
}

/// Parsed ICE candidate: (address, type).
fn candidates(p: &ProbeReport) -> Vec<(String, String)> {
    p.rtc
        .candidates
        .iter()
        .filter_map(|c| {
            let f: Vec<&str> = c.trim_start_matches("a=").split_whitespace().collect();
            let t = f.iter().position(|x| *x == "typ")?;
            Some((f.get(4)?.to_string(), f.get(t + 1)?.to_string()))
        })
        .collect()
}

fn same_strs(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x == y)
}

// ---------------------------------------------------------------- Network & IP

fn net_exit(i: &HealthInput) -> R {
    match i.exit.ip {
        None => fail("No exit IP was measured through the relay."),
        Some(ip) if i.guard.host_ips.contains(&ip) => {
            fail("The exit IP is this PC's own address: traffic is not going through the proxy.")
        }
        Some(_) => pass("Requests leave through the proxy exit IP, not your connection."),
    }
}

fn net_direct(i: &HealthInput) -> R {
    let g = &i.guard;
    if !g.engine_uses_relay {
        return fail("The engine is not pointed at this profile's relay.");
    }
    ok_or(
        g.relay_armed,
        "Kill switch armed; nothing leaves except through the local relay.",
        "The relay's kill switch is tripped or the relay is not running.".into(),
    )
}

fn net_asn(i: &HealthInput) -> R {
    match i.exit.asn_kind {
        Some(AsnKind::Residential | AsnKind::Isp | AsnKind::Mobile) => {
            pass("Exit ASN is a residential / ISP network.")
        }
        Some(AsnKind::Hosting) => {
            warn("Exit ASN belongs to a hosting network. Fine for QA, risky for accounts.")
        }
        _ => warn("Exit ASN type is unknown."),
    }
}

fn net_black(i: &HealthInput) -> R {
    match i.exit.blacklisted {
        Some(false) => pass("Exit IP is not on the bundled blacklists."),
        Some(true) => fail("Exit IP is on a bundled blacklist."),
        None => warn("Blacklist status was not checked."),
    }
}

fn net_geo(i: &HealthInput) -> R {
    let p = probe!(i);
    let Some(country) = i.exit.country.as_deref() else {
        return warn("Exit country unknown; timezone could not be compared.");
    };
    if let Some(geo) = &i.expected.geo {
        if !geo.country.eq_ignore_ascii_case(country) {
            return fail(format!(
                "Profile location is {} but the exit IP is in {country}. Run Geo Auto-Match.",
                geo.country
            ));
        }
        if p.timezone != geo.timezone {
            return fail(format!(
                "Page timezone {} differs from the profile's {}.",
                p.timezone, geo.timezone
            ));
        }
    }
    match timezones_for(country) {
        Some(zones) if zones.contains(&p.timezone.as_str()) => pass(format!(
            "Timezone {} matches exit country {country}.",
            p.timezone
        )),
        Some(_) => fail(format!(
            "Timezone {} does not match exit country {country}. Run Geo Auto-Match.",
            p.timezone
        )),
        None => warn(format!("No timezone table for {country}; not verified.")),
    }
}

fn net_reach(i: &HealthInput) -> R {
    ok_or(
        i.guard.proxy_reachable,
        "Proxy answered at launch.",
        "Proxy did not answer; launch stays blocked until it is back or replaced.".into(),
    )
}

fn net_sticky(i: &HealthInput) -> R {
    let s = &i.exit.sticky_samples;
    if s.len() < 2 {
        return warn("Sticky session not tested.");
    }
    if s.iter().all(|x| *x == s[0]) {
        pass("Repeated requests kept the same exit IP.")
    } else {
        warn("The exit IP changed between requests; the session is not sticky.")
    }
}

fn net_ipv6(i: &HealthInput) -> R {
    if !i.guard.ipv6_blocked {
        return fail("IPv6 is not blocked; an IPv6 route could skip the IPv4-only proxy.");
    }
    if let Some(p) = &i.probe {
        if candidates(p)
            .iter()
            .any(|(a, _)| a.parse::<IpAddr>().map(|ip| ip.is_ipv6()).unwrap_or(false))
        {
            return fail("The page saw an IPv6 address in WebRTC candidates.");
        }
    }
    pass("IPv6 path blocked.")
}

fn net_hdr(i: &HealthInput) -> R {
    const BAD: [&str; 6] = [
        "via",
        "x-forwarded-for",
        "forwarded",
        "x-real-ip",
        "proxy-connection",
        "x-proxy-id",
    ];
    let mut found: Vec<String> = i.exit.revealing_headers.clone();
    if let Some(h) = &i.http1 {
        found.extend(h.names().into_iter().filter(|n| BAD.contains(&n.as_str())));
    }
    if found.is_empty() {
        pass("No proxy-revealing headers.")
    } else {
        fail(format!(
            "Proxy-revealing headers seen: {}.",
            found.join(", ")
        ))
    }
}

fn net_lan(i: &HealthInput) -> R {
    ok_or(
        i.guard.lan_blocked,
        "Pages cannot reach the local network.",
        "LAN access is allowed for this profile.".into(),
    )
}

// ---------------------------------------------------------- TLS / HTTP2 / QUIC

fn tls_ja4(i: &HealthInput) -> R {
    let Some(t) = &i.tls else {
        return fail("No TLS ClientHello was captured.");
    };
    let r = &i.reference;
    if t.ja4 == r.ja4 {
        return pass(format!("JA4 {} = Chrome reference.", t.ja4));
    }
    if r.ja4_variants.contains(&t.ja4) {
        return warn(format!(
            "JA4 {} is a Chromium variant, not the Chrome reference {}.",
            t.ja4, r.ja4
        ));
    }
    let cipher = |s: &str| s.split('_').nth(1).map(str::to_string);
    if cipher(&t.ja4) == cipher(&r.ja4) && t.ja4.get(..4) == r.ja4.get(..4) {
        warn(format!(
            "JA4 {} has Chrome's cipher list but a different extension set (reference {}).",
            t.ja4, r.ja4
        ))
    } else {
        fail(format!(
            "JA4 {} is not Chrome's ({}): the TLS stack is not Chrome's.",
            t.ja4, r.ja4
        ))
    }
}

fn tls_alpn(i: &HealthInput) -> R {
    let Some(t) = &i.tls else {
        return fail("No TLS ClientHello was captured.");
    };
    ok_or(
        same_strs(&t.alpn, &i.reference.alpn),
        "ALPN offers h2, http/1.1 like Chrome.",
        format!(
            "ALPN offered {:?}, Chrome offers {:?}.",
            t.alpn, i.reference.alpn
        ),
    )
}

fn tls_h2set(i: &HealthInput) -> R {
    let Some(h) = &i.h2 else {
        return fail("No HTTP/2 connection was captured.");
    };
    let r = &i.reference;
    if h.settings != r.h2_settings {
        return fail(format!(
            "HTTP/2 SETTINGS {:?} differ from Chrome {:?}.",
            h.settings, r.h2_settings
        ));
    }
    ok_or(
        h.window_update == Some(r.h2_window_update),
        "HTTP/2 SETTINGS and WINDOW_UPDATE = Chrome.",
        format!(
            "WINDOW_UPDATE {:?} differs from Chrome {}.",
            h.window_update, r.h2_window_update
        ),
    )
}

fn tls_pseudo(i: &HealthInput) -> R {
    let Some(h) = &i.h2 else {
        return fail("No HTTP/2 connection was captured.");
    };
    ok_or(
        same_strs(&h.pseudo_order, &i.reference.pseudo_order),
        ":method :authority :scheme :path, like Chrome.",
        format!("Pseudo-header order {:?}.", h.pseudo_order),
    )
}

fn tls_hdr(i: &HealthInput) -> R {
    let Some(h) = &i.http1 else {
        return fail("No HTTP/1.1 navigation was captured.");
    };
    let n = h.names();
    let pos = |k: &str| n.iter().position(|x| x == k);
    if pos("host") != Some(0) {
        return fail("Host is not the first header.");
    }
    let order = [
        ("sec-ch-ua", "user-agent"),
        ("user-agent", "accept"),
        ("accept", "accept-encoding"),
        ("accept-encoding", "accept-language"),
    ];
    for (a, b) in order {
        match (pos(a), pos(b)) {
            (Some(x), Some(y)) if x < y => {}
            (None, _) | (_, None) => return fail(format!("Header {a} or {b} is missing.")),
            _ => return fail(format!("{a} comes after {b}; Chrome sends it first.")),
        }
    }
    pass("Request header order = Chrome.")
}

fn tls_quic(i: &HealthInput) -> R {
    let g = &i.guard;
    if g.proxy_udp || g.quic_disabled {
        pass(if g.proxy_udp {
            "Proxy carries UDP; QUIC may run through it."
        } else {
            "Proxy has no UDP: QUIC is off and Chrome uses TCP."
        })
    } else {
        fail("QUIC is enabled but the proxy has no UDP: QUIC would bypass or fail.")
    }
}

// --------------------------------------------------------------- WebRTC & DNS

fn rtc_pub(i: &HealthInput) -> R {
    let p = probe!(i);
    if !p.rtc.available {
        return warn("RTCPeerConnection is missing; sites can tell WebRTC is disabled.");
    }
    for (addr, ty) in candidates(p) {
        let Ok(ip) = addr.parse::<IpAddr>() else {
            continue;
        };
        if i.guard.host_ips.contains(&ip) {
            return fail(format!(
                "WebRTC exposes this PC's address in a {ty} candidate."
            ));
        }
        if (ty == "srflx" || ty == "prflx") && Some(ip) != i.exit.ip && !ip.is_loopback() {
            return fail(format!(
                "WebRTC public candidate {ip} is not the proxy exit IP."
            ));
        }
    }
    pass("WebRTC shows no address other than the proxy exit.")
}

fn rtc_host(i: &HealthInput) -> R {
    let p = probe!(i);
    let raw: Vec<String> = candidates(p)
        .into_iter()
        .filter(|(a, t)| t == "host" && a.parse::<IpAddr>().is_ok())
        .map(|(a, _)| a)
        .collect();
    ok_or(
        raw.is_empty(),
        "No local IP is exposed in host candidates.",
        format!("Host candidates expose local IPs: {}.", raw.join(", ")),
    )
}

fn rtc_mdns(i: &HealthInput) -> R {
    let p = probe!(i);
    let hosts: Vec<(String, String)> = candidates(p)
        .into_iter()
        .filter(|(_, t)| t == "host")
        .collect();
    if hosts.is_empty() {
        return pass("No host candidates are gathered (proxy-only WebRTC).");
    }
    ok_or(
        hosts.iter().all(|(a, _)| a.ends_with(".local")),
        "Host candidates use .local mDNS names like Chrome.",
        "Some host candidates are raw addresses instead of mDNS names.".into(),
    )
}

fn dns_doh(i: &HealthInput) -> R {
    ok_or(
        i.guard.doh_through_proxy,
        "The relay resolves names over DoH through the proxy.",
        "The relay does not use DoH through the proxy.".into(),
    )
}

fn dns_leak(i: &HealthInput) -> R {
    match &i.dns {
        None => fail("The DNS leak test did not run."),
        Some(d) if d.all_via_doh() => pass(format!(
            "All {} unique test names were resolved through DoH.",
            d.expected
        )),
        Some(d) if d.expected == 0 => fail("The DNS leak test had no names."),
        Some(d) => fail(format!(
            "{} of {} unique test names never reached DoH: DNS leaks.",
            d.missing.len(),
            d.expected
        )),
    }
}

fn rtc_stun(i: &HealthInput) -> R {
    if i.guard.proxy_udp {
        return pass("Proxy supports UDP ASSOCIATE; STUN may use it.");
    }
    let n = i.stun.len();
    ok_or(
        n == 0,
        "No raw UDP STUN request left the browser.",
        format!("{n} STUN request(s) went out as raw UDP, outside the proxy."),
    )
}

// ---------------------------------------------------------- Navigator & UA-CH

fn nav_ua(i: &HealthInput) -> R {
    let p = probe!(i);
    let want = &i.expected.user_agent;
    if &p.ua != want {
        return fail(format!(
            "navigator.userAgent is '{}', expected '{want}'.",
            p.ua
        ));
    }
    if let Some(h) = i.http1.as_ref().and_then(|h| h.header("user-agent")) {
        if h != want {
            return fail(format!("User-Agent header '{h}' differs from navigator."));
        }
    }
    pass(format!(
        "User-Agent = engine {}.",
        i.expected.engine.reduced()
    ))
}

fn nav_brands(i: &HealthInput) -> R {
    let p = probe!(i);
    let Some(u) = &p.ua_data else {
        return fail("navigator.userAgentData is missing.");
    };
    let got: Vec<(String, String)> = u
        .brands
        .iter()
        .map(|b| (b.brand.clone(), b.version.clone()))
        .collect();
    if got != i.expected.ua_ch.brands {
        return fail(format!("Brands {got:?} differ from the expected list."));
    }
    let full: Vec<(String, String)> = u
        .full_version_list
        .iter()
        .map(|b| (b.brand.clone(), b.version.clone()))
        .collect();
    if !full.is_empty() && full != i.expected.ua_ch.full_version_list {
        return fail("fullVersionList differs from the engine version.".to_string());
    }
    if let Some(h) = i.http1.as_ref().and_then(|h| h.header("sec-ch-ua")) {
        if h != i.expected.sec_ch_ua() {
            return fail(format!(
                "Sec-CH-UA header '{h}' differs from the brand list."
            ));
        }
    }
    pass("Brand list, GREASE brand and versions match the engine.")
}

fn nav_pv(i: &HealthInput) -> R {
    let p = probe!(i);
    let Some(u) = &p.ua_data else {
        return fail("navigator.userAgentData is missing.");
    };
    let e = &i.expected.ua_ch;
    if u.platform != e.platform {
        return fail(format!(
            "UA-CH platform '{}', expected '{}'.",
            u.platform, e.platform
        ));
    }
    match &u.platform_version {
        Some(v) if v == &e.platform_version => {
            pass(format!("platform {} {} matches the OS.", u.platform, v))
        }
        Some(v) => fail(format!(
            "platformVersion {v}, expected {} for {:?}.",
            e.platform_version, i.expected.os
        )),
        None => fail("platformVersion was not reported."),
    }
}

fn nav_platform(i: &HealthInput) -> R {
    let p = probe!(i);
    ok_or(
        p.platform == "Win32" && p.platform == i.expected.platform,
        "navigator.platform = Win32.",
        format!("navigator.platform is '{}'.", p.platform),
    )
}

fn nav_cores(i: &HealthInput) -> R {
    let p = probe!(i);
    ok_or(
        p.hardware_concurrency == i.expected.hardware_concurrency,
        "hardwareConcurrency matches the device record.",
        format!(
            "hardwareConcurrency {} vs {} in the record.",
            p.hardware_concurrency, i.expected.hardware_concurrency
        ),
    )
}

fn nav_mem(i: &HealthInput) -> R {
    let p = probe!(i);
    match p.device_memory {
        Some(m) if m > 8.0 => fail(format!("deviceMemory {m} is above Chrome's cap of 8.")),
        Some(m) if (m - i.expected.device_memory).abs() < f64::EPSILON => {
            pass(format!("deviceMemory {m} (≤ 8)."))
        }
        Some(m) => fail(format!(
            "deviceMemory {m} vs {} in the record.",
            i.expected.device_memory
        )),
        None => fail("navigator.deviceMemory is missing."),
    }
}

fn nav_lang(i: &HealthInput) -> R {
    let p = probe!(i);
    if !same_strs(&p.languages, &i.expected.languages) {
        return fail(format!(
            "navigator.languages {:?}, expected {:?}.",
            p.languages, i.expected.languages
        ));
    }
    if let Some(h) = i.http1.as_ref().and_then(|h| h.header("accept-language")) {
        if h != i.expected.accept_language() {
            return fail(format!(
                "Accept-Language '{h}' does not match navigator.languages."
            ));
        }
    }
    pass("navigator.languages = Accept-Language.")
}

fn realm_diff(page: &ProbeReport, r: &RealmValues) -> Option<&'static str> {
    if r.ua != page.ua {
        Some("userAgent")
    } else if r.platform != page.platform {
        Some("platform")
    } else if r.languages != page.languages {
        Some("languages")
    } else if r.hardware_concurrency != page.hardware_concurrency {
        Some("hardwareConcurrency")
    } else if r.device_memory != page.device_memory {
        Some("deviceMemory")
    } else if r.timezone != page.timezone {
        Some("timezone")
    } else if r.webdriver.unwrap_or(false) != page.webdriver.unwrap_or(false) {
        Some("webdriver")
    } else {
        None
    }
}

fn nav_worker(i: &HealthInput) -> R {
    let p = probe!(i);
    let Some(w) = &p.worker else {
        return fail("The Web Worker did not report.");
    };
    match realm_diff(p, w) {
        None => pass("The worker sees the same navigator as the page."),
        Some(f) => fail(format!("Worker {f} differs from the page.")),
    }
}

fn nav_iframe(i: &HealthInput) -> R {
    let p = probe!(i);
    let Some(w) = &p.iframe else {
        return fail("The iframe did not report.");
    };
    match realm_diff(p, w) {
        None => pass("The iframe sees the same navigator as the page."),
        Some(f) => fail(format!("iframe {f} differs from the page.")),
    }
}

// ------------------------------------------------------------------- Graphics

/// "Google Inc. (NVIDIA)" -> "nvidia"; "ANGLE (NVIDIA, ..." -> "nvidia".
fn gpu_maker(s: &str) -> Option<String> {
    let inner = s.split_once('(')?.1;
    let end = inner.find([',', ')'])?;
    Some(inner[..end].trim().to_ascii_lowercase())
}

fn gfx_pair(i: &HealthInput) -> R {
    let p = probe!(i);
    let Some(g) = &p.webgl else {
        return fail("WebGL is unavailable.");
    };
    if gpu_maker(&g.vendor).is_none() || gpu_maker(&g.vendor) != gpu_maker(&g.renderer) {
        return fail(format!(
            "WebGL vendor '{}' and renderer name different makers.",
            g.vendor
        ));
    }
    ok_or(
        g.vendor == i.expected.gpu.vendor && g.renderer == i.expected.gpu.renderer,
        "WebGL vendor and renderer match the device record.",
        format!("WebGL renderer '{}' is not the record's GPU.", g.renderer),
    )
}

fn gfx_d3d(i: &HealthInput) -> R {
    let p = probe!(i);
    let Some(g) = &p.webgl else {
        return fail("WebGL is unavailable.");
    };
    let r = g.renderer.to_ascii_lowercase();
    if ["swiftshader", "llvmpipe", "basic render", "software"]
        .iter()
        .any(|s| r.contains(s))
    {
        return fail("Software renderer: looks like a VM or headless browser.");
    }
    ok_or(
        r.starts_with("angle (") && r.contains("direct3d"),
        "Renderer is a Windows ANGLE Direct3D string.",
        format!("Renderer '{}' is not ANGLE Direct3D.", g.renderer),
    )
}

fn gfx_params(i: &HealthInput) -> R {
    let p = probe!(i);
    let Some(g) = &p.webgl else {
        return fail("WebGL is unavailable.");
    };
    ok_or(
        g.max_texture_size == 16384,
        "MAX_TEXTURE_SIZE 16384, as on Direct3D 11 hardware.",
        format!(
            "MAX_TEXTURE_SIZE {} is unusual for D3D11.",
            g.max_texture_size
        ),
    )
}

/// Extensions every Chrome-on-D3D11 WebGL1 context exposes.
const WEBGL_BASELINE: [&str; 8] = [
    "ANGLE_instanced_arrays",
    "EXT_blend_minmax",
    "EXT_texture_filter_anisotropic",
    "OES_standard_derivatives",
    "OES_texture_float",
    "WEBGL_compressed_texture_s3tc",
    "WEBGL_debug_renderer_info",
    "WEBGL_lose_context",
];

fn gfx_ext(i: &HealthInput) -> R {
    let p = probe!(i);
    let Some(g) = &p.webgl else {
        return fail("WebGL is unavailable.");
    };
    let missing: Vec<&str> = WEBGL_BASELINE
        .iter()
        .copied()
        .filter(|e| !g.extensions.iter().any(|x| x == e))
        .collect();
    if !missing.is_empty() {
        return warn(format!("WebGL extensions missing: {}.", missing.join(", ")));
    }
    ok_or(
        (20..=45).contains(&g.extensions.len()),
        "WebGL extension list looks like real Windows hardware.",
        format!("{} WebGL extensions is unusual.", g.extensions.len()),
    )
}

fn stable(reads: &[String]) -> bool {
    reads.len() >= 2 && reads.iter().all(|r| !r.is_empty() && *r == reads[0])
}

fn gfx_canvas(i: &HealthInput) -> R {
    let p = probe!(i);
    if i.expected.canvas == SurfaceMode::Block {
        return ok_or(
            p.canvas.iter().all(|c| c.is_empty()),
            "Canvas is blocked as configured.",
            "Canvas returned data although it is set to Block.".into(),
        );
    }
    ok_or(
        stable(&p.canvas),
        "Canvas render identical across 3 reads.",
        "Canvas reads differ: per-read noise is detectable.".into(),
    )
}

fn gfx_webgpu(i: &HealthInput) -> R {
    let p = probe!(i);
    let Some(w) = &p.webgpu else {
        return warn("WebGPU adapter unavailable (Chrome on Windows normally has one).");
    };
    let e = &i.expected.gpu;
    ok_or(
        w.vendor == e.webgpu_vendor && w.architecture == e.webgpu_arch,
        "WebGPU adapter info agrees with WebGL.",
        format!(
            "WebGPU {}/{} vs expected {}/{}.",
            w.vendor, w.architecture, e.webgpu_vendor, e.webgpu_arch
        ),
    )
}

fn gfx_screen(i: &HealthInput) -> R {
    let p = probe!(i);
    let (s, e) = (&p.screen, &i.expected.screen);
    ok_or(
        s.width == e.width
            && s.height == e.height
            && s.avail_width == e.avail_width
            && s.avail_height == e.avail_height
            && s.color_depth == e.color_depth,
        "Screen and available size match the record.",
        format!(
            "Screen {}x{} (avail {}x{}) vs record {}x{} (avail {}x{}).",
            s.width,
            s.height,
            s.avail_width,
            s.avail_height,
            e.width,
            e.height,
            e.avail_width,
            e.avail_height
        ),
    )
}

fn gfx_dpr(i: &HealthInput) -> R {
    let p = probe!(i);
    ok_or(
        (p.device_pixel_ratio - i.expected.device_pixel_ratio).abs() < 1e-6,
        "devicePixelRatio matches the screen.",
        format!(
            "devicePixelRatio {} vs {}.",
            p.device_pixel_ratio, i.expected.device_pixel_ratio
        ),
    )
}

// --------------------------------------------------------------- Audio & media

fn aud_ctx(i: &HealthInput) -> R {
    let p = probe!(i);
    if i.expected.audio == SurfaceMode::Block {
        return ok_or(
            p.audio.is_empty(),
            "Audio is blocked as configured.",
            "Audio returned data although it is set to Block.".into(),
        );
    }
    ok_or(
        stable(&p.audio),
        "AudioContext output identical across reads.",
        "AudioContext output differs between reads.".into(),
    )
}

fn aud_dev(i: &HealthInput) -> R {
    let p = probe!(i);
    let Some(m) = p.media else {
        return fail("enumerateDevices is unavailable.");
    };
    let e = i.expected.media_devices;
    // Without a media permission Chrome lists at most one device per kind.
    let ok = |got: u32, want: u32| got == want || got == want.min(1);
    ok_or(
        ok(m.audioinput, e.audioinput)
            && ok(m.audiooutput, e.audiooutput)
            && ok(m.videoinput, e.videoinput),
        "Media device counts match the record.",
        format!(
            "Media devices {}/{}/{} (mic/speaker/cam) vs {}/{}/{}.",
            m.audioinput, m.audiooutput, m.videoinput, e.audioinput, e.audiooutput, e.videoinput
        ),
    )
}

fn aud_voices(i: &HealthInput) -> R {
    let p = probe!(i);
    if p.voices.is_empty() {
        return warn("No speech voices; a Windows PC lists Microsoft voices.");
    }
    const FOREIGN: [&str; 6] = ["Samantha", "Alex", "Daniel", "Karen", "espeak", "Fred"];
    if let Some(v) = p.voices.iter().find(|v| {
        FOREIGN
            .iter()
            .any(|f| v.split_whitespace().next() == Some(f))
    }) {
        return fail(format!("Voice '{v}' comes from another OS."));
    }
    ok_or(
        p.voices.iter().any(|v| v.starts_with("Microsoft ")),
        "Microsoft voices present, as on Windows.",
        "No Microsoft voice: not a Windows voice list.".into(),
    )
}

/// canPlayType answers of Chrome on Windows (proprietary codecs on).
const CODECS: [(&str, &str); 6] = [
    ("video/mp4; codecs=\"avc1.42E01E\"", "probably"),
    ("video/webm; codecs=\"vp9\"", "probably"),
    ("video/webm; codecs=\"vp8\"", "probably"),
    ("audio/mpeg", "probably"),
    ("audio/mp4; codecs=\"mp4a.40.2\"", "probably"),
    ("audio/ogg; codecs=\"opus\"", "probably"),
];

fn aud_codec(i: &HealthInput) -> R {
    let p = probe!(i);
    let bad: Vec<&str> = CODECS
        .iter()
        .filter(|(t, want)| p.codecs.get(*t).map(String::as_str) != Some(*want))
        .map(|(t, _)| *t)
        .collect();
    ok_or(
        bad.is_empty(),
        "Codec support = Chrome on Windows.",
        format!("Codec answers differ for: {}.", bad.join("; ")),
    )
}

// -------------------------------------------------------------- Fonts & layout

const WIN11_ONLY_FONTS: [&str; 2] = ["Segoe UI Variable", "Segoe Fluent Icons"];

/// Fonts the page should test for this persona: its own list, Windows 11-only fonts and
/// fonts of other operating systems.
pub fn fonts_to_test(i: &HealthInput) -> Vec<String> {
    let mut v = i.expected.fonts.clone();
    for f in WIN11_ONLY_FONTS.iter().chain(FOREIGN_FONTS) {
        if !v.iter().any(|x| x == f) {
            v.push(f.to_string());
        }
    }
    v
}

fn fnt_list(i: &HealthInput) -> R {
    let p = probe!(i);
    if p.fonts_tested.is_empty() {
        return fail("No fonts were tested.");
    }
    let tested = |f: &String| p.fonts_tested.contains(f);
    let missing: Vec<&String> = i
        .expected
        .fonts
        .iter()
        .filter(|f| tested(f) && !p.fonts.contains(f))
        .collect();
    let extra: Vec<&String> = p
        .fonts
        .iter()
        .filter(|f| !i.expected.fonts.contains(f))
        .collect();
    if !missing.is_empty() {
        return fail(format!(
            "{} record fonts not available (e.g. {}).",
            missing.len(),
            missing[0]
        ));
    }
    ok_or(
        extra.is_empty(),
        "Font list is exactly the record's Windows set.",
        format!("Fonts outside the record: {}.", extra.len()),
    )
}

fn fnt_os(i: &HealthInput) -> R {
    let p = probe!(i);
    if let Some(r) = rules::check(&i.expected, i.expected.engine)
        .into_iter()
        .find(|r| r.id == "C013" && r.level == Level::Fail)
    {
        return fail(r.message);
    }
    if let Some(f) = p.fonts.iter().find(|f| FOREIGN_FONTS.contains(&f.as_str())) {
        return fail(format!("Font '{f}' belongs to another OS."));
    }
    if i.expected.os == OsKind::Windows10 {
        if let Some(f) = p
            .fonts
            .iter()
            .find(|f| WIN11_ONLY_FONTS.contains(&f.as_str()))
        {
            return fail(format!("Windows 11-only font '{f}' on Windows 10."));
        }
    }
    pass("Fonts match the Windows version.")
}

fn fnt_rects(i: &HealthInput) -> R {
    let p = probe!(i);
    ok_or(
        stable(&p.rects),
        "ClientRects identical on every read.",
        "ClientRects differ between reads.".into(),
    )
}

fn fnt_emoji(i: &HealthInput) -> R {
    let p = probe!(i);
    ok_or(
        p.fonts.iter().any(|f| f == "Segoe UI Emoji"),
        "Segoe UI Emoji present, as on Windows.",
        "Segoe UI Emoji not found.".into(),
    )
}

fn fnt_metrics(i: &HealthInput) -> R {
    let p = probe!(i);
    let w = p.worker.as_ref().and_then(|w| w.text_metrics.as_ref());
    match (p.text_metrics.as_ref(), w) {
        (Some(a), Some(b)) if a == b => pass("Text metrics agree between page and worker."),
        (Some(_), Some(_)) => fail("Text metrics differ between page and worker."),
        _ => fail("Text metrics were not measured in both realms."),
    }
}

// ------------------------------------------------------------ Automation flags

fn aut_webdriver(i: &HealthInput) -> R {
    let p = probe!(i);
    ok_or(
        p.webdriver == Some(false),
        "navigator.webdriver is false.",
        format!("navigator.webdriver is {:?}.", p.webdriver),
    )
}

fn aut_cdp(i: &HealthInput) -> R {
    let p = probe!(i);
    ok_or(
        !p.cdp_trace,
        "No DevTools protocol traces.",
        "A DevTools protocol client is attached (console serialisation observed).".into(),
    )
}

fn aut_headless(i: &HealthInput) -> R {
    let p = probe!(i);
    if p.ua.contains("Headless") {
        return fail("HeadlessChrome token in the User-Agent.");
    }
    ok_or(
        p.window.outer_width > 0 && p.window.outer_height > 0,
        "Normal window metrics.",
        "outerWidth/outerHeight are 0, as in headless mode.".into(),
    )
}

fn aut_chrome(i: &HealthInput) -> R {
    let p = probe!(i);
    ok_or(
        p.chrome_object,
        "window.chrome is present.",
        "window.chrome is missing.".into(),
    )
}

fn aut_perm(i: &HealthInput) -> R {
    let p = probe!(i);
    let want = match p.notification_permission.as_str() {
        "default" => "prompt",
        "granted" => "granted",
        "denied" => "denied",
        _ => return fail("Notification.permission is missing."),
    };
    ok_or(
        p.permission_query == want,
        "Notification.permission and permissions.query agree.",
        format!(
            "Notification.permission '{}' but permissions.query says '{}'.",
            p.notification_permission, p.permission_query
        ),
    )
}

fn aut_plugins(i: &HealthInput) -> R {
    let p = probe!(i);
    ok_or(
        p.plugins == 5 && p.mime_types == 2,
        "Five PDF plugins and two MIME types, like current Chrome.",
        format!("{} plugins / {} MIME types.", p.plugins, p.mime_types),
    )
}

fn aut_ext(i: &HealthInput) -> R {
    let p = probe!(i);
    ok_or(
        p.automation_globals.is_empty(),
        "No automation globals or extensions.",
        format!("Automation globals: {}.", p.automation_globals.join(", ")),
    )
}

fn aut_notif(i: &HealthInput) -> R {
    let p = probe!(i);
    ok_or(
        p.notification_permission == "default",
        "Notification.permission = default.",
        format!(
            "Notification.permission is '{}' (fresh Chrome says default).",
            p.notification_permission
        ),
    )
}

// ---------------------------------------------------------------- the table

macro_rules! c {
    ($id:literal, $key:literal, $area:ident, $sev:ident, $title:literal, $f:ident) => {
        CheckDef {
            id: $id,
            key: $key,
            area: Area::$area,
            severity: Severity::$sev,
            title: $title,
            run: $f,
        }
    };
}

/// All 56 checks, in screen order.
pub const CHECKS: [CheckDef; 56] = [
    c!(
        "H01",
        "net.exit",
        NetworkIp,
        Critical,
        "Exit IP matches the assigned proxy",
        net_exit
    ),
    c!(
        "H02",
        "net.direct",
        NetworkIp,
        Critical,
        "No direct-IP leak",
        net_direct
    ),
    c!(
        "H03",
        "net.asn",
        NetworkIp,
        Info,
        "Exit ASN is a residential / ISP network",
        net_asn
    ),
    c!(
        "H04",
        "net.black",
        NetworkIp,
        Info,
        "Exit IP not on public blacklists",
        net_black
    ),
    c!(
        "H05",
        "net.geo",
        NetworkIp,
        Critical,
        "Exit country = profile timezone & locale",
        net_geo
    ),
    c!(
        "H06",
        "net.reach",
        NetworkIp,
        Critical,
        "Proxy reachable at launch",
        net_reach
    ),
    c!(
        "H07",
        "net.sticky",
        NetworkIp,
        Info,
        "Sticky session keeps the same exit IP",
        net_sticky
    ),
    c!(
        "H08",
        "net.ipv6",
        NetworkIp,
        Warn,
        "IPv6 path blocked",
        net_ipv6
    ),
    c!(
        "H09",
        "net.hdr",
        NetworkIp,
        Warn,
        "No proxy-revealing headers",
        net_hdr
    ),
    c!(
        "H10",
        "net.lan",
        NetworkIp,
        Warn,
        "Local network not reachable from pages",
        net_lan
    ),
    c!(
        "H11",
        "tls.ja4",
        TlsHttp2Quic,
        Warn,
        "TLS ClientHello JA4 = Chrome reference",
        tls_ja4
    ),
    c!(
        "H12",
        "tls.alpn",
        TlsHttp2Quic,
        Warn,
        "ALPN offers h2, http/1.1",
        tls_alpn
    ),
    c!(
        "H13",
        "tls.h2set",
        TlsHttp2Quic,
        Warn,
        "HTTP/2 SETTINGS frame = Chrome",
        tls_h2set
    ),
    c!(
        "H14",
        "tls.pseudo",
        TlsHttp2Quic,
        Warn,
        "HTTP/2 pseudo-header order = Chrome",
        tls_pseudo
    ),
    c!(
        "H15",
        "tls.hdr",
        TlsHttp2Quic,
        Warn,
        "Request header order = Chrome",
        tls_hdr
    ),
    c!(
        "H16",
        "tls.quic",
        TlsHttp2Quic,
        Warn,
        "QUIC handled correctly for this proxy",
        tls_quic
    ),
    c!(
        "H17",
        "rtc.pub",
        WebRtcDns,
        Critical,
        "WebRTC public candidate = exit IP",
        rtc_pub
    ),
    c!(
        "H18",
        "rtc.host",
        WebRtcDns,
        Critical,
        "No host (local IP) candidate exposed",
        rtc_host
    ),
    c!(
        "H19",
        "rtc.mdns",
        WebRtcDns,
        Info,
        "mDNS candidates behave like Chrome",
        rtc_mdns
    ),
    c!(
        "H20",
        "dns.doh",
        WebRtcDns,
        Critical,
        "DNS goes through DoH via the relay",
        dns_doh
    ),
    c!(
        "H21",
        "dns.leak",
        WebRtcDns,
        Critical,
        "No DNS query outside DoH",
        dns_leak
    ),
    c!(
        "H22",
        "rtc.stun",
        WebRtcDns,
        Warn,
        "STUN traffic goes through the proxy",
        rtc_stun
    ),
    c!(
        "H23",
        "nav.ua",
        NavigatorUaCh,
        Critical,
        "User-Agent version = engine",
        nav_ua
    ),
    c!(
        "H24",
        "nav.brands",
        NavigatorUaCh,
        Warn,
        "Sec-CH-UA brand list is valid",
        nav_brands
    ),
    c!(
        "H25",
        "nav.pv",
        NavigatorUaCh,
        Warn,
        "UA-CH platform & platformVersion match the OS",
        nav_pv
    ),
    c!(
        "H26",
        "nav.platform",
        NavigatorUaCh,
        Warn,
        "navigator.platform = Win32",
        nav_platform
    ),
    c!(
        "H27",
        "nav.cores",
        NavigatorUaCh,
        Warn,
        "hardwareConcurrency plausible for the device",
        nav_cores
    ),
    c!(
        "H28",
        "nav.mem",
        NavigatorUaCh,
        Warn,
        "deviceMemory ≤ 8 and = record",
        nav_mem
    ),
    c!(
        "H29",
        "nav.lang",
        NavigatorUaCh,
        Warn,
        "navigator.languages = Accept-Language",
        nav_lang
    ),
    c!(
        "H30",
        "nav.worker",
        NavigatorUaCh,
        Warn,
        "Web Worker sees the same navigator",
        nav_worker
    ),
    c!(
        "H31",
        "nav.iframe",
        NavigatorUaCh,
        Warn,
        "iframes see the same navigator",
        nav_iframe
    ),
    c!(
        "H32",
        "gfx.pair",
        Graphics,
        Warn,
        "WebGL vendor matches renderer",
        gfx_pair
    ),
    c!(
        "H33",
        "gfx.d3d",
        Graphics,
        Warn,
        "Renderer is a Windows D3D ANGLE string",
        gfx_d3d
    ),
    c!(
        "H34",
        "gfx.params",
        Graphics,
        Info,
        "WebGL parameters match the device",
        gfx_params
    ),
    c!(
        "H35",
        "gfx.ext",
        Graphics,
        Info,
        "WebGL extension list matches real devices",
        gfx_ext
    ),
    c!(
        "H36",
        "gfx.canvas",
        Graphics,
        Warn,
        "Canvas render stable across 3 reads",
        gfx_canvas
    ),
    c!(
        "H37",
        "gfx.webgpu",
        Graphics,
        Warn,
        "WebGPU adapter info = WebGL vendor",
        gfx_webgpu
    ),
    c!(
        "H38",
        "gfx.screen",
        Graphics,
        Warn,
        "Screen & available size plausible",
        gfx_screen
    ),
    c!(
        "H39",
        "gfx.dpr",
        Graphics,
        Warn,
        "devicePixelRatio consistent with screen",
        gfx_dpr
    ),
    c!(
        "H40",
        "aud.ctx",
        AudioMedia,
        Warn,
        "AudioContext output stable per profile",
        aud_ctx
    ),
    c!(
        "H41",
        "aud.dev",
        AudioMedia,
        Warn,
        "Media device counts plausible",
        aud_dev
    ),
    c!(
        "H42",
        "aud.voices",
        AudioMedia,
        Info,
        "Speech voices match Windows",
        aud_voices
    ),
    c!(
        "H43",
        "aud.codec",
        AudioMedia,
        Info,
        "Codec support = Chrome on Windows",
        aud_codec
    ),
    c!(
        "H44",
        "fnt.list",
        FontsLayout,
        Warn,
        "Font list is the record's Windows set",
        fnt_list
    ),
    c!(
        "H45",
        "fnt.os",
        FontsLayout,
        Warn,
        "Fonts match the Windows version",
        fnt_os
    ),
    c!(
        "H46",
        "fnt.rects",
        FontsLayout,
        Warn,
        "ClientRects stable across reads",
        fnt_rects
    ),
    c!(
        "H47",
        "fnt.emoji",
        FontsLayout,
        Info,
        "Emoji font is Segoe UI Emoji",
        fnt_emoji
    ),
    c!(
        "H48",
        "fnt.metrics",
        FontsLayout,
        Warn,
        "Text metrics equal in page and worker",
        fnt_metrics
    ),
    c!(
        "H49",
        "aut.webdriver",
        Automation,
        Critical,
        "navigator.webdriver is false",
        aut_webdriver
    ),
    c!(
        "H50",
        "aut.cdp",
        Automation,
        Critical,
        "No DevTools protocol traces",
        aut_cdp
    ),
    c!(
        "H51",
        "aut.headless",
        Automation,
        Warn,
        "No headless tokens in UA or window",
        aut_headless
    ),
    c!(
        "H52",
        "aut.chrome",
        Automation,
        Warn,
        "window.chrome object present",
        aut_chrome
    ),
    c!(
        "H53",
        "aut.perm",
        Automation,
        Warn,
        "Permissions API consistent",
        aut_perm
    ),
    c!(
        "H54",
        "aut.plugins",
        Automation,
        Info,
        "plugins & mimeTypes = Chrome PDF viewer",
        aut_plugins
    ),
    c!(
        "H55",
        "aut.ext",
        Automation,
        Warn,
        "No automation globals or extensions",
        aut_ext
    ),
    c!(
        "H56",
        "aut.notif",
        Automation,
        Info,
        "Notification.permission = default",
        aut_notif
    ),
];

/// Run every check.
pub fn run_all(i: &HealthInput) -> Vec<CheckResult> {
    CHECKS
        .iter()
        .map(|c| {
            let (outcome, message) = (c.run)(i);
            CheckResult {
                id: c.id,
                key: c.key,
                area: c.area,
                severity: c.severity,
                title: c.title,
                outcome,
                message,
            }
        })
        .collect()
}
