//! Fixtures: a fully consistent health run for a persona, as the real engine with every
//! guard on would produce it. Tests break one thing at a time from here. Public so the app
//! and other crates can test against the same baseline.

use crate::checks::fonts_to_test;
use crate::dns::DnsLeakResult;
use crate::h2::{chrome_like_client_start, parse_client_start};
use crate::input::{AsnKind, ExitInfo, GuardSnapshot, HealthInput, NetReference, TlsCapture};
use crate::probe::ProbeReport;
use crate::reflector::{Http1Request, HOST};
use serde_json::json;
use std::net::IpAddr;
use vanta_fingerprint::{device, Geo, Persona};
use vanta_types::EngineVersion;

pub const ENGINE: EngineVersion = EngineVersion::new(156, 0, 8078, 79);
/// The proxy exit used by the fixtures (documentation range).
pub const EXIT_IP: &str = "203.0.113.50";
/// The host's own addresses in the fixtures.
pub const HOST_IPS: [&str; 2] = ["192.168.1.20", "198.51.100.77"];

/// Windows 10 / RTX 3060 persona, German locale, located in Berlin.
pub fn persona() -> Persona {
    let mut p = Persona::from_device(&device::builtin()[0], ENGINE, 7, "de-DE").expect("record");
    p.apply_geo(
        Geo {
            country: "DE".into(),
            timezone: "Europe/Berlin".into(),
            latitude: 52.52,
            longitude: 13.40,
            accuracy_m: 2000,
        },
        None,
    );
    p
}

/// Real WebGL1 extension list of Chrome on a D3D11 NVIDIA GPU.
pub const WEBGL_EXTENSIONS: [&str; 33] = [
    "ANGLE_instanced_arrays",
    "EXT_blend_minmax",
    "EXT_clip_control",
    "EXT_color_buffer_half_float",
    "EXT_depth_clamp",
    "EXT_disjoint_timer_query",
    "EXT_float_blend",
    "EXT_frag_depth",
    "EXT_polygon_offset_clamp",
    "EXT_shader_texture_lod",
    "EXT_texture_compression_bptc",
    "EXT_texture_compression_rgtc",
    "EXT_texture_filter_anisotropic",
    "EXT_texture_mirror_clamp_to_edge",
    "EXT_sRGB",
    "KHR_parallel_shader_compile",
    "OES_element_index_uint",
    "OES_fbo_render_mipmap",
    "OES_standard_derivatives",
    "OES_texture_float",
    "OES_texture_float_linear",
    "OES_texture_half_float",
    "OES_texture_half_float_linear",
    "OES_vertex_array_object",
    "WEBGL_blend_func_extended",
    "WEBGL_color_buffer_float",
    "WEBGL_compressed_texture_s3tc",
    "WEBGL_compressed_texture_s3tc_srgb",
    "WEBGL_debug_renderer_info",
    "WEBGL_debug_shaders",
    "WEBGL_depth_texture",
    "WEBGL_draw_buffers",
    "WEBGL_lose_context",
];

/// The probe page's JSON for `p`, as the page would POST it.
pub fn probe_json(p: &Persona, input: &HealthInput) -> serde_json::Value {
    let brands: Vec<_> = p
        .ua_ch
        .brands
        .iter()
        .map(|(b, v)| json!({"brand": b, "version": v}))
        .collect();
    let full: Vec<_> = p
        .ua_ch
        .full_version_list
        .iter()
        .map(|(b, v)| json!({"brand": b, "version": v}))
        .collect();
    let tz = p
        .geo
        .as_ref()
        .map(|g| g.timezone.clone())
        .unwrap_or_default();
    let realm = json!({
        "ua": p.user_agent, "platform": p.platform, "languages": p.languages,
        "hardwareConcurrency": p.hardware_concurrency, "deviceMemory": p.device_memory,
        "timezone": tz, "webdriver": false, "textMetrics": "151.234,162.008,48.500"
    });
    let tested = fonts_to_test(input);
    let m = p.media_devices;
    json!({
        "token": "t0",
        "ua": p.user_agent,
        "platform": p.platform,
        "vendor": "Google Inc.",
        "language": p.languages[0],
        "languages": p.languages,
        "hardwareConcurrency": p.hardware_concurrency,
        "deviceMemory": p.device_memory,
        "maxTouchPoints": p.max_touch_points,
        "webdriver": false,
        "uaData": {
            "brands": brands, "mobile": false, "platform": p.ua_ch.platform,
            "platformVersion": p.ua_ch.platform_version, "architecture": p.ua_ch.architecture,
            "bitness": p.ua_ch.bitness, "model": p.ua_ch.model, "wow64": p.ua_ch.wow64,
            "fullVersionList": full
        },
        "screen": {
            "width": p.screen.width, "height": p.screen.height,
            "availWidth": p.screen.avail_width, "availHeight": p.screen.avail_height,
            "colorDepth": p.screen.color_depth
        },
        "devicePixelRatio": p.device_pixel_ratio,
        "window": {"outerWidth": 1920, "outerHeight": 1040, "innerWidth": 1920, "innerHeight": 937},
        "timezone": tz,
        "intlLocale": p.locale,
        "webgl": {
            "vendor": p.gpu.vendor, "renderer": p.gpu.renderer,
            "maxTextureSize": 16384, "extensions": WEBGL_EXTENSIONS.to_vec()
        },
        "webgpu": {"vendor": p.gpu.webgpu_vendor, "architecture": p.gpu.webgpu_arch},
        "canvas": ["9f3a61c0d2e4b5a6c7d8e9f0", "9f3a61c0d2e4b5a6c7d8e9f0", "9f3a61c0d2e4b5a6c7d8e9f0"],
        "audio": ["1b2c3d4e5f60718293a4b5c6", "1b2c3d4e5f60718293a4b5c6"],
        "rects": ["a1b2c3d4e5f6a7b8c9d0e1f2", "a1b2c3d4e5f6a7b8c9d0e1f2"],
        "textMetrics": "151.234,162.008,48.500",
        "fonts": p.fonts,
        "fontsTested": tested,
        "media": {"audioinput": m.audioinput.min(1), "audiooutput": m.audiooutput.min(1), "videoinput": m.videoinput.min(1)},
        "voices": [
            "Microsoft Hedda - German (Germany)",
            "Microsoft David - English (United States)",
            "Microsoft Zira - English (United States)"
        ],
        "codecs": {
            "video/mp4; codecs=\"avc1.42E01E\"": "probably",
            "video/webm; codecs=\"vp9\"": "probably",
            "video/webm; codecs=\"vp8\"": "probably",
            "video/mp4; codecs=\"av01.0.05M.08\"": "probably",
            "audio/mpeg": "probably",
            "audio/mp4; codecs=\"mp4a.40.2\"": "probably",
            "audio/ogg; codecs=\"opus\"": "probably",
            "audio/ogg; codecs=\"vorbis\"": "probably",
            "audio/wav; codecs=\"1\"": "probably"
        },
        "worker": realm,
        "iframe": realm,
        "rtc": {"available": true, "candidates": []},
        "chromeObject": true,
        "plugins": 5,
        "mimeTypes": 2,
        "notificationPermission": "default",
        "permissionQuery": "prompt",
        "cdpTrace": false,
        "automationGlobals": [],
        "dnsNames": []
    })
}

/// Chrome's navigation request headers over HTTP/1.1, in Chrome's order.
pub fn navigation(p: &Persona) -> Http1Request {
    let h = |k: &str, v: &str| (k.to_string(), v.to_string());
    Http1Request {
        method: "GET".into(),
        path: "/".into(),
        headers: vec![
            h("Host", &format!("{HOST}:40443")),
            h("Connection", "keep-alive"),
            h("sec-ch-ua", &p.sec_ch_ua()),
            h("sec-ch-ua-mobile", "?0"),
            h("sec-ch-ua-platform", "\"Windows\""),
            h("Upgrade-Insecure-Requests", "1"),
            h("User-Agent", &p.user_agent),
            h("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"),
            h("Sec-Fetch-Site", "none"),
            h("Sec-Fetch-Mode", "navigate"),
            h("Sec-Fetch-User", "?1"),
            h("Sec-Fetch-Dest", "document"),
            h("Accept-Encoding", "gzip, deflate, br, zstd"),
            h("Accept-Language", &p.accept_language()),
        ],
    }
}

/// A complete, consistent health input: every check passes.
pub fn consistent() -> HealthInput {
    let p = persona();
    let mut i = HealthInput::new(p.clone());
    let probe: ProbeReport = serde_json::from_value(probe_json(&p, &i)).expect("fixture json");
    i.probe = Some(probe);
    let r = NetReference::chrome_windows();
    i.tls = Some(TlsCapture {
        ja4: r.ja4.clone(),
        alpn: r.alpn.clone(),
        sni: Some(HOST.into()),
    });
    i.h2 = Some(parse_client_start(&chrome_like_client_start(HOST)).expect("h2 fixture"));
    i.http1 = Some(navigation(&p));
    i.dns = Some(DnsLeakResult {
        expected: 3,
        via_doh: 3,
        missing: vec![],
    });
    let exit: IpAddr = EXIT_IP.parse().expect("ip");
    i.exit = ExitInfo {
        ip: Some(exit),
        country: Some("DE".into()),
        asn_kind: Some(AsnKind::Residential),
        blacklisted: Some(false),
        sticky_samples: vec![exit; 3],
        revealing_headers: vec![],
    };
    i.guard = GuardSnapshot {
        host_ips: HOST_IPS.iter().map(|s| s.parse().expect("ip")).collect(),
        ..GuardSnapshot::default()
    };
    i
}
