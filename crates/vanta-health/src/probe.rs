//! What the probe page reports (JSON POSTed to the reflector) and the page itself.
//!
//! The page is static HTML + inline JS (no external fetch, no CDP). Every field is
//! optional on the Rust side: a value the page could not read is simply absent, and the
//! checks that need it say so.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Brand {
    pub brand: String,
    pub version: String,
}

/// `navigator.userAgentData` (low entropy + getHighEntropyValues).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UaData {
    pub brands: Vec<Brand>,
    pub mobile: bool,
    pub platform: String,
    pub platform_version: Option<String>,
    pub architecture: Option<String>,
    pub bitness: Option<String>,
    pub model: Option<String>,
    pub wow64: Option<bool>,
    pub full_version_list: Vec<Brand>,
}

#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ScreenInfo {
    pub width: u32,
    pub height: u32,
    pub avail_width: u32,
    pub avail_height: u32,
    pub color_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WebGlInfo {
    pub vendor: String,
    pub renderer: String,
    pub max_texture_size: u32,
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WebGpuInfo {
    pub vendor: String,
    pub architecture: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MediaCounts {
    pub audioinput: u32,
    pub audiooutput: u32,
    pub videoinput: u32,
}

/// Values read inside a dedicated worker or a same-origin iframe, compared with the page.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RealmValues {
    pub ua: String,
    pub platform: String,
    pub languages: Vec<String>,
    pub hardware_concurrency: u32,
    pub device_memory: Option<f64>,
    pub timezone: String,
    pub webdriver: Option<bool>,
    /// Text width hash measured in this realm (OffscreenCanvas in the worker).
    pub text_metrics: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RtcInfo {
    /// Whether RTCPeerConnection exists.
    pub available: bool,
    /// Raw ICE candidate lines gathered with the local STUN responder as ICE server.
    pub candidates: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WindowInfo {
    pub outer_width: u32,
    pub outer_height: u32,
    pub inner_width: u32,
    pub inner_height: u32,
}

/// The probe page's report.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProbeReport {
    /// Echo of the run token embedded in the page (ties a report to its run).
    pub token: String,
    pub ua: String,
    pub platform: String,
    pub vendor: String,
    pub language: String,
    pub languages: Vec<String>,
    pub hardware_concurrency: u32,
    pub device_memory: Option<f64>,
    pub max_touch_points: u32,
    pub webdriver: Option<bool>,
    pub ua_data: Option<UaData>,
    pub screen: ScreenInfo,
    pub device_pixel_ratio: f64,
    pub window: WindowInfo,
    pub timezone: String,
    /// `Intl.DateTimeFormat().resolvedOptions().locale`.
    pub intl_locale: String,
    pub webgl: Option<WebGlInfo>,
    pub webgpu: Option<WebGpuInfo>,
    /// Hashes of three canvas reads.
    pub canvas: Vec<String>,
    /// Hashes of repeated OfflineAudioContext renders.
    pub audio: Vec<String>,
    /// Hashes of repeated getClientRects reads.
    pub rects: Vec<String>,
    pub text_metrics: Option<String>,
    /// Fonts the width test found, out of the list the page was given.
    pub fonts: Vec<String>,
    pub fonts_tested: Vec<String>,
    pub media: Option<MediaCounts>,
    pub voices: Vec<String>,
    pub codecs: BTreeMap<String, String>,
    pub worker: Option<RealmValues>,
    pub iframe: Option<RealmValues>,
    pub rtc: RtcInfo,
    pub chrome_object: bool,
    pub plugins: u32,
    pub mime_types: u32,
    pub notification_permission: String,
    pub permission_query: String,
    /// `true` when DevTools protocol side effects were observed (Error.stack getter hit).
    pub cdp_trace: bool,
    /// Global names typical of automation tools found on `window`.
    pub automation_globals: Vec<String>,
    /// Unique leak-test names the page requested (echo of what it was given).
    pub dns_names: Vec<String>,
}

impl ProbeReport {
    pub fn from_json(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
    }
}

/// Fonts that only exist on other operating systems; the page tests them too.
pub const FOREIGN_FONTS: &[&str] = &[
    "Helvetica Neue",
    "Menlo",
    "Monaco",
    "Geneva",
    "Ubuntu",
    "DejaVu Sans",
    "Liberation Sans",
    "Cantarell",
    "Noto Color Emoji",
    "Apple Color Emoji",
];

/// Settings the reflector puts into the page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageConfig {
    pub token: String,
    /// `https://host:port/h2` on the HTTP/2 sniffer.
    pub h2_url: String,
    /// `stun:127.0.0.1:port`.
    pub stun_url: String,
    pub fonts: Vec<String>,
    /// Leak-test URLs (`https://<unique>.leak.vanta.invalid/`), fetched through the relay.
    pub dns_urls: Vec<String>,
}

const PAGE: &str = include_str!("probe.html");

/// The probe page with `cfg` embedded. `<` is escaped in the JSON so no value can close
/// the script element.
pub fn page(cfg: &PageConfig) -> String {
    let json = serde_json::to_string(cfg)
        .expect("page config serializes")
        .replace('<', "\\u003c");
    PAGE.replace("/*VANTA_CONFIG*/{}", &json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_embeds_config_safely() {
        let cfg = PageConfig {
            token: "</script><b>".into(),
            h2_url: "https://vanta-health.localhost:1/h2".into(),
            stun_url: "stun:127.0.0.1:2".into(),
            fonts: vec!["Arial".into()],
            dns_urls: vec![],
        };
        let p = page(&cfg);
        assert!(p.contains("stun:127.0.0.1:2"));
        assert!(!p.contains("</script><b>"));
        assert!(!p.contains("/*VANTA_CONFIG*/"));
        // Local-only: the page never references another origin.
        for bad in ["http://", "//cdn", "googleapis", "src=\"http"] {
            assert!(!PAGE.contains(bad), "{bad}");
        }
        assert!(!PAGE.contains("debugger"));
    }

    #[test]
    fn report_parses_sparse_json() {
        let r = ProbeReport::from_json(r#"{"ua":"x","rtc":{"available":true}}"#).unwrap();
        assert_eq!(r.ua, "x");
        assert!(r.rtc.available && r.rtc.candidates.is_empty());
        assert!(r.webgl.is_none());
    }
}
