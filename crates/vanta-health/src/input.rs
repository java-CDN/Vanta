//! Everything one health run looks at ([`HealthInput`]) and the network reference values.

use crate::dns::DnsLeakResult;
use crate::h2::H2Capture;
use crate::probe::ProbeReport;
use crate::reflector::{Captures, Http1Request};
use crate::stun::StunRequest;
use crate::tls::ClientHello;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use vanta_fingerprint::Persona;

/// Measured reference values for current Chrome on Windows.
///
/// - JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99`: Google Chrome 156.0.8078.73 on Windows 11
///   (and Chrome 152–155), as measured and published at
///   <https://www.clearcotelabs.com/ja4-fingerprint> (2026-10-28). The 17 extensions include
///   trust anchors (0xca34); Chromium builds without it (Edge 153, Brave 154) give
///   `t13d1516h2_8daaf6152771_806a8c22fdea`, accepted here as a Chromium variant (warn).
/// - HTTP/2 `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p` (same source).
///
/// These must be re-checked against the Vanta engine build itself (ungoogled-chromium has
/// no field trials, which can change the extension set); the reference is data, not code,
/// so a calibrated value replaces it without touching the checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetReference {
    pub ja4: String,
    /// Other Chromium JA4s: same cipher hash, different extension set (warn, not fail).
    pub ja4_variants: Vec<String>,
    pub alpn: Vec<String>,
    pub h2_settings: Vec<(u16, u32)>,
    pub h2_window_update: u32,
    pub pseudo_order: Vec<String>,
}

impl Default for NetReference {
    fn default() -> Self {
        Self::chrome_windows()
    }
}

impl NetReference {
    pub fn chrome_windows() -> Self {
        Self {
            ja4: "t13d1517h2_8daaf6152771_cb7bf5808d99".into(),
            ja4_variants: vec!["t13d1516h2_8daaf6152771_806a8c22fdea".into()],
            alpn: vec!["h2".into(), "http/1.1".into()],
            h2_settings: vec![(1, 65536), (2, 0), (4, 6_291_456), (6, 262_144)],
            h2_window_update: 15_663_105,
            pseudo_order: [":method", ":authority", ":scheme", ":path"]
                .map(String::from)
                .to_vec(),
        }
    }
}

/// TLS capture of the page navigation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TlsCapture {
    pub ja4: String,
    pub alpn: Vec<String>,
    pub sni: Option<String>,
}

impl From<&ClientHello> for TlsCapture {
    fn from(h: &ClientHello) -> Self {
        Self {
            ja4: h.ja4(),
            alpn: h.alpn.clone(),
            sni: h.server_name.clone(),
        }
    }
}

/// Network type of the exit IP's ASN (from the offline GeoIP/ASN data, F07).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AsnKind {
    Residential,
    Isp,
    Mobile,
    Hosting,
    Unknown,
}

/// The proxy exit as measured through the relay before the run (F04 / F07).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ExitInfo {
    pub ip: Option<IpAddr>,
    /// ISO country of the exit IP.
    pub country: Option<String>,
    pub asn_kind: Option<AsnKind>,
    /// From the bundled blacklist snapshot; `None` = not checked.
    pub blacklisted: Option<bool>,
    /// Exit IPs of repeated requests (sticky-session test).
    pub sticky_samples: Vec<IpAddr>,
    /// Proxy-revealing headers an echo service saw (Via, X-Forwarded-For...).
    pub revealing_headers: Vec<String>,
}

/// Network Guard state during the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardSnapshot {
    /// Upstream proxy answered the relay's check at launch.
    pub proxy_reachable: bool,
    /// Relay running with its kill switch armed.
    pub relay_armed: bool,
    /// The engine's only proxy is this profile's relay.
    pub engine_uses_relay: bool,
    /// The relay resolves names with DoH routed through the proxy.
    pub doh_through_proxy: bool,
    pub ipv6_blocked: bool,
    pub lan_blocked: bool,
    /// The proxy (and relay) carries UDP.
    pub proxy_udp: bool,
    /// `--disable-quic` is on the engine command line.
    pub quic_disabled: bool,
    pub webrtc_policy: String,
    /// The host's own addresses (interfaces and, if known, the ISP public IP). Never shown;
    /// only compared with what the page and exit reveal.
    pub host_ips: Vec<IpAddr>,
}

impl Default for GuardSnapshot {
    fn default() -> Self {
        Self {
            proxy_reachable: true,
            relay_armed: true,
            engine_uses_relay: true,
            doh_through_proxy: true,
            ipv6_blocked: vanta_proxy::GuardPolicy::BLOCK_IPV6,
            lan_blocked: vanta_proxy::GuardPolicy::BLOCK_LAN,
            proxy_udp: false,
            quic_disabled: true,
            webrtc_policy: vanta_proxy::WebRtcPolicy::default().as_str().into(),
            host_ips: Vec::new(),
        }
    }
}

/// Input of one health run. Every check is a pure function of this value.
#[derive(Debug, Clone)]
pub struct HealthInput {
    /// The persona the engine was launched with (bound to the installed engine).
    pub expected: Persona,
    /// The probe page's report; `None` when the page never reported.
    pub probe: Option<ProbeReport>,
    pub tls: Option<TlsCapture>,
    pub h2: Option<H2Capture>,
    /// The navigation request (HTTP/1.1) to the reflector.
    pub http1: Option<Http1Request>,
    /// Binding Requests that reached the local STUN responder.
    pub stun: Vec<StunRequest>,
    pub dns: Option<DnsLeakResult>,
    pub exit: ExitInfo,
    pub guard: GuardSnapshot,
    pub reference: NetReference,
}

impl HealthInput {
    pub fn new(expected: Persona) -> Self {
        Self {
            expected,
            probe: None,
            tls: None,
            h2: None,
            http1: None,
            stun: Vec::new(),
            dns: None,
            exit: ExitInfo::default(),
            guard: GuardSnapshot::default(),
            reference: NetReference::default(),
        }
    }

    /// Fill the probe report and network captures from a reflector run.
    pub fn with_captures(mut self, caps: &Captures, token: &str) -> Self {
        self.probe = caps
            .reports
            .iter()
            .rev()
            .find(|r| r.token == token)
            .cloned();
        self.tls = caps.page_hello().map(TlsCapture::from);
        self.h2 = caps.h2.first().cloned();
        self.http1 = caps.navigation().cloned();
        self
    }
}
