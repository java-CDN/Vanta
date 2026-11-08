//! Proxy Hub extended checks (F04): exit IP with ASN / organisation / country, speed,
//! SOCKS5 UDP support and DNS blocklists.
//!
//! **Every request goes through the proxy under test**, never directly:
//!
//! - [`ip_info_via_proxy`] and [`speed_via_proxy`] open a tunnel with the relay's own code
//!   ([`crate::net::open_tunnel`]) and hand the service's host name to the proxy, so nothing
//!   is resolved locally; TLS is verified for that host name.
//! - [`udp_check`] only asks the proxy for UDP ASSOCIATE over its TCP control connection;
//!   no datagram is sent (QUIC stays off either way: the relay carries no UDP).
//! - [`dnsbl_check`] asks A records with a [`Resolver`]; in the app that is the DoH
//!   resolver routed through the proxy ([`crate::doh::DohRoute::ViaProxy`]).
//!
//! Results are values for the Proxy Hub record only; nothing here logs or sends them.
//!
//! **Blocklists.** Each zone is first asked for its RFC 5782 test entries: `127.0.0.2` must
//! answer as listed and `127.0.0.1` must not. Only then is the exit IP's own answer used;
//! otherwise the result is `unknown`. This matters because public resolvers (Cloudflare,
//! Google, Quad9, i.e. every DoH provider Vanta offers by default) are refused by Spamhaus:
//! Cloudflare and Quad9 get the error code `127.255.255.254` for every name, Google gets
//! `NXDOMAIN` for every name (which would read as "not listed"). With the test entries
//! both cases come out as `unknown` instead of a guess. Answers in `127.255.255.0/24` are
//! error codes, never listings; answers outside `127.0.0.0/8` mean the resolver rewrote
//! the reply (NXDOMAIN hijacking).

use crate::doh::Resolver;
use crate::echo::{get_body, send_get, tls_via_proxy, EchoUrl};
use crate::endpoint::ProxyEndpoint;
use crate::guard::is_blocked_ip;
use crate::net::{with_timeout, BoxStream, NetError, NetResult};
use crate::state::{udp_associate_probe, UdpSupport};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::Instant;

/// Default IP information endpoint: ipinfo.io's JSON answer for the caller (`ip`,
/// `country`, `org` = "AS<number> <name>"), usable without a token.
pub const DEFAULT_IP_INFO_URL: &str = "https://ipinfo.io/json";
/// Default speed test download: 2 MB of zeros from Cloudflare's speed test.
pub const DEFAULT_SPEED_TEST_URL: &str = "https://speed.cloudflare.com/__down?bytes=2000000";
/// Hard cap on what a speed test downloads, whatever the URL serves.
pub const SPEED_MAX_BYTES: u64 = 2_000_000;
/// A download cut short by the time limit is still reported when it got this far.
pub const SPEED_MIN_PARTIAL_BYTES: u64 = 256 * 1024;
/// Below this a finished download is too small for a meaningful rate.
pub const SPEED_MIN_BYTES: u64 = 64 * 1024;
/// Time limit of a speed test, tunnel and TLS included.
pub const SPEED_TIMEOUT: Duration = Duration::from_secs(20);
/// Time limit of all blocklist lookups together.
pub const DNSBL_TIMEOUT: Duration = Duration::from_secs(15);

/// One DNS blocklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsblZone {
    pub zone: &'static str,
    pub name: &'static str,
}

/// Lists whose published terms allow this kind of low-volume lookup: Spamhaus ZEN (free for
/// low-volume non-commercial use; refuses public resolvers, so usually `unknown` here),
/// SpamCop (free), DroneBL (free for commercial and non-commercial use; lists open proxies
/// and drones) and PSBL ("anybody is free to use PSBL").
pub const DNSBL_ZONES: [DnsblZone; 4] = [
    DnsblZone {
        zone: "zen.spamhaus.org",
        name: "Spamhaus ZEN",
    },
    DnsblZone {
        zone: "bl.spamcop.net",
        name: "SpamCop",
    },
    DnsblZone {
        zone: "dnsbl.dronebl.org",
        name: "DroneBL",
    },
    DnsblZone {
        zone: "psbl.surriel.com",
        name: "PSBL",
    },
];

/// Outcome of one sub-check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Check<T> {
    Ok { result: T },
    Failed { reason: String },
    Skipped { reason: String },
}

impl<T> Check<T> {
    pub fn from_net(r: NetResult<T>) -> Self {
        match r {
            Ok(result) => Check::Ok { result },
            Err(e) => Check::Failed {
                reason: e.to_string(),
            },
        }
    }

    pub fn skipped(reason: &str) -> Self {
        Check::Skipped {
            reason: reason.into(),
        }
    }

    pub fn ok(&self) -> Option<&T> {
        match self {
            Check::Ok { result } => Some(result),
            _ => None,
        }
    }
}

/// What the IP information endpoint said about the exit. Any field may be missing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpInfo {
    pub ip: Option<IpAddr>,
    /// Autonomous system number.
    pub asn: Option<u32>,
    /// AS / ISP organisation name.
    pub org: Option<String>,
    /// ISO 3166-1 alpha-2, upper case.
    pub country: Option<String>,
}

/// Result of the speed test download.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpeedResult {
    /// Body bytes received (at most [`SPEED_MAX_BYTES`]).
    pub bytes: u64,
    /// From the end of the response head to the last byte.
    pub millis: u64,
    /// Megabits per second, two decimals.
    pub mbps: f64,
    /// False when the time limit cut the download short.
    pub complete: bool,
}

/// SOCKS5 UDP ASSOCIATE capability (informational).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "support", rename_all = "snake_case")]
pub enum UdpResult {
    Supported,
    /// SOCKS5 reply code (7 = command not supported).
    Unsupported {
        reply: u8,
    },
    NotSocks5,
}

/// One blocklist's answer for the exit IP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Listing {
    Listed { codes: Vec<String> },
    NotListed,
    Unknown { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsblResult {
    pub zone: String,
    pub name: String,
    #[serde(flatten)]
    pub listing: Listing,
}

/// Everything the extended check found, stored with the Proxy Hub entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyChecks {
    pub checked_ms: i64,
    pub exit: Check<IpInfo>,
    pub udp: Check<UdpResult>,
    pub blacklist: Check<Vec<DnsblResult>>,
    /// Only run on request; kept from the last run otherwise.
    #[serde(default)]
    pub speed: Option<SpeedRun>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpeedRun {
    pub checked_ms: i64,
    pub result: Check<SpeedResult>,
}

// ---- exit IP, ASN, organisation, country ---------------------------------------------

fn clean_text(s: &str) -> Option<String> {
    let t: String = s
        .chars()
        .filter(|c| !c.is_control())
        .take(128)
        .collect::<String>()
        .trim()
        .to_string();
    (!t.is_empty()).then_some(t)
}

/// `15169`, `"15169"`, `"AS15169"`, `"AS15169 Google LLC"` -> 15169.
fn parse_asn(v: &serde_json::Value) -> Option<u32> {
    match v {
        serde_json::Value::Number(n) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
        serde_json::Value::String(s) => {
            let s = s.trim();
            let s = s
                .strip_prefix("AS")
                .or_else(|| s.strip_prefix("as"))
                .unwrap_or(s);
            let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse().ok()
        }
        _ => None,
    }
}

/// `"AS15169 Google LLC"` -> `"Google LLC"`; other strings as they are.
fn strip_as_prefix(s: &str) -> &str {
    let t = s.trim();
    match t.strip_prefix("AS") {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit()) => rest
            .trim_start_matches(|c: char| c.is_ascii_digit())
            .trim_start(),
        _ => t,
    }
}

/// Read the JSON answer of an IP information service. Understands the field names of
/// ipinfo.io (`ip`, `country`, `org`), ipwho.is (`country_code`, `connection.asn/org`),
/// ip.sb (`asn`, `asn_organization`, `country_code`), ipinfo Lite (`as_name`) and
/// ip-api (`query`, `countryCode`, `as`). Missing fields stay `None`; an answer that is not
/// a JSON object, or says it failed, is an error.
pub fn parse_ip_info(body: &[u8]) -> NetResult<IpInfo> {
    let bad = |m: &str| NetError::Protocol(format!("IP info: {m}"));
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| bad("answer is not JSON"))?;
    let o = v
        .as_object()
        .ok_or_else(|| bad("answer is not a JSON object"))?;
    if o.get("success").and_then(|x| x.as_bool()) == Some(false)
        || o.get("error")
            .is_some_and(|x| x.as_bool() != Some(false) && !x.is_null())
        || o.get("status").and_then(|x| x.as_str()) == Some("fail")
    {
        return Err(bad("the service reported an error"));
    }
    let s = |k: &str| o.get(k).and_then(|x| x.as_str());
    let conn = o.get("connection").and_then(|x| x.as_object());
    let ip = s("ip")
        .or_else(|| s("query"))
        .and_then(|x| x.trim().parse::<IpAddr>().ok());
    let country = [s("country_code"), s("countryCode"), s("country")]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic()))
        .map(|c| c.to_ascii_uppercase());
    let asn = o
        .get("asn")
        .and_then(parse_asn)
        .or_else(|| conn.and_then(|c| c.get("asn")).and_then(parse_asn))
        .or_else(|| o.get("as").and_then(parse_asn))
        .or_else(|| o.get("org").and_then(parse_asn));
    let org = [
        s("as_name"),
        s("asn_organization"),
        conn.and_then(|c| c.get("org")).and_then(|x| x.as_str()),
        s("org"),
        s("as"),
        conn.and_then(|c| c.get("isp")).and_then(|x| x.as_str()),
        s("isp"),
        s("organization"),
    ]
    .into_iter()
    .flatten()
    .map(strip_as_prefix)
    .find_map(clean_text);
    Ok(IpInfo {
        ip,
        asn,
        org,
        country,
    })
}

/// One IP information request over an open (TLS) stream.
pub async fn ip_info_exchange(s: BoxStream, url: &EchoUrl) -> NetResult<IpInfo> {
    let body = get_body(s, url, "application/json", "IP info").await?;
    parse_ip_info(&body)
}

/// Exit IP, ASN, organisation and country of `proxy` (resolved to `addr`).
pub async fn ip_info_via_proxy(
    url: &EchoUrl,
    proxy: &ProxyEndpoint,
    addr: SocketAddr,
    timeout: Duration,
) -> NetResult<IpInfo> {
    with_timeout(timeout, async {
        let tls = tls_via_proxy(url, proxy, addr, timeout).await?;
        ip_info_exchange(tls, url).await
    })
    .await
}

// ---- speed -----------------------------------------------------------------------------

fn rate(bytes: u64, elapsed: Duration, complete: bool) -> SpeedResult {
    let secs = elapsed.as_secs_f64().max(0.001);
    let mbps = (bytes as f64 * 8.0 / secs / 1_000_000.0 * 100.0).round() / 100.0;
    SpeedResult {
        bytes,
        millis: elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
        mbps,
        complete,
    }
}

/// Timed download over an open (TLS) stream: status 200, then up to `cap` body bytes or
/// until `deadline`. The clock starts when the response head is complete.
pub async fn speed_exchange(
    mut s: BoxStream,
    url: &EchoUrl,
    cap: u64,
    deadline: Instant,
) -> NetResult<SpeedResult> {
    let in_time = |r: Result<std::io::Result<usize>, tokio::time::error::Elapsed>| match r {
        Ok(r) => r.map(Some),
        Err(_) => Ok(None),
    };
    tokio::time::timeout_at(deadline, send_get(&mut s, url, "*/*"))
        .await
        .unwrap_or(Err(NetError::Timeout))?;
    let mut buf = vec![0u8; 16 * 1024];
    let mut head = Vec::new();
    let mut body: u64;
    loop {
        let n = match in_time(tokio::time::timeout_at(deadline, s.read(&mut buf)).await)? {
            None => return Err(NetError::Timeout),
            Some(0) => return Err(NetError::Protocol("speed test: no HTTP response".into())),
            Some(n) => n,
        };
        head.extend_from_slice(&buf[..n]);
        if let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            let text = std::str::from_utf8(&head[..end])
                .map_err(|_| NetError::Protocol("speed test: bad HTTP head".into()))?;
            let status = crate::net::http_status(text)?;
            if status != 200 {
                return Err(NetError::Refused(status));
            }
            body = (head.len() - end - 4) as u64;
            break;
        }
        if head.len() > 16 * 1024 {
            return Err(NetError::Protocol("speed test: HTTP head too large".into()));
        }
    }
    let start = Instant::now();
    let mut complete = true;
    while body < cap {
        match in_time(tokio::time::timeout_at(deadline, s.read(&mut buf)).await) {
            Ok(None) => {
                complete = false;
                break;
            }
            Ok(Some(0)) => break,
            Ok(Some(n)) => body += n as u64,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
    }
    let body = body.min(cap);
    let elapsed = start.elapsed();
    if !complete {
        return if body >= SPEED_MIN_PARTIAL_BYTES {
            Ok(rate(body, elapsed, false))
        } else {
            Err(NetError::Timeout)
        };
    }
    if body < SPEED_MIN_BYTES {
        return Err(NetError::Protocol(format!(
            "speed test: only {body} bytes received, too few to measure"
        )));
    }
    Ok(rate(body, elapsed, true))
}

/// Download speed through `proxy` (resolved to `addr`): at most `cap` bytes (never more
/// than [`SPEED_MAX_BYTES`]) within `timeout`, tunnel and TLS included.
pub async fn speed_via_proxy(
    url: &EchoUrl,
    proxy: &ProxyEndpoint,
    addr: SocketAddr,
    timeout: Duration,
    cap: u64,
) -> NetResult<SpeedResult> {
    let deadline = Instant::now() + timeout;
    let tls = tokio::time::timeout_at(deadline, tls_via_proxy(url, proxy, addr, timeout))
        .await
        .unwrap_or(Err(NetError::Timeout))?;
    speed_exchange(tls, url, cap.min(SPEED_MAX_BYTES), deadline).await
}

// ---- UDP -------------------------------------------------------------------------------

/// SOCKS5 UDP ASSOCIATE support of `proxy` (no datagram is sent).
pub async fn udp_check(
    proxy: &ProxyEndpoint,
    addr: SocketAddr,
    timeout: Duration,
) -> Check<UdpResult> {
    let r = with_timeout(timeout, udp_associate_probe(proxy, addr, timeout)).await;
    Check::from_net(r.map(|u| match u {
        UdpSupport::Supported { .. } => UdpResult::Supported,
        UdpSupport::Unsupported { reply } => UdpResult::Unsupported { reply },
        UdpSupport::NotSocks5 => UdpResult::NotSocks5,
    }))
}

// ---- DNS blocklists --------------------------------------------------------------------

fn reversed(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0])
}

/// What one A lookup in a blocklist zone means.
fn classify(answers: &[Ipv4Addr]) -> Listing {
    if answers.is_empty() {
        return Listing::NotListed;
    }
    if let Some(e) = answers.iter().find(|a| a.octets()[..3] == [127, 255, 255]) {
        let why = match e.octets()[3] {
            252 => "typing error in the list name",
            254 => "the list refuses queries from public resolvers",
            255 => "too many queries",
            _ => "error code",
        };
        return Listing::Unknown {
            reason: format!("{why} ({e})"),
        };
    }
    if answers.iter().any(|a| a.octets()[0] != 127) {
        return Listing::Unknown {
            reason: "the resolver rewrote the answer (not a 127.x code)".into(),
        };
    }
    let mut codes: Vec<String> = answers.iter().map(|a| a.to_string()).collect();
    codes.sort();
    codes.dedup();
    Listing::Listed { codes }
}

async fn ask(resolver: &dyn Resolver, name: &str) -> Result<Listing, String> {
    resolver
        .resolve(name)
        .await
        .map(|a| classify(&a))
        .map_err(|e| e.to_string())
}

/// One zone: test entries first, then the exit IP.
pub async fn dnsbl_zone(resolver: &dyn Resolver, ip: Ipv4Addr, zone: DnsblZone) -> DnsblResult {
    let (pos_name, neg_name) = (
        format!("2.0.0.127.{}", zone.zone),
        format!("1.0.0.127.{}", zone.zone),
    );
    let target_name = format!("{}.{}", reversed(ip), zone.zone);
    let (pos, neg, target) = tokio::join!(
        ask(resolver, &pos_name),
        ask(resolver, &neg_name),
        ask(resolver, &target_name),
    );
    let unknown = |reason: String| Listing::Unknown { reason };
    let listing = match (pos, neg, target) {
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => unknown(format!("lookup failed: {e}")),
        (Ok(Listing::Unknown { reason }), _, _) => unknown(format!("test entry 127.0.0.2: {reason}")),
        (Ok(Listing::NotListed), _, _) => unknown(
            "test entry 127.0.0.2 did not answer as listed through this resolver (public resolvers are often refused); result not reliable".into(),
        ),
        (_, Ok(Listing::Listed { .. } | Listing::Unknown { .. }), _) => {
            unknown("test entry 127.0.0.1 answered as listed; result not reliable".into())
        }
        (Ok(Listing::Listed { .. }), Ok(Listing::NotListed), Ok(t)) => t,
    };
    DnsblResult {
        zone: zone.zone.into(),
        name: zone.name.into(),
        listing,
    }
}

/// Look `ip` up in every zone (all at once), within `timeout`. Only public IPv4 addresses
/// are looked up; anything else is `unknown` without a query.
pub async fn dnsbl_check(
    resolver: Arc<dyn Resolver>,
    ip: IpAddr,
    zones: &[DnsblZone],
    timeout: Duration,
) -> Vec<DnsblResult> {
    let all_unknown = |reason: &str| {
        zones
            .iter()
            .map(|z| DnsblResult {
                zone: z.zone.into(),
                name: z.name.into(),
                listing: Listing::Unknown {
                    reason: reason.into(),
                },
            })
            .collect()
    };
    let v4 = match ip {
        IpAddr::V4(v4) if !is_blocked_ip(ip) => v4,
        IpAddr::V4(_) => return all_unknown("the exit IP is not a public address"),
        IpAddr::V6(_) => return all_unknown("only IPv4 exit addresses are looked up"),
    };
    let mut set = tokio::task::JoinSet::new();
    for (i, z) in zones.iter().copied().enumerate() {
        let r = resolver.clone();
        set.spawn(async move { (i, dnsbl_zone(&*r, v4, z).await) });
    }
    let mut out: Vec<Option<DnsblResult>> = vec![None; zones.len()];
    let collect = async {
        while let Some(Ok((i, r))) = set.join_next().await {
            out[i] = Some(r);
        }
    };
    let _ = tokio::time::timeout(timeout, collect).await;
    out.into_iter()
        .zip(zones)
        .map(|(r, z)| {
            r.unwrap_or_else(|| DnsblResult {
                zone: z.zone.into(),
                name: z.name.into(),
                listing: Listing::Unknown {
                    reason: "timed out".into(),
                },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doh::BoxFuture;
    use crate::endpoint::{Credentials, ProxyScheme};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // ---- IP info ----

    #[test]
    fn ip_info_formats() {
        let ipinfo = br#"{"ip":"52.26.208.45","city":"Boardman","country":"US","org":"AS16509 Amazon.com, Inc.","readme":"x"}"#;
        assert_eq!(
            parse_ip_info(ipinfo).unwrap(),
            IpInfo {
                ip: Some("52.26.208.45".parse().unwrap()),
                asn: Some(16509),
                org: Some("Amazon.com, Inc.".into()),
                country: Some("US".into()),
            }
        );
        let ipwho = br#"{"ip":"203.0.113.9","success":true,"country":"Germany","country_code":"DE","connection":{"asn":3320,"org":"Deutsche Telekom AG","isp":"DTAG"}}"#;
        let i = parse_ip_info(ipwho).unwrap();
        assert_eq!(
            (i.asn, i.org.as_deref(), i.country.as_deref()),
            (Some(3320), Some("Deutsche Telekom AG"), Some("DE"))
        );
        let ipsb = br#"{"asn":16509,"asn_organization":"Amazon.com, Inc.","ip":"52.26.208.45","country":"United States","country_code":"US"}"#;
        let i = parse_ip_info(ipsb).unwrap();
        assert_eq!((i.asn, i.country.as_deref()), (Some(16509), Some("US")));
        let lite = br#"{"ip":"8.8.8.8","asn":"AS15169","as_name":"Google LLC","country_code":"US","country":"United States"}"#;
        let i = parse_ip_info(lite).unwrap();
        assert_eq!((i.asn, i.org.as_deref()), (Some(15169), Some("Google LLC")));
        let ipapi = br#"{"status":"success","query":"198.51.100.1","countryCode":"NL","as":"AS1136 KPN B.V.","isp":"KPN"}"#;
        let i = parse_ip_info(ipapi).unwrap();
        assert_eq!(
            (
                i.ip.unwrap().to_string().as_str(),
                i.asn,
                i.org.as_deref(),
                i.country.as_deref()
            ),
            ("198.51.100.1", Some(1136), Some("KPN B.V."), Some("NL"))
        );
    }

    #[test]
    fn ip_info_missing_fields_and_errors() {
        // Only the IP: everything else stays None. A full country name is not a code.
        let i =
            parse_ip_info(br#"{"ip":"192.0.2.1","country":"United States","org":"  "}"#).unwrap();
        assert_eq!(
            i,
            IpInfo {
                ip: Some("192.0.2.1".parse().unwrap()),
                ..Default::default()
            }
        );
        assert_eq!(parse_ip_info(b"{}").unwrap(), IpInfo::default());
        // Bad IP text is dropped, control characters cut, long names capped.
        let long = format!(
            r#"{{"ip":"nope","org":"AS1 Evil\u0007Corp{}"}}"#,
            "x".repeat(300)
        );
        let i = parse_ip_info(long.as_bytes()).unwrap();
        assert_eq!(i.ip, None);
        assert_eq!(i.asn, Some(1));
        assert!(
            i.org.as_deref().unwrap().starts_with("EvilCorp")
                && i.org.unwrap().chars().count() <= 128
        );
        for bad in [
            &b"203.0.113.7"[..],
            b"[1,2]",
            br#"{"error":true,"reason":"RateLimited"}"#,
            br#"{"success":false}"#,
            br#"{"status":"fail"}"#,
        ] {
            assert!(
                matches!(parse_ip_info(bad), Err(NetError::Protocol(_))),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    /// Serve one canned HTTP response on a duplex pipe; return what the client sent.
    async fn serve(response: Vec<u8>) -> (BoxStream, tokio::task::JoinHandle<String>) {
        let (client, mut server) = tokio::io::duplex(256 * 1024);
        let h = tokio::spawn(async move {
            let mut req = Vec::new();
            let mut b = [0u8; 1024];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = server.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&b[..n]);
            }
            let _ = server.write_all(&response).await;
            let _ = server.shutdown().await;
            String::from_utf8(req).unwrap()
        });
        (Box::new(client), h)
    }

    #[tokio::test]
    async fn ip_info_exchange_sends_a_plain_get() {
        let url = EchoUrl::parse(DEFAULT_IP_INFO_URL).unwrap();
        let body = br#"{"ip":"198.51.100.20","country":"de","org":"AS3320 DTAG"}"#;
        let mut resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        resp.extend_from_slice(body);
        let (s, h) = serve(resp).await;
        let i = ip_info_exchange(s, &url).await.unwrap();
        assert_eq!((i.asn, i.country.as_deref()), (Some(3320), Some("DE")));
        let req = h.await.unwrap();
        assert!(
            req.starts_with(
                "GET /json HTTP/1.1\r\nHost: ipinfo.io\r\nAccept: application/json\r\n"
            ),
            "{req}"
        );
        assert!(!req.to_ascii_lowercase().contains("user-agent"));
        let (s, _) = serve(b"HTTP/1.1 429 Too Many\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
        assert_eq!(
            ip_info_exchange(s, &url).await.unwrap_err(),
            NetError::Refused(429)
        );
    }

    /// A SOCKS5 proxy that records the CONNECT target, then is not a TLS server.
    async fn recording_socks() -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = l.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).await.unwrap();
            s.write_all(&[5, 0]).await.unwrap();
            let mut req = [0u8; 5];
            s.read_exact(&mut req).await.unwrap();
            let mut name = vec![0u8; req[4] as usize + 2];
            s.read_exact(&mut name).await.unwrap();
            s2.lock().unwrap().extend_from_slice(&req);
            s2.lock().unwrap().extend_from_slice(&name);
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });
        (addr, seen)
    }

    /// IP info and speed go to the proxy, by host name: nothing is resolved or connected
    /// locally.
    #[tokio::test]
    async fn ip_info_and_speed_go_through_the_proxy_by_name() {
        for which in ["info", "speed"] {
            let (addr, seen) = recording_socks().await;
            let proxy = ProxyEndpoint::new(ProxyScheme::Socks5, "127.0.0.1", addr.port(), None);
            let t = Duration::from_secs(3);
            let host = if which == "info" {
                let r = ip_info_via_proxy(
                    &EchoUrl::parse(DEFAULT_IP_INFO_URL).unwrap(),
                    &proxy,
                    addr,
                    t,
                )
                .await;
                assert!(r.is_err());
                "ipinfo.io"
            } else {
                let r = speed_via_proxy(
                    &EchoUrl::parse(DEFAULT_SPEED_TEST_URL).unwrap(),
                    &proxy,
                    addr,
                    t,
                    SPEED_MAX_BYTES,
                )
                .await;
                assert!(r.is_err());
                "speed.cloudflare.com"
            };
            let seen = seen.lock().unwrap().clone();
            assert_eq!(
                &seen[..4],
                &[5, 1, 0, 3],
                "{which}: SOCKS5 CONNECT by domain name"
            );
            assert_eq!(&seen[5..5 + host.len()], host.as_bytes());
            assert_eq!(&seen[seen.len() - 2..], &443u16.to_be_bytes());
        }
    }

    // ---- speed ----

    fn speed_url() -> EchoUrl {
        EchoUrl::parse(DEFAULT_SPEED_TEST_URL).unwrap()
    }

    #[tokio::test]
    async fn speed_counts_body_bytes_up_to_the_cap() {
        let mut resp = b"HTTP/1.1 200 OK\r\nContent-Length: 3000000\r\n\r\n".to_vec();
        resp.extend(std::iter::repeat_n(0u8, 3_000_000));
        let (s, h) = serve(resp).await;
        let r = speed_exchange(
            s,
            &speed_url(),
            SPEED_MAX_BYTES,
            Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!(r.bytes, SPEED_MAX_BYTES, "hard cap");
        assert!(r.complete && r.mbps > 0.0);
        let req = h.await.unwrap();
        assert!(
            req.starts_with("GET /__down?bytes=2000000 HTTP/1.1\r\nHost: speed.cloudflare.com\r\n"),
            "{req}"
        );
        // A shorter body that the server closes is fine when big enough.
        let mut resp = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        resp.extend(std::iter::repeat_n(1u8, 100_000));
        let (s, _) = serve(resp).await;
        let r = speed_exchange(
            s,
            &speed_url(),
            SPEED_MAX_BYTES,
            Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!((r.bytes, r.complete), (100_000, true));
    }

    #[tokio::test]
    async fn speed_errors_and_partial_results() {
        let deadline = || Instant::now() + Duration::from_secs(5);
        let (s, _) = serve(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
        assert_eq!(
            speed_exchange(s, &speed_url(), SPEED_MAX_BYTES, deadline())
                .await
                .unwrap_err(),
            NetError::Refused(404)
        );
        let (s, _) = serve(b"HTTP/1.1 200 OK\r\n\r\ntiny".to_vec()).await;
        assert!(matches!(
            speed_exchange(s, &speed_url(), SPEED_MAX_BYTES, deadline()).await,
            Err(NetError::Protocol(_))
        ));
        let (s, _) = serve(b"garbage\r\n\r\n".to_vec()).await;
        assert!(speed_exchange(s, &speed_url(), SPEED_MAX_BYTES, deadline())
            .await
            .is_err());
        // A server that stalls: nothing useful before the deadline -> timeout.
        let (client, mut server) = tokio::io::duplex(1024 * 1024);
        let stall = tokio::spawn(async move {
            let mut b = [0u8; 512];
            let _ = server.read(&mut b).await;
            server.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            server.write_all(&[0u8; 1000]).await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(server);
        });
        let t = Instant::now();
        let r = speed_exchange(
            Box::new(client),
            &speed_url(),
            SPEED_MAX_BYTES,
            Instant::now() + Duration::from_millis(300),
        )
        .await;
        assert_eq!(r.unwrap_err(), NetError::Timeout);
        assert!(t.elapsed() < Duration::from_secs(2));
        stall.abort();
        // Enough bytes, then a stall: a partial result.
        let (client, mut server) = tokio::io::duplex(1024 * 1024);
        let stall = tokio::spawn(async move {
            let mut b = [0u8; 512];
            let _ = server.read(&mut b).await;
            server.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            server.write_all(&vec![0u8; 300 * 1024]).await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(server);
        });
        let r = speed_exchange(
            Box::new(client),
            &speed_url(),
            SPEED_MAX_BYTES,
            Instant::now() + Duration::from_millis(400),
        )
        .await
        .unwrap();
        assert!(!r.complete && r.bytes >= SPEED_MIN_PARTIAL_BYTES);
        stall.abort();
    }

    #[test]
    fn rate_math() {
        let r = rate(2_000_000, Duration::from_millis(1600), true);
        assert_eq!((r.mbps, r.millis), (10.0, 1600));
    }

    // ---- UDP ----

    #[tokio::test]
    async fn udp_check_maps_the_probe() {
        let http = ProxyEndpoint::new(ProxyScheme::Http, "127.0.0.1", 1, None);
        let a: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert_eq!(
            udp_check(&http, a, Duration::from_secs(1)).await,
            Check::Ok {
                result: UdpResult::NotSocks5
            }
        );
        // Nothing listening: a failure, not "unsupported".
        let dead = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let s5 = ProxyEndpoint::new(
            ProxyScheme::Socks5,
            "127.0.0.1",
            dead.port(),
            Some(Credentials::new("u", "p")),
        );
        assert!(matches!(
            udp_check(&s5, dead, Duration::from_secs(2)).await,
            Check::Failed { .. }
        ));
        // Refused with code 7.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).await.unwrap();
            s.write_all(&[5, 0]).await.unwrap();
            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.unwrap();
            s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });
        let p = ProxyEndpoint::new(ProxyScheme::Socks5, "127.0.0.1", addr.port(), None);
        assert_eq!(
            udp_check(&p, addr, Duration::from_secs(2)).await,
            Check::Ok {
                result: UdpResult::Unsupported { reply: 7 }
            }
        );
    }

    // ---- DNSBL ----

    /// Answers by name; unknown names are NXDOMAIN; `fail` names error; records queries.
    struct FakeDns {
        answers: HashMap<String, Vec<Ipv4Addr>>,
        fail: Vec<String>,
        delay: Duration,
        asked: Mutex<Vec<String>>,
    }

    impl FakeDns {
        fn new(entries: &[(&str, &[[u8; 4]])]) -> Self {
            Self {
                answers: entries
                    .iter()
                    .map(|(n, a)| {
                        (
                            n.to_string(),
                            a.iter().map(|o| Ipv4Addr::from(*o)).collect(),
                        )
                    })
                    .collect(),
                fail: vec![],
                delay: Duration::ZERO,
                asked: Mutex::new(vec![]),
            }
        }
    }

    impl Resolver for FakeDns {
        fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, NetResult<Vec<Ipv4Addr>>> {
            self.asked.lock().unwrap().push(host.to_string());
            Box::pin(async move {
                tokio::time::sleep(self.delay).await;
                if self.fail.iter().any(|f| f == host) {
                    return Err(NetError::Timeout);
                }
                Ok(self.answers.get(host).cloned().unwrap_or_default())
            })
        }
    }

    const Z: DnsblZone = DnsblZone {
        zone: "bl.example",
        name: "Example BL",
    };
    const EXIT: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

    fn working(extra: &[(&str, &[[u8; 4]])]) -> FakeDns {
        let mut e: Vec<(&str, &[[u8; 4]])> = vec![("2.0.0.127.bl.example", &[[127, 0, 0, 2]])];
        e.extend_from_slice(extra);
        FakeDns::new(&e)
    }

    #[tokio::test]
    async fn dnsbl_listed_and_not_listed_with_a_working_resolver() {
        let dns = working(&[(
            "20.100.51.198.bl.example",
            &[[127, 0, 0, 4], [127, 0, 0, 2], [127, 0, 0, 4]],
        )]);
        let r = dnsbl_zone(&dns, EXIT, Z).await;
        assert_eq!(
            r.listing,
            Listing::Listed {
                codes: vec!["127.0.0.2".into(), "127.0.0.4".into()]
            }
        );
        let mut asked = dns.asked.lock().unwrap().clone();
        asked.sort();
        assert_eq!(
            asked,
            [
                "1.0.0.127.bl.example",
                "2.0.0.127.bl.example",
                "20.100.51.198.bl.example"
            ]
        );
        let r = dnsbl_zone(&working(&[]), EXIT, Z).await;
        assert_eq!(r.listing, Listing::NotListed);
    }

    #[tokio::test]
    async fn dnsbl_public_resolver_cases_are_unknown_not_guessed() {
        let unknown = |l: &Listing| matches!(l, Listing::Unknown { .. });
        // Cloudflare / Quad9 with Spamhaus: 127.255.255.254 for every name.
        let all = &[[127, 255, 255, 254]][..];
        let cf = FakeDns::new(&[
            ("2.0.0.127.bl.example", all),
            ("1.0.0.127.bl.example", all),
            ("20.100.51.198.bl.example", all),
        ]);
        let r = dnsbl_zone(&cf, EXIT, Z).await;
        assert!(unknown(&r.listing));
        assert!(
            format!("{:?}", r.listing).contains("public resolvers"),
            "{:?}",
            r.listing
        );
        // Google with Spamhaus: NXDOMAIN for every name, which alone would read "not listed".
        let r = dnsbl_zone(&FakeDns::new(&[]), EXIT, Z).await;
        assert!(unknown(&r.listing), "{:?}", r.listing);
        // NXDOMAIN hijacking: every name answers with a web server address.
        let w = &[[203, 0, 113, 80]][..];
        let hij = FakeDns::new(&[
            ("2.0.0.127.bl.example", w),
            ("1.0.0.127.bl.example", w),
            ("20.100.51.198.bl.example", w),
        ]);
        assert!(unknown(&dnsbl_zone(&hij, EXIT, Z).await.listing));
        // Negative test entry answering as listed.
        let both = working(&[("1.0.0.127.bl.example", &[[127, 0, 0, 2]])]);
        assert!(unknown(&dnsbl_zone(&both, EXIT, Z).await.listing));
        // Working test entries, but the exit's own answer is an error code / a rewrite.
        let rl = working(&[("20.100.51.198.bl.example", &[[127, 255, 255, 255]])]);
        let l = dnsbl_zone(&rl, EXIT, Z).await.listing;
        assert!(unknown(&l) && format!("{l:?}").contains("too many"));
        // A failed lookup.
        let mut f = working(&[]);
        f.fail = vec!["20.100.51.198.bl.example".into()];
        assert!(unknown(&dnsbl_zone(&f, EXIT, Z).await.listing));
    }

    #[tokio::test]
    async fn dnsbl_check_order_timeouts_and_non_public_ips() {
        let zones = [
            Z,
            DnsblZone {
                zone: "two.example",
                name: "Two",
            },
        ];
        let dns: Arc<dyn Resolver> =
            Arc::new(working(&[("20.100.51.198.bl.example", &[[127, 0, 0, 2]])]));
        let r = dnsbl_check(
            dns.clone(),
            IpAddr::V4(EXIT),
            &zones,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(r.len(), 2);
        assert_eq!(
            (r[0].zone.as_str(), &r[0].listing),
            (
                "bl.example",
                &Listing::Listed {
                    codes: vec!["127.0.0.2".into()]
                }
            )
        );
        assert!(
            matches!(r[1].listing, Listing::Unknown { .. }),
            "two.example has no test entry"
        );
        // Slow resolver: every zone times out as unknown.
        let mut slow = working(&[]);
        slow.delay = Duration::from_secs(5);
        let r = dnsbl_check(
            Arc::new(slow),
            IpAddr::V4(EXIT),
            &zones,
            Duration::from_millis(200),
        )
        .await;
        assert!(r.iter().all(|x| x.listing
            == Listing::Unknown {
                reason: "timed out".into()
            }));
        // IPv6 and private exits are not looked up at all.
        let fake = Arc::new(working(&[]));
        for ip in ["2001:db8::1", "192.168.1.5", "127.0.0.1"] {
            let r = dnsbl_check(
                fake.clone(),
                ip.parse().unwrap(),
                &zones,
                Duration::from_secs(1),
            )
            .await;
            assert!(r
                .iter()
                .all(|x| matches!(x.listing, Listing::Unknown { .. })));
        }
        assert!(fake.asked.lock().unwrap().is_empty());
    }

    #[test]
    fn zones_and_serialization() {
        assert_eq!(DNSBL_ZONES[0].zone, "zen.spamhaus.org");
        assert!(DNSBL_ZONES
            .iter()
            .all(|z| crate::doh::valid_hostname(&format!("2.0.0.127.{}", z.zone))));
        let r = DnsblResult {
            zone: "z".into(),
            name: "Z".into(),
            listing: Listing::Listed {
                codes: vec!["127.0.0.2".into()],
            },
        };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"zone":"z","name":"Z","state":"listed","codes":["127.0.0.2"]}"#
        );
        let c: Check<UdpResult> = Check::Ok {
            result: UdpResult::Unsupported { reply: 7 },
        };
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            r#"{"status":"ok","result":{"support":"unsupported","reply":7}}"#
        );
        let checks = ProxyChecks {
            checked_ms: 1,
            exit: Check::Ok {
                result: IpInfo {
                    asn: Some(1),
                    ..Default::default()
                },
            },
            udp: Check::skipped("x"),
            blacklist: Check::Failed { reason: "y".into() },
            speed: None,
        };
        let j = serde_json::to_string(&checks).unwrap();
        assert_eq!(serde_json::from_str::<ProxyChecks>(&j).unwrap(), checks);
        assert_eq!(
            EchoUrl::parse(DEFAULT_IP_INFO_URL).unwrap().to_string(),
            DEFAULT_IP_INFO_URL
        );
        assert_eq!(
            EchoUrl::parse(DEFAULT_SPEED_TEST_URL).unwrap().to_string(),
            DEFAULT_SPEED_TEST_URL
        );
    }
}
