//! DNS-over-HTTPS (F05): hostnames are resolved over HTTPS (RFC 8484, POST
//! `application/dns-message`), never with the system resolver, so no plaintext DNS leaves
//! the machine.
//!
//! In the relay the DoH request itself travels through the profile's upstream proxy
//! ([`DohRoute::ViaProxy`]), so the DoH provider sees the proxy's exit IP, not the user's.
//! [`DohRoute::Direct`] exists only to bootstrap a proxy given by host name.
//!
//! Transport is HTTP/2 when the provider agrees to it by ALPN (`h2`, offered first), else
//! HTTP/1.1. RFC 8484 section 5.2 names HTTP/2 as the minimum recommended version and
//! some providers enforce it: Quad9 answers every HTTP/1.1 request with
//! `505 HTTP Version Not Supported`.
//!
//! The provider is reached by IP literal (no bootstrap lookup) and authenticated by its
//! certificate for the provider host name (rustls + webpki-roots). Only A records are
//! asked for: IPv6 is blocked by Network Guard.
//!
//! The resolver is a trait so tests inject a mock and the relay never touches system DNS.

use crate::endpoint::ProxyEndpoint;
use crate::net::{
    open_tunnel, tls_config, tls_connect_with, with_timeout, BoxStream, IoStream, NetError,
    NetResult, TargetAddr,
};
use bytes::Bytes;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Resolves a host name to IPv4 addresses without using the system resolver.
pub trait Resolver: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, NetResult<Vec<Ipv4Addr>>>;
}

/// DoH provider. Defaults: Cloudflare, Google, Quad9.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DohProvider {
    #[default]
    Cloudflare,
    Google,
    Quad9,
    /// Any RFC 8484 server, reached at `ip:443` with a certificate for `host`.
    Custom {
        ip: IpAddr,
        host: String,
        path: String,
    },
}

impl DohProvider {
    pub fn ip(&self) -> IpAddr {
        match self {
            DohProvider::Cloudflare => IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            DohProvider::Google => IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            DohProvider::Quad9 => IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            DohProvider::Custom { ip, .. } => *ip,
        }
    }

    pub fn host(&self) -> &str {
        match self {
            DohProvider::Cloudflare => "cloudflare-dns.com",
            DohProvider::Google => "dns.google",
            DohProvider::Quad9 => "dns.quad9.net",
            DohProvider::Custom { host, .. } => host,
        }
    }

    pub fn path(&self) -> &str {
        match self {
            DohProvider::Custom { path, .. } => path,
            _ => "/dns-query",
        }
    }
}

// ---- DNS wire format ----------------------------------------------------------------

fn bad(m: &str) -> NetError {
    NetError::Protocol(format!("DNS: {m}"))
}

/// Validate a host name for a DNS query (LDH labels, ≤ 253 bytes).
pub fn valid_hostname(name: &str) -> bool {
    let n = name.trim_end_matches('.');
    !n.is_empty()
        && n.len() <= 253
        && n.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Build a recursive A query.
pub fn build_query(id: u16, name: &str) -> NetResult<Vec<u8>> {
    if !valid_hostname(name) {
        return Err(bad("invalid host name"));
    }
    let mut q = Vec::with_capacity(18 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, 1 question
    for label in name.trim_end_matches('.').split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.to_ascii_lowercase().as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]); // root, QTYPE A, QCLASS IN
    Ok(q)
}

fn skip_name(b: &[u8], mut i: usize) -> NetResult<usize> {
    loop {
        let len = *b.get(i).ok_or_else(|| bad("truncated name"))?;
        if len & 0xC0 == 0xC0 {
            return if i + 2 <= b.len() {
                Ok(i + 2)
            } else {
                Err(bad("truncated pointer"))
            };
        }
        if len & 0xC0 != 0 {
            return Err(bad("bad label"));
        }
        if len == 0 {
            return Ok(i + 1);
        }
        i += 1 + len as usize;
    }
}

/// Parse a response to [`build_query`]: IPv4 answers and the smallest TTL (seconds).
/// NXDOMAIN yields an empty list.
pub fn parse_response(b: &[u8], id: u16) -> NetResult<(Vec<Ipv4Addr>, u32)> {
    if b.len() < 12 {
        return Err(bad("short message"));
    }
    if u16::from_be_bytes([b[0], b[1]]) != id {
        return Err(bad("id mismatch"));
    }
    if b[2] & 0x80 == 0 {
        return Err(bad("not a response"));
    }
    let rcode = b[3] & 0x0F;
    if rcode == 3 {
        return Ok((Vec::new(), 60));
    }
    if rcode != 0 {
        return Err(bad(&format!("rcode {rcode}")));
    }
    let qd = u16::from_be_bytes([b[4], b[5]]);
    let an = u16::from_be_bytes([b[6], b[7]]);
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(b, i)? + 4;
    }
    let mut ips = Vec::new();
    let mut ttl = u32::MAX;
    for _ in 0..an {
        i = skip_name(b, i)?;
        let h = b.get(i..i + 10).ok_or_else(|| bad("truncated answer"))?;
        let rtype = u16::from_be_bytes([h[0], h[1]]);
        let class = u16::from_be_bytes([h[2], h[3]]);
        let rttl = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        let rdlen = u16::from_be_bytes([h[8], h[9]]) as usize;
        i += 10;
        let rdata = b.get(i..i + rdlen).ok_or_else(|| bad("truncated rdata"))?;
        if rtype == 1 && class == 1 && rdlen == 4 {
            ips.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
            ttl = ttl.min(rttl);
        }
        i += rdlen;
    }
    Ok((ips, if ttl == u32::MAX { 60 } else { ttl }))
}

// ---- Minimal HTTP/1.1 client --------------------------------------------------------

fn dechunk(mut body: &[u8]) -> NetResult<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let pos = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| bad("bad chunk"))?;
        let size_str = std::str::from_utf8(&body[..pos]).map_err(|_| bad("bad chunk"))?;
        let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| bad("bad chunk size"))?;
        body = &body[pos + 2..];
        if size == 0 {
            return Ok(out);
        }
        out.extend_from_slice(body.get(..size).ok_or_else(|| bad("truncated chunk"))?);
        body = body.get(size + 2..).ok_or_else(|| bad("truncated chunk"))?;
    }
}

/// Split a full HTTP response into status and body (handles Content-Length, chunked,
/// and read-to-close).
pub(crate) fn parse_http_response(raw: &[u8]) -> NetResult<(u16, Vec<u8>)> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| bad("no HTTP head"))?;
    let head = std::str::from_utf8(&raw[..end]).map_err(|_| bad("HTTP head not UTF-8"))?;
    let status = crate::net::http_status(head)?;
    let body = &raw[end + 4..];
    let mut chunked = false;
    let mut len = None;
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            } else if k == "content-length" {
                len = v.parse::<usize>().ok();
            }
        }
    }
    let body = if chunked {
        dechunk(body)?
    } else if let Some(n) = len {
        body.get(..n).ok_or_else(|| bad("truncated body"))?.to_vec()
    } else {
        body.to_vec()
    };
    Ok((status, body))
}

/// Largest DoH response body accepted.
const MAX_DOH_RESPONSE: usize = 64 * 1024;

const DNS_MESSAGE: &str = "application/dns-message";

/// HTTP version agreed with the provider during the TLS handshake (ALPN).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HttpVersion {
    H2,
    Http11,
}

impl HttpVersion {
    /// `h2` means HTTP/2; `http/1.1` or no ALPN answer at all means HTTP/1.1.
    pub(crate) fn from_alpn(proto: Option<&[u8]>) -> Self {
        if proto == Some(b"h2".as_slice()) {
            HttpVersion::H2
        } else {
            HttpVersion::Http11
        }
    }
}

/// rustls config for DoH: the shared roots and provider, plus ALPN `h2` then `http/1.1`.
/// Kept apart from [`tls_config`] so the HTTP/1.1-only callers (IP echo, checks) never
/// get HTTP/2 negotiated on them.
pub(crate) fn doh_tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut cfg = (*tls_config()).clone();
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(cfg)
    })
    .clone()
}

/// TLS handshake with the provider; returns the stream and the agreed HTTP version.
async fn doh_tls_connect(
    io: BoxStream,
    provider: &DohProvider,
) -> NetResult<(BoxStream, HttpVersion)> {
    let tls = tls_connect_with(io, provider.host(), doh_tls_config()).await?;
    let version = HttpVersion::from_alpn(tls.get_ref().1.alpn_protocol());
    Ok((Box::new(tls), version))
}

/// One DoH exchange (RFC 8484 POST) over an already-open TLS stream, in `version`.
async fn doh_exchange(
    mut s: BoxStream,
    version: HttpVersion,
    provider: &DohProvider,
    query: &[u8],
) -> NetResult<Vec<u8>> {
    match version {
        HttpVersion::H2 => h2_exchange(s, provider, query).await,
        HttpVersion::Http11 => h1_exchange(&mut *s, provider, query).await,
    }
}

/// HTTP/1.1 exchange (providers that do not offer `h2`).
async fn h1_exchange<S: IoStream + ?Sized>(
    s: &mut S,
    provider: &DohProvider,
    query: &[u8],
) -> NetResult<Vec<u8>> {
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {DNS_MESSAGE}\r\nAccept: {DNS_MESSAGE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        provider.path(),
        provider.host(),
        query.len()
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(query).await?;
    s.flush().await?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > MAX_DOH_RESPONSE {
                    return Err(bad("DoH response too large"));
                }
            }
            // Servers that close without TLS close_notify: keep what was read.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => break,
            Err(e) => return Err(e.into()),
        }
    }
    let (status, body) = parse_http_response(&raw)?;
    if status != 200 {
        return Err(NetError::Refused(status));
    }
    Ok(body)
}

fn h2_err(e: h2::Error) -> NetError {
    match e.get_io() {
        Some(io) => NetError::Io(io.kind().to_string()),
        None => NetError::Protocol(format!("HTTP/2: {e}")),
    }
}

/// HTTP/2 exchange: one stream on a fresh connection (no server push). The connection
/// task is dropped as soon as the response body is read or the exchange fails.
async fn h2_exchange<S: IoStream + 'static>(
    s: S,
    provider: &DohProvider,
    query: &[u8],
) -> NetResult<Vec<u8>> {
    let (client, conn) = h2::client::Builder::new()
        .enable_push(false)
        .handshake::<_, Bytes>(s)
        .await
        .map_err(h2_err)?;
    let driver = tokio::spawn(conn);
    let result = h2_request(client, provider, query).await;
    driver.abort();
    result
}

async fn h2_request(
    client: h2::client::SendRequest<Bytes>,
    provider: &DohProvider,
    query: &[u8],
) -> NetResult<Vec<u8>> {
    use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
    let mut client = client.ready().await.map_err(h2_err)?;
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("https://{}{}", provider.host(), provider.path()))
        .header(CONTENT_TYPE, DNS_MESSAGE)
        .header(ACCEPT, DNS_MESSAGE)
        .header(CONTENT_LENGTH, query.len())
        .body(())
        .map_err(|_| bad("invalid DoH URL"))?;
    let (response, mut send) = client.send_request(req, false).map_err(h2_err)?;
    send.send_data(Bytes::copy_from_slice(query), true)
        .map_err(h2_err)?;
    let response = response.await.map_err(h2_err)?;
    let status = response.status().as_u16();
    let mut body = response.into_body();
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(h2_err)?;
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
        if out.len() > MAX_DOH_RESPONSE {
            return Err(bad("DoH response too large"));
        }
    }
    if status != 200 {
        return Err(NetError::Refused(status));
    }
    Ok(out)
}

/// How DoH requests reach the provider.
#[derive(Debug, Clone)]
pub enum DohRoute {
    /// Straight to the provider (bootstrap only).
    Direct,
    /// Through the profile's upstream proxy, resolved to `addr`.
    ViaProxy {
        proxy: ProxyEndpoint,
        addr: SocketAddr,
    },
}

/// DoH resolver with a small TTL cache (TTL clamped to 30 s ..= 10 min).
pub struct DohResolver {
    provider: DohProvider,
    route: DohRoute,
    timeout: Duration,
    cache: Mutex<HashMap<String, (Vec<Ipv4Addr>, Instant)>>,
}

impl DohResolver {
    pub fn new(provider: DohProvider, route: DohRoute, timeout: Duration) -> Self {
        Self {
            provider,
            route,
            timeout,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn provider(&self) -> &DohProvider {
        &self.provider
    }

    async fn lookup(&self, host: &str) -> NetResult<Vec<Ipv4Addr>> {
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some((ips, exp)) = self.cache.lock().expect("cache lock").get(&key) {
            if *exp > Instant::now() {
                return Ok(ips.clone());
            }
        }
        let mut idb = [0u8; 2];
        rand::rngs::OsRng.fill_bytes(&mut idb);
        let id = u16::from_be_bytes(idb);
        let query = build_query(id, &key)?;
        let target = SocketAddr::new(self.provider.ip(), 443);
        let body = with_timeout(self.timeout, async {
            let raw: BoxStream = match &self.route {
                DohRoute::Direct => Box::new(TcpStream::connect(target).await?),
                DohRoute::ViaProxy { proxy, addr } => {
                    open_tunnel(proxy, *addr, &TargetAddr::Ip(target), self.timeout).await?
                }
            };
            let (tls, version) = doh_tls_connect(raw, &self.provider).await?;
            doh_exchange(tls, version, &self.provider, &query).await
        })
        .await?;
        let (ips, ttl) = parse_response(&body, id)?;
        let ttl = Duration::from_secs(u64::from(ttl.clamp(30, 600)));
        self.cache
            .lock()
            .expect("cache lock")
            .insert(key, (ips.clone(), Instant::now() + ttl));
        Ok(ips)
    }
}

impl Resolver for DohResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, NetResult<Vec<Ipv4Addr>>> {
        Box::pin(self.lookup(host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(id: u16, ips: &[[u8; 4]], ttl: u32) -> Vec<u8> {
        let mut q = build_query(id, "example.test").unwrap();
        q[2] = 0x81;
        q[3] = 0x80;
        q[7] = ips.len() as u8;
        // a CNAME first, to exercise skipping non-A records
        q.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 10, 0, 2, 0xC0, 12]);
        q[7] += 1;
        for ip in ips {
            q.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
            q.extend_from_slice(&ttl.to_be_bytes());
            q.extend_from_slice(&[0, 4]);
            q.extend_from_slice(ip);
        }
        q
    }

    #[test]
    fn query_layout() {
        let q = build_query(0xBEEF, "A.Example.test.").unwrap();
        assert_eq!(&q[..2], &[0xBE, 0xEF]);
        assert_eq!(&q[12..], b"\x01a\x07example\x04test\x00\x00\x01\x00\x01");
        assert!(build_query(1, "bad host").is_err());
        assert!(build_query(1, "").is_err());
        assert!(build_query(1, &"a".repeat(64)).is_err());
    }

    #[test]
    fn parses_answers() {
        let r = answer(7, &[[203, 0, 113, 7], [203, 0, 113, 8]], 300);
        let (ips, ttl) = parse_response(&r, 7).unwrap();
        assert_eq!(
            ips,
            [Ipv4Addr::new(203, 0, 113, 7), Ipv4Addr::new(203, 0, 113, 8)]
        );
        assert_eq!(ttl, 300);
        assert!(parse_response(&r, 8).is_err());
        assert!(parse_response(&r[..r.len() - 2], 7).is_err());
    }

    #[test]
    fn nxdomain_is_empty() {
        let mut r = build_query(9, "nope.test").unwrap();
        r[2] = 0x81;
        r[3] = 0x83;
        assert_eq!(parse_response(&r, 9).unwrap().0, Vec::<Ipv4Addr>::new());
    }

    #[test]
    fn http_bodies() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcEXTRA";
        assert_eq!(parse_http_response(raw).unwrap(), (200, b"abc".to_vec()));
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n";
        assert_eq!(parse_http_response(raw).unwrap(), (200, b"abcde".to_vec()));
        let raw = b"HTTP/1.1 400 Bad\r\n\r\n";
        assert_eq!(parse_http_response(raw).unwrap().0, 400);
    }

    #[test]
    fn providers() {
        assert_eq!(DohProvider::default(), DohProvider::Cloudflare);
        assert_eq!(DohProvider::Google.host(), "dns.google");
        assert_eq!(DohProvider::Quad9.ip().to_string(), "9.9.9.9");
        assert_eq!(DohProvider::Cloudflare.path(), "/dns-query");
    }

    #[test]
    fn alpn_selects_version() {
        assert_eq!(HttpVersion::from_alpn(Some(b"h2")), HttpVersion::H2);
        assert_eq!(
            HttpVersion::from_alpn(Some(b"http/1.1")),
            HttpVersion::Http11
        );
        assert_eq!(HttpVersion::from_alpn(None), HttpVersion::Http11);
    }

    #[test]
    fn doh_offers_h2_first_and_shared_config_stays_http11() {
        assert_eq!(
            doh_tls_config().alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        // IP echo / checks speak HTTP/1.1 only: they must never negotiate h2.
        assert!(tls_config().alpn_protocols.is_empty());
    }

    /// Minimal in-process HTTP/2 DoH server: checks the request, answers `status` with
    /// `answer` (a DNS message for `id`) split in two DATA frames.
    async fn h2_server(io: tokio::io::DuplexStream, status: u16, body: Vec<u8>) {
        let mut conn = h2::server::handshake(io).await.unwrap();
        while let Some(req) = conn.accept().await {
            let Ok((req, mut respond)) = req else { break };
            let body = body.clone();
            tokio::spawn(async move {
                assert_eq!(req.method(), http::Method::POST);
                assert_eq!(req.uri().path(), "/dns-query");
                assert_eq!(req.uri().authority().unwrap().as_str(), "dns.quad9.net");
                assert_eq!(req.headers()["content-type"], DNS_MESSAGE);
                assert_eq!(req.headers()["accept"], DNS_MESSAGE);
                let mut rb = req.into_body();
                let mut got = Vec::new();
                while let Some(c) = rb.data().await {
                    let c = c.unwrap();
                    let _ = rb.flow_control().release_capacity(c.len());
                    got.extend_from_slice(&c);
                }
                assert_eq!(&got[12..], b"\x07example\x04test\x00\x00\x01\x00\x01");
                let resp = http::Response::builder()
                    .status(status)
                    .header("content-type", DNS_MESSAGE)
                    .body(())
                    .unwrap();
                let mut send = respond.send_response(resp, false).unwrap();
                let mid = body.len() / 2;
                send.send_data(Bytes::copy_from_slice(&body[..mid]), false)
                    .unwrap();
                send.send_data(Bytes::copy_from_slice(&body[mid..]), true)
                    .unwrap();
            });
        }
    }

    #[tokio::test]
    async fn h2_exchange_round_trip() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let reply = answer(0x1234, &[[203, 0, 113, 9]], 120);
        tokio::spawn(h2_server(server, 200, reply.clone()));
        let q = build_query(0x1234, "example.test").unwrap();
        let body = h2_exchange(client, &DohProvider::Quad9, &q).await.unwrap();
        assert_eq!(body, reply);
        let (ips, ttl) = parse_response(&body, 0x1234).unwrap();
        assert_eq!((ips, ttl), (vec![Ipv4Addr::new(203, 0, 113, 9)], 120));
    }

    #[tokio::test]
    async fn h2_exchange_non_200_is_refused() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(h2_server(server, 400, b"bad".to_vec()));
        let q = build_query(1, "example.test").unwrap();
        assert_eq!(
            h2_exchange(client, &DohProvider::Quad9, &q).await,
            Err(NetError::Refused(400))
        );
    }

    #[tokio::test]
    async fn h2_exchange_caps_response_size() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(h2_server(server, 200, vec![0u8; MAX_DOH_RESPONSE + 10]));
        let q = build_query(1, "example.test").unwrap();
        assert!(matches!(
            h2_exchange(client, &DohProvider::Quad9, &q).await,
            Err(NetError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn h2_exchange_rejects_non_h2_peer() {
        // A peer that answers in HTTP/1.1 (no h2 preface) fails cleanly, not hangs.
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = server.read(&mut buf).await;
            let _ = server
                .write_all(b"HTTP/1.1 505 HTTP Version Not Supported\r\nConnection: close\r\n\r\n")
                .await;
        });
        let q = build_query(1, "example.test").unwrap();
        let r = with_timeout(
            Duration::from_secs(5),
            h2_exchange(client, &DohProvider::Quad9, &q),
        )
        .await;
        assert!(r.is_err() && r != Err(NetError::Timeout), "{r:?}");
    }

    #[tokio::test]
    async fn http11_fallback_exchange() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let reply = answer(7, &[[198, 51, 100, 1]], 60);
        let r2 = reply.clone();
        tokio::spawn(async move {
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = server.read(&mut buf).await.unwrap();
                req.extend_from_slice(&buf[..n]);
            }
            let head = String::from_utf8_lossy(&req).to_string();
            assert!(head.starts_with("POST /dns-query HTTP/1.1\r\nHost: cloudflare-dns.com\r\n"));
            let mut resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {DNS_MESSAGE}\r\nContent-Length: {}\r\n\r\n",
                r2.len()
            )
            .into_bytes();
            resp.extend_from_slice(&r2);
            server.write_all(&resp).await.unwrap();
        });
        let q = build_query(7, "example.test").unwrap();
        let s: BoxStream = Box::new(client);
        let body = doh_exchange(s, HttpVersion::Http11, &DohProvider::Cloudflare, &q)
            .await
            .unwrap();
        assert_eq!(body, reply);
    }

    /// Live: resolves through each built-in provider over the real internet (direct route).
    /// Run with `cargo test -p vanta-proxy live_doh -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "needs internet"]
    async fn live_doh_all_providers() {
        for p in [
            DohProvider::Cloudflare,
            DohProvider::Google,
            DohProvider::Quad9,
        ] {
            // ALPN outcome, for the record (Quad9 requires h2).
            let tcp = TcpStream::connect(SocketAddr::new(p.ip(), 443))
                .await
                .unwrap();
            let (_, version) = doh_tls_connect(Box::new(tcp), &p).await.unwrap();
            let r = DohResolver::new(p.clone(), DohRoute::Direct, Duration::from_secs(10));
            let ips = r.resolve("example.com").await;
            println!("{:?}: ALPN {:?}, example.com -> {:?}", p, version, ips);
            assert_eq!(version, HttpVersion::H2, "{p:?}");
            assert!(!ips.unwrap().is_empty(), "{p:?}");
        }
    }

    /// Live: the HTTP/1.1 path still works where the provider allows it, and Quad9's
    /// refusal of HTTP/1.1 is the 505 this module works around.
    #[tokio::test]
    #[ignore = "needs internet"]
    async fn live_doh_http11_path() {
        let q = build_query(0x4242, "example.com").unwrap();
        for (p, want_ok) in [
            (DohProvider::Cloudflare, true),
            (DohProvider::Google, true),
            (DohProvider::Quad9, false),
        ] {
            let tcp = TcpStream::connect(SocketAddr::new(p.ip(), 443))
                .await
                .unwrap();
            let tls = crate::net::tls_connect(tcp, p.host()).await.unwrap();
            let r = doh_exchange(tls, HttpVersion::Http11, &p, &q).await;
            println!("{p:?} over HTTP/1.1: {:?}", r.as_ref().map(|b| b.len()));
            if want_ok {
                assert!(parse_response(&r.unwrap(), 0x4242).is_ok());
            } else {
                assert_eq!(r, Err(NetError::Refused(505)));
            }
        }
    }

    /// Live, through an HTTP CONNECT proxy (the production route): set
    /// `VANTA_LIVE_PROXY=http://user:pass@host:port` (percent-encoded login), then
    /// `cargo test -p vanta-proxy live_doh_via_proxy -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "needs internet and VANTA_LIVE_PROXY"]
    async fn live_doh_via_proxy() {
        let Ok(url) = std::env::var("VANTA_LIVE_PROXY") else {
            println!("VANTA_LIVE_PROXY not set: skipped");
            return;
        };
        let rest = url.strip_prefix("http://").expect("http:// proxy URL");
        let (login, hostport) = rest.rsplit_once('@').expect("user:pass@host:port");
        let (user, pass) = login.split_once(':').expect("user:pass");
        let unpct = |v: &str| {
            let b = v.as_bytes();
            let mut out = Vec::new();
            let mut i = 0;
            while i < b.len() {
                if b[i] == b'%' && i + 2 < b.len() {
                    out.push(u8::from_str_radix(&v[i + 1..i + 3], 16).unwrap());
                    i += 3;
                } else {
                    out.push(b[i]);
                    i += 1;
                }
            }
            String::from_utf8(out).unwrap()
        };
        let (host, port) = hostport.rsplit_once(':').unwrap();
        let port: u16 = port.parse().unwrap();
        let proxy = ProxyEndpoint::new(
            crate::endpoint::ProxyScheme::Http,
            host,
            port,
            Some(crate::endpoint::Credentials::new(unpct(user), unpct(pass))),
        );
        // Test harness only: the proxy host is resolved with the system resolver here.
        let addr = tokio::net::lookup_host((host, port))
            .await
            .unwrap()
            .find(|a| a.is_ipv4())
            .unwrap();
        for p in [
            DohProvider::Cloudflare,
            DohProvider::Google,
            DohProvider::Quad9,
        ] {
            let route = DohRoute::ViaProxy {
                proxy: proxy.clone(),
                addr,
            };
            let r = DohResolver::new(p.clone(), route, Duration::from_secs(15));
            let ips = r.resolve("example.com").await;
            println!("{p:?} via proxy: example.com -> {ips:?}");
            assert!(!ips.unwrap().is_empty(), "{p:?}");
        }
    }
}
