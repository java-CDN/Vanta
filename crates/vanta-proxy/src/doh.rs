//! DNS-over-HTTPS (F05): hostnames are resolved over HTTPS (RFC 8484, POST
//! `application/dns-message`), never with the system resolver, so no plaintext DNS leaves
//! the machine.
//!
//! In the relay the DoH request itself travels through the profile's upstream proxy
//! ([`DohRoute::ViaProxy`]), so the DoH provider sees the proxy's exit IP, not the user's.
//! [`DohRoute::Direct`] exists only to bootstrap a proxy given by host name.
//!
//! The provider is reached by IP literal (no bootstrap lookup) and authenticated by its
//! certificate for the provider host name (rustls + webpki-roots). Only A records are
//! asked for: IPv6 is blocked by Network Guard.
//!
//! The resolver is a trait so tests inject a mock and the relay never touches system DNS.

use crate::endpoint::ProxyEndpoint;
use crate::net::{
    open_tunnel, tls_connect, with_timeout, BoxStream, NetError, NetResult, TargetAddr,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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

/// One DoH exchange over an already-open TLS stream.
async fn doh_exchange(
    mut s: BoxStream,
    provider: &DohProvider,
    query: &[u8],
) -> NetResult<Vec<u8>> {
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
                if raw.len() > 64 * 1024 {
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
            let tls = tls_connect(raw, self.provider.host()).await?;
            doh_exchange(tls, &self.provider, &query).await
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
}
