//! IP echo for the Health Check (F03): which public address a request leaves from.
//!
//! An IP echo endpoint is a plain-text HTTPS service that answers `GET <path>` with the
//! caller's address and nothing else (the default is [`DEFAULT_IP_ECHO_URL`]). The user can
//! point Vanta at another one (Settings › Privacy); [`EchoUrl::parse`] checks it.
//!
//! - [`exit_ip_via_proxy`]: the profile's **exit IP**. The request goes through the
//!   profile's upstream proxy with the same tunnel code the relay uses
//!   ([`crate::net::open_tunnel`]); the echo host name is handed to the proxy, so nothing is
//!   resolved locally.
//! - [`host_ip_direct`]: the PC's own **public IP**, over a direct connection (the echo host
//!   is resolved with the given resolver, the DoH bootstrap in production, never the
//!   system resolver). Health runs only compare it with what the exit and the page
//!   reveal; it is never sent anywhere else and never logged.
//! - [`primary_local_ip`]: the PC's own address on the interface that routes to the
//!   internet (a connected UDP socket; no packet is sent).
//!
//! Errors are [`NetError`] values, which never carry an address or a password.

use crate::doh::{parse_http_response, valid_hostname, Resolver};
use crate::endpoint::ProxyEndpoint;
use crate::guard::is_blocked_ip;
use crate::net::{
    open_tunnel, tls_connect, with_timeout, BoxStream, NetError, NetResult, TargetAddr,
};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use vanta_types::{Result, VantaError};

/// Default IP echo endpoint: ipify's plain-text API (IPv4, answers `203.0.113.7`).
pub const DEFAULT_IP_ECHO_URL: &str = "https://api.ipify.org/";

/// Largest echo / IP-info response read (head and body).
pub(crate) const MAX_RESPONSE: usize = 16 * 1024;

/// A validated `https://host[:port][/path]` IP echo URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoUrl {
    host: String,
    port: u16,
    /// Starts with `/`; may carry a query (`/?format=text`).
    path: String,
}

impl Default for EchoUrl {
    fn default() -> Self {
        Self::parse(DEFAULT_IP_ECHO_URL).expect("default IP echo URL is valid")
    }
}

impl fmt::Display for EchoUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.port == 443 {
            write!(f, "https://{}{}", self.host, self.path)
        } else {
            write!(f, "https://{}:{}{}", self.host, self.port, self.path)
        }
    }
}

fn invalid(m: &str) -> VantaError {
    VantaError::Invalid(format!("IP echo URL: {m}"))
}

impl EchoUrl {
    /// Accepts `https://` URLs to a public host name or IPv4 address, with an optional port
    /// and path. Refused: other schemes, user info, fragments, IPv6 literals, `localhost`,
    /// and addresses the Network Guard blocks (LAN, loopback...).
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.len() > 512 {
            return Err(invalid("too long"));
        }
        if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(invalid("contains spaces or control characters"));
        }
        let rest = match s.get(..8) {
            Some(p) if p.eq_ignore_ascii_case("https://") => &s[8..],
            _ => return Err(invalid("must start with https://")),
        };
        if rest.contains('#') {
            return Err(invalid("must not contain a fragment (#)"));
        }
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
            Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
            None => (rest, "/".to_string()),
        };
        if authority.contains('@') {
            return Err(invalid("must not contain a user name or password"));
        }
        if authority.starts_with('[') {
            return Err(invalid(
                "IPv6 addresses are not supported (IPv6 is blocked)",
            ));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                let port: u16 = p.parse().map_err(|_| invalid("bad port"))?;
                if port == 0 {
                    return Err(invalid("bad port"));
                }
                (h, port)
            }
            None => (authority, 443),
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return Err(invalid("missing host"));
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_blocked_ip(ip) {
                return Err(invalid("must be a public address"));
            }
        } else if !valid_hostname(&host) || !host.contains('.') {
            return Err(invalid("bad host name"));
        } else if host == "localhost" || host.ends_with(".localhost") {
            return Err(invalid("must be a public host"));
        }
        Ok(Self { host, port, path })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn target(&self) -> TargetAddr {
        match self.host.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, self.port)),
            Err(_) => TargetAddr::Domain(self.host.clone(), self.port),
        }
    }
}

/// The echo answer: one IP address, optionally surrounded by whitespace.
pub fn parse_echo_body(body: &[u8]) -> NetResult<IpAddr> {
    let bad = || NetError::Protocol("IP echo: answer is not a plain IP address".into());
    if body.len() > 64 {
        return Err(bad());
    }
    std::str::from_utf8(body)
        .map_err(|_| bad())?
        .trim()
        .parse::<IpAddr>()
        .map_err(|_| bad())
}

/// Send `GET <path>` for `url` with only `Host`, `Accept` and `Connection: close` (nothing
/// that identifies Vanta or the PC).
pub(crate) async fn send_get(s: &mut BoxStream, url: &EchoUrl, accept: &str) -> NetResult<()> {
    let host = if url.port == 443 {
        url.host.clone()
    } else {
        format!("{}:{}", url.host, url.port)
    };
    let head = format!(
        "GET {} HTTP/1.1\r\nHost: {host}\r\nAccept: {accept}\r\nConnection: close\r\n\r\n",
        url.path
    );
    s.write_all(head.as_bytes()).await?;
    s.flush().await?;
    Ok(())
}

/// Read a whole response (until the server closes), refusing more than `max` bytes.
pub(crate) async fn read_capped(s: &mut BoxStream, max: usize, what: &str) -> NetResult<Vec<u8>> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 2048];
    loop {
        match s.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > max {
                    return Err(NetError::Protocol(format!("{what}: response too large")));
                }
            }
            // Servers that close without TLS close_notify: keep what was read.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(raw)
}

/// One small `GET`: status 200 and the body, or an error.
pub(crate) async fn get_body(
    mut s: BoxStream,
    url: &EchoUrl,
    accept: &str,
    what: &str,
) -> NetResult<Vec<u8>> {
    send_get(&mut s, url, accept).await?;
    let raw = read_capped(&mut s, MAX_RESPONSE, what).await?;
    let (status, body) = parse_http_response(&raw)
        .map_err(|_| NetError::Protocol(format!("{what}: malformed HTTP response")))?;
    if status != 200 {
        return Err(NetError::Refused(status));
    }
    Ok(body)
}

/// One `GET` over an open (TLS) stream to the echo endpoint.
pub async fn echo_exchange(s: BoxStream, url: &EchoUrl) -> NetResult<IpAddr> {
    let body = get_body(s, url, "text/plain", "IP echo").await?;
    parse_echo_body(&body)
}

/// TLS to `url` through a tunnel opened by `proxy` (resolved to `addr`); the proxy
/// resolves the host name, nothing is resolved locally.
pub(crate) async fn tls_via_proxy(
    url: &EchoUrl,
    proxy: &ProxyEndpoint,
    addr: SocketAddr,
    timeout: Duration,
) -> NetResult<BoxStream> {
    let tunnel = open_tunnel(proxy, addr, &url.target(), timeout).await?;
    tls_connect(tunnel, &url.host).await
}

/// The exit IP of `proxy` (resolved to `addr`): TLS to the echo endpoint through a tunnel
/// opened by the proxy, which also resolves the echo host.
pub async fn exit_ip_via_proxy(
    url: &EchoUrl,
    proxy: &ProxyEndpoint,
    addr: SocketAddr,
    timeout: Duration,
) -> NetResult<IpAddr> {
    with_timeout(timeout, async {
        let tls = tls_via_proxy(url, proxy, addr, timeout).await?;
        echo_exchange(tls, url).await
    })
    .await
}

/// The PC's public IP over a direct connection to the echo endpoint. The echo host is
/// resolved with `resolver` (DoH, never the system resolver).
pub async fn host_ip_direct(
    url: &EchoUrl,
    resolver: &dyn Resolver,
    timeout: Duration,
) -> NetResult<IpAddr> {
    with_timeout(timeout, async {
        let ip = match url.host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => resolver
                .resolve(&url.host)
                .await?
                .into_iter()
                .find(|ip| !is_blocked_ip(IpAddr::V4(*ip)))
                .map(IpAddr::V4)
                .ok_or_else(|| NetError::Protocol("IP echo: host did not resolve".into()))?,
        };
        let tcp = TcpStream::connect(SocketAddr::new(ip, url.port)).await?;
        let tls = tls_connect(tcp, &url.host).await?;
        echo_exchange(tls, url).await
    })
    .await
}

/// The PC's own address on the interface that routes towards `toward` (a public address).
/// Connecting a UDP socket only picks the route; no packet is sent.
pub fn primary_local_ip(toward: IpAddr) -> Option<IpAddr> {
    let bind: SocketAddr = match toward {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => return None,
    };
    let s = UdpSocket::bind(bind).ok()?;
    s.connect(SocketAddr::new(toward, 443)).ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_unspecified() && !ip.is_loopback()).then_some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::ProxyScheme;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[test]
    fn default_url() {
        let u = EchoUrl::default();
        assert_eq!(u.host(), "api.ipify.org");
        assert_eq!(u.port(), 443);
        assert_eq!(u.path(), "/");
        assert_eq!(u.to_string(), DEFAULT_IP_ECHO_URL);
    }

    #[test]
    fn url_grammar() {
        let u = EchoUrl::parse(" HTTPS://Icanhazip.com ").unwrap();
        assert_eq!((u.host(), u.port(), u.path()), ("icanhazip.com", 443, "/"));
        let u = EchoUrl::parse("https://ifconfig.me:8443/ip").unwrap();
        assert_eq!((u.host(), u.port(), u.path()), ("ifconfig.me", 8443, "/ip"));
        assert_eq!(u.to_string(), "https://ifconfig.me:8443/ip");
        let u = EchoUrl::parse("https://api.ipify.org?format=text").unwrap();
        assert_eq!(u.path(), "/?format=text");
        let u = EchoUrl::parse("https://1.1.1.1/cdn-cgi/trace").unwrap();
        assert!(matches!(u.target(), TargetAddr::Ip(_)));
        assert!(matches!(
            EchoUrl::default().target(),
            TargetAddr::Domain(h, 443) if h == "api.ipify.org"
        ));
        for bad in [
            "",
            "http://api.ipify.org/",
            "ftp://x.example/",
            "api.ipify.org",
            "https://",
            "https://user:pw@api.ipify.org/",
            "https://api.ipify.org/#x",
            "https://api ipify.org/",
            "https://[2001:db8::1]/",
            "https://localhost/",
            "https://echo.localhost/",
            "https://127.0.0.1/",
            "https://192.168.1.1/",
            "https://10.0.0.1/",
            "https://api.ipify.org:0/",
            "https://api.ipify.org:99999/",
            "https://intranet/",
        ] {
            assert!(EchoUrl::parse(bad).is_err(), "{bad} should be refused");
        }
        assert!(EchoUrl::parse(&format!("https://a.example/{}", "x".repeat(600))).is_err());
    }

    #[test]
    fn echo_body() {
        assert_eq!(
            parse_echo_body(b"203.0.113.7\n").unwrap(),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
        assert!(parse_echo_body(b" 2001:db8::7 ").unwrap().is_ipv6());
        assert!(parse_echo_body(b"<html>203.0.113.7</html>").is_err());
        assert!(parse_echo_body(b"").is_err());
        assert!(parse_echo_body(&[b'1'; 100]).is_err());
    }

    /// Serve one canned HTTP response on a duplex pipe; return what the client sent.
    async fn exchange_with(response: &'static [u8], url: &EchoUrl) -> (NetResult<IpAddr>, String) {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(async move {
            let mut req = Vec::new();
            let mut b = [0u8; 1024];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = server.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&b[..n]);
            }
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
            String::from_utf8(req).unwrap()
        });
        let r = echo_exchange(Box::new(client), url).await;
        (r, srv.await.unwrap())
    }

    #[tokio::test]
    async fn exchange_reads_the_ip() {
        let url = EchoUrl::parse("https://echo.example:8443/ip?x=1").unwrap();
        let (r, req) = exchange_with(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\n198.51.100.9",
            &url,
        )
        .await;
        assert_eq!(r.unwrap(), "198.51.100.9".parse::<IpAddr>().unwrap());
        assert!(req.starts_with("GET /ip?x=1 HTTP/1.1\r\n"), "{req}");
        assert!(req.contains("\r\nHost: echo.example:8443\r\n"), "{req}");
        // Nothing that identifies Vanta or the PC goes into the request.
        assert!(!req.to_ascii_lowercase().contains("user-agent"));

        let (r, _) = exchange_with(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nb\r\n203.0.113.5\r\n0\r\n\r\n",
            &EchoUrl::default(),
        )
        .await;
        assert_eq!(r.unwrap(), "203.0.113.5".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn exchange_errors() {
        let u = EchoUrl::default();
        let (r, _) = exchange_with(b"HTTP/1.1 429 Too Many\r\nContent-Length: 0\r\n\r\n", &u).await;
        assert_eq!(r.unwrap_err(), NetError::Refused(429));
        let (r, _) = exchange_with(b"HTTP/1.1 200 OK\r\n\r\n{\"ip\":\"1.2.3.4\"}", &u).await;
        assert!(matches!(r, Err(NetError::Protocol(_))));
        let (r, _) = exchange_with(b"garbage", &u).await;
        assert!(matches!(r, Err(NetError::Protocol(_))));
    }

    /// The exit-IP request goes to the proxy, with the echo host name for the proxy to
    /// resolve; nothing is resolved or connected locally.
    #[tokio::test]
    async fn exit_ip_goes_through_the_proxy_by_name() {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = l.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
        let s2 = seen.clone();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).await.unwrap(); // 05 01 00 (no auth offered)
            s.write_all(&[5, 0]).await.unwrap();
            let mut req = [0u8; 5];
            s.read_exact(&mut req).await.unwrap(); // 05 01 00 03 len
            let mut name = vec![0u8; req[4] as usize + 2];
            s.read_exact(&mut name).await.unwrap();
            s2.lock().unwrap().extend_from_slice(&req);
            s2.lock().unwrap().extend_from_slice(&name);
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            // Not a TLS server: the handshake fails after the tunnel is up.
        });
        let proxy = ProxyEndpoint::new(ProxyScheme::Socks5, "127.0.0.1", addr.port(), None);
        let r = exit_ip_via_proxy(&EchoUrl::default(), &proxy, addr, Duration::from_secs(3)).await;
        assert!(r.is_err());
        let seen = seen.lock().unwrap().clone();
        assert_eq!(&seen[..4], &[5, 1, 0, 3], "SOCKS5 CONNECT by domain name");
        assert_eq!(&seen[5..5 + 13], b"api.ipify.org");
        assert_eq!(&seen[seen.len() - 2..], &443u16.to_be_bytes());
    }

    struct NoDns;
    impl Resolver for NoDns {
        fn resolve<'a>(
            &'a self,
            _: &'a str,
        ) -> crate::doh::BoxFuture<'a, NetResult<Vec<Ipv4Addr>>> {
            Box::pin(async { Ok(vec![Ipv4Addr::new(192, 168, 1, 1)]) })
        }
    }

    #[tokio::test]
    async fn host_ip_refuses_a_private_answer() {
        // A resolver that answers with a LAN address is not followed.
        let r = host_ip_direct(&EchoUrl::default(), &NoDns, Duration::from_secs(1)).await;
        assert!(matches!(r, Err(NetError::Protocol(_))));
    }

    #[test]
    fn local_ip_is_never_loopback() {
        if let Some(ip) = primary_local_ip("192.0.2.1".parse().unwrap()) {
            assert!(!ip.is_loopback() && !ip.is_unspecified());
        }
        assert_eq!(primary_local_ip("2001:db8::1".parse().unwrap()), None);
    }
}
