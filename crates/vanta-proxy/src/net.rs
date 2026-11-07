//! Client side of the upstream protocols: SOCKS5 (RFC 1928 + RFC 1929 login), HTTP CONNECT
//! and HTTPS (TLS to the proxy, rustls/ring, then CONNECT). Shared by the probe, the DoH
//! resolver and the Network Guard relay.

use crate::endpoint::{Credentials, ProxyEndpoint, ProxyScheme};
use base64::Engine;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self, pki_types::ServerName};
use vanta_types::VantaError;

/// Any bidirectional byte stream (plain TCP or TLS).
pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}
pub type BoxStream = Box<dyn IoStream>;

/// Why talking to a proxy failed. Never carries a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    /// TCP connect / read / write failed.
    Io(String),
    Timeout,
    /// The proxy rejected the login.
    Auth,
    /// The proxy spoke something unexpected.
    Protocol(String),
    /// The proxy answered but refused the request (SOCKS reply code or HTTP status).
    Refused(u16),
}

impl NetError {
    /// True when the failure means the proxy itself is down or unusable (trips the kill
    /// switch), as opposed to the proxy refusing one particular target.
    pub fn proxy_down(&self) -> bool {
        matches!(
            self,
            NetError::Io(_) | NetError::Timeout | NetError::Auth | NetError::Protocol(_)
        )
    }
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::Io(e) => write!(f, "connection failed: {e}"),
            NetError::Timeout => f.write_str("timed out"),
            NetError::Auth => f.write_str("proxy rejected the login"),
            NetError::Protocol(e) => write!(f, "protocol error: {e}"),
            NetError::Refused(c) => write!(f, "proxy refused the request ({c})"),
        }
    }
}

impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        NetError::Io(e.kind().to_string())
    }
}

impl From<NetError> for VantaError {
    fn from(e: NetError) -> Self {
        VantaError::Network(e.to_string())
    }
}

pub type NetResult<T> = std::result::Result<T, NetError>;

/// Destination asked of a proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddr::Ip(a) => a.fmt(f),
            TargetAddr::Domain(h, p) => write!(f, "{h}:{p}"),
        }
    }
}

pub(crate) async fn with_timeout<T>(
    d: Duration,
    fut: impl std::future::Future<Output = NetResult<T>>,
) -> NetResult<T> {
    tokio::time::timeout(d, fut)
        .await
        .unwrap_or(Err(NetError::Timeout))
}

/// Shared rustls client config: ring provider, Mozilla roots (webpki-roots), no client auth.
pub(crate) fn tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        Arc::new(cfg)
    })
    .clone()
}

/// TLS client handshake over `io` for `server_name` (DNS name or IP literal).
pub(crate) async fn tls_connect<S>(io: S, server_name: &str) -> NetResult<BoxStream>
where
    S: IoStream + 'static,
{
    let name = match server_name.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(server_name.to_string())
            .map_err(|_| NetError::Protocol("invalid TLS server name".into()))?,
    };
    let connector = tokio_rustls::TlsConnector::from(tls_config());
    let s = connector
        .connect(name, io)
        .await
        .map_err(|e| NetError::Protocol(format!("TLS: {}", e.kind())))?;
    Ok(Box::new(s))
}

// ---- SOCKS5 -------------------------------------------------------------------------

/// Greeting plus optional username/password login (RFC 1929).
pub async fn socks5_handshake<S: IoStream + ?Sized>(
    s: &mut S,
    auth: Option<&Credentials>,
) -> NetResult<()> {
    if auth.is_some() {
        s.write_all(&[5, 2, 0, 2]).await?;
    } else {
        s.write_all(&[5, 1, 0]).await?;
    }
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await?;
    if r[0] != 5 {
        return Err(NetError::Protocol("not a SOCKS5 server".into()));
    }
    match (r[1], auth) {
        (0, _) => Ok(()),
        (2, Some(c)) => {
            let (u, p) = (c.username.as_bytes(), c.password().as_bytes());
            if u.len() > 255 || p.len() > 255 {
                return Err(NetError::Protocol("login longer than 255 bytes".into()));
            }
            let mut msg = Vec::with_capacity(3 + u.len() + p.len());
            msg.push(1);
            msg.push(u.len() as u8);
            msg.extend_from_slice(u);
            msg.push(p.len() as u8);
            msg.extend_from_slice(p);
            s.write_all(&msg).await?;
            let mut a = [0u8; 2];
            s.read_exact(&mut a).await?;
            if a[1] == 0 {
                Ok(())
            } else {
                Err(NetError::Auth)
            }
        }
        (0xFF, _) | (2, None) => Err(NetError::Auth),
        _ => Err(NetError::Protocol("unsupported SOCKS5 auth method".into())),
    }
}

pub(crate) fn encode_socks_addr(out: &mut Vec<u8>, target: &TargetAddr) -> NetResult<()> {
    match target {
        TargetAddr::Ip(SocketAddr::V4(a)) => {
            out.push(1);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        TargetAddr::Ip(SocketAddr::V6(a)) => {
            out.push(4);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        TargetAddr::Domain(h, p) => {
            if h.is_empty() || h.len() > 255 {
                return Err(NetError::Protocol("bad target host".into()));
            }
            out.push(3);
            out.push(h.len() as u8);
            out.extend_from_slice(h.as_bytes());
            out.extend_from_slice(&p.to_be_bytes());
        }
    }
    Ok(())
}

/// Read a SOCKS5 address (ATYP + address + port).
pub(crate) async fn read_socks_addr<S: IoStream + ?Sized>(s: &mut S) -> NetResult<TargetAddr> {
    let atyp = s.read_u8().await?;
    Ok(match atyp {
        1 => {
            let mut b = [0u8; 6];
            s.read_exact(&mut b).await?;
            let ip = std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            TargetAddr::Ip(SocketAddr::new(ip.into(), u16::from_be_bytes([b[4], b[5]])))
        }
        4 => {
            let mut b = [0u8; 18];
            s.read_exact(&mut b).await?;
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[..16]);
            let ip = std::net::Ipv6Addr::from(o);
            TargetAddr::Ip(SocketAddr::new(
                ip.into(),
                u16::from_be_bytes([b[16], b[17]]),
            ))
        }
        3 => {
            let n = s.read_u8().await? as usize;
            let mut h = vec![0u8; n];
            s.read_exact(&mut h).await?;
            let port = s.read_u16().await?;
            let h = String::from_utf8(h).map_err(|_| NetError::Protocol("bad host".into()))?;
            TargetAddr::Domain(h, port)
        }
        _ => return Err(NetError::Protocol("bad SOCKS5 address type".into())),
    })
}

/// Send a SOCKS5 request (`cmd` 1 = CONNECT, 3 = UDP ASSOCIATE) and read the reply.
/// Returns the server's bound address on success.
pub async fn socks5_request<S: IoStream + ?Sized>(
    s: &mut S,
    cmd: u8,
    target: &TargetAddr,
) -> NetResult<TargetAddr> {
    let mut req = vec![5, cmd, 0];
    encode_socks_addr(&mut req, target)?;
    s.write_all(&req).await?;
    let mut h = [0u8; 3];
    s.read_exact(&mut h).await?;
    if h[0] != 5 {
        return Err(NetError::Protocol("bad SOCKS5 reply".into()));
    }
    let bound = read_socks_addr(s).await?;
    if h[1] != 0 {
        return Err(NetError::Refused(u16::from(h[1])));
    }
    Ok(bound)
}

// ---- HTTP CONNECT -------------------------------------------------------------------

/// Read an HTTP head (up to and including CRLFCRLF) byte by byte, so no tunnel bytes are
/// consumed. Capped at 16 KiB.
pub(crate) async fn read_http_head<S: IoStream + ?Sized>(s: &mut S) -> NetResult<String> {
    let mut buf = Vec::with_capacity(256);
    loop {
        let b = s.read_u8().await?;
        buf.push(b);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(NetError::Protocol("HTTP head too large".into()));
        }
    }
    String::from_utf8(buf).map_err(|_| NetError::Protocol("HTTP head not UTF-8".into()))
}

pub(crate) fn http_status(head: &str) -> NetResult<u16> {
    let line = head.lines().next().unwrap_or("");
    let mut it = line.split_whitespace();
    match (it.next(), it.next().and_then(|c| c.parse::<u16>().ok())) {
        (Some(v), Some(code)) if v.starts_with("HTTP/1.") => Ok(code),
        _ => Err(NetError::Protocol("bad HTTP status line".into())),
    }
}

/// Ask an HTTP proxy for a CONNECT tunnel to `target`.
pub async fn http_connect<S: IoStream + ?Sized>(
    s: &mut S,
    target: &TargetAddr,
    auth: Option<&Credentials>,
) -> NetResult<()> {
    let hp = match target {
        TargetAddr::Ip(SocketAddr::V6(a)) => format!("[{}]:{}", a.ip(), a.port()),
        other => other.to_string(),
    };
    let mut req = format!("CONNECT {hp} HTTP/1.1\r\nHost: {hp}\r\n");
    if let Some(c) = auth {
        let token = base64::engine::general_purpose::STANDARD.encode(format!(
            "{}:{}",
            c.username,
            c.password()
        ));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    let req = zeroize::Zeroizing::new(req);
    s.write_all(req.as_bytes()).await?;
    let head = read_http_head(s).await?;
    match http_status(&head)? {
        200..=299 => Ok(()),
        407 => Err(NetError::Auth),
        code => Err(NetError::Refused(code)),
    }
}

// ---- Tunnels ------------------------------------------------------------------------

/// Connect to the proxy (TCP, plus TLS for `https`) and finish its greeting/login.
pub(crate) async fn connect_proxy(
    proxy: &ProxyEndpoint,
    addr: SocketAddr,
    timeout: Duration,
) -> NetResult<BoxStream> {
    with_timeout(timeout, async {
        let tcp = TcpStream::connect(addr).await?;
        let _ = tcp.set_nodelay(true);
        let mut s: BoxStream = match proxy.scheme {
            ProxyScheme::Https => tls_connect(tcp, &proxy.host).await?,
            _ => Box::new(tcp),
        };
        if proxy.scheme == ProxyScheme::Socks5 {
            socks5_handshake(&mut *s, proxy.auth.as_ref()).await?;
        }
        Ok(s)
    })
    .await
}

/// Open a tunnel through `proxy` (already resolved to `addr`) to `target`. The returned
/// stream carries raw bytes to and from the target.
pub async fn open_tunnel(
    proxy: &ProxyEndpoint,
    addr: SocketAddr,
    target: &TargetAddr,
    timeout: Duration,
) -> NetResult<BoxStream> {
    with_timeout(timeout, async {
        let mut s = connect_proxy(proxy, addr, timeout).await?;
        match proxy.scheme {
            ProxyScheme::Socks5 => {
                socks5_request(&mut *s, 1, target).await?;
            }
            ProxyScheme::Http | ProxyScheme::Https => {
                http_connect(&mut *s, target, proxy.auth.as_ref()).await?;
            }
        }
        Ok(s)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_line() {
        assert_eq!(
            http_status("HTTP/1.1 200 Connection established\r\n\r\n"),
            Ok(200)
        );
        assert_eq!(http_status("HTTP/1.0 407 Auth\r\n\r\n"), Ok(407));
        assert!(http_status("SSH-2.0\r\n\r\n").is_err());
    }

    #[test]
    fn socks_addr_encoding() {
        let mut v = Vec::new();
        encode_socks_addr(&mut v, &TargetAddr::Domain("a.example".into(), 443)).unwrap();
        assert_eq!(v[0], 3);
        assert_eq!(v[1] as usize, "a.example".len());
        assert_eq!(&v[v.len() - 2..], &443u16.to_be_bytes());
        let mut v = Vec::new();
        encode_socks_addr(&mut v, &TargetAddr::Ip("1.2.3.4:80".parse().unwrap())).unwrap();
        assert_eq!(v, [1, 1, 2, 3, 4, 0, 80]);
    }

    #[test]
    fn proxy_down_classification() {
        assert!(NetError::Timeout.proxy_down());
        assert!(NetError::Auth.proxy_down());
        assert!(!NetError::Refused(5).proxy_down());
    }

    #[test]
    fn tls_config_builds() {
        let _ = tls_config();
    }
}
