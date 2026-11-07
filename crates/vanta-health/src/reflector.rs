//! Local HTTPS reflector on `127.0.0.1` (two ephemeral ports).
//!
//! - **Page port** (ALPN `http/1.1` only): serves the probe page at `/`, takes the page's
//!   JSON at `POST /report`, and records every request's header names in wire order.
//! - **HTTP/2 port** (ALPN `h2` only): records the connection preface, the first SETTINGS
//!   frame (order and values), WINDOW_UPDATE, PRIORITY and the pseudo-header order of the
//!   first request, answers `:status 204` and closes. The page triggers it with one
//!   `fetch(..., {mode: 'no-cors'})`.
//!
//! On both ports the first TLS record(s) are read and parsed *before* rustls sees them
//! (`ClientHello` + JA4), then replayed into rustls.
//!
//! The certificate is self-signed and generated at start (rcgen, ring backend) for
//! [`HOST`], `localhost` and `127.0.0.1`. The engine is told to trust exactly this key for
//! the health run with `--ignore-certificate-errors-spki-list=<`[`Reflector::spki_pin`]`>`.
//! The page is served at `https://vanta-health.localhost:<port>/`: Chrome maps
//! `*.localhost` to loopback itself, bypasses the proxy for it, and sends SNI for a name
//! (it sends none for an IP literal), so the JA4 has the same `d` form as on real sites.

use crate::h2::{parse_client_start, server_reply, H2Capture, H2Error};
use crate::probe::{page, PageConfig, ProbeReport};
use crate::tls::{handshake_from_records, parse_handshake, ClientHello, HelloError};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;
use tokio_rustls::rustls::{self, pki_types};
use vanta_types::{Result, VantaError};

/// Host name the probe page is served at.
pub const HOST: &str = "vanta-health.localhost";
const MAX_HELLO: usize = 64 * 1024;
const MAX_HEAD: usize = 64 * 1024;
const MAX_BODY: usize = 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Which reflector port a capture came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Port {
    Page,
    H2,
}

/// One HTTP/1.1 request as received.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct Http1Request {
    pub method: String,
    pub path: String,
    /// Header (name, value) in wire order, names as sent.
    pub headers: Vec<(String, String)>,
}

impl Http1Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Lower-case header names in order.
    pub fn names(&self) -> Vec<String> {
        self.headers
            .iter()
            .map(|(k, _)| k.to_ascii_lowercase())
            .collect()
    }
}

/// Everything the reflector saw.
#[derive(Debug, Clone, Default)]
pub struct Captures {
    pub hellos: Vec<(Port, ClientHello)>,
    pub hello_errors: Vec<String>,
    pub http1: Vec<Http1Request>,
    pub h2: Vec<H2Capture>,
    pub reports: Vec<ProbeReport>,
}

impl Captures {
    /// ClientHello of the page port (the navigation), if any.
    pub fn page_hello(&self) -> Option<&ClientHello> {
        self.hellos
            .iter()
            .find(|(p, _)| *p == Port::Page)
            .map(|(_, h)| h)
    }

    /// The navigation request for `/`.
    pub fn navigation(&self) -> Option<&Http1Request> {
        self.http1
            .iter()
            .find(|r| r.method == "GET" && r.path == "/")
    }
}

/// Settings of one reflector run.
#[derive(Debug, Clone, Default)]
pub struct ReflectorConfig {
    /// Run token embedded in the page and expected back in the report.
    pub token: String,
    /// The STUN responder the page uses as its ICE server.
    pub stun: Option<SocketAddr>,
    /// Fonts the page tests (the persona's fonts plus foreign ones).
    pub fonts: Vec<String>,
    /// Leak-test host names (see [`crate::dns::DnsLeakTest`]).
    pub dns_names: Vec<String>,
}

struct Shared {
    cfg: ReflectorConfig,
    page_port: u16,
    h2_port: u16,
    caps: Mutex<Captures>,
    report_in: Notify,
}

/// Self-signed certificate and key for the reflector.
pub struct ReflectorCert {
    pub cert_der: pki_types::CertificateDer<'static>,
    key_der: Vec<u8>,
    spki_der: Vec<u8>,
}

impl ReflectorCert {
    pub fn generate() -> Result<Self> {
        let err = |e: rcgen::Error| VantaError::Invalid(format!("reflector certificate: {e}"));
        let kp = rcgen::KeyPair::generate().map_err(err)?;
        let mut params =
            rcgen::CertificateParams::new(vec![HOST.to_string(), "localhost".to_string()])
                .map_err(err)?;
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(Ipv4Addr::LOCALHOST.into()));
        let cert = params.self_signed(&kp).map_err(err)?;
        Ok(Self {
            cert_der: cert.der().clone(),
            key_der: kp.serialize_der(),
            spki_der: kp.public_key_der(),
        })
    }

    /// base64(SHA-256(SubjectPublicKeyInfo)), the form
    /// `--ignore-certificate-errors-spki-list` takes.
    pub fn spki_pin(&self) -> String {
        STANDARD.encode(Sha256::digest(&self.spki_der))
    }

    fn server_config(&self, alpn: &[u8]) -> Result<Arc<rustls::ServerConfig>> {
        let key = pki_types::PrivateKeyDer::Pkcs8(pki_types::PrivatePkcs8KeyDer::from(
            self.key_der.clone(),
        ));
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| VantaError::Invalid(format!("tls versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(vec![self.cert_der.clone()], key)
        .map_err(|e| VantaError::Invalid(format!("tls cert: {e}")))?;
        cfg.alpn_protocols = vec![alpn.to_vec()];
        Ok(Arc::new(cfg))
    }
}

/// A running reflector.
pub struct Reflector {
    shared: Arc<Shared>,
    spki_pin: String,
    cert_der: pki_types::CertificateDer<'static>,
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl Reflector {
    pub async fn start(cfg: ReflectorConfig) -> Result<Self> {
        let cert = ReflectorCert::generate()?;
        let bind = || async {
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(|e| VantaError::Network(format!("reflector bind: {e}")))
        };
        let (pl, hl) = (bind().await?, bind().await?);
        let port = |l: &TcpListener| {
            l.local_addr()
                .map(|a| a.port())
                .map_err(|e| VantaError::Network(format!("reflector addr: {e}")))
        };
        let shared = Arc::new(Shared {
            cfg,
            page_port: port(&pl)?,
            h2_port: port(&hl)?,
            caps: Mutex::new(Captures::default()),
            report_in: Notify::new(),
        });
        let (stop, _) = watch::channel(false);
        let tasks = vec![
            tokio::spawn(serve(
                pl,
                Port::Page,
                cert.server_config(b"http/1.1")?,
                shared.clone(),
                stop.subscribe(),
            )),
            tokio::spawn(serve(
                hl,
                Port::H2,
                cert.server_config(b"h2")?,
                shared.clone(),
                stop.subscribe(),
            )),
        ];
        Ok(Self {
            shared,
            spki_pin: cert.spki_pin(),
            cert_der: cert.cert_der.clone(),
            stop,
            tasks,
        })
    }

    /// `https://vanta-health.localhost:<page port>/`, the URL the engine opens.
    pub fn page_url(&self) -> String {
        format!("https://{HOST}:{}/", self.shared.page_port)
    }

    pub fn page_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.shared.page_port))
    }

    pub fn h2_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.shared.h2_port))
    }

    /// For `--ignore-certificate-errors-spki-list` (health runs only).
    pub fn spki_pin(&self) -> String {
        self.spki_pin.clone()
    }

    /// The reflector's self-signed certificate (DER).
    pub fn cert_der(&self) -> pki_types::CertificateDer<'static> {
        self.cert_der.clone()
    }

    /// Snapshot of everything captured so far.
    pub fn captures(&self) -> Captures {
        self.shared.caps.lock().expect("captures").clone()
    }

    /// Wait until the page's report with the run token arrived (or `timeout`).
    pub async fn wait_for_report(&self, timeout: Duration) -> Option<ProbeReport> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.shared.report_in.notified();
            if let Some(r) = self.report() {
                return Some(r);
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.report();
            }
        }
    }

    fn report(&self) -> Option<ProbeReport> {
        let caps = self.shared.caps.lock().expect("captures");
        caps.reports
            .iter()
            .rev()
            .find(|r| r.token == self.shared.cfg.token)
            .cloned()
    }

    pub async fn shutdown(mut self) {
        self.stop.send_replace(true);
        for t in self.tasks.drain(..) {
            let _ = t.await;
        }
    }
}

impl Drop for Reflector {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        for t in &self.tasks {
            t.abort();
        }
    }
}

async fn serve(
    l: TcpListener,
    port: Port,
    tls: Arc<rustls::ServerConfig>,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    let mut conns = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            r = l.accept() => {
                let Ok((s, peer)) = r else { continue };
                // Loopback only; the listener is bound to 127.0.0.1, this is belt and braces.
                if !peer.ip().is_loopback() {
                    continue;
                }
                let (tls, sh) = (tls.clone(), shared.clone());
                conns.spawn(async move {
                    let _ = tokio::time::timeout(IO_TIMEOUT, conn(s, port, tls, sh)).await;
                });
            }
        }
    }
}

/// Read the ClientHello off the socket and return it with the bytes consumed so far.
async fn read_hello(s: &mut TcpStream) -> (Vec<u8>, std::result::Result<ClientHello, String>) {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    loop {
        match handshake_from_records(&buf) {
            Ok((hs, _)) => {
                let r = parse_handshake(&hs).map_err(|e| e.to_string());
                return (buf, r);
            }
            Err(HelloError::Incomplete(_)) if buf.len() < MAX_HELLO => {}
            Err(e) => return (buf, Err(e.to_string())),
        }
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => return (buf, Err("connection closed before ClientHello".into())),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

async fn conn(mut s: TcpStream, port: Port, tls: Arc<rustls::ServerConfig>, sh: Arc<Shared>) {
    let (pre, hello) = read_hello(&mut s).await;
    match hello {
        Ok(h) => sh.caps.lock().expect("captures").hellos.push((port, h)),
        Err(e) => {
            sh.caps.lock().expect("captures").hello_errors.push(e);
            return;
        }
    }
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let Ok(mut t) = acceptor
        .accept(Prefixed {
            pre,
            pos: 0,
            inner: s,
        })
        .await
    else {
        return;
    };
    match port {
        Port::Page => {
            let _ = http1(&mut t, &sh).await;
        }
        Port::H2 => {
            let _ = h2(&mut t, &sh).await;
        }
    }
    let _ = t.shutdown().await;
}

async fn h2<S: AsyncRead + AsyncWrite + Unpin>(t: &mut S, sh: &Shared) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match parse_client_start(&buf) {
            Ok(cap) => {
                sh.caps.lock().expect("captures").h2.push(cap);
                t.write_all(&server_reply(1)).await?;
                return t.flush().await;
            }
            Err(H2Error::Incomplete) if buf.len() < MAX_HEAD => {}
            Err(_) => return Ok(()),
        }
        let n = t.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Parse an HTTP/1.1 head (request line + headers, without the final CRLF CRLF).
pub fn parse_http1_head(head: &str) -> Option<Http1Request> {
    let mut lines = head.split("\r\n");
    let mut rl = lines.next()?.split(' ');
    let (method, path) = (rl.next()?.to_string(), rl.next()?.to_string());
    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            break;
        }
        let (k, v) = l.split_once(':')?;
        headers.push((k.to_string(), v.trim().to_string()));
    }
    Some(Http1Request {
        method,
        path,
        headers,
    })
}

async fn http1<S: AsyncRead + AsyncWrite + Unpin>(t: &mut S, sh: &Shared) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return Ok(());
        }
        let n = t.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let Some(req) = parse_http1_head(&String::from_utf8_lossy(&buf[..head_end])) else {
        return respond(t, "400 Bad Request", "text/plain", b"").await;
    };
    sh.caps.lock().expect("captures").http1.push(req.clone());
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => {
            let cfg = PageConfig {
                token: sh.cfg.token.clone(),
                h2_url: format!("https://{HOST}:{}/h2", sh.h2_port),
                stun_url: sh.cfg.stun.map(|a| format!("stun:{a}")).unwrap_or_default(),
                fonts: sh.cfg.fonts.clone(),
                dns_urls: sh
                    .cfg
                    .dns_names
                    .iter()
                    .map(|n| format!("https://{n}/"))
                    .collect(),
            };
            respond(
                t,
                "200 OK",
                "text/html; charset=utf-8",
                page(&cfg).as_bytes(),
            )
            .await
        }
        ("POST", "/report") => {
            let len: usize = req
                .header("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if len > MAX_BODY {
                return respond(t, "413 Payload Too Large", "text/plain", b"").await;
            }
            let mut body = buf[head_end + 4..].to_vec();
            while body.len() < len {
                let n = t.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..n]);
            }
            body.truncate(len);
            match serde_json::from_slice::<ProbeReport>(&body) {
                Ok(r) => {
                    sh.caps.lock().expect("captures").reports.push(r);
                    sh.report_in.notify_waiters();
                    respond(t, "204 No Content", "text/plain", b"").await
                }
                Err(_) => respond(t, "400 Bad Request", "text/plain", b"").await,
            }
        }
        _ => respond(t, "404 Not Found", "text/plain", b"").await,
    }
}

async fn respond<S: AsyncWrite + Unpin>(
    t: &mut S,
    status: &str,
    ctype: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'self' 'unsafe-inline' blob:; connect-src 'self' https:\r\nConnection: close\r\n\r\n",
        body.len()
    );
    t.write_all(head.as_bytes()).await?;
    t.write_all(body).await?;
    t.flush().await
}

/// A stream that first yields bytes already read off the socket.
struct Prefixed {
    pre: Vec<u8>,
    pos: usize,
    inner: TcpStream,
}

impl AsyncRead for Prefixed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.pre.len() {
            let n = (self.pre.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.pre[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Prefixed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http1_head_keeps_order_and_case() {
        let r = parse_http1_head(
            "GET / HTTP/1.1\r\nHost: a\r\nsec-ch-ua: \"x\"\r\nUser-Agent: U\r\nAccept: */*",
        )
        .unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.names(), ["host", "sec-ch-ua", "user-agent", "accept"]);
        assert_eq!(r.header("user-agent"), Some("U"));
        assert!(parse_http1_head("garbage").is_none());
    }

    #[test]
    fn cert_pin_is_sha256_base64() {
        let c = ReflectorCert::generate().unwrap();
        let pin = c.spki_pin();
        assert_eq!(STANDARD.decode(&pin).unwrap().len(), 32);
        assert_ne!(
            pin,
            ReflectorCert::generate().unwrap().spki_pin(),
            "fresh key per run"
        );
        assert!(c.server_config(b"h2").is_ok());
    }
}
