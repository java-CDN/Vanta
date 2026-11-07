//! Integration: reflector, STUN responder and DNS leak hook on loopback, driven from the
//! test with crafted ClientHello / TLS / HTTP/2 / STUN traffic. No outbound network.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::rustls::{self, pki_types};
use vanta_health::dns::{DnsLeakTest, LeakWatch};
use vanta_health::h2::chrome_like_client_start;
use vanta_health::reflector::{Port, HOST};
use vanta_health::stun::{binding_request, decode_xor_mapped};
use vanta_health::tls::chrome;
use vanta_health::{testkit, HealthInput, HealthLab, Reflector, ReflectorConfig, StunResponder};
use vanta_proxy::doh::BoxFuture;
use vanta_proxy::net::NetResult;
use vanta_proxy::{AllowedClients, ProxyEndpoint, ProxyScheme, Relay, RelayConfig, Resolver};

/// Accepts exactly the reflector's certificate, like Chrome with
/// `--ignore-certificate-errors-spki-list`.
#[derive(Debug)]
struct Pinned(pki_types::CertificateDer<'static>);

impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &pki_types::CertificateDer<'_>,
        _: &[pki_types::CertificateDer<'_>],
        _: &pki_types::ServerName<'_>,
        _: &[u8],
        _: pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.0.as_ref() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("not the reflector".into()))
        }
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &algs())
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &algs())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        algs().supported_schemes()
    }
}

fn algs() -> rustls::crypto::WebPkiSupportedAlgorithms {
    rustls::crypto::ring::default_provider().signature_verification_algorithms
}

async fn tls_client(
    r: &Reflector,
    addr: SocketAddr,
    alpn: &[u8],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(Pinned(r.cert_der())))
    .with_no_client_auth();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    let tcp = TcpStream::connect(addr).await.unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(pki_types::ServerName::try_from(HOST).unwrap(), tcp)
        .await
        .unwrap()
}

async fn read_all<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Vec<u8> {
    let mut v = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut v)).await;
    v
}

async fn wait_for(mut f: impl FnMut() -> bool) {
    for _ in 0..250 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("condition not reached");
}

#[tokio::test]
async fn crafted_client_hello_is_captured_before_tls() {
    let r = Reflector::start(ReflectorConfig::default()).await.unwrap();
    assert!(r.page_addr().ip().is_loopback() && r.h2_addr().ip().is_loopback());
    let mut s = TcpStream::connect(r.page_addr()).await.unwrap();
    s.write_all(&chrome::client_hello(HOST)).await.unwrap();
    // The synthetic hello has no usable key share, so rustls aborts the handshake; the
    // capture happened before rustls saw a byte.
    let _ = read_all(&mut s).await;
    wait_for(|| !r.captures().hellos.is_empty()).await;
    let caps = r.captures();
    let (port, h) = &caps.hellos[0];
    assert_eq!(*port, Port::Page);
    assert_eq!(h.server_name.as_deref(), Some(HOST));
    assert_eq!(h.alpn, ["h2", "http/1.1"]);
    assert_eq!(h.cipher_suites, chrome::CIPHERS);
    assert!(h.ja4().starts_with("t13d1516h2_8daaf6152771_"));

    // Not TLS at all: recorded as an error, nothing served.
    let mut p = TcpStream::connect(r.page_addr()).await.unwrap();
    p.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let _ = read_all(&mut p).await;
    wait_for(|| !r.captures().hello_errors.is_empty()).await;
    r.shutdown().await;
}

#[tokio::test]
async fn page_report_and_http1_header_order() {
    let r = Reflector::start(ReflectorConfig {
        token: "tok123".into(),
        stun: Some("127.0.0.1:3478".parse().unwrap()),
        fonts: vec!["Arial".into()],
        dns_names: vec!["abc.leak.vanta.invalid".into()],
    })
    .await
    .unwrap();
    assert_eq!(
        r.page_url(),
        format!("https://{HOST}:{}/", r.page_addr().port())
    );

    let mut t = tls_client(&r, r.page_addr(), b"http/1.1").await;
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {HOST}\r\nsec-ch-ua: \"x\"\r\nUser-Agent: UA\r\nAccept: text/html\r\nAccept-Encoding: gzip\r\nAccept-Language: de-DE\r\n\r\n"
    );
    t.write_all(req.as_bytes()).await.unwrap();
    let resp = String::from_utf8(read_all(&mut t).await).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.contains("tok123") && resp.contains("stun:127.0.0.1:3478"));
    assert!(resp.contains("https://abc.leak.vanta.invalid/"));

    let caps = r.captures();
    let nav = caps.navigation().unwrap();
    assert_eq!(
        nav.names(),
        [
            "host",
            "sec-ch-ua",
            "user-agent",
            "accept",
            "accept-encoding",
            "accept-language"
        ]
    );
    let hello = caps.page_hello().unwrap();
    assert_eq!(hello.server_name.as_deref(), Some(HOST));
    assert_eq!(hello.alpn, ["http/1.1"]);

    // The page posts its JSON back.
    let body = br#"{"token":"tok123","ua":"UA","webdriver":false}"#;
    let mut t = tls_client(&r, r.page_addr(), b"http/1.1").await;
    t.write_all(
        format!(
            "POST /report HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    t.write_all(body).await.unwrap();
    let resp = String::from_utf8(read_all(&mut t).await).unwrap();
    assert!(resp.starts_with("HTTP/1.1 204"), "{resp}");
    let rep = r.wait_for_report(Duration::from_secs(2)).await.unwrap();
    assert_eq!(rep.ua, "UA");
    assert_eq!(rep.webdriver, Some(false));
    r.shutdown().await;
}

#[tokio::test]
async fn http2_settings_and_pseudo_order_are_captured() {
    let r = Reflector::start(ReflectorConfig::default()).await.unwrap();
    let mut t = tls_client(&r, r.h2_addr(), b"h2").await;
    t.write_all(&chrome_like_client_start(HOST)).await.unwrap();
    let resp = read_all(&mut t).await;
    // SETTINGS, SETTINGS ACK, HEADERS(:status 204), GOAWAY.
    assert!(resp.len() >= 9 * 4 + 1 + 8);
    assert_eq!(resp[3], 4);
    let caps = r.captures();
    assert_eq!(caps.h2.len(), 1);
    assert_eq!(
        caps.h2[0].akamai(),
        "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
    );
    assert!(caps
        .hellos
        .iter()
        .any(|(p, h)| *p == Port::H2 && h.alpn == ["h2"]));
    r.shutdown().await;
}

#[tokio::test]
async fn stun_binding_request_is_answered_and_recorded() {
    let stun = StunResponder::start().await.unwrap();
    assert!(stun.local_addr().ip().is_loopback());
    let c = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    c.send_to(&binding_request([7; 12]), stun.local_addr())
        .await
        .unwrap();
    let mut buf = [0u8; 256];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), c.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(decode_xor_mapped(&buf[..n]), Some(c.local_addr().unwrap()));
    // Garbage is ignored, not answered.
    c.send_to(b"not stun", stun.local_addr()).await.unwrap();
    let reqs = stun.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].transaction_id, [7; 12]);
    assert_eq!(reqs[0].from, c.local_addr().unwrap());
    stun.shutdown().await;
}

/// Mock DoH resolver: every name resolves to a documentation address.
struct MockDoh(Mutex<Vec<String>>);
impl Resolver for MockDoh {
    fn resolve<'a>(&'a self, h: &'a str) -> BoxFuture<'a, NetResult<Vec<Ipv4Addr>>> {
        self.0.lock().unwrap().push(h.to_string());
        Box::pin(async { Ok(vec![Ipv4Addr::new(203, 0, 113, 7)]) })
    }
}

/// Minimal no-auth SOCKS5 upstream that accepts every CONNECT and echoes.
async fn mock_socks_upstream() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut g = [0u8; 2];
                s.read_exact(&mut g).await?;
                let mut m = vec![0u8; g[1] as usize];
                s.read_exact(&mut m).await?;
                s.write_all(&[5, 0]).await?;
                let mut h = [0u8; 4];
                if s.read_exact(&mut h).await.is_err() {
                    return Ok::<(), std::io::Error>(()); // heartbeat
                }
                let skip = match h[3] {
                    1 => 6,
                    4 => 18,
                    _ => s.read_u8().await? as usize + 2,
                };
                let mut rest = vec![0u8; skip];
                s.read_exact(&mut rest).await?;
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                let (mut r, mut w) = s.into_split();
                tokio::io::copy(&mut r, &mut w).await?;
                Ok(())
            });
        }
    });
    a
}

async fn socks_connect_domain(relay: SocketAddr, host: &str) -> u8 {
    let mut c = TcpStream::connect(relay).await.unwrap();
    c.write_all(&[5, 1, 0]).await.unwrap();
    c.read_exact(&mut [0u8; 2]).await.unwrap();
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&443u16.to_be_bytes());
    c.write_all(&req).await.unwrap();
    let mut r = [0u8; 10];
    c.read_exact(&mut r).await.unwrap();
    r[1]
}

#[tokio::test]
async fn dns_leak_hook_sees_names_resolved_by_the_relay() {
    let up = mock_socks_upstream().await;
    let doh = Arc::new(MockDoh(Mutex::new(Vec::new())));
    let watch = Arc::new(LeakWatch::new(doh.clone()));
    let cfg = RelayConfig::new(
        ProxyEndpoint::new(ProxyScheme::Socks5, "127.0.0.1", up.port(), None),
        up,
        watch.clone(),
    )
    .with_clients(AllowedClients::Any);
    let relay = Relay::start(cfg).await.unwrap();
    let test = DnsLeakTest::new(3);
    // The engine hands host names to the relay (SOCKS5 remote DNS): no leak.
    for n in &test.names {
        assert_eq!(socks_connect_domain(relay.local_addr(), n).await, 0);
    }
    let r = test.evaluate(&watch);
    assert!(r.all_via_doh(), "{r:?}");
    assert_eq!(doh.0.lock().unwrap().len(), 3, "the DoH resolver answered");

    // A browser that resolved locally would send IP literals: DoH never sees the names.
    let leaky = DnsLeakTest::new(2);
    let r = leaky.evaluate(&watch);
    assert_eq!(r.missing.len(), 2);
    assert!(!r.all_via_doh());
    relay.shutdown().await;
}

#[tokio::test]
async fn lab_collects_a_run_into_health_input() {
    let base = testkit::consistent();
    let lab = HealthLab::start(&base).await.unwrap();
    let args = lab.engine_args();
    assert!(args[0].starts_with("--ignore-certificate-errors-spki-list="));
    assert_eq!(args[1], lab.reflector.page_url());

    // Play the browser: load the page, post the report with the run token.
    let mut t = tls_client(&lab.reflector, lab.reflector.page_addr(), b"http/1.1").await;
    t.write_all(format!("GET / HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let page = String::from_utf8(read_all(&mut t).await).unwrap();
    assert!(page.contains(&lab.token));
    let mut probe = base.probe.clone().unwrap();
    probe.token = lab.token.clone();
    let body = serde_json::to_vec(&probe).unwrap();
    let mut t = tls_client(&lab.reflector, lab.reflector.page_addr(), b"http/1.1").await;
    t.write_all(
        format!(
            "POST /report HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    t.write_all(&body).await.unwrap();
    let _ = read_all(&mut t).await;

    let watch = LeakWatch::new(Arc::new(MockDoh(Mutex::new(Vec::new()))));
    lab.dns.run_through(&watch).await;
    let input: HealthInput = lab
        .collect(
            HealthInput::new(base.expected.clone()),
            &watch,
            Duration::from_secs(2),
        )
        .await;
    assert_eq!(input.probe.as_ref().unwrap().ua, base.expected.user_agent);
    assert!(input.tls.is_some() && input.http1.is_some());
    assert!(input.stun.is_empty());
    assert!(input.dns.as_ref().unwrap().all_via_doh());
}
