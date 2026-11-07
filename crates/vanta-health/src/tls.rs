//! TLS ClientHello parsing and the JA4 fingerprint (FoxIO JA4, TCP form).
//!
//! The reflector reads the client's first TLS record(s) itself, before rustls sees them,
//! so the fingerprint is taken from the exact bytes the browser sent.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Extension numbers used below.
pub mod ext {
    pub const SERVER_NAME: u16 = 0x0000;
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub const ALPN: u16 = 0x0010;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
}

/// A parsed ClientHello. Lists keep the wire order, GREASE values included.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
    pub supported_groups: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
}

/// Why a ClientHello could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloError {
    /// More bytes are needed (the value is the total the parser wants so far).
    Incomplete(usize),
    NotHandshake,
    NotClientHello,
    Malformed(&'static str),
}

impl std::fmt::Display for HelloError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HelloError::Incomplete(n) => write!(f, "incomplete ClientHello (need {n} bytes)"),
            HelloError::NotHandshake => f.write_str("first record is not a TLS handshake"),
            HelloError::NotClientHello => f.write_str("first handshake is not a ClientHello"),
            HelloError::Malformed(w) => write!(f, "malformed ClientHello: {w}"),
        }
    }
}

/// RFC 8701 GREASE value (0x0a0a, 0x1a1a, ... 0xfafa).
pub fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], HelloError> {
        if self.p + n > self.b.len() {
            return Err(HelloError::Malformed("length past end"));
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, HelloError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, HelloError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn vec8(&mut self) -> Result<&'a [u8], HelloError> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn vec16(&mut self) -> Result<&'a [u8], HelloError> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn done(&self) -> bool {
        self.p >= self.b.len()
    }
}

fn u16_list(b: &[u8]) -> Vec<u16> {
    b.as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect()
}

/// Collect the handshake message from the start of the client's byte stream (one or more
/// TLS records). Returns the handshake body and how many stream bytes it used.
pub fn handshake_from_records(stream: &[u8]) -> Result<(Vec<u8>, usize), HelloError> {
    let mut hs = Vec::new();
    let mut p = 0;
    loop {
        if stream.len() < p + 5 {
            return Err(HelloError::Incomplete(p + 5));
        }
        if stream[p] != 0x16 {
            return Err(HelloError::NotHandshake);
        }
        let len = u16::from_be_bytes([stream[p + 3], stream[p + 4]]) as usize;
        if len == 0 || len > 16384 + 256 {
            return Err(HelloError::Malformed("record length"));
        }
        if stream.len() < p + 5 + len {
            return Err(HelloError::Incomplete(p + 5 + len));
        }
        hs.extend_from_slice(&stream[p + 5..p + 5 + len]);
        p += 5 + len;
        if hs.len() >= 4 {
            if hs[0] != 1 {
                return Err(HelloError::NotClientHello);
            }
            let need = 4 + (((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize);
            if need > 1 << 17 {
                return Err(HelloError::Malformed("handshake length"));
            }
            if hs.len() >= need {
                hs.truncate(need);
                return Ok((hs, p));
            }
        }
    }
}

/// Parse a ClientHello from the start of a TLS byte stream.
pub fn parse_client_hello(stream: &[u8]) -> Result<ClientHello, HelloError> {
    let (hs, _) = handshake_from_records(stream)?;
    parse_handshake(&hs)
}

/// Parse a ClientHello handshake message (type, 3-byte length, body).
pub fn parse_handshake(hs: &[u8]) -> Result<ClientHello, HelloError> {
    let mut r = Rd::new(hs);
    if r.u8()? != 1 {
        return Err(HelloError::NotClientHello);
    }
    r.take(3)?;
    let mut h = ClientHello {
        legacy_version: r.u16()?,
        ..Default::default()
    };
    r.take(32)?; // random
    r.vec8()?; // legacy session id
    h.cipher_suites = u16_list(r.vec16()?);
    r.vec8()?; // compression methods
    if r.done() {
        return Ok(h);
    }
    let mut exts = Rd::new(r.vec16()?);
    while !exts.done() {
        let ty = exts.u16()?;
        let body = exts.vec16()?;
        h.extensions.push(ty);
        // A malformed body of a known extension is recorded as present but not decoded.
        let _ = decode_ext(&mut h, ty, body);
    }
    Ok(h)
}

fn decode_ext(h: &mut ClientHello, ty: u16, body: &[u8]) -> Result<(), HelloError> {
    let mut b = Rd::new(body);
    match ty {
        ext::SERVER_NAME => {
            let mut list = Rd::new(b.vec16()?);
            while !list.done() {
                let kind = list.u8()?;
                let name = list.vec16()?;
                if kind == 0 {
                    h.server_name = Some(String::from_utf8_lossy(name).into_owned());
                }
            }
        }
        ext::ALPN => {
            let mut list = Rd::new(b.vec16()?);
            while !list.done() {
                h.alpn
                    .push(String::from_utf8_lossy(list.vec8()?).into_owned());
            }
        }
        ext::SUPPORTED_GROUPS => h.supported_groups = u16_list(b.vec16()?),
        ext::SIGNATURE_ALGORITHMS => h.signature_algorithms = u16_list(b.vec16()?),
        ext::SUPPORTED_VERSIONS => h.supported_versions = u16_list(b.vec8()?),
        ext::EC_POINT_FORMATS => h.ec_point_formats = b.vec8()?.to_vec(),
        _ => {}
    }
    Ok(())
}

fn hash12(s: &str) -> String {
    let d = Sha256::digest(s.as_bytes());
    d.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

fn hex_list(v: impl Iterator<Item = u16>) -> String {
    v.map(|x| format!("{x:04x}")).collect::<Vec<_>>().join(",")
}

fn version_code(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

fn alpn_code(first: Option<&String>) -> String {
    let Some(a) = first.filter(|a| !a.is_empty()) else {
        return "00".into();
    };
    let b = a.as_bytes();
    let (f, l) = (b[0], b[b.len() - 1]);
    if f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric() {
        format!("{}{}", f as char, l as char)
    } else {
        let h = format!("{f:02x}{l:02x}");
        format!("{}{}", &h[..1], &h[3..])
    }
}

impl ClientHello {
    /// Highest non-GREASE TLS version offered (supported_versions, else legacy).
    pub fn max_version(&self) -> u16 {
        self.supported_versions
            .iter()
            .copied()
            .filter(|v| !is_grease(*v))
            .max()
            .unwrap_or(self.legacy_version)
    }

    pub fn ja4_a(&self) -> String {
        let ciphers = self
            .cipher_suites
            .iter()
            .filter(|c| !is_grease(**c))
            .count();
        let exts = self.extensions.iter().filter(|e| !is_grease(**e)).count();
        format!(
            "t{}{}{:02}{:02}{}",
            version_code(self.max_version()),
            if self.server_name.is_some() { 'd' } else { 'i' },
            ciphers.min(99),
            exts.min(99),
            alpn_code(self.alpn.first())
        )
    }

    /// JA4 part b: sorted cipher suites (GREASE removed), SHA-256, first 12 hex.
    pub fn ja4_b(&self) -> String {
        let mut c: Vec<u16> = self
            .cipher_suites
            .iter()
            .copied()
            .filter(|c| !is_grease(*c))
            .collect();
        if c.is_empty() {
            return "000000000000".into();
        }
        c.sort_unstable();
        hash12(&hex_list(c.into_iter()))
    }

    /// JA4 part c: sorted extensions without GREASE, SNI and ALPN, then `_` and the
    /// signature algorithms in wire order; SHA-256, first 12 hex.
    pub fn ja4_c(&self) -> String {
        let mut e: Vec<u16> = self
            .extensions
            .iter()
            .copied()
            .filter(|e| !is_grease(*e) && *e != ext::SERVER_NAME && *e != ext::ALPN)
            .collect();
        if e.is_empty() {
            return "000000000000".into();
        }
        e.sort_unstable();
        let mut s = hex_list(e.into_iter());
        let sig: Vec<u16> = self
            .signature_algorithms
            .iter()
            .copied()
            .filter(|s| !is_grease(*s))
            .collect();
        if !sig.is_empty() {
            s.push('_');
            s.push_str(&hex_list(sig.into_iter()));
        }
        hash12(&s)
    }

    /// Full JA4 string `a_b_c`.
    pub fn ja4(&self) -> String {
        format!("{}_{}_{}", self.ja4_a(), self.ja4_b(), self.ja4_c())
    }

    /// Extensions without GREASE, in wire order.
    pub fn extensions_no_grease(&self) -> Vec<u16> {
        self.extensions
            .iter()
            .copied()
            .filter(|e| !is_grease(*e))
            .collect()
    }
}

/// Build a ClientHello record (for tests and the integration test): `ciphers`, then
/// `extensions` as `(type, body)` pairs in order.
pub fn build_client_hello(ciphers: &[u16], extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[7u8; 32]);
    body.push(32);
    body.extend_from_slice(&[9u8; 32]);
    body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for c in ciphers {
        body.extend_from_slice(&c.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]);
    let mut ex = Vec::new();
    for (t, b) in extensions {
        ex.extend_from_slice(&t.to_be_bytes());
        ex.extend_from_slice(&(b.len() as u16).to_be_bytes());
        ex.extend_from_slice(b);
    }
    body.extend_from_slice(&(ex.len() as u16).to_be_bytes());
    body.extend_from_slice(&ex);
    let mut hs = vec![1u8];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// Extension body helpers for [`build_client_hello`].
pub mod body {
    pub fn sni(name: &str) -> Vec<u8> {
        let mut e = vec![0u8];
        e.extend_from_slice(&(name.len() as u16).to_be_bytes());
        e.extend_from_slice(name.as_bytes());
        let mut b = (e.len() as u16).to_be_bytes().to_vec();
        b.extend_from_slice(&e);
        b
    }
    pub fn alpn(protos: &[&str]) -> Vec<u8> {
        let mut l = Vec::new();
        for p in protos {
            l.push(p.len() as u8);
            l.extend_from_slice(p.as_bytes());
        }
        let mut b = (l.len() as u16).to_be_bytes().to_vec();
        b.extend_from_slice(&l);
        b
    }
    pub fn u16_list16(v: &[u16]) -> Vec<u8> {
        let mut b = ((v.len() * 2) as u16).to_be_bytes().to_vec();
        for x in v {
            b.extend_from_slice(&x.to_be_bytes());
        }
        b
    }
    pub fn u16_list8(v: &[u16]) -> Vec<u8> {
        let mut b = vec![(v.len() * 2) as u8];
        for x in v {
            b.extend_from_slice(&x.to_be_bytes());
        }
        b
    }
}

/// A Chromium-shaped ClientHello (Chrome's cipher suites, signature algorithms, groups and
/// ALPN; GREASE as 0x0a0a/0x1a1a) for tests and the loopback integration test. It is a
/// synthetic hello, not a capture: the reference JA4 the checks compare against is the
/// measured value in [`crate::reference`].
pub mod chrome {
    pub const CIPHERS: [u16; 16] = [
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ];
    /// Non-GREASE extensions (ALPS 0x44cd, ECH GREASE 0xfe0d).
    pub const EXTENSIONS: [u16; 16] = [
        0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 0x0017, 0x001b, 0x0023, 0x002b,
        0x002d, 0x0033, 0x44cd, 0xfe0d, 0xff01,
    ];
    pub const SIG_ALGS: [u16; 8] = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    /// GREASE, X25519MLKEM768, X25519, P-256, P-384.
    pub const GROUPS: [u16; 5] = [0x0a0a, 0x11ec, 0x001d, 0x0017, 0x0018];
    pub const ALPN: [&str; 2] = ["h2", "http/1.1"];

    /// A ClientHello record with this shape for `sni`.
    pub fn client_hello(sni: &str) -> Vec<u8> {
        use super::body;
        let mut ext: Vec<(u16, Vec<u8>)> = vec![(0x1a1a, vec![])];
        for e in EXTENSIONS {
            let b = match e {
                0x0000 => body::sni(sni),
                0x0010 => body::alpn(&ALPN),
                0x000a => body::u16_list16(&GROUPS),
                0x000d => body::u16_list16(&SIG_ALGS),
                0x002b => body::u16_list8(&[0x2a2a, 0x0304, 0x0303]),
                0x000b => vec![1, 0],
                _ => vec![],
            };
            ext.push((e, b));
        }
        ext.push((0x2a2a, vec![0]));
        super::build_client_hello(&CIPHERS, &ext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_values() {
        assert!(is_grease(0x0a0a) && is_grease(0xfafa) && is_grease(0x3a3a));
        assert!(!is_grease(0x0a1a) && !is_grease(0x1301) && !is_grease(0x0000));
    }

    /// The worked example of the FoxIO JA4 specification (Chrome, with padding 0x0015 and
    /// the old ALPS code point 0x4469) gives t13d1516h2_8daaf6152771_e5627efa2ab1.
    #[test]
    fn ja4_matches_the_foxio_reference_example() {
        let exts: Vec<(u16, Vec<u8>)> = [
            0x0000u16, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 0x0015, 0x0017, 0x001b,
            0x0023, 0x002b, 0x002d, 0x0033, 0x4469, 0xff01,
        ]
        .iter()
        .map(|e| {
            let b = match *e {
                0x0000 => body::sni("example.com"),
                0x0010 => body::alpn(&["h2", "http/1.1"]),
                0x000d => body::u16_list16(&chrome::SIG_ALGS),
                0x002b => body::u16_list8(&[0x0304, 0x0303]),
                _ => vec![],
            };
            (*e, b)
        })
        .collect();
        let rec = build_client_hello(&chrome::CIPHERS, &exts);
        let h = parse_client_hello(&rec).unwrap();
        assert_eq!(h.ja4(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }

    #[test]
    fn parses_every_field_in_wire_order() {
        let rec = chrome::client_hello("vanta-health.localhost");
        let h = parse_client_hello(&rec).unwrap();
        assert_eq!(h.cipher_suites, chrome::CIPHERS);
        assert_eq!(h.extensions.len(), 18);
        assert_eq!(h.extensions[0], 0x1a1a);
        assert_eq!(h.server_name.as_deref(), Some("vanta-health.localhost"));
        assert_eq!(h.alpn, ["h2", "http/1.1"]);
        assert_eq!(h.supported_groups, chrome::GROUPS);
        assert_eq!(h.signature_algorithms, chrome::SIG_ALGS);
        assert_eq!(h.max_version(), 0x0304);
        assert_eq!(h.ec_point_formats, [0]);
        assert!(h.ja4().starts_with("t13d1516h2_8daaf6152771_"));
    }

    #[test]
    fn extension_order_does_not_change_ja4() {
        let a = parse_client_hello(&chrome::client_hello("a.localhost")).unwrap();
        let mut b = a.clone();
        b.extensions.reverse();
        assert_eq!(a.ja4(), b.ja4());
        let mut c = a.clone();
        c.signature_algorithms.swap(0, 1);
        assert_ne!(a.ja4_c(), c.ja4_c(), "sig alg order is part of JA4");
    }

    #[test]
    fn no_sni_no_alpn() {
        let rec = build_client_hello(&[0x1301], &[(0x002b, body::u16_list8(&[0x0304]))]);
        let h = parse_client_hello(&rec).unwrap();
        assert_eq!(h.ja4_a(), "t13i0101".to_string() + "00");
    }

    #[test]
    fn split_across_records_and_incomplete() {
        let rec = chrome::client_hello("x.localhost");
        let hs = &rec[5..];
        let (a, b) = hs.split_at(100);
        let mut two = vec![0x16, 3, 1];
        two.extend_from_slice(&(a.len() as u16).to_be_bytes());
        two.extend_from_slice(a);
        two.extend_from_slice(&[0x16, 3, 1]);
        two.extend_from_slice(&(b.len() as u16).to_be_bytes());
        two.extend_from_slice(b);
        let (_, used) = handshake_from_records(&two).unwrap();
        assert_eq!(used, two.len());
        assert_eq!(
            parse_client_hello(&two).unwrap(),
            parse_client_hello(&rec).unwrap()
        );
        assert!(matches!(
            parse_client_hello(&rec[..50]),
            Err(HelloError::Incomplete(_))
        ));
        assert_eq!(
            parse_client_hello(b"GET / HTTP/1.1\r\n"),
            Err(HelloError::NotHandshake)
        );
    }

    #[test]
    fn garbage_is_rejected_not_panicking() {
        let mut rec = chrome::client_hello("x.localhost");
        for i in 9..rec.len().min(300) {
            let mut r = rec.clone();
            r[i] = 0xff;
            let _ = parse_client_hello(&r);
        }
        rec.truncate(rec.len() - 3);
        assert!(parse_client_hello(&rec).is_err());
    }
}
