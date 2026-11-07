//! HTTP/2 client start: connection preface, the first SETTINGS frame (ids and values in the
//! order sent), WINDOW_UPDATE, PRIORITY frames and the first HEADERS block.
//!
//! The header block is walked with a small HPACK reader. Pseudo-headers are always encoded
//! by static-table name index, so their order is exact. A regular header name sent as a
//! Huffman-coded literal is recorded as `?` (no Huffman decoder here); names taken from the
//! static or dynamic table are exact. Full header order is read from HTTP/1.1 instead.

use serde::{Deserialize, Serialize};

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const HEADERS: u8 = 1;
const PRIORITY: u8 = 2;
const SETTINGS: u8 = 4;
const WINDOW_UPDATE: u8 = 8;
const CONTINUATION: u8 = 9;

const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY_FLAG: u8 = 0x20;

/// Priority as sent in a PRIORITY frame or a HEADERS frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Priority {
    pub stream: u32,
    pub exclusive: bool,
    pub depends_on: u32,
    /// Weight 1–256 (wire value + 1).
    pub weight: u16,
}

/// What the client sent before its first request completed.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct H2Capture {
    /// SETTINGS (id, value) in wire order.
    pub settings: Vec<(u16, u32)>,
    /// Connection-level WINDOW_UPDATE increment.
    pub window_update: Option<u32>,
    pub priority_frames: Vec<Priority>,
    pub headers_priority: Option<Priority>,
    /// Pseudo-headers in order (":method", ":authority", ...).
    pub pseudo_order: Vec<String>,
    /// Regular header names in order; `?` for a Huffman-coded literal name.
    pub header_names: Vec<String>,
}

impl H2Capture {
    /// Akamai-style summary: `SETTINGS|WINDOW_UPDATE|PRIORITY frames|pseudo order`.
    pub fn akamai(&self) -> String {
        let s = self
            .settings
            .iter()
            .map(|(k, v)| format!("{k}:{v}"))
            .collect::<Vec<_>>()
            .join(";");
        let p = if self.priority_frames.is_empty() {
            "0".to_string()
        } else {
            self.priority_frames
                .iter()
                .map(|p| {
                    format!(
                        "{}:{}:{}:{}",
                        p.stream, p.exclusive as u8, p.depends_on, p.weight
                    )
                })
                .collect::<Vec<_>>()
                .join(",")
        };
        let o = self
            .pseudo_order
            .iter()
            .map(|h| h.trim_start_matches(':').chars().next().unwrap_or('?'))
            .map(String::from)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{s}|{}|{p}|{o}",
            self.window_update
                .map(|w| w.to_string())
                .unwrap_or_default()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H2Error {
    /// Need more bytes.
    Incomplete,
    BadPreface,
    Malformed(&'static str),
}

impl std::fmt::Display for H2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            H2Error::Incomplete => f.write_str("incomplete HTTP/2 client start"),
            H2Error::BadPreface => f.write_str("not an HTTP/2 connection preface"),
            H2Error::Malformed(w) => write!(f, "malformed HTTP/2 frame: {w}"),
        }
    }
}

/// HPACK static table names (RFC 7541 Appendix A), index 1..=61.
const STATIC_NAMES: [&str; 61] = [
    ":authority",
    ":method",
    ":method",
    ":path",
    ":path",
    ":scheme",
    ":scheme",
    ":status",
    ":status",
    ":status",
    ":status",
    ":status",
    ":status",
    ":status",
    "accept-charset",
    "accept-encoding",
    "accept-language",
    "accept-ranges",
    "accept",
    "access-control-allow-origin",
    "age",
    "allow",
    "authorization",
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-length",
    "content-location",
    "content-range",
    "content-type",
    "cookie",
    "date",
    "etag",
    "expect",
    "expires",
    "from",
    "host",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "last-modified",
    "link",
    "location",
    "max-forwards",
    "proxy-authenticate",
    "proxy-authorization",
    "range",
    "referer",
    "refresh",
    "retry-after",
    "server",
    "set-cookie",
    "strict-transport-security",
    "transfer-encoding",
    "user-agent",
    "vary",
    "via",
    "www-authenticate",
];

fn hpack_int(b: &[u8], p: &mut usize, prefix: u8) -> Result<usize, H2Error> {
    let first = *b.get(*p).ok_or(H2Error::Malformed("hpack int"))?;
    *p += 1;
    let max = (1usize << prefix) - 1;
    let mut v = (first as usize) & max;
    if v < max {
        return Ok(v);
    }
    let mut shift = 0;
    loop {
        let c = *b.get(*p).ok_or(H2Error::Malformed("hpack int"))?;
        *p += 1;
        v += ((c & 0x7f) as usize) << shift;
        if c & 0x80 == 0 {
            return Ok(v);
        }
        shift += 7;
        if shift > 28 {
            return Err(H2Error::Malformed("hpack int overflow"));
        }
    }
}

/// Returns the string, or `None` if Huffman-coded.
fn hpack_str(b: &[u8], p: &mut usize) -> Result<Option<String>, H2Error> {
    let huff = b.get(*p).ok_or(H2Error::Malformed("hpack string"))? & 0x80 != 0;
    let n = hpack_int(b, p, 7)?;
    let s = b
        .get(*p..*p + n)
        .ok_or(H2Error::Malformed("hpack string length"))?;
    *p += n;
    Ok(if huff {
        None
    } else {
        Some(String::from_utf8_lossy(s).into_owned())
    })
}

/// Header names of one header block, in order (`?` for Huffman literal names).
pub fn header_block_names(b: &[u8]) -> Result<Vec<String>, H2Error> {
    let mut dynamic: Vec<String> = Vec::new(); // newest first
    let name_at = |i: usize, dynamic: &Vec<String>| -> Result<String, H2Error> {
        if i == 0 {
            return Err(H2Error::Malformed("hpack index 0"));
        }
        if i <= 61 {
            return Ok(STATIC_NAMES[i - 1].to_string());
        }
        dynamic
            .get(i - 62)
            .cloned()
            .ok_or(H2Error::Malformed("hpack dynamic index"))
    };
    let mut out = Vec::new();
    let mut p = 0;
    while p < b.len() {
        let c = b[p];
        if c & 0x80 != 0 {
            let i = hpack_int(b, &mut p, 7)?;
            out.push(name_at(i, &dynamic)?);
        } else if c & 0xe0 == 0x20 {
            hpack_int(b, &mut p, 5)?; // dynamic table size update
        } else {
            let (prefix, index) = if c & 0xc0 == 0x40 {
                (6, true)
            } else {
                (4, false)
            };
            let i = hpack_int(b, &mut p, prefix)?;
            let name = if i == 0 {
                hpack_str(b, &mut p)?.unwrap_or_else(|| "?".into())
            } else {
                name_at(i, &dynamic)?
            };
            hpack_str(b, &mut p)?; // value
            if index {
                dynamic.insert(0, name.clone());
            }
            out.push(name);
        }
    }
    Ok(out)
}

/// Parse the client's start of an HTTP/2 connection (after TLS) up to and including its
/// first complete header block.
pub fn parse_client_start(buf: &[u8]) -> Result<H2Capture, H2Error> {
    if buf.len() < PREFACE.len() {
        return if PREFACE.starts_with(buf) {
            Err(H2Error::Incomplete)
        } else {
            Err(H2Error::BadPreface)
        };
    }
    if &buf[..PREFACE.len()] != PREFACE {
        return Err(H2Error::BadPreface);
    }
    let mut cap = H2Capture::default();
    let mut p = PREFACE.len();
    let mut block: Vec<u8> = Vec::new();
    let mut in_headers = false;
    let mut seen_settings = false;
    loop {
        if buf.len() < p + 9 {
            return Err(H2Error::Incomplete);
        }
        let len = ((buf[p] as usize) << 16) | ((buf[p + 1] as usize) << 8) | buf[p + 2] as usize;
        let (ty, flags) = (buf[p + 3], buf[p + 4]);
        let stream =
            u32::from_be_bytes([buf[p + 5], buf[p + 6], buf[p + 7], buf[p + 8]]) & 0x7fff_ffff;
        if len > 1 << 20 {
            return Err(H2Error::Malformed("frame too large"));
        }
        if buf.len() < p + 9 + len {
            return Err(H2Error::Incomplete);
        }
        let payload = &buf[p + 9..p + 9 + len];
        p += 9 + len;
        if in_headers && ty != CONTINUATION {
            return Err(H2Error::Malformed("expected CONTINUATION"));
        }
        match ty {
            SETTINGS if flags & ACK == 0 && !seen_settings => {
                seen_settings = true;
                if !len.is_multiple_of(6) {
                    return Err(H2Error::Malformed("SETTINGS length"));
                }
                for c in payload.as_chunks::<6>().0 {
                    cap.settings.push((
                        u16::from_be_bytes([c[0], c[1]]),
                        u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
                    ));
                }
            }
            WINDOW_UPDATE if stream == 0 && len == 4 => {
                cap.window_update = Some(
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                        & 0x7fff_ffff,
                );
            }
            PRIORITY if len == 5 => cap.priority_frames.push(read_priority(stream, payload)),
            HEADERS => {
                let mut b = payload;
                if flags & PADDED != 0 {
                    let pad = *b.first().ok_or(H2Error::Malformed("pad"))? as usize;
                    b = b
                        .get(1..b.len().saturating_sub(pad))
                        .ok_or(H2Error::Malformed("pad length"))?;
                }
                if flags & PRIORITY_FLAG != 0 {
                    if b.len() < 5 {
                        return Err(H2Error::Malformed("HEADERS priority"));
                    }
                    cap.headers_priority = Some(read_priority(stream, &b[..5]));
                    b = &b[5..];
                }
                block.extend_from_slice(b);
                in_headers = flags & END_HEADERS == 0;
                if !in_headers {
                    break;
                }
            }
            CONTINUATION if in_headers => {
                block.extend_from_slice(payload);
                in_headers = flags & END_HEADERS == 0;
                if !in_headers {
                    break;
                }
            }
            _ => {}
        }
    }
    let names = header_block_names(&block)?;
    for n in names {
        if n.starts_with(':') {
            cap.pseudo_order.push(n);
        } else {
            cap.header_names.push(n);
        }
    }
    Ok(cap)
}

fn read_priority(stream: u32, b: &[u8]) -> Priority {
    let d = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    Priority {
        stream,
        exclusive: d & 0x8000_0000 != 0,
        depends_on: d & 0x7fff_ffff,
        weight: b[4] as u16 + 1,
    }
}

/// Encode a frame (used by the reflector's minimal responses and by tests).
pub fn frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(9 + payload.len());
    f.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    f.push(ty);
    f.push(flags);
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// The reflector's whole answer to the first request: empty SETTINGS, SETTINGS ACK, a
/// `:status 204` HEADERS frame (static index 9) ending the stream, and GOAWAY.
pub fn server_reply(stream: u32) -> Vec<u8> {
    let mut out = frame(SETTINGS, 0, 0, &[]);
    out.extend(frame(SETTINGS, ACK, 0, &[]));
    out.extend(frame(HEADERS, END_HEADERS | END_STREAM, stream, &[0x89]));
    let mut goaway = stream.to_be_bytes().to_vec();
    goaway.extend_from_slice(&0u32.to_be_bytes());
    out.extend(frame(7, 0, 0, &goaway));
    out
}

/// A Chrome-shaped client start (for tests): Chrome's SETTINGS and WINDOW_UPDATE, then a
/// GET with pseudo-headers in m,a,s,p order and a few regular headers.
pub fn chrome_like_client_start(authority: &str) -> Vec<u8> {
    let mut out = PREFACE.to_vec();
    let mut s = Vec::new();
    for (k, v) in [(1u16, 65536u32), (2, 0), (4, 6_291_456), (6, 262_144)] {
        s.extend_from_slice(&k.to_be_bytes());
        s.extend_from_slice(&v.to_be_bytes());
    }
    out.extend(frame(SETTINGS, 0, 0, &s));
    out.extend(frame(WINDOW_UPDATE, 0, 0, &15_663_105u32.to_be_bytes()));
    let mut hb = vec![0x82]; // :method GET
    hb.push(0x41); // :authority, literal with indexing, name index 1
    hb.push(authority.len() as u8);
    hb.extend_from_slice(authority.as_bytes());
    hb.push(0x87); // :scheme https
    hb.push(0x84); // :path /
    hb.push(0x40); // literal new name "sec-ch-ua" (not Huffman)
    hb.push(9);
    hb.extend_from_slice(b"sec-ch-ua");
    hb.push(1);
    hb.push(b'x');
    hb.push(0x40 | 58); // user-agent
    hb.push(1);
    hb.push(b'y');
    hb.push(0x40);
    hb.push(0x80 | 3); // Huffman-coded literal name (3 bytes)
    hb.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    hb.push(0);
    let mut pr = 0x8000_0000u32.to_be_bytes().to_vec(); // exclusive, depends on 0
    pr.push(255);
    pr.extend_from_slice(&hb);
    out.extend(frame(
        HEADERS,
        END_HEADERS | END_STREAM | PRIORITY_FLAG,
        1,
        &pr,
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_like_start_gives_chrome_akamai_string() {
        let cap = parse_client_start(&chrome_like_client_start("vanta-health.localhost")).unwrap();
        assert_eq!(
            cap.akamai(),
            "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
        );
        assert_eq!(
            cap.pseudo_order,
            [":method", ":authority", ":scheme", ":path"]
        );
        assert_eq!(cap.header_names, ["sec-ch-ua", "user-agent", "?"]);
        assert_eq!(
            cap.headers_priority,
            Some(Priority {
                stream: 1,
                exclusive: true,
                depends_on: 0,
                weight: 256
            })
        );
    }

    #[test]
    fn dynamic_table_names_resolve() {
        // literal with indexing "x-a", then indexed 62 (the dynamic entry).
        let b = [0x40, 3, b'x', b'-', b'a', 1, b'1', 0xbe];
        assert_eq!(header_block_names(&b).unwrap(), ["x-a", "x-a"]);
        assert!(header_block_names(&[0xbf]).is_err());
        // multi-byte integer: index 62 + 0 via prefix overflow on 7 bits (127 + ...).
        assert!(header_block_names(&[0xff, 0x80]).is_err());
    }

    #[test]
    fn continuation_and_incomplete() {
        let full = chrome_like_client_start("a.localhost");
        for cut in [10, PREFACE.len() + 3, full.len() - 1] {
            assert_eq!(parse_client_start(&full[..cut]), Err(H2Error::Incomplete));
        }
        assert_eq!(
            parse_client_start(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"),
            Err(H2Error::BadPreface)
        );
        // Split the header block into HEADERS + CONTINUATION.
        let mut s = PREFACE.to_vec();
        s.extend(frame(SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 100]));
        s.extend(frame(HEADERS, 0, 1, &[0x82, 0x84]));
        s.extend(frame(CONTINUATION, END_HEADERS, 1, &[0x87, 0x41, 1, b'h']));
        let cap = parse_client_start(&s).unwrap();
        assert_eq!(
            cap.pseudo_order,
            [":method", ":path", ":scheme", ":authority"]
        );
        assert!(cap.akamai().ends_with("|m,p,s,a"));
        assert_eq!(cap.settings, [(3, 100)]);
    }

    #[test]
    fn server_reply_is_well_formed() {
        let r = server_reply(1);
        assert_eq!(&r[..9], &[0, 0, 0, SETTINGS, 0, 0, 0, 0, 0]);
        assert!(r.windows(1).any(|w| w == [0x89]));
    }
}
