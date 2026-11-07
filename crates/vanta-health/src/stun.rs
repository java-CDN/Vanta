//! STUN responder on `127.0.0.1:<ephemeral>/udp` (RFC 5389 Binding).
//!
//! The probe page lists this responder as its ICE server. With the Network Guard WebRTC
//! rule (`disable_non_proxied_udp`) and a proxy without UDP, Chrome must not send any raw
//! UDP at all, so a Binding Request arriving here means WebRTC can leave outside the proxy.
//! Every request is recorded; each one is answered with XOR-MAPPED-ADDRESS like a real
//! STUN server so the page sees the same candidate a public server would produce.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use vanta_types::{Result, VantaError};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_SUCCESS: u16 = 0x0101;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_USERNAME: u16 = 0x0006;

/// One Binding Request seen by the responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunRequest {
    pub from: SocketAddr,
    pub transaction_id: [u8; 12],
    /// Attribute types in order.
    pub attributes: Vec<u16>,
    pub username: Option<String>,
}

/// Parse a STUN Binding Request (header + attributes). `None` for anything else.
pub fn parse_binding_request(b: &[u8], from: SocketAddr) -> Option<StunRequest> {
    if b.len() < 20 || b[0] & 0xc0 != 0 {
        return None;
    }
    let ty = u16::from_be_bytes([b[0], b[1]]);
    let len = u16::from_be_bytes([b[2], b[3]]) as usize;
    let cookie = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
    if ty != BINDING_REQUEST
        || cookie != MAGIC_COOKIE
        || !len.is_multiple_of(4)
        || b.len() < 20 + len
    {
        return None;
    }
    let mut tid = [0u8; 12];
    tid.copy_from_slice(&b[8..20]);
    let mut attributes = Vec::new();
    let mut username = None;
    let mut p = 20;
    while p + 4 <= 20 + len {
        let at = u16::from_be_bytes([b[p], b[p + 1]]);
        let al = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
        if p + 4 + al > 20 + len {
            return None;
        }
        if at == ATTR_USERNAME {
            username = Some(String::from_utf8_lossy(&b[p + 4..p + 4 + al]).into_owned());
        }
        attributes.push(at);
        p += 4 + al.div_ceil(4) * 4;
    }
    Some(StunRequest {
        from,
        transaction_id: tid,
        attributes,
        username,
    })
}

/// Binding Success Response carrying XOR-MAPPED-ADDRESS for `mapped`.
pub fn binding_success(tid: &[u8; 12], mapped: SocketAddr) -> Vec<u8> {
    let mut attr = Vec::new();
    let xport = mapped.port() ^ (MAGIC_COOKIE >> 16) as u16;
    match mapped.ip() {
        IpAddr::V4(ip) => {
            attr.extend_from_slice(&[0, 1]);
            attr.extend_from_slice(&xport.to_be_bytes());
            attr.extend_from_slice(&(u32::from(ip) ^ MAGIC_COOKIE).to_be_bytes());
        }
        IpAddr::V6(ip) => {
            attr.extend_from_slice(&[0, 2]);
            attr.extend_from_slice(&xport.to_be_bytes());
            let mut key = MAGIC_COOKIE.to_be_bytes().to_vec();
            key.extend_from_slice(tid);
            for (o, k) in ip.octets().iter().zip(key) {
                attr.push(o ^ k);
            }
        }
    }
    let mut m = BINDING_SUCCESS.to_be_bytes().to_vec();
    m.extend_from_slice(&((4 + attr.len()) as u16).to_be_bytes());
    m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    m.extend_from_slice(tid);
    m.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    m.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    m.extend_from_slice(&attr);
    m
}

/// Decode XOR-MAPPED-ADDRESS from a Binding Success Response (IPv4 only; for tests and
/// tools).
pub fn decode_xor_mapped(resp: &[u8]) -> Option<SocketAddr> {
    if resp.len() < 32 || u16::from_be_bytes([resp[0], resp[1]]) != BINDING_SUCCESS {
        return None;
    }
    let mut p = 20;
    while p + 4 <= resp.len() {
        let at = u16::from_be_bytes([resp[p], resp[p + 1]]);
        let al = u16::from_be_bytes([resp[p + 2], resp[p + 3]]) as usize;
        if at == ATTR_XOR_MAPPED_ADDRESS && al == 8 && resp[p + 5] == 1 {
            let port = u16::from_be_bytes([resp[p + 6], resp[p + 7]]) ^ (MAGIC_COOKIE >> 16) as u16;
            let ip = u32::from_be_bytes([resp[p + 8], resp[p + 9], resp[p + 10], resp[p + 11]])
                ^ MAGIC_COOKIE;
            return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port));
        }
        p += 4 + al.div_ceil(4) * 4;
    }
    None
}

/// Build a Binding Request (for tests).
pub fn binding_request(tid: [u8; 12]) -> Vec<u8> {
    let mut m = BINDING_REQUEST.to_be_bytes().to_vec();
    m.extend_from_slice(&0u16.to_be_bytes());
    m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    m.extend_from_slice(&tid);
    m
}

/// A running STUN responder.
pub struct StunResponder {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<StunRequest>>>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl StunResponder {
    /// Bind `127.0.0.1:0/udp` and start answering.
    pub async fn start() -> Result<Self> {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|e| VantaError::Network(format!("stun bind: {e}")))?;
        let addr = sock
            .local_addr()
            .map_err(|e| VantaError::Network(format!("stun addr: {e}")))?;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (stop, mut rx) = watch::channel(false);
        let s2 = seen.clone();
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    r = sock.recv_from(&mut buf) => {
                        let Ok((n, from)) = r else { continue };
                        if let Some(req) = parse_binding_request(&buf[..n], from) {
                            let reply = binding_success(&req.transaction_id, from);
                            s2.lock().expect("stun log").push(req);
                            let _ = sock.send_to(&reply, from).await;
                        }
                    }
                }
            }
        });
        Ok(Self {
            addr,
            seen,
            stop,
            task: Some(task),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Every Binding Request received so far.
    pub fn requests(&self) -> Vec<StunRequest> {
        self.seen.lock().expect("stun log").clone()
    }

    pub async fn shutdown(mut self) {
        self.stop.send_replace(true);
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
    }
}

impl Drop for StunResponder {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        if let Some(t) = &self.task {
            t.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_v4() {
        let from: SocketAddr = "203.0.113.9:40000".parse().unwrap();
        let req = binding_request([1; 12]);
        let r = parse_binding_request(&req, from).unwrap();
        assert_eq!(r.transaction_id, [1; 12]);
        let resp = binding_success(&r.transaction_id, from);
        assert_eq!(decode_xor_mapped(&resp), Some(from));
        // The address is XOR-ed, never in clear.
        assert!(!resp.windows(4).any(|w| w == [203, 0, 113, 9]));
    }

    #[test]
    fn rejects_non_stun_and_parses_username() {
        let from: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(parse_binding_request(b"hello world, not stun!", from).is_none());
        let mut bad_cookie = binding_request([2; 12]);
        bad_cookie[4] = 0;
        assert!(parse_binding_request(&bad_cookie, from).is_none());
        let mut m = binding_request([3; 12]);
        m[2..4].copy_from_slice(&8u16.to_be_bytes());
        m.extend_from_slice(&[0, 6, 0, 3, b'a', b':', b'b', 0]);
        let r = parse_binding_request(&m, from).unwrap();
        assert_eq!(r.username.as_deref(), Some("a:b"));
        assert_eq!(r.attributes, [ATTR_USERNAME]);
    }

    #[test]
    fn v6_mapping_is_xored_with_cookie_and_tid() {
        let from: SocketAddr = "[2001:db8::1]:5000".parse().unwrap();
        let resp = binding_success(&[4; 12], from);
        assert_eq!(resp.len(), 20 + 4 + 20);
        assert_eq!(decode_xor_mapped(&resp), None, "decoder is IPv4 only");
    }
}
