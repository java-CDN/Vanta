//! Proxy online/offline state and the launch gate (F04): a profile whose proxy is offline,
//! unchecked or checked too long ago must not launch. This module only answers the
//! question; `vanta-launcher` enforces it.
//!
//! Also the SOCKS5 UDP ASSOCIATE capability probe: when the proxy has no UDP, QUIC and
//! WebRTC UDP stay off (F05).

use crate::endpoint::{ProxyEndpoint, ProxyScheme};
use crate::net::{connect_proxy, socks5_request, NetError, TargetAddr};
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A check older than this blocks launch until the proxy is re-checked.
pub const MAX_CHECK_AGE_MS: i64 = 5 * 60 * 1000;

/// Milliseconds since the Unix epoch (wall clock).
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Why a proxy counts as offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineReason {
    Unreachable,
    Timeout,
    AuthFailed,
    ProtocolError,
}

impl OfflineReason {
    pub fn from_net(e: &NetError) -> Self {
        match e {
            NetError::Io(_) => OfflineReason::Unreachable,
            NetError::Timeout => OfflineReason::Timeout,
            NetError::Auth => OfflineReason::AuthFailed,
            NetError::Protocol(_) | NetError::Refused(_) => OfflineReason::ProtocolError,
        }
    }
}

impl fmt::Display for OfflineReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OfflineReason::Unreachable => "proxy unreachable",
            OfflineReason::Timeout => "proxy timed out",
            OfflineReason::AuthFailed => "proxy rejected the login",
            OfflineReason::ProtocolError => "proxy protocol error",
        })
    }
}

/// Last known state of a proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProxyState {
    Unknown,
    Online {
        checked_ms: i64,
        latency_ms: u32,
    },
    Offline {
        checked_ms: i64,
        reason: OfflineReason,
    },
}

/// Why the launch gate said no.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchBlock {
    ProxyOffline(OfflineReason),
    ProxyUnchecked,
    ProxyCheckStale { age_ms: i64 },
}

impl fmt::Display for LaunchBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LaunchBlock::ProxyOffline(r) => write!(f, "launch blocked: {r}"),
            LaunchBlock::ProxyUnchecked => f.write_str("launch blocked: proxy not checked yet"),
            LaunchBlock::ProxyCheckStale { age_ms } => {
                write!(
                    f,
                    "launch blocked: proxy last checked {}s ago",
                    age_ms / 1000
                )
            }
        }
    }
}

impl ProxyState {
    pub fn is_online(&self) -> bool {
        matches!(self, ProxyState::Online { .. })
    }

    /// The launch gate. `Ok` only for an `Online` check no older than `max_age_ms`
    /// (a check stamped in the future, e.g. after a clock change, counts as fresh).
    pub fn launch_gate(&self, now_ms: i64, max_age_ms: i64) -> Result<(), LaunchBlock> {
        match *self {
            ProxyState::Unknown => Err(LaunchBlock::ProxyUnchecked),
            ProxyState::Offline { reason, .. } => Err(LaunchBlock::ProxyOffline(reason)),
            ProxyState::Online { checked_ms, .. } => {
                let age = now_ms - checked_ms;
                if age > max_age_ms {
                    Err(LaunchBlock::ProxyCheckStale { age_ms: age })
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// Reachability probe: TCP connect (+TLS for https) and, for SOCKS5, the greeting and
/// login. HTTP proxies cannot verify a login without a CONNECT target, so for them this
/// checks reachability only; the full 8-step check (vanta-health / Proxy Hub) goes further.
pub async fn probe(proxy: &ProxyEndpoint, addr: SocketAddr, timeout: Duration) -> ProxyState {
    let start = Instant::now();
    let r = connect_proxy(proxy, addr, timeout).await;
    let checked_ms = now_ms();
    match r {
        Ok(_) => ProxyState::Online {
            checked_ms,
            latency_ms: start.elapsed().as_millis().min(u32::MAX as u128) as u32,
        },
        Err(e) => ProxyState::Offline {
            checked_ms,
            reason: OfflineReason::from_net(&e),
        },
    }
}

/// Result of the UDP ASSOCIATE capability probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpSupport {
    /// The proxy granted a UDP relay at this address. This is a capability answer only:
    /// whether datagrams really pass is the health check's job.
    Supported { relay: String },
    /// The proxy refused UDP ASSOCIATE with this SOCKS5 reply code (7 = not supported).
    Unsupported { reply: u8 },
    /// HTTP(S) proxies have no UDP.
    NotSocks5,
}

impl UdpSupport {
    pub fn is_supported(&self) -> bool {
        matches!(self, UdpSupport::Supported { .. })
    }
}

/// Ask a SOCKS5 proxy for UDP ASSOCIATE. Errors mean the proxy itself failed.
pub async fn udp_associate_probe(
    proxy: &ProxyEndpoint,
    addr: SocketAddr,
    timeout: Duration,
) -> Result<UdpSupport, NetError> {
    if proxy.scheme != ProxyScheme::Socks5 {
        return Ok(UdpSupport::NotSocks5);
    }
    let mut s = connect_proxy(proxy, addr, timeout).await?;
    let any: SocketAddr = "0.0.0.0:0".parse().expect("valid");
    let r = tokio::time::timeout(timeout, socks5_request(&mut *s, 3, &TargetAddr::Ip(any)))
        .await
        .unwrap_or(Err(NetError::Timeout));
    match r {
        Ok(bound) => Ok(UdpSupport::Supported {
            relay: bound.to_string(),
        }),
        Err(NetError::Refused(code)) => Ok(UdpSupport::Unsupported { reply: code as u8 }),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn gate() {
        let now = 10_000_000;
        assert_eq!(
            ProxyState::Unknown.launch_gate(now, MAX_CHECK_AGE_MS),
            Err(LaunchBlock::ProxyUnchecked)
        );
        let off = ProxyState::Offline {
            checked_ms: now,
            reason: OfflineReason::Timeout,
        };
        assert_eq!(
            off.launch_gate(now, MAX_CHECK_AGE_MS),
            Err(LaunchBlock::ProxyOffline(OfflineReason::Timeout))
        );
        let fresh = ProxyState::Online {
            checked_ms: now - 1000,
            latency_ms: 40,
        };
        assert!(fresh.launch_gate(now, MAX_CHECK_AGE_MS).is_ok());
        let stale = ProxyState::Online {
            checked_ms: now - MAX_CHECK_AGE_MS - 1,
            latency_ms: 40,
        };
        assert!(matches!(
            stale.launch_gate(now, MAX_CHECK_AGE_MS),
            Err(LaunchBlock::ProxyCheckStale { .. })
        ));
        assert!(!off.is_online() && fresh.is_online());
    }

    #[test]
    fn state_serializes_tagged() {
        let s = ProxyState::Offline {
            checked_ms: 5,
            reason: OfflineReason::AuthFailed,
        };
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(
            j,
            r#"{"state":"offline","checked_ms":5,"reason":"auth_failed"}"#
        );
        assert_eq!(serde_json::from_str::<ProxyState>(&j).unwrap(), s);
    }

    /// Minimal SOCKS5 server answering one UDP ASSOCIATE with `reply`.
    async fn udp_server(reply: u8) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).await.unwrap();
            s.write_all(&[5, 0]).await.unwrap();
            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.unwrap();
            assert_eq!(req[1], 3, "UDP ASSOCIATE");
            s.write_all(&[5, reply, 0, 1, 127, 0, 0, 1, 0x1f, 0x90])
                .await
                .unwrap();
            let _ = s.read(&mut [0u8; 1]).await;
        });
        addr
    }

    #[tokio::test]
    async fn udp_probe_supported_and_not() {
        let p = ProxyEndpoint::new(ProxyScheme::Socks5, "127.0.0.1", 1, None);
        let t = Duration::from_secs(5);
        let ok = udp_associate_probe(&p, udp_server(0).await, t)
            .await
            .unwrap();
        assert_eq!(
            ok,
            UdpSupport::Supported {
                relay: "127.0.0.1:8080".into()
            }
        );
        let no = udp_associate_probe(&p, udp_server(7).await, t)
            .await
            .unwrap();
        assert_eq!(no, UdpSupport::Unsupported { reply: 7 });
        let http = ProxyEndpoint::new(ProxyScheme::Http, "127.0.0.1", 1, None);
        assert_eq!(
            udp_associate_probe(&http, udp_server(0).await, t)
                .await
                .unwrap(),
            UdpSupport::NotSocks5
        );
    }

    #[tokio::test]
    async fn probe_offline_when_nothing_listens() {
        // Bind then drop to get a port with no listener.
        let addr = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let p = ProxyEndpoint::new(ProxyScheme::Socks5, "127.0.0.1", addr.port(), None);
        let s = probe(&p, addr, Duration::from_secs(3)).await;
        assert!(matches!(s, ProxyState::Offline { .. }), "{s:?}");
        assert!(s.launch_gate(now_ms(), MAX_CHECK_AGE_MS).is_err());
    }

    #[tokio::test]
    async fn probe_online_with_login() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut g = [0u8; 4];
            s.read_exact(&mut g).await.unwrap();
            s.write_all(&[5, 2]).await.unwrap();
            let mut buf = [0u8; 64];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(&[1, 0]).await.unwrap();
        });
        let p = ProxyEndpoint::new(
            ProxyScheme::Socks5,
            "127.0.0.1",
            addr.port(),
            Some(crate::endpoint::Credentials::new("u", "p")),
        );
        let s = probe(&p, addr, Duration::from_secs(3)).await;
        assert!(s.is_online(), "{s:?}");
    }
}
