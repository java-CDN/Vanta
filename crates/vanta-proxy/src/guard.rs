//! Network Guard policy (F05).
//!
//! The kill switch and the WebRTC rule are not settings: each is a one-variant type, so a
//! profile record or an API call cannot carry an "off" value at all (deserializing one
//! fails). IPv6 and LAN blocking are constants. Only the DoH provider is configurable.

use crate::doh::DohProvider;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

/// Kill switch: the relay cuts every client connection the moment the upstream proxy
/// fails and never falls back to a direct connection. There is no other mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitch {
    #[default]
    FailClosed,
}

/// WebRTC IP handling. Only `disable_non_proxied_udp` exists (rule C024; enforced in the
/// engine patch and passed as `--force-webrtc-ip-handling-policy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcPolicy {
    #[default]
    DisableNonProxiedUdp,
}

impl WebRtcPolicy {
    pub fn as_str(&self) -> &'static str {
        "disable_non_proxied_udp"
    }
}

/// Per-profile Network Guard policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardPolicy {
    #[serde(default)]
    pub kill_switch: KillSwitch,
    #[serde(default)]
    pub webrtc: WebRtcPolicy,
    #[serde(default)]
    pub doh: DohProvider,
}

impl GuardPolicy {
    /// IPv6 targets are always refused (the relay only speaks IPv4 upstream).
    pub const BLOCK_IPV6: bool = true;
    /// LAN, loopback and other non-public targets are always refused.
    pub const BLOCK_LAN: bool = true;

    /// QUIC may only run when UDP really goes through the proxy. The relay does not carry
    /// UDP, so today this is false for every profile.
    pub fn quic_allowed(&self, relay_carries_udp: bool) -> bool {
        relay_carries_udp
    }

    /// Engine switches that put this policy into effect.
    pub fn engine_args(&self, relay_proxy_url: &str) -> Vec<String> {
        vec![
            format!("--proxy-server={relay_proxy_url}"),
            // With a SOCKS5 proxy Chromium resolves names at the proxy; never locally.
            "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1".into(),
            format!("--force-webrtc-ip-handling-policy={}", self.webrtc.as_str()),
            "--disable-quic".into(),
        ]
    }
}

/// True for addresses the relay must never connect to: loopback, private (RFC 1918),
/// link-local, CGNAT (100.64/10), unspecified, broadcast, multicast, reserved 240/4,
/// benchmarking 198.18/15 and "this network" 0/8.
pub fn is_blocked_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 100 && (o[1] & 0xC0) == 64)
        || (o[0] == 198 && (o[1] & 0xFE) == 18)
}

/// Whether a target address is refused by the guard (all IPv6 is refused).
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_blocked_ipv4(v4) || GuardPolicy::BLOCK_IPV6,
            None => GuardPolicy::BLOCK_IPV6,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_off_switch_exists() {
        for bad in [
            r#"{"kill_switch":"off"}"#,
            r#"{"kill_switch":false}"#,
            r#"{"webrtc":"default"}"#,
            r#"{"webrtc":"default_public_interface_only"}"#,
            r#"{"block_lan":false}"#,
        ] {
            assert!(serde_json::from_str::<GuardPolicy>(bad).is_err(), "{bad}");
        }
        let p: GuardPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(p.kill_switch, KillSwitch::FailClosed);
        assert_eq!(p.webrtc.as_str(), "disable_non_proxied_udp");
        let q: GuardPolicy = serde_json::from_str(r#"{"doh":"quad9"}"#).unwrap();
        assert_eq!(q.doh, DohProvider::Quad9);
    }

    #[test]
    fn engine_args_carry_policy() {
        let a = GuardPolicy::default().engine_args("socks5://127.0.0.1:5555");
        assert!(a.contains(&"--proxy-server=socks5://127.0.0.1:5555".to_string()));
        assert!(a.iter().any(|x| x.ends_with("disable_non_proxied_udp")));
        assert!(a.contains(&"--disable-quic".to_string()));
        assert!(!GuardPolicy::default().quic_allowed(false));
    }

    #[test]
    fn blocked_ranges() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "240.0.0.1",
            "198.18.0.1",
            "0.1.2.3",
        ] {
            assert!(is_blocked_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "1.1.1.1",
            "93.184.216.34",
            "203.0.113.7",
            "100.128.0.1",
            "172.32.0.1",
        ] {
            assert!(!is_blocked_ip(ip.parse().unwrap()), "{ip}");
        }
        assert!(is_blocked_ip("2606:4700::1111".parse().unwrap()));
        assert!(is_blocked_ip("::ffff:1.1.1.1".parse().unwrap()));
    }
}
