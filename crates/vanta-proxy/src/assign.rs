//! One proxy, one profile (F04): warn when a proxy is assigned to a second profile.
//!
//! Pure functions over the current assignments; the UI decides how to show the warning.
//! Two endpoints are "the same proxy" when scheme, host, port and username match. The
//! username is part of the identity because provider presets put the sticky session in it:
//! the same gateway with two different session usernames gives two different exits.

use crate::endpoint::{ProxyEndpoint, ProxyScheme};
use std::collections::BTreeMap;
use vanta_types::ProfileId;

/// What makes two endpoints the same exit (password excluded).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProxyIdentity {
    pub scheme: &'static str,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
}

impl ProxyIdentity {
    pub fn of(e: &ProxyEndpoint) -> Self {
        Self {
            scheme: match e.scheme {
                ProxyScheme::Http => "http",
                ProxyScheme::Https => "https",
                ProxyScheme::Socks5 => "socks5",
            },
            host: e.host.to_ascii_lowercase(),
            port: e.port,
            username: e.auth.as_ref().map(|c| c.username.clone()),
        }
    }
}

/// The proxy is already used by `other_profiles`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedProxyWarning {
    pub proxy: ProxyIdentity,
    pub other_profiles: Vec<ProfileId>,
}

/// Warning for assigning `proxy` to `profile`, given the current assignments.
/// The profile's own current assignment is ignored (re-saving is not a conflict).
pub fn check_assignment<'a, I>(
    assignments: I,
    profile: ProfileId,
    proxy: &ProxyEndpoint,
) -> Option<SharedProxyWarning>
where
    I: IntoIterator<Item = (ProfileId, &'a ProxyEndpoint)>,
{
    let id = ProxyIdentity::of(proxy);
    let mut others: Vec<ProfileId> = assignments
        .into_iter()
        .filter(|(p, e)| *p != profile && ProxyIdentity::of(e) == id)
        .map(|(p, _)| p)
        .collect();
    if others.is_empty() {
        return None;
    }
    others.sort();
    others.dedup();
    Some(SharedProxyWarning {
        proxy: id,
        other_profiles: others,
    })
}

/// Every proxy currently used by more than one profile.
pub fn shared_proxies<'a, I>(assignments: I) -> Vec<SharedProxyWarning>
where
    I: IntoIterator<Item = (ProfileId, &'a ProxyEndpoint)>,
{
    let mut by: BTreeMap<ProxyIdentity, Vec<ProfileId>> = BTreeMap::new();
    for (p, e) in assignments {
        by.entry(ProxyIdentity::of(e)).or_default().push(p);
    }
    by.into_iter()
        .filter_map(|(proxy, mut ps)| {
            ps.sort();
            ps.dedup();
            (ps.len() > 1).then_some(SharedProxyWarning {
                proxy,
                other_profiles: ps,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::{parse_line, ProxyScheme::*};

    fn pid(n: u128) -> ProfileId {
        ProfileId(uuid::Uuid::from_u128(n))
    }

    #[test]
    fn warns_on_second_profile() {
        let a = parse_line("u:p1@gw.example:1000", Socks5).unwrap();
        let same_other_pw = parse_line("u:p2@GW.example:1000", Socks5).unwrap();
        let current = [(pid(1), &a)];
        let w = check_assignment(current, pid(2), &same_other_pw).unwrap();
        assert_eq!(w.other_profiles, [pid(1)]);
        assert_eq!(w.proxy.host, "gw.example");
    }

    #[test]
    fn same_profile_or_different_session_is_fine() {
        let a = parse_line("u-session-aaa:p@gw.example:1000", Socks5).unwrap();
        let b = parse_line("u-session-bbb:p@gw.example:1000", Socks5).unwrap();
        let http = parse_line("u-session-aaa:p@gw.example:1000", Http).unwrap();
        assert!(check_assignment([(pid(1), &a)], pid(1), &a).is_none());
        assert!(check_assignment([(pid(1), &a)], pid(2), &b).is_none());
        assert!(check_assignment([(pid(1), &a)], pid(2), &http).is_none());
    }

    #[test]
    fn lists_all_shared() {
        let a = parse_line("h1.example:1", Http).unwrap();
        let b = parse_line("h2.example:1", Http).unwrap();
        let all = [(pid(3), &a), (pid(1), &a), (pid(2), &b)];
        let s = shared_proxies(all);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].other_profiles, [pid(1), pid(3)]);
    }
}
