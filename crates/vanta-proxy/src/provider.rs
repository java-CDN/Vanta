//! Provider presets: build the gateway username that selects geo targeting and a STICKY
//! session per profile (F04).
//!
//! The session id is derived deterministically from the profile id, the provider and the
//! targeting parameters, so a profile keeps the same exit IP across launches (for as long as
//! the provider keeps the session alive) and two profiles never share a session. Bump
//! [`SessionParams::rotation`] to deliberately move a profile to a new session.
//!
//! Grammars, as documented by each provider for its residential gateways at the time of
//! writing (the caller supplies the account's base username exactly as shown in the
//! provider's dashboard):
//!
//! | Provider    | Base username            | Built username |
//! |-------------|--------------------------|----------------|
//! | Bright Data | `brd-customer-ID-zone-Z` | `…-country-us-city-newyork-session-<sid>` |
//! | SOAX        | `package-ID`             | `…-country-us-city-new+york-sessionid-<sid>-sessionlength-<secs>` |
//! | Geonode     | `geonode_USER`           | `…-type-residential-country-us-city-newyork-session-<sid>-lifetime-<min>` |
//! | DataImpulse | `LOGIN`                  | `LOGIN__cr.us;city.newyork;sessid.<sid>;sessttl.<min>` |
//! | Webshare    | `USER`                   | `USER-US-<n>` (sticky = numbered endpoint `n` in 1..=pool) |
//! | Thordata    | `td-customer-USER`       | `…-country-us-city-newyork-sessid-<sid>-sesstime-<min>` |
//!
//! A parameter the provider has no syntax for is rejected (never silently dropped), so the
//! UI can disable it instead of producing an exit that does not match what was asked for.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vanta_types::{ProfileId, Result, VantaError};

/// Residential proxy providers with a built-in username grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    BrightData,
    Soax,
    Geonode,
    DataImpulse,
    Webshare,
    Thordata,
}

impl Provider {
    pub const ALL: [Provider; 6] = [
        Provider::BrightData,
        Provider::Soax,
        Provider::Geonode,
        Provider::DataImpulse,
        Provider::Webshare,
        Provider::Thordata,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Provider::BrightData => "Bright Data",
            Provider::Soax => "SOAX",
            Provider::Geonode => "Geonode",
            Provider::DataImpulse => "DataImpulse",
            Provider::Webshare => "Webshare",
            Provider::Thordata => "Thordata",
        }
    }

    fn tag(&self) -> &'static str {
        match self {
            Provider::BrightData => "brightdata",
            Provider::Soax => "soax",
            Provider::Geonode => "geonode",
            Provider::DataImpulse => "dataimpulse",
            Provider::Webshare => "webshare",
            Provider::Thordata => "thordata",
        }
    }

    /// Whether the grammar can target a city.
    pub fn supports_city(&self) -> bool {
        !matches!(self, Provider::Webshare)
    }

    /// Whether the grammar can set a session lifetime.
    pub fn supports_ttl(&self) -> bool {
        !matches!(self, Provider::BrightData | Provider::Webshare)
    }
}

/// Targeting and session options for a provider preset.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionParams {
    /// ISO 3166-1 alpha-2 country code.
    pub country: Option<String>,
    /// City name as the provider spells it ("New York").
    pub city: Option<String>,
    /// Requested sticky-session lifetime in minutes.
    pub session_ttl_min: Option<u32>,
    /// Webshare only: number of numbered endpoints in the plan (sticky slot = 1..=pool).
    pub pool_size: Option<u32>,
    /// Incremented by the user to get a fresh session; 0 by default.
    pub rotation: u32,
}

fn digest(provider: Provider, profile: ProfileId, params: &SessionParams) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"vanta/proxy-session/v1\0");
    h.update(provider.tag().as_bytes());
    h.update([0]);
    h.update(profile.as_bytes());
    h.update(params.country.as_deref().unwrap_or("").to_ascii_lowercase());
    h.update([0]);
    h.update(params.city.as_deref().unwrap_or("").to_lowercase());
    h.update([0]);
    h.update(params.session_ttl_min.unwrap_or(0).to_le_bytes());
    h.update(params.rotation.to_le_bytes());
    h.finalize().into()
}

/// Deterministic sticky session id: 12 lowercase hex characters (safe in every grammar).
pub fn session_id(provider: Provider, profile: ProfileId, params: &SessionParams) -> String {
    digest(provider, profile, params)[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn invalid(msg: String) -> VantaError {
    VantaError::Invalid(msg)
}

fn country(params: &SessionParams) -> Result<Option<String>> {
    match params.country.as_deref() {
        None => Ok(None),
        Some(c) if c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic()) => {
            Ok(Some(c.to_ascii_lowercase()))
        }
        Some(_) => Err(invalid("country must be a two-letter ISO code".into())),
    }
}

/// City with spaces replaced by `space` and everything except [a-z0-9] dropped.
fn city(params: &SessionParams, space: &str) -> Result<Option<String>> {
    let Some(c) = params.city.as_deref() else {
        return Ok(None);
    };
    let words: Vec<String> = c
        .split_whitespace()
        .map(|w| {
            w.chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .collect::<String>()
                .to_ascii_lowercase()
        })
        .filter(|w| !w.is_empty())
        .collect();
    if words.is_empty() {
        return Err(invalid("city name has no letters".into()));
    }
    Ok(Some(words.join(space)))
}

fn check_base(base: &str) -> Result<()> {
    if base.is_empty() || base.len() > 200 {
        return Err(invalid("base username is empty or too long".into()));
    }
    if base
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b == b':' || b == b'@')
    {
        return Err(invalid(
            "base username contains whitespace, ':' or '@'".into(),
        ));
    }
    Ok(())
}

fn unsupported(provider: Provider, what: &str) -> VantaError {
    invalid(format!("{} has no {what} parameter", provider.name()))
}

/// Build the gateway username for `profile`.
pub fn build_username(
    provider: Provider,
    base_user: &str,
    profile: ProfileId,
    params: &SessionParams,
) -> Result<String> {
    check_base(base_user)?;
    if params.city.is_some() && params.country.is_none() {
        return Err(invalid("a city needs a country".into()));
    }
    if params.city.is_some() && !provider.supports_city() {
        return Err(unsupported(provider, "city"));
    }
    if params.session_ttl_min.is_some() && !provider.supports_ttl() {
        return Err(unsupported(provider, "session lifetime"));
    }
    if params.pool_size.is_some() && provider != Provider::Webshare {
        return Err(unsupported(provider, "pool size"));
    }
    if let Some(t) = params.session_ttl_min {
        if !(1..=1440).contains(&t) {
            return Err(invalid("session lifetime must be 1 to 1440 minutes".into()));
        }
    }
    let sid = session_id(provider, profile, params);
    let cc = country(params)?;
    let mut u = String::from(base_user);
    let mut push = |k: &str, v: &str| {
        u.push('-');
        u.push_str(k);
        u.push('-');
        u.push_str(v);
    };
    match provider {
        Provider::BrightData => {
            if !base_user.starts_with("brd-customer-") || !base_user.contains("-zone-") {
                return Err(invalid(
                    "Bright Data base username looks like brd-customer-<id>-zone-<zone>".into(),
                ));
            }
            if let Some(c) = &cc {
                push("country", c);
            }
            if let Some(c) = city(params, "")? {
                push("city", &c);
            }
            push("session", &sid);
        }
        Provider::Soax => {
            if !base_user.starts_with("package-") {
                return Err(invalid("SOAX base username looks like package-<id>".into()));
            }
            if let Some(c) = &cc {
                push("country", c);
            }
            if let Some(c) = city(params, "+")? {
                push("city", &c);
            }
            push("sessionid", &sid);
            if let Some(t) = params.session_ttl_min {
                push("sessionlength", &(u64::from(t) * 60).to_string());
            }
        }
        Provider::Geonode => {
            if !base_user.starts_with("geonode_") {
                return Err(invalid(
                    "Geonode base username looks like geonode_<user>".into(),
                ));
            }
            push("type", "residential");
            if let Some(c) = &cc {
                push("country", c);
            }
            if let Some(c) = city(params, "")? {
                push("city", &c);
            }
            push("session", &sid);
            if let Some(t) = params.session_ttl_min {
                push("lifetime", &t.to_string());
            }
        }
        Provider::Thordata => {
            if !base_user.starts_with("td-customer-") {
                u = format!("td-customer-{base_user}");
            }
            let mut push = |k: &str, v: &str| {
                u.push('-');
                u.push_str(k);
                u.push('-');
                u.push_str(v);
            };
            if let Some(c) = &cc {
                push("country", c);
            }
            if let Some(c) = city(params, "")? {
                push("city", &c);
            }
            push("sessid", &sid);
            if let Some(t) = params.session_ttl_min {
                push("sesstime", &t.to_string());
            }
        }
        Provider::DataImpulse => {
            if base_user.contains("__") {
                return Err(invalid(
                    "DataImpulse base login must not already carry __ parameters".into(),
                ));
            }
            let mut kv = Vec::new();
            if let Some(c) = &cc {
                kv.push(format!("cr.{c}"));
            }
            if let Some(c) = city(params, "")? {
                kv.push(format!("city.{c}"));
            }
            kv.push(format!("sessid.{sid}"));
            if let Some(t) = params.session_ttl_min {
                kv.push(format!("sessttl.{t}"));
            }
            u = format!("{base_user}__{}", kv.join(";"));
        }
        Provider::Webshare => {
            let pool = params
                .pool_size
                .filter(|p| *p >= 1)
                .ok_or_else(|| invalid("Webshare sticky sessions need pool_size >= 1".into()))?;
            let d = digest(provider, profile, params);
            let n = u64::from_le_bytes(d[..8].try_into().expect("8 bytes")) % u64::from(pool) + 1;
            if let Some(c) = &cc {
                u.push('-');
                u.push_str(&c.to_ascii_uppercase());
            }
            u.push('-');
            u.push_str(&n.to_string());
        }
    }
    Ok(u)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u128) -> ProfileId {
        ProfileId(uuid::Uuid::from_u128(n))
    }

    fn us_ny() -> SessionParams {
        SessionParams {
            country: Some("US".into()),
            city: Some("New York".into()),
            session_ttl_min: Some(30),
            ..Default::default()
        }
    }

    #[test]
    fn session_id_is_sticky_and_distinct() {
        let p = us_ny();
        let a = session_id(Provider::Soax, pid(1), &p);
        assert_eq!(a, session_id(Provider::Soax, pid(1), &p));
        assert_eq!(a.len(), 12);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, session_id(Provider::Soax, pid(2), &p));
        assert_ne!(a, session_id(Provider::Geonode, pid(1), &p));
        let rotated = SessionParams {
            rotation: 1,
            ..p.clone()
        };
        assert_ne!(a, session_id(Provider::Soax, pid(1), &rotated));
        let other_country = SessionParams {
            country: Some("de".into()),
            city: None,
            ..p
        };
        assert_ne!(a, session_id(Provider::Soax, pid(1), &other_country));
    }

    #[test]
    fn bright_data() {
        let p = SessionParams {
            session_ttl_min: None,
            ..us_ny()
        };
        let u = build_username(
            Provider::BrightData,
            "brd-customer-hl_1234-zone-res",
            pid(1),
            &p,
        )
        .unwrap();
        let sid = session_id(Provider::BrightData, pid(1), &p);
        assert_eq!(
            u,
            format!("brd-customer-hl_1234-zone-res-country-us-city-newyork-session-{sid}")
        );
        assert!(build_username(Provider::BrightData, "someone", pid(1), &p).is_err());
        assert!(build_username(
            Provider::BrightData,
            "brd-customer-1-zone-r",
            pid(1),
            &us_ny()
        )
        .is_err());
    }

    #[test]
    fn soax() {
        let p = us_ny();
        let u = build_username(Provider::Soax, "package-123456", pid(1), &p).unwrap();
        let sid = session_id(Provider::Soax, pid(1), &p);
        assert_eq!(
            u,
            format!("package-123456-country-us-city-new+york-sessionid-{sid}-sessionlength-1800")
        );
    }

    #[test]
    fn geonode() {
        let p = us_ny();
        let u = build_username(Provider::Geonode, "geonode_abc", pid(1), &p).unwrap();
        let sid = session_id(Provider::Geonode, pid(1), &p);
        assert_eq!(
            u,
            format!(
                "geonode_abc-type-residential-country-us-city-newyork-session-{sid}-lifetime-30"
            )
        );
    }

    #[test]
    fn data_impulse() {
        let p = us_ny();
        let u = build_username(Provider::DataImpulse, "login1", pid(1), &p).unwrap();
        let sid = session_id(Provider::DataImpulse, pid(1), &p);
        assert_eq!(
            u,
            format!("login1__cr.us;city.newyork;sessid.{sid};sessttl.30")
        );
        assert!(build_username(Provider::DataImpulse, "login1__cr.de", pid(1), &p).is_err());
    }

    #[test]
    fn thordata() {
        let p = us_ny();
        let u = build_username(Provider::Thordata, "user9", pid(1), &p).unwrap();
        let sid = session_id(Provider::Thordata, pid(1), &p);
        assert_eq!(
            u,
            format!("td-customer-user9-country-us-city-newyork-sessid-{sid}-sesstime-30")
        );
        let u2 = build_username(Provider::Thordata, "td-customer-user9", pid(1), &p).unwrap();
        assert_eq!(u, u2);
    }

    #[test]
    fn webshare_slot_is_sticky_and_in_range() {
        let p = SessionParams {
            country: Some("gb".into()),
            pool_size: Some(10),
            ..Default::default()
        };
        let u = build_username(Provider::Webshare, "abcd", pid(7), &p).unwrap();
        assert_eq!(
            u,
            build_username(Provider::Webshare, "abcd", pid(7), &p).unwrap()
        );
        let n: u32 = u.strip_prefix("abcd-GB-").unwrap().parse().unwrap();
        assert!((1..=10).contains(&n));
        assert!(build_username(
            Provider::Webshare,
            "abcd",
            pid(7),
            &SessionParams::default()
        )
        .is_err());
        assert!(build_username(Provider::Webshare, "abcd", pid(7), &us_ny()).is_err());
    }

    #[test]
    fn validation() {
        let bad_cc = SessionParams {
            country: Some("USA".into()),
            ..Default::default()
        };
        let city_only = SessionParams {
            city: Some("Paris".into()),
            ..Default::default()
        };
        let long_ttl = SessionParams {
            session_ttl_min: Some(5000),
            ..Default::default()
        };
        for p in [bad_cc, city_only, long_ttl] {
            assert!(build_username(Provider::Soax, "package-1", pid(1), &p).is_err());
        }
        assert!(build_username(
            Provider::Soax,
            "package 1",
            pid(1),
            &SessionParams::default()
        )
        .is_err());
        assert!(build_username(
            Provider::Soax,
            "package-1:x",
            pid(1),
            &SessionParams::default()
        )
        .is_err());
        let pool = SessionParams {
            pool_size: Some(3),
            ..Default::default()
        };
        assert!(build_username(Provider::Soax, "package-1", pid(1), &pool).is_err());
    }

    #[test]
    fn every_provider_builds_without_params() {
        let base = |p: Provider| match p {
            Provider::BrightData => "brd-customer-1-zone-z",
            Provider::Soax => "package-1",
            Provider::Geonode => "geonode_u",
            _ => "user",
        };
        for p in Provider::ALL {
            let params = SessionParams {
                pool_size: (p == Provider::Webshare).then_some(5),
                ..Default::default()
            };
            let u = build_username(p, base(p), pid(3), &params).unwrap();
            assert!(
                u.starts_with(base(p)) || p == Provider::Thordata,
                "{p:?}: {u}"
            );
            assert!(!u.contains(' '));
        }
    }
}
