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
//!
//! **These grammars are taken from the providers' public documentation and have not been
//! verified against live accounts** ([`PROVIDER_PRESETS_VERIFIED_LIVE`] is `false`); the
//! Proxy Hub says so next to every preset.
//!
//! Proxy Hub entries ([`ProviderPreset`]) derive their session from a random
//! [`SessionKey`] stored with the preset (one entry = one session, one proxy per profile);
//! [`build_username`] derives it from a profile id. Both use the same derivation.

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

/// The grammars above come from public documentation, not from tests with live accounts.
pub const PROVIDER_PRESETS_VERIFIED_LIVE: bool = false;

/// What the UI needs to know about a provider's grammar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderSpec {
    pub provider: Provider,
    pub name: &'static str,
    /// What the base username looks like in the provider's dashboard.
    pub base_hint: &'static str,
    pub supports_city: bool,
    pub supports_ttl: bool,
    /// Webshare: the sticky slot is a numbered endpoint, so the plan's pool size is needed.
    pub needs_pool: bool,
    /// Always `false` for now: taken from public docs, not verified live.
    pub verified_live: bool,
}

impl Provider {
    pub fn spec(&self) -> ProviderSpec {
        ProviderSpec {
            provider: *self,
            name: self.name(),
            base_hint: match self {
                Provider::BrightData => "brd-customer-<id>-zone-<zone>",
                Provider::Soax => "package-<id>",
                Provider::Geonode => "geonode_<user>",
                Provider::DataImpulse => "<login>",
                Provider::Webshare => "<username>",
                Provider::Thordata => "td-customer-<user> or <user>",
            },
            supports_city: self.supports_city(),
            supports_ttl: self.supports_ttl(),
            needs_pool: matches!(self, Provider::Webshare),
            verified_live: PROVIDER_PRESETS_VERIFIED_LIVE,
        }
    }
}

/// The value a sticky session id is derived from: 16 bytes, a profile id or a random key
/// kept with a Proxy Hub preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKey(pub [u8; 16]);

impl From<ProfileId> for SessionKey {
    fn from(p: ProfileId) -> Self {
        SessionKey(*p.as_bytes())
    }
}

impl SessionKey {
    /// A fresh random key.
    pub fn random() -> Self {
        let mut b = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
        SessionKey(b)
    }

    /// 32 hex digits, optionally with UUID hyphens.
    pub fn parse(s: &str) -> Result<Self> {
        let hex: String = s.chars().filter(|c| *c != '-').collect();
        if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid("session key must be 32 hex digits".into()));
        }
        let mut b = [0u8; 16];
        for (i, out) in b.iter_mut().enumerate() {
            *out = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex checked");
        }
        Ok(SessionKey(b))
    }

    /// Lowercase hex, 32 digits.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// A Proxy Hub entry built from a provider grammar. Holds no password (that stays in the
/// vault); the stored username is always `self.username()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderPreset {
    pub provider: Provider,
    /// The account's base username exactly as the provider's dashboard shows it.
    pub base_user: String,
    #[serde(default)]
    pub params: SessionParams,
    /// [`SessionKey`] as hex; kept across edits so the entry keeps its session.
    pub session_key: String,
}

impl ProviderPreset {
    /// The gateway username this preset stands for.
    pub fn username(&self) -> Result<String> {
        let key = SessionKey::parse(&self.session_key)?;
        build_username_for(self.provider, self.base_user.trim(), key, &self.params)
    }

    /// Same preset with the base username trimmed, the country upper-cased, empty optional
    /// texts dropped and the session key normalised (an empty key gets a fresh one).
    pub fn normalized(mut self) -> Result<Self> {
        self.base_user = self.base_user.trim().to_string();
        let opt = |v: Option<String>| v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        self.params.country = opt(self.params.country).map(|c| c.to_ascii_uppercase());
        self.params.city = opt(self.params.city);
        self.session_key = if self.session_key.trim().is_empty() {
            SessionKey::random().to_hex()
        } else {
            SessionKey::parse(self.session_key.trim())?.to_hex()
        };
        self.username()?;
        Ok(self)
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

fn digest(provider: Provider, key: SessionKey, params: &SessionParams) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"vanta/proxy-session/v1\0");
    h.update(provider.tag().as_bytes());
    h.update([0]);
    h.update(key.0);
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
    session_id_for(provider, profile.into(), params)
}

/// [`session_id`] for any [`SessionKey`].
pub fn session_id_for(provider: Provider, key: SessionKey, params: &SessionParams) -> String {
    digest(provider, key, params)[..6]
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
    build_username_for(provider, base_user, profile.into(), params)
}

/// [`build_username`] for any [`SessionKey`].
pub fn build_username_for(
    provider: Provider,
    base_user: &str,
    key: SessionKey,
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
    let sid = session_id_for(provider, key, params);
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
            let d = digest(provider, key, params);
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

    /// Fixed vector shared with the UI's TypeScript port (ui/tests/presets.test.ts).
    #[test]
    fn preset_vector_matches_the_ui_port() {
        let p = ProviderPreset {
            provider: Provider::Soax,
            base_user: " package-123456 ".into(),
            params: SessionParams {
                country: Some("us".into()),
                city: Some("New York".into()),
                session_ttl_min: Some(30),
                pool_size: None,
                rotation: 2,
            },
            session_key: "00112233-4455-6677-8899-AABBCCDDEEFF".into(),
        }
        .normalized()
        .unwrap();
        assert_eq!(p.session_key, "00112233445566778899aabbccddeeff");
        assert_eq!(p.base_user, "package-123456");
        assert_eq!(p.params.country.as_deref(), Some("US"));
        let key = SessionKey::parse(&p.session_key).unwrap();
        let sid = session_id_for(Provider::Soax, key, &p.params);
        assert_eq!(sid, SOAX_VECTOR_SID);
        assert_eq!(
            p.username().unwrap(),
            format!("package-123456-country-us-city-new+york-sessionid-{sid}-sessionlength-1800")
        );
        // Webshare slot vector.
        let w = ProviderPreset {
            provider: Provider::Webshare,
            base_user: "abcd".into(),
            params: SessionParams {
                country: Some("gb".into()),
                pool_size: Some(10),
                ..Default::default()
            },
            session_key: "00112233445566778899aabbccddeeff".into(),
        };
        assert_eq!(w.username().unwrap(), WEBSHARE_VECTOR);
    }

    const SOAX_VECTOR_SID: &str = "04d3accaaada";
    const WEBSHARE_VECTOR: &str = "abcd-GB-8";

    #[test]
    fn session_key_grammar_and_profile_equivalence() {
        let id = pid(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff);
        let k = SessionKey::from(id);
        assert_eq!(k.to_hex(), "00112233445566778899aabbccddeeff");
        assert_eq!(SessionKey::parse(&k.to_hex()).unwrap(), k);
        let p = us_ny();
        // A profile and the same bytes as a preset key give the same session.
        assert_eq!(
            session_id(Provider::Geonode, id, &p),
            session_id_for(Provider::Geonode, k, &p)
        );
        for bad in ["", "xyz", "0011", &"g".repeat(32), &"0".repeat(33)] {
            assert!(SessionKey::parse(bad).is_err(), "{bad}");
        }
        assert_ne!(SessionKey::random(), SessionKey::random());
    }

    #[test]
    fn preset_normalizes_and_rejects() {
        let base = ProviderPreset {
            provider: Provider::Geonode,
            base_user: "geonode_u".into(),
            params: SessionParams {
                country: Some(" de ".into()),
                city: Some("  ".into()),
                ..Default::default()
            },
            session_key: String::new(),
        };
        let n = base.clone().normalized().unwrap();
        assert_eq!(n.params.country.as_deref(), Some("DE"));
        assert_eq!(n.params.city, None);
        assert_eq!(n.session_key.len(), 32);
        // Same key, same username; a new rotation moves the session.
        let u = n.username().unwrap();
        assert_eq!(u, n.clone().normalized().unwrap().username().unwrap());
        let mut r = n.clone();
        r.params.rotation += 1;
        assert_ne!(u, r.username().unwrap());
        // Wrong base, unsupported parameter, bad key.
        let mut bad = base.clone();
        bad.base_user = "someone".into();
        assert!(bad.normalized().is_err());
        let mut bad = base.clone();
        bad.provider = Provider::BrightData;
        bad.base_user = "brd-customer-1-zone-z".into();
        bad.params.session_ttl_min = Some(10);
        assert!(bad.normalized().is_err());
        let mut bad = base;
        bad.session_key = "nothex".into();
        assert!(bad.normalized().is_err());
        // Serialized form (stored with the Proxy Hub entry): no password field at all.
        let j = serde_json::to_value(&n).unwrap();
        assert_eq!(j["provider"], "geonode");
        assert!(j.get("password").is_none());
    }

    #[test]
    fn specs_say_not_verified() {
        for p in Provider::ALL {
            let s = p.spec();
            assert!(!s.verified_live);
            assert_eq!(s.supports_city, p.supports_city());
            assert_eq!(s.needs_pool, p == Provider::Webshare);
        }
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
