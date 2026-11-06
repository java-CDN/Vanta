//! Shared types for every Vanta crate. Defined once here (Master Plan v2, section 3).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Stable identifier of a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProfileId(pub uuid::Uuid);

impl ProfileId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Default for ProfileId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for ProfileId {
    type Err = VantaError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        uuid::Uuid::parse_str(s)
            .map(Self)
            .map_err(|e| VantaError::Invalid(format!("profile id: {e}")))
    }
}

/// Four-part Chromium version, e.g. 156.0.8078.79.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EngineVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub patch: u32,
}

impl EngineVersion {
    pub const fn new(major: u32, minor: u32, build: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            build,
            patch,
        }
    }
    /// Reduced form used in the User-Agent string ("156.0.0.0").
    pub fn reduced(&self) -> String {
        format!("{}.0.0.0", self.major)
    }
}

impl fmt::Display for EngineVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.build, self.patch
        )
    }
}

impl FromStr for EngineVersion {
    type Err = VantaError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // Accept "156.0.8078.79" and ungoogled tags like "156.0.8078.79-1.1".
        let core = s.trim().split('-').next().unwrap_or("");
        let parts: Vec<&str> = core.split('.').collect();
        if parts.len() != 4 {
            return Err(VantaError::Invalid(format!("engine version '{s}'")));
        }
        let mut n = [0u32; 4];
        for (i, p) in parts.iter().enumerate() {
            n[i] = p
                .parse()
                .map_err(|_| VantaError::Invalid(format!("engine version '{s}'")))?;
        }
        Ok(Self::new(n[0], n[1], n[2], n[3]))
    }
}

/// Operating system a persona claims to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsKind {
    Windows10,
    Windows11,
    MacOs,
    Linux,
    Android,
}

impl OsKind {
    pub fn is_mobile(&self) -> bool {
        matches!(self, OsKind::Android)
    }
    pub fn family(&self) -> &'static str {
        match self {
            OsKind::Windows10 | OsKind::Windows11 => "Windows",
            OsKind::MacOs => "macOS",
            OsKind::Linux => "Linux",
            OsKind::Android => "Android",
        }
    }
}

/// Runtime state of a profile, as reported by the launcher (never guessed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileStatus {
    Stopped,
    Starting,
    Running,
    Sleeping,
    Blocked,
}

impl ProfileStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProfileStatus::Stopped => "stopped",
            ProfileStatus::Starting => "starting",
            ProfileStatus::Running => "running",
            ProfileStatus::Sleeping => "sleeping",
            ProfileStatus::Blocked => "blocked",
        }
    }
}

impl FromStr for ProfileStatus {
    type Err = VantaError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "stopped" => Self::Stopped,
            "starting" => Self::Starting,
            "running" => Self::Running,
            "sleeping" => Self::Sleeping,
            "blocked" => Self::Blocked,
            _ => return Err(VantaError::Invalid(format!("status '{s}'"))),
        })
    }
}

/// Exit codes shared by launcher and engine patch (Master Plan v2, section 6).
pub mod exit_codes {
    pub const BAD_CONFIG_SIGNATURE: i32 = 86;
    pub const VERSION_MISMATCH: i32 = 87;
    pub const ISOLATION_BROKEN: i32 = 88;
}

#[derive(Debug, thiserror::Error)]
pub enum VantaError {
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("vault is locked")]
    Locked,
    #[error("wrong password or corrupted data")]
    Crypto,
    #[error("storage error: {0}")]
    Storage(String),
    #[error("version lock (C031): persona Chrome {persona} != engine {engine}")]
    VersionMismatch { persona: String, engine: String },
}

pub type Result<T> = std::result::Result<T, VantaError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_version_parses_ungoogled_tag() {
        let v: EngineVersion = "156.0.8078.79-1.1".parse().unwrap();
        assert_eq!(v, EngineVersion::new(156, 0, 8078, 79));
        assert_eq!(v.to_string(), "156.0.8078.79");
        assert_eq!(v.reduced(), "156.0.0.0");
    }

    #[test]
    fn engine_version_rejects_garbage() {
        assert!("156.0.8078".parse::<EngineVersion>().is_err());
        assert!("a.b.c.d".parse::<EngineVersion>().is_err());
    }

    #[test]
    fn engine_version_orders() {
        let a: EngineVersion = "156.0.8078.73".parse().unwrap();
        let b: EngineVersion = "156.0.8078.79".parse().unwrap();
        assert!(a < b);
    }

    #[test]
    fn status_roundtrip() {
        for s in ["stopped", "starting", "running", "sleeping", "blocked"] {
            assert_eq!(s.parse::<ProfileStatus>().unwrap().as_str(), s);
        }
    }

    #[test]
    fn profile_id_roundtrip() {
        let id = ProfileId::new();
        let back: ProfileId = id.to_string().parse().unwrap();
        assert_eq!(id, back);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<ProfileId>(&json).unwrap(), id);
    }

    #[test]
    fn exit_codes_are_distinct() {
        use exit_codes::*;
        assert_ne!(BAD_CONFIG_SIGNATURE, VERSION_MISMATCH);
        assert_ne!(VERSION_MISMATCH, ISOLATION_BROKEN);
    }
}
