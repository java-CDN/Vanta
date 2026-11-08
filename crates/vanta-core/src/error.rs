//! Errors as the UI sees them: one serializable enum, tagged by `kind`.

use serde::Serialize;
use vanta_launcher::Block;
use vanta_types::VantaError;

/// One reason the launch gate refused a profile. `code` is stable for the UI; `message`
/// is ready to show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockReason {
    pub code: String,
    pub message: String,
}

impl BlockReason {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn no_proxy() -> Self {
        Self::new(
            "no_proxy",
            "launch blocked: the profile has no proxy (Vanta never connects directly)",
        )
    }

    pub fn from_block(b: &Block) -> Self {
        use vanta_proxy::LaunchBlock;
        let code = match b {
            Block::Proxy(LaunchBlock::ProxyOffline(_)) => "proxy_offline",
            Block::Proxy(LaunchBlock::ProxyUnchecked) => "proxy_unchecked",
            Block::Proxy(LaunchBlock::ProxyCheckStale { .. }) => "proxy_check_stale",
            Block::GuardNotArmed => "guard_not_armed",
            Block::RulesFailed => "rules_failed",
            Block::HealthTooLow { .. } => "health_too_low",
            Block::HealthMissing => "health_missing",
            Block::HealthExpired { .. } => "health_expired",
        };
        Self::new(code, b.to_string())
    }
}

#[derive(Debug, thiserror::Error, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CoreError {
    #[error("the vault has not been created yet")]
    NotInitialized,
    #[error("the vault already exists")]
    AlreadyInitialized,
    #[error("vault is locked")]
    Locked,
    #[error("wrong password or corrupted data")]
    Crypto,
    #[error("not found: {message}")]
    NotFound { message: String },
    #[error("invalid input: {message}")]
    Invalid { message: String },
    #[error("profile is already running")]
    AlreadyRunning,
    #[error("profile is not running")]
    NotRunning,
    /// The launch gate refused; every reason is listed.
    #[error("launch blocked: {}", .reasons.iter().map(|r| r.message.as_str()).collect::<Vec<_>>().join("; "))]
    Blocked { reasons: Vec<BlockReason> },
    /// The engine refused the launch config (exit 86).
    #[error("the engine rejected the launch config signature (exit 86)")]
    BadConfigSignature,
    /// The engine's own version differs from the persona's (exit 87, C030).
    #[error("persona version does not match the installed engine {expected} (exit 87, C030)")]
    VersionMismatch { expected: String },
    /// The engine ended during its start-up window.
    #[error("the engine exited during start-up (code {code:?})")]
    EngineExited { code: Option<i32> },
    /// The host cannot run the engine (non-Windows developer build).
    #[error("unsupported: {message}")]
    Unsupported { message: String },
    #[error("storage error: {message}")]
    Storage { message: String },
    #[error("network error: {message}")]
    Network { message: String },
    /// The profile's last [`crate::MAX_FAILED_LAUNCHES`] launches failed in a row; the user
    /// has to confirm before another attempt ([`crate::VantaApp::launch_profile_confirmed`]).
    #[error(
        "the last {failures} launches failed in a row (last: {last_error}); confirm to try again"
    )]
    ConfirmRequired { failures: u32, last_error: String },
    /// The engine shipped with the installer failed (or has not finished) its SHA256SUMS
    /// check ([`crate::EngineCheck`]); nothing is started.
    #[error("engine integrity: {message}")]
    EngineIntegrity { message: String },
}

impl CoreError {
    /// A launch attempt that failed on its own terms: the gate refused (preflight block),
    /// the engine refused its config (exit 86/87) or ended in its start-up window.
    pub fn is_failed_launch(&self) -> bool {
        matches!(
            self,
            CoreError::Blocked { .. }
                | CoreError::BadConfigSignature
                | CoreError::VersionMismatch { .. }
                | CoreError::EngineExited { .. }
        )
    }
}

impl From<VantaError> for CoreError {
    fn from(e: VantaError) -> Self {
        match e {
            VantaError::Invalid(message) => CoreError::Invalid { message },
            VantaError::NotFound(message) => CoreError::NotFound { message },
            VantaError::Locked => CoreError::Locked,
            VantaError::Crypto => CoreError::Crypto,
            VantaError::Storage(message) => CoreError::Storage { message },
            VantaError::Network(message) => CoreError::Network { message },
            VantaError::VersionMismatch { engine, .. } => {
                CoreError::VersionMismatch { expected: engine }
            }
        }
    }
}

pub type CoreResult<T> = std::result::Result<T, CoreError>;
