//! Serializable values the Tauri shell sends and receives. None of them can carry a
//! password, a key or a recovery secret except [`VaultCreated`] (shown once).

use serde::{Deserialize, Serialize};
use vanta_fingerprint::SurfaceMode;
use vanta_log::{LogEntry, LogKind};
use vanta_proxy::{ProviderPreset, ProxyChecks, ProxyScheme, ProxyState};
use vanta_store::{HealthSummary, ProfileMeta};
use vanta_types::{OsKind, ProfileId, ProfileStatus};

/// Returned once by `create_vault`: the recovery key to print. Never stored.
#[derive(Debug, Clone, Serialize)]
pub struct VaultCreated {
    pub recovery_key: String,
}

/// Integrity of the activity log, checked at every unlock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LogIntegrity {
    Ok,
    /// The chain verifies but its head differs from the one kept in the vault: entries
    /// were removed from the end (or the log was replaced by an older copy).
    HeadMismatch {
        detail: String,
    },
    /// The log file could not be read or authenticated; it was set aside and a new log
    /// started.
    Unreadable {
        detail: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct UnlockReport {
    pub log_integrity: LogIntegrity,
    /// Inline proxy lines from an older database moved into the vault at this unlock.
    pub migrated_proxies: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfilePage {
    pub items: Vec<ProfileMeta>,
    pub total: i64,
}

/// What a profile looks like (non-secret summary of its persona).
#[derive(Debug, Clone, Serialize)]
pub struct PersonaSummary {
    pub device_id: String,
    pub os: OsKind,
    pub user_agent: String,
    pub screen: String,
    pub gpu: String,
    pub locale: String,
    pub hardware_concurrency: u32,
    pub device_memory: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileDetail {
    pub meta: ProfileMeta,
    pub persona: PersonaSummary,
    pub health: Option<HealthSummary>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NewProfile {
    pub name: String,
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// `None`: any Windows 10/11 device, by real-world weight.
    #[serde(default)]
    pub os: Option<OsKind>,
    /// Defaults to `en-US`.
    #[serde(default)]
    pub locale: Option<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub color: String,
    #[serde(default)]
    pub proxy_id: Option<String>,
    /// Seed (64-bit, hex) from [`crate::VantaApp::preview_fingerprint`], so the saved
    /// persona is the one the user saw. `None`: a fresh random seed.
    #[serde(default)]
    pub seed: Option<String>,
}

/// Fields to change; `None` keeps the current value.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProfileEdit {
    pub name: Option<String>,
    pub folder: Option<String>,
    pub tags: Option<Vec<String>>,
    pub notes: Option<String>,
    pub color: Option<String>,
}

/// A Proxy Hub entry as the UI sees it: never the password.
#[derive(Debug, Clone, Serialize)]
pub struct ProxyView {
    pub id: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub has_password: bool,
    pub label: String,
    pub state: ProxyState,
    /// `scheme://user:***@host:port`.
    pub display: String,
    /// Provider preset the username is built from (no password; that stays in the vault).
    pub preset: Option<ProviderPreset>,
    /// Last extended check (exit IP / ASN / country, UDP, blocklists, speed).
    pub checks: Option<ProxyChecks>,
}

/// The non-secret fields of a Proxy Hub entry, as typed into the add / edit form. With a
/// `preset`, the username is built from it and `username` is ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyForm {
    pub scheme: ProxyScheme,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub preset: Option<ProviderPreset>,
}

/// A preset as the backend normalised it (a fresh session key when it had none) and the
/// username it builds.
#[derive(Debug, Clone, Serialize)]
pub struct PresetPreview {
    pub preset: ProviderPreset,
    pub username: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportLineError {
    pub line: usize,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportResult {
    pub added: Vec<ProxyView>,
    pub errors: Vec<ImportLineError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssignResult {
    /// Other profiles already using the same exit (same scheme, host, port and user).
    pub shared_with: Vec<ProfileId>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckProblem {
    pub id: String,
    pub title: String,
    pub outcome: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthResult {
    pub summary: HealthSummary,
    /// Non-passing checks, worst first.
    pub problems: Vec<CheckProblem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LaunchInfo {
    pub profile_id: ProfileId,
    pub pid: u32,
    pub relay_port: u16,
    pub engine_version: String,
}

/// A status the watcher wrote to the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusChange {
    pub profile_id: ProfileId,
    pub status: ProfileStatus,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct LogQuery {
    #[serde(default)]
    pub kinds: Vec<LogKind>,
    #[serde(default)]
    pub profile: Option<ProfileId>,
    #[serde(default)]
    pub from_ms: Option<i64>,
    #[serde(default)]
    pub to_ms: Option<i64>,
    #[serde(default)]
    pub offset: usize,
    /// 0 = 100.
    #[serde(default)]
    pub limit: usize,
}

/// A page of the activity log, newest first.
#[derive(Debug, Clone, Serialize)]
pub struct LogPage {
    pub entries: Vec<LogEntry>,
    pub total: usize,
}

/// One consistency rule result (C001–C030). `level`: `pass`, `note` or `fail`.
#[derive(Debug, Clone, Serialize)]
pub struct RuleView {
    pub id: String,
    pub level: String,
    pub message: String,
}

/// Everything Fingerprint Studio shows about a persona (read-only: the identity changes
/// only by regenerating it). The Chrome version is the installed engine's (R5).
/// Seeds are not included; `seed_prefix` is the first 4 hex digits, for recognition only.
#[derive(Debug, Clone, Serialize)]
pub struct FingerprintView {
    pub device_id: String,
    pub os: OsKind,
    pub engine: String,
    pub user_agent: String,
    pub sec_ch_ua: String,
    pub navigator_platform: String,
    pub ua_platform: String,
    pub platform_version: String,
    pub architecture: String,
    pub bitness: String,
    pub screen_width: u32,
    pub screen_height: u32,
    pub avail_width: u32,
    pub avail_height: u32,
    pub color_depth: u32,
    pub device_pixel_ratio: f64,
    pub hardware_concurrency: u32,
    pub device_memory: f64,
    pub max_touch_points: u32,
    pub gpu_vendor: String,
    pub gpu_renderer: String,
    pub webgpu_vendor: String,
    pub webgpu_arch: String,
    pub fonts: Vec<String>,
    pub microphones: u32,
    pub cameras: u32,
    pub speakers: u32,
    pub locale: String,
    pub languages: Vec<String>,
    pub accept_language: String,
    pub timezone: Option<String>,
    pub country: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub canvas: SurfaceMode,
    pub webgl_image: SurfaceMode,
    pub audio: SurfaceMode,
    pub webrtc_policy: String,
    pub seed_prefix: String,
    pub rules: Vec<RuleView>,
}

/// State of the offline GeoIP database (Geo Auto-Match, F07).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GeoDbStatus {
    NotBundled,
    Loading,
    Ready { info: vanta_geo::GeoDbInfo },
    Failed { message: String },
}

/// Where an exit IP is, per the offline database.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GeoLocationView {
    pub country: String,
    pub country_name: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    pub timezone: Option<String>,
}

/// One value Geo Auto-Match would change. `language` changes are applied only when the
/// user keeps "languages" selected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GeoFieldChange {
    /// `country`, `timezone`, `geolocation`, `locale`, `languages`, `accept_language`.
    pub field: String,
    pub from: Option<String>,
    pub to: String,
    pub language: bool,
}

/// Preview of Geo Auto-Match for one profile. Empty `changes` and no `problem` = already
/// matched.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GeoPlan {
    pub profile_id: ProfileId,
    pub name: String,
    pub proxy_id: Option<String>,
    pub exit_ip: Option<String>,
    pub location: Option<GeoLocationView>,
    pub changes: Vec<GeoFieldChange>,
    pub problem: Option<String>,
}

/// One confirmed match: the exit IP the preview showed, and whether locale / languages /
/// Accept-Language follow it too.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GeoApply {
    pub profile_id: ProfileId,
    pub exit_ip: String,
    pub languages: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GeoApplyResult {
    pub profile_id: ProfileId,
    /// The persona changed (its health report was cleared).
    pub changed: bool,
    pub error: Option<String>,
}
