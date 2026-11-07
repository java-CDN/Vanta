//! Where Vanta keeps its data and finds its engine.

use std::path::{Path, PathBuf};
use vanta_types::EngineVersion;

/// The engine version this build was made for (`engine/VERSION`). Used when the installed
/// engine folder has no VERSION file of its own.
const BUILT_FOR_ENGINE: &str = include_str!("../../../../engine/VERSION");

/// `%LOCALAPPDATA%` (Windows) or the platform's local data folder from Tauri.
pub fn local_app_data(fallback: impl FnOnce() -> PathBuf) -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(fallback)
}

/// Expand `%LOCALAPPDATA%` in a user-entered path.
pub fn expand(p: &str, local: &Path) -> PathBuf {
    const VAR: &str = "%localappdata%";
    if p.len() >= VAR.len()
        && p.is_char_boundary(VAR.len())
        && p[..VAR.len()].eq_ignore_ascii_case(VAR)
    {
        local.join(p[VAR.len()..].trim_start_matches(['\\', '/']))
    } else {
        PathBuf::from(p)
    }
}

/// Default install location of the engine (the installer will put it here, P3).
pub fn default_engine(local: &Path) -> PathBuf {
    local
        .join("Programs")
        .join("Vanta")
        .join("engine")
        .join("vanta-chromium.exe")
}

/// The engine's version: `VERSION` next to the executable, else the one this build was
/// made for.
pub fn engine_version(exe: &Path) -> EngineVersion {
    exe.parent()
        .and_then(|d| std::fs::read_to_string(d.join("VERSION")).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| {
            BUILT_FOR_ENGINE
                .trim()
                .parse()
                .expect("engine/VERSION is a valid version")
        })
}
