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

/// The engine shipped with the installer: `engine\` in the app's resource folder (next to
/// `vanta.exe` on Windows), with its `SHA256SUMS`. Present only in builds made with an
/// engine (`scripts/stage_engine.py`).
pub fn bundled_engine(resource_dir: &Path) -> PathBuf {
    resource_dir.join("engine").join("vanta-chromium.exe")
}

/// Which engine to use: the path set in Settings, else the bundled engine when the
/// installer shipped one, else the default install location.
pub fn choose_engine(setting: Option<&str>, local: &Path, resource_dir: Option<&Path>) -> PathBuf {
    if let Some(p) = setting {
        return expand(p, local);
    }
    match resource_dir.map(bundled_engine) {
        Some(b) if b.is_file() => b,
        _ => default_engine(local),
    }
}

/// Default install location of an engine installed separately.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_choice_order() {
        let base = std::env::temp_dir().join(format!("vanta-paths-{}", std::process::id()));
        let local = base.join("local");
        let res = base.join("res");
        let _ = std::fs::remove_dir_all(&base);
        // Nothing bundled: the default install path.
        assert_eq!(
            choose_engine(None, &local, Some(&res)),
            default_engine(&local)
        );
        assert_eq!(choose_engine(None, &local, None), default_engine(&local));
        // Bundled engine present: it wins over the default path.
        std::fs::create_dir_all(res.join("engine")).unwrap();
        std::fs::write(bundled_engine(&res), b"MZ").unwrap();
        assert_eq!(
            choose_engine(None, &local, Some(&res)),
            bundled_engine(&res)
        );
        // A Settings override wins over both.
        assert_eq!(
            choose_engine(
                Some("%LOCALAPPDATA%\\dev\\vanta-chromium.exe"),
                &local,
                Some(&res)
            ),
            local.join("dev\\vanta-chromium.exe")
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
