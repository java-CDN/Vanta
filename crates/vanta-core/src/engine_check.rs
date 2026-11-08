//! Integrity of an engine shipped with the installer.
//!
//! `engine/scripts/package_engine.py` produces `vanta-engine-win64.zip` and `SHA256SUMS`
//! (`<sha256>  vanta-engine-win64.zip`, `<sha256>  vanta-engine-win64/vanta-chromium.exe`).
//! When the desktop build bundles an engine, `scripts/stage_engine.py` checks the zip
//! against that file, extracts it and installs `SHA256SUMS` next to the engine with one
//! more line per extracted file. At start the app checks every installed file listed there
//! ([`verify_engine_dir`]); until the result is [`EngineCheck::Verified`], launches and
//! health runs are refused with a clear error.
//!
//! An engine folder without `SHA256SUMS` (installed by hand, or a developer path in
//! Settings) is [`EngineCheck::NotBundled`] and behaves as before.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Component, Path};

/// The checksum file next to a bundled engine.
pub const ENGINE_SUMS: &str = "SHA256SUMS";
/// Top folder inside `vanta-engine-win64.zip`; the installed folder is its contents.
pub const ENGINE_TOP: &str = "vanta-engine-win64";
/// The packaged archive. Checked at build time; not installed.
pub const ENGINE_ZIP: &str = "vanta-engine-win64.zip";
/// The engine executable; its line must be present.
pub const ENGINE_EXE: &str = "vanta-chromium.exe";

/// Result of the engine integrity check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EngineCheck {
    /// No `SHA256SUMS` next to the engine: not an engine shipped with the installer.
    NotBundled,
    /// The check is still running (large files are hashed in the background at start).
    Pending,
    /// Every listed file matched.
    Verified { files: usize },
    /// A file is missing or differs, or `SHA256SUMS` is unreadable. Launches are refused.
    Failed { message: String },
}

impl EngineCheck {
    /// Why a launch must not start, if it must not.
    pub fn launch_problem(&self) -> Option<String> {
        match self {
            EngineCheck::NotBundled | EngineCheck::Verified { .. } => None,
            EngineCheck::Pending => {
                Some("the engine files are still being checked; try again in a moment".into())
            }
            EngineCheck::Failed { message } => Some(format!(
                "the installed engine does not match its SHA256SUMS ({message}); reinstall Vanta"
            )),
        }
    }
}

/// One `SHA256SUMS` line: lowercase hex digest and the path as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumLine {
    pub sha256: String,
    pub path: String,
}

/// Parse `sha256sum` output: `<64 hex> <space><space or *><path>` per line; blank lines are
/// skipped. Paths must be relative, use `/`, and stay inside the folder.
pub fn parse_sums(text: &str) -> Result<Vec<SumLine>, String> {
    let mut out = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        let bad = |what: &str| format!("SHA256SUMS line {}: {what}", n + 1);
        let (hash, rest) = line.split_at_checked(64).ok_or_else(|| bad("too short"))?;
        if !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(bad("digest is not 64 hex digits"));
        }
        let path = rest
            .strip_prefix("  ")
            .or_else(|| rest.strip_prefix(" *"))
            .ok_or_else(|| bad("expected two spaces after the digest"))?;
        let p = Path::new(path);
        if path.is_empty()
            || path.contains('\\')
            || !p.components().all(|c| matches!(c, Component::Normal(_)))
        {
            return Err(bad(
                "path must be relative and stay inside the engine folder",
            ));
        }
        out.push(SumLine {
            sha256: hash.to_ascii_lowercase(),
            path: path.to_string(),
        });
    }
    Ok(out)
}

/// SHA-256 of a file, streamed.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Check the engine folder `dir` against its `SHA256SUMS`.
///
/// Lines for `vanta-engine-win64/<file>` are checked at `dir/<file>`; the archive line
/// (`vanta-engine-win64.zip`) is skipped. The executable's line must be there.
pub fn verify_engine_dir(dir: &Path) -> EngineCheck {
    let text = match std::fs::read_to_string(dir.join(ENGINE_SUMS)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return EngineCheck::NotBundled,
        Err(e) => {
            return EngineCheck::Failed {
                message: format!("{ENGINE_SUMS} unreadable: {}", e.kind()),
            }
        }
    };
    let lines = match parse_sums(&text) {
        Ok(l) => l,
        Err(message) => return EngineCheck::Failed { message },
    };
    let prefix = format!("{ENGINE_TOP}/");
    let exe = format!("{prefix}{ENGINE_EXE}");
    if !lines.iter().any(|l| l.path == exe) {
        return EngineCheck::Failed {
            message: format!("{ENGINE_SUMS} has no line for {ENGINE_EXE}"),
        };
    }
    let mut files = 0;
    for l in &lines {
        if l.path == ENGINE_ZIP {
            continue;
        }
        let Some(rel) = l.path.strip_prefix(&prefix) else {
            return EngineCheck::Failed {
                message: format!("unexpected path {} in {ENGINE_SUMS}", l.path),
            };
        };
        match sha256_file(&dir.join(rel)) {
            Ok(h) if h == l.sha256 => files += 1,
            Ok(_) => {
                return EngineCheck::Failed {
                    message: format!("{rel} differs"),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return EngineCheck::Failed {
                    message: format!("{rel} is missing"),
                }
            }
            Err(e) => {
                return EngineCheck::Failed {
                    message: format!("{rel} unreadable: {}", e.kind()),
                }
            }
        }
    }
    EngineCheck::Verified { files }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sha(b: &[u8]) -> String {
        Sha256::digest(b)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// An installed engine folder the way stage_engine.py leaves it.
    fn engine(files: &[(&str, &[u8])]) -> Dir {
        let d = Dir(std::env::temp_dir().join(format!("vanta-engine-{}", uuid::Uuid::new_v4())));
        let mut sums = format!("{}  {ENGINE_ZIP}\n", "ab".repeat(32));
        for (name, data) in files {
            let p = d.0.join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, data).unwrap();
            sums.push_str(&format!("{}  {ENGINE_TOP}/{name}\n", sha(data)));
        }
        std::fs::write(d.0.join(ENGINE_SUMS), sums).unwrap();
        d
    }

    #[test]
    fn verified_when_every_file_matches() {
        let d = engine(&[
            (ENGINE_EXE, b"MZ engine"),
            ("chrome.dll", b"MZ dll"),
            ("locales/en-US.pak", b"pak"),
        ]);
        assert_eq!(verify_engine_dir(&d.0), EngineCheck::Verified { files: 3 });
        assert_eq!(verify_engine_dir(&d.0).launch_problem(), None);
    }

    #[test]
    fn changed_or_missing_file_fails() {
        let d = engine(&[(ENGINE_EXE, b"MZ engine"), ("chrome.dll", b"MZ dll")]);
        std::fs::write(d.0.join("chrome.dll"), b"MZ evil").unwrap();
        let c = verify_engine_dir(&d.0);
        assert_eq!(
            c,
            EngineCheck::Failed {
                message: "chrome.dll differs".into()
            }
        );
        assert!(c.launch_problem().unwrap().contains("reinstall Vanta"));
        std::fs::remove_file(d.0.join(ENGINE_EXE)).unwrap();
        assert!(matches!(
            verify_engine_dir(&d.0),
            EngineCheck::Failed { message } if message.contains("missing")
        ));
    }

    #[test]
    fn no_sums_is_not_bundled() {
        let d = engine(&[(ENGINE_EXE, b"MZ")]);
        std::fs::remove_file(d.0.join(ENGINE_SUMS)).unwrap();
        assert_eq!(verify_engine_dir(&d.0), EngineCheck::NotBundled);
        assert_eq!(EngineCheck::NotBundled.launch_problem(), None);
        assert!(EngineCheck::Pending.launch_problem().is_some());
    }

    #[test]
    fn package_engine_output_without_exe_line_or_with_foreign_path_fails() {
        let d = engine(&[("chrome.dll", b"x")]);
        assert!(matches!(
            verify_engine_dir(&d.0),
            EngineCheck::Failed { message } if message.contains(ENGINE_EXE)
        ));
        let d = engine(&[(ENGINE_EXE, b"MZ")]);
        let mut s = std::fs::read_to_string(d.0.join(ENGINE_SUMS)).unwrap();
        s.push_str(&format!("{}  other/file.dll\n", sha(b"x")));
        std::fs::write(d.0.join(ENGINE_SUMS), s).unwrap();
        assert!(matches!(
            verify_engine_dir(&d.0),
            EngineCheck::Failed { message } if message.contains("unexpected path")
        ));
    }

    #[test]
    fn sums_grammar() {
        let h = "0123456789abcdef".repeat(4);
        let l = parse_sums(&format!(
            "{}  a/b.dll\r\n\n{} *c.pak\n",
            h.to_uppercase(),
            h
        ))
        .unwrap();
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].sha256, h);
        assert_eq!(l[0].path, "a/b.dll");
        assert_eq!(l[1].path, "c.pak");
        for bad in [
            format!("{h} a.dll"),
            format!("{}  a.dll", &h[1..]),
            format!("{}  a.dll", "z".repeat(64)),
            format!("{h}  ../a.dll"),
            format!("{h}  /etc/a.dll"),
            format!("{h}  a\\b.dll"),
            format!("{h}  "),
            "short".to_string(),
        ] {
            assert!(parse_sums(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn check_serializes_for_the_ui() {
        assert_eq!(
            serde_json::to_value(EngineCheck::Verified { files: 2 }).unwrap(),
            serde_json::json!({"state": "verified", "files": 2})
        );
        assert_eq!(
            serde_json::to_value(EngineCheck::NotBundled).unwrap(),
            serde_json::json!({"state": "not_bundled"})
        );
    }
}
