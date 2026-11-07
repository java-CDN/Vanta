//! Shell settings (`settings.json` in the data folder). Non-secret UI preferences only;
//! everything sensitive lives in the vault.

use serde::{Deserialize, Serialize};
use std::path::Path;
use vanta_core::CoreError;

/// Auto-lock choices offered by the UI (minutes; 0 = never).
pub const AUTOLOCK_CHOICES: [u32; 7] = [0, 1, 5, 10, 15, 30, 60];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub autolock_minutes: u32,
    pub theme: String,
    pub max_launch: u32,
    pub confirm_delete: bool,
    /// Engine executable override; `None` = the default install path. Read at start-up.
    pub engine_path: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            autolock_minutes: 10,
            theme: "dark".into(),
            max_launch: 12,
            confirm_delete: true,
            engine_path: None,
        }
    }
}

fn invalid(m: impl Into<String>) -> CoreError {
    CoreError::Invalid { message: m.into() }
}

impl Settings {
    pub fn validate(&self) -> Result<(), CoreError> {
        if !AUTOLOCK_CHOICES.contains(&self.autolock_minutes) {
            return Err(invalid(
                "auto-lock must be one of 0, 1, 5, 10, 15, 30, 60 minutes",
            ));
        }
        if self.theme != "dark" && self.theme != "light" {
            return Err(invalid("theme must be dark or light"));
        }
        if !(1..=1000).contains(&self.max_launch) {
            return Err(invalid("launch limit must be 1-1000"));
        }
        if let Some(p) = &self.engine_path {
            if p.trim().is_empty() || p.len() > 1024 {
                return Err(invalid("engine path is empty or too long"));
            }
        }
        Ok(())
    }

    /// Missing or unreadable file: defaults (a broken file never blocks start-up).
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str::<Settings>(&s).ok())
            .filter(|s| s.validate().is_ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), CoreError> {
        let json = serde_json::to_string_pretty(self).map_err(|e| CoreError::Storage {
            message: format!("settings: {e}"),
        })?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json)
            .and_then(|_| std::fs::rename(&tmp, path))
            .map_err(|e| CoreError::Storage {
                message: format!("settings: {e}"),
            })
    }
}
