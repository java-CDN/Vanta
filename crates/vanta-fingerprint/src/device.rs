//! Real-device records (R11). A record is a whole, coherent device: fields are never mixed
//! across records. Browser version fields in the JSON are ignored; the UA is always built
//! from the installed engine (R5).

use serde::{Deserialize, Serialize};
use vanta_types::{OsKind, Result, VantaError};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UaChRecord {
    pub platform_version: String,
    pub architecture: String,
    pub bitness: String,
    pub model: String,
    pub wow64: bool,
    pub form_factors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Screen {
    pub width: u32,
    pub height: u32,
    pub avail_width: u32,
    pub avail_height: u32,
    pub color_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gpu {
    pub vendor: String,
    pub renderer: String,
    pub webgpu_vendor: String,
    pub webgpu_arch: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaDevices {
    pub audioinput: u32,
    pub audiooutput: u32,
    pub videoinput: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: String,
    pub source: String,
    pub weight: u32,
    pub os: String,
    pub os_version: String,
    pub platform: String,
    pub ua_ch: UaChRecord,
    pub screen: Screen,
    pub device_pixel_ratio: f64,
    pub hardware_concurrency: u32,
    pub device_memory: f64,
    pub max_touch_points: u32,
    pub gpu: Gpu,
    pub fonts: Vec<String>,
    pub media_devices: MediaDevices,
}

impl DeviceRecord {
    pub fn os_kind(&self) -> Result<OsKind> {
        Ok(match (self.os.as_str(), self.os_version.as_str()) {
            ("windows", "11") => OsKind::Windows11,
            ("windows", _) => OsKind::Windows10,
            ("macos", _) => OsKind::MacOs,
            ("linux", _) => OsKind::Linux,
            ("android", _) => OsKind::Android,
            (o, _) => {
                return Err(VantaError::Invalid(format!(
                    "record {}: unsupported os '{o}'",
                    self.id
                )))
            }
        })
    }
}

const BUILTIN: &str = include_str!("../data/devices.json");

/// The device database shipped with Vanta.
pub fn builtin() -> Vec<DeviceRecord> {
    serde_json::from_str(BUILTIN).expect("bundled devices.json is valid")
}

pub fn parse(json: &str) -> Result<Vec<DeviceRecord>> {
    serde_json::from_str(json).map_err(|e| VantaError::Invalid(format!("devices.json: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_loads_and_ids_unique() {
        let d = builtin();
        assert_eq!(d.len(), 16);
        let mut ids: Vec<_> = d.iter().map(|r| r.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 16);
        for r in &d {
            r.os_kind().unwrap();
        }
    }
}
