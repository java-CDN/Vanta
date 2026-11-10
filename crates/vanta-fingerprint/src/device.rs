//! Real-device records (R11). A record is a whole, coherent device: fields are never mixed
//! across records. Browser version fields in the JSON are ignored; the UA is always built
//! from the installed engine (R5). Windows 10/11 records only (R1).

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

/// GPU maker. Canvas, WebGL and WebGPU render on the host GPU, so a persona must claim a
/// GPU of the host's family (native-family selection); see [`crate::rules::host_gpu_gate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuFamily {
    Nvidia,
    Amd,
    Intel,
    Qualcomm,
}

impl GpuFamily {
    /// From a PCI vendor id (DXGI_ADAPTER_DESC::VendorId). Software adapters
    /// (Microsoft Basic Render Driver 0x1414) and unknown makers give `None`.
    pub fn from_pci_vendor(id: u32) -> Option<Self> {
        match id {
            0x10DE => Some(Self::Nvidia),
            0x1002 | 0x1022 => Some(Self::Amd),
            0x8086 => Some(Self::Intel),
            0x5143 | 0x4D4F4351 => Some(Self::Qualcomm),
            _ => None,
        }
    }

    /// From a WebGL vendor / renderer / WebGPU vendor string.
    pub fn from_gpu_string(s: &str) -> Option<Self> {
        let l = s.to_lowercase();
        for (k, v) in [
            ("nvidia", Self::Nvidia),
            ("amd", Self::Amd),
            ("radeon", Self::Amd),
            ("intel", Self::Intel),
            ("qualcomm", Self::Qualcomm),
            ("adreno", Self::Qualcomm),
        ] {
            if l.contains(k) {
                return Some(v);
            }
        }
        None
    }

    /// "nvidia" | "amd" | "intel" | "qualcomm" (also accepted by [`GpuFamily::parse`]).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nvidia => "nvidia",
            Self::Amd => "amd",
            Self::Intel => "intel",
            Self::Qualcomm => "qualcomm",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "nvidia" => Some(Self::Nvidia),
            "amd" => Some(Self::Amd),
            "intel" => Some(Self::Intel),
            "qualcomm" => Some(Self::Qualcomm),
            _ => None,
        }
    }
}

impl Gpu {
    /// The family the WebGL renderer string names.
    pub fn family(&self) -> Option<GpuFamily> {
        GpuFamily::from_gpu_string(&self.renderer)
    }
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
            ("windows", "10") => OsKind::Windows10,
            (o, v) => {
                return Err(VantaError::Invalid(format!(
                    "record {}: unsupported os '{o} {v}' (Windows 10/11 only)",
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
        assert!(d.len() >= 60, "only {} device records", d.len());
        let mut ids: Vec<_> = d.iter().map(|r| r.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), d.len());
        for r in &d {
            r.os_kind().unwrap();
            assert_eq!(r.os, "windows");
        }
    }

    #[test]
    fn every_gpu_family_is_covered_on_both_windows_releases() {
        let d = builtin();
        for fam in [GpuFamily::Nvidia, GpuFamily::Amd, GpuFamily::Intel] {
            for os in [OsKind::Windows10, OsKind::Windows11] {
                assert!(
                    d.iter()
                        .any(|r| r.gpu.family() == Some(fam) && r.os_kind().unwrap() == os),
                    "no {fam:?} record for {os:?}"
                );
            }
        }
        for r in &d {
            let fam = r.gpu.family().expect("GPU family");
            assert_eq!(GpuFamily::from_gpu_string(&r.gpu.webgpu_vendor), Some(fam));
            // ANGLE's device id is the PCI id of the family's vendor.
            assert!(r.gpu.renderer.contains(" (0x0000"), "{}", r.id);
        }
    }

    #[test]
    fn non_windows_record_rejected() {
        let mut r = builtin().remove(0);
        for (os, ver) in [("macos", "10_15_7"), ("linux", "x86_64"), ("windows", "8")] {
            r.os = os.into();
            r.os_version = ver.into();
            assert!(r.os_kind().is_err(), "{os} {ver}");
        }
    }
}
