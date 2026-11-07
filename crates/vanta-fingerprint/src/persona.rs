//! A persona = one device record + engine version + seed + location (F02, F07).

use crate::device::{DeviceRecord, Gpu, MediaDevices, Screen};
use crate::ua;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vanta_types::{EngineVersion, OsKind, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceMode {
    /// Real values from the host GPU / audio stack.
    Real,
    /// Small, stable per-profile perturbation (seeded).
    Noise,
    /// API reports as unavailable.
    Block,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UaCh {
    pub brands: Vec<(String, String)>,
    pub full_version_list: Vec<(String, String)>,
    pub platform: String,
    pub platform_version: String,
    pub architecture: String,
    pub bitness: String,
    pub model: String,
    pub mobile: bool,
    pub wow64: bool,
    pub form_factors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Geo {
    pub country: String,
    pub timezone: String,
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy_m: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Persona {
    pub schema: u32,
    pub seed: u64,
    pub device_id: String,
    pub os: OsKind,
    pub engine: EngineVersion,
    pub brand: String,
    pub user_agent: String,
    pub platform: String,
    pub ua_ch: UaCh,
    pub screen: Screen,
    pub device_pixel_ratio: f64,
    pub hardware_concurrency: u32,
    pub device_memory: f64,
    pub max_touch_points: u32,
    pub gpu: Gpu,
    pub fonts: Vec<String>,
    pub media_devices: MediaDevices,
    pub locale: String,
    pub languages: Vec<String>,
    pub geo: Option<Geo>,
    pub canvas: SurfaceMode,
    pub webgl_image: SurfaceMode,
    pub audio: SurfaceMode,
    /// Per-surface noise seeds derived from `seed`, so the engine never invents randomness.
    pub canvas_seed: u64,
    pub audio_seed: u64,
    pub clientrects_seed: u64,
    /// Always "disable_non_proxied_udp" (C024).
    pub webrtc_policy: String,
}

pub const BRAND: &str = "Google Chrome";

fn sub_seed(seed: u64, label: &str) -> u64 {
    let mut h = Sha256::new();
    h.update(seed.to_le_bytes());
    h.update(label.as_bytes());
    let d = h.finalize();
    let s = u64::from_le_bytes(d[..8].try_into().expect("8 bytes"));
    s.max(1)
}

impl Persona {
    pub fn from_device(
        dev: &DeviceRecord,
        engine: EngineVersion,
        seed: u64,
        locale: &str,
    ) -> Result<Self> {
        let os = dev.os_kind()?;
        let ua_ch = UaCh {
            brands: ua::brands(&engine, BRAND),
            full_version_list: ua::full_version_list(&engine, BRAND),
            platform: ua::ch_platform(os).into(),
            platform_version: dev.ua_ch.platform_version.clone(),
            architecture: dev.ua_ch.architecture.clone(),
            bitness: dev.ua_ch.bitness.clone(),
            model: dev.ua_ch.model.clone(),
            mobile: false,
            wow64: dev.ua_ch.wow64,
            form_factors: dev.ua_ch.form_factors.clone(),
        };
        let languages = languages_for(locale);
        Ok(Self {
            schema: 1,
            seed,
            device_id: dev.id.clone(),
            os,
            engine,
            brand: BRAND.into(),
            user_agent: ua::user_agent(os, &engine),
            platform: dev.platform.clone(),
            ua_ch,
            screen: dev.screen,
            device_pixel_ratio: dev.device_pixel_ratio,
            hardware_concurrency: dev.hardware_concurrency,
            device_memory: dev.device_memory,
            max_touch_points: dev.max_touch_points,
            gpu: dev.gpu.clone(),
            fonts: dev.fonts.clone(),
            media_devices: dev.media_devices,
            locale: locale.into(),
            languages,
            geo: None,
            canvas: SurfaceMode::Real,
            webgl_image: SurfaceMode::Real,
            audio: SurfaceMode::Noise,
            canvas_seed: sub_seed(seed, "canvas"),
            audio_seed: sub_seed(seed, "audio"),
            clientrects_seed: sub_seed(seed, "clientrects"),
            webrtc_policy: "disable_non_proxied_udp".into(),
        })
    }

    /// Pick a record by weight with a seeded RNG (same seed -> same device).
    pub fn generate(
        db: &[DeviceRecord],
        filter: impl Fn(&DeviceRecord) -> bool,
        engine: EngineVersion,
        seed: u64,
        locale: &str,
    ) -> Result<Self> {
        let pool: Vec<&DeviceRecord> = db.iter().filter(|d| filter(d)).collect();
        if pool.is_empty() {
            return Err(vanta_types::VantaError::NotFound(
                "no device record matches the filter".into(),
            ));
        }
        let total: u64 = pool.iter().map(|d| d.weight.max(1) as u64).sum();
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut pick = rng.gen_range(0..total);
        let mut chosen = pool[0];
        for d in &pool {
            let w = d.weight.max(1) as u64;
            if pick < w {
                chosen = d;
                break;
            }
            pick -= w;
        }
        Self::from_device(chosen, engine, seed, locale)
    }

    /// Value Chrome sends as Accept-Language for `languages`.
    pub fn accept_language(&self) -> String {
        let mut out = Vec::new();
        for (i, l) in self.languages.iter().enumerate() {
            if i == 0 {
                out.push(l.clone());
            } else {
                let q = 1.0 - (i as f64) * 0.1;
                out.push(format!("{l};q={:.1}", q.max(0.1)));
            }
        }
        out.join(",")
    }

    /// Geo Auto-Match (F07): timezone and location always follow the exit IP;
    /// language changes only when the user opts in.
    pub fn apply_geo(&mut self, geo: Geo, change_language_to: Option<&str>) {
        if let Some(loc) = change_language_to {
            self.locale = loc.into();
            self.languages = languages_for(loc);
        }
        self.geo = Some(geo);
    }

    /// Bind the persona to the installed engine (R5). Called at every launch, so the
    /// Chrome version is never stored separately and can never drift from the engine.
    pub fn bind_engine(&mut self, engine: EngineVersion) {
        self.engine = engine;
        self.user_agent = ua::user_agent(self.os, &engine);
        self.ua_ch.brands = ua::brands(&engine, &self.brand);
        self.ua_ch.full_version_list = ua::full_version_list(&engine, &self.brand);
    }

    pub fn sec_ch_ua(&self) -> String {
        ua::header(&self.ua_ch.brands)
    }
}

/// "de-DE" -> ["de-DE", "de", "en-US", "en"]; "en-US" -> ["en-US", "en"].
pub fn languages_for(locale: &str) -> Vec<String> {
    let mut v = vec![locale.to_string()];
    if let Some((lang, _)) = locale.split_once('-') {
        v.push(lang.to_string());
    }
    if !locale.starts_with("en") {
        v.push("en-US".into());
        v.push("en".into());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::builtin;
    const V: EngineVersion = EngineVersion::new(156, 0, 8078, 79);

    #[test]
    fn same_seed_same_persona() {
        let db = builtin();
        let a = Persona::generate(&db, |_| true, V, 42, "de-DE").unwrap();
        let b = Persona::generate(&db, |_| true, V, 42, "de-DE").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn filter_respected() {
        let db = builtin();
        for seed in 0..50 {
            let p = Persona::generate(&db, |d| d.os == "windows", V, seed, "en-US").unwrap();
            assert!(matches!(p.os, OsKind::Windows10 | OsKind::Windows11));
        }
        assert!(Persona::generate(&db, |d| d.os == "ios", V, 1, "en-US").is_err());
    }

    #[test]
    fn subseeds_differ_and_nonzero() {
        let db = builtin();
        let p = Persona::from_device(&db[0], V, 7, "en-US").unwrap();
        assert_ne!(p.canvas_seed, p.audio_seed);
        assert!(p.canvas_seed != 0 && p.audio_seed != 0 && p.clientrects_seed != 0);
    }

    #[test]
    fn accept_language_format() {
        let db = builtin();
        let p = Persona::from_device(&db[0], V, 1, "de-DE").unwrap();
        assert_eq!(p.accept_language(), "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7");
    }

    #[test]
    fn geo_keeps_language_unless_opted_in() {
        let db = builtin();
        let mut p = Persona::from_device(&db[0], V, 1, "de-DE").unwrap();
        let g = Geo {
            country: "NL".into(),
            timezone: "Europe/Amsterdam".into(),
            latitude: 52.37,
            longitude: 4.9,
            accuracy_m: 2000,
        };
        p.apply_geo(g.clone(), None);
        assert_eq!(p.locale, "de-DE");
        p.apply_geo(g, Some("nl-NL"));
        assert_eq!(p.languages[0], "nl-NL");
    }

    #[test]
    fn bind_engine_updates_every_version_field() {
        let db = builtin();
        let mut p =
            Persona::from_device(&db[0], EngineVersion::new(155, 0, 8059, 84), 1, "en-US").unwrap();
        p.bind_engine(V);
        assert!(p.user_agent.contains("Chrome/156.0.0.0"));
        assert!(p.sec_ch_ua().contains("\"Chromium\";v=\"156\""));
        assert!(p
            .ua_ch
            .full_version_list
            .iter()
            .any(|(_, v)| v == "156.0.8078.79"));
    }
}
