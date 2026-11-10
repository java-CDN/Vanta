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
    /// Serialized as decimal strings: the engine's JSON reader (Chromium base::JSONReader)
    /// keeps integers above 2^31 only as doubles, which would lose bits of a u64.
    #[serde(with = "seed_str")]
    pub canvas_seed: u64,
    #[serde(with = "seed_str")]
    pub audio_seed: u64,
    #[serde(with = "seed_str")]
    pub clientrects_seed: u64,
    /// Always "disable_non_proxied_udp" (C024).
    pub webrtc_policy: String,
    /// WebGL readPixels/toDataURL noise seed (engine patch group G4). Personas stored
    /// before this field existed read 0 and get it from `bind_engine`.
    #[serde(default, with = "seed_str")]
    pub webgl_seed: u64,
    /// Font enumeration / text-metrics seed (engine patch group G6). Same migration.
    #[serde(default, with = "seed_str")]
    pub font_seed: u64,
}

/// u64 seeds as decimal strings in JSON; numbers are still accepted on read, so personas
/// stored before the change keep loading.
mod seed_str {
    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    struct SeedVisitor;

    impl Visitor<'_> for SeedVisitor {
        type Value = u64;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a u64 seed as a decimal string or a number")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<u64, E> {
            Ok(v)
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<u64, E> {
            u64::try_from(v).map_err(|_| E::custom("negative seed"))
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<u64, E> {
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(E::custom("seed must be decimal digits"));
            }
            v.parse().map_err(E::custom)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        d.deserialize_any(SeedVisitor)
    }
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
            // Noise by default: the pixels come from the host GPU, and a seeded edge
            // perturbation keeps the per-profile canvas/WebGL hash distinct (G4).
            canvas: SurfaceMode::Noise,
            webgl_image: SurfaceMode::Noise,
            audio: SurfaceMode::Noise,
            canvas_seed: sub_seed(seed, "canvas"),
            audio_seed: sub_seed(seed, "audio"),
            clientrects_seed: sub_seed(seed, "clientrects"),
            webrtc_policy: "disable_non_proxied_udp".into(),
            webgl_seed: sub_seed(seed, "webgl"),
            font_seed: sub_seed(seed, "font"),
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
        // The engine builds UA-CH brands as GREASE + "Chromium" + this brand (patch 0007),
        // so the persona always carries real Chrome's brand.
        self.brand = BRAND.into();
        self.user_agent = ua::user_agent(self.os, &engine);
        self.ua_ch.brands = ua::brands(&engine, &self.brand);
        self.ua_ch.full_version_list = ua::full_version_list(&engine, &self.brand);
        // Personas stored before webgl_seed / font_seed existed read 0 (serde default).
        if self.webgl_seed == 0 {
            self.webgl_seed = sub_seed(self.seed, "webgl");
        }
        if self.font_seed == 0 {
            self.font_seed = sub_seed(self.seed, "font");
        }
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
        assert!(p.webgl_seed != 0 && p.font_seed != 0);
        let all = [
            p.canvas_seed,
            p.audio_seed,
            p.clientrects_seed,
            p.webgl_seed,
            p.font_seed,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn seeds_serialize_as_decimal_strings() {
        let db = builtin();
        let mut p = Persona::from_device(&db[0], V, 7, "en-US").unwrap();
        p.canvas_seed = u64::MAX;
        let v: serde_json::Value = serde_json::to_value(&p).unwrap();
        assert_eq!(v["canvas_seed"], "18446744073709551615");
        for k in [
            "canvas_seed",
            "audio_seed",
            "clientrects_seed",
            "webgl_seed",
            "font_seed",
        ] {
            assert!(v[k].is_string(), "{k}");
        }
        let back: Persona = serde_json::from_value(v).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn stored_persona_with_numeric_seeds_and_no_new_seeds_still_loads() {
        let db = builtin();
        let p = Persona::from_device(&db[0], V, 7, "en-US").unwrap();
        let mut v: serde_json::Value = serde_json::to_value(&p).unwrap();
        let o = v.as_object_mut().unwrap();
        o.insert("canvas_seed".into(), serde_json::json!(p.canvas_seed));
        o.insert("audio_seed".into(), serde_json::json!(p.audio_seed));
        o.insert(
            "clientrects_seed".into(),
            serde_json::json!(p.clientrects_seed),
        );
        o.remove("webgl_seed");
        o.remove("font_seed");
        let mut old: Persona = serde_json::from_value(v).unwrap();
        assert_eq!(old.canvas_seed, p.canvas_seed);
        assert_eq!((old.webgl_seed, old.font_seed), (0, 0));
        old.bind_engine(V);
        assert_eq!(old, p);
    }

    #[test]
    fn malformed_seed_strings_rejected() {
        let db = builtin();
        let p = Persona::from_device(&db[0], V, 7, "en-US").unwrap();
        for bad in ["", "-1", "+1", "0x10", "1e3", "18446744073709551616"] {
            let mut v: serde_json::Value = serde_json::to_value(&p).unwrap();
            v["canvas_seed"] = serde_json::json!(bad);
            assert!(serde_json::from_value::<Persona>(v).is_err(), "{bad:?}");
        }
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
