//! Signed launch config (Ed25519). The engine patch verifies the signature with the public
//! key passed at launch and refuses a config whose version differs from its own (exit 87).

use crate::persona::Persona;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use vanta_types::{exit_codes, EngineVersion, Result, VantaError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedConfig {
    /// Canonical JSON of the persona (field order fixed by the struct).
    pub payload: String,
    pub signature: String,
}

/// What a launch adds to the persona: which profile, which relay port, when. Signed
/// together with the persona, so a config cannot be replayed against another relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchBinding {
    pub profile_id: String,
    /// Port of the profile's relay on 127.0.0.1 (the engine's only proxy).
    pub relay_port: u16,
    pub issued_ms: i64,
}

/// The signed payload of a launch: the persona's own fields at the top level (the engine
/// patch 0002 reads `engine.{major,minor,build,patch}` from the top-level object) plus
/// `accept_language` and `vanta_launch`. Engine patch 0003 (`components/vanta/persona.cc`)
/// parses the persona fields; `docs/persona-interface.md` lists them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LaunchPayload {
    #[serde(flatten)]
    pub persona: Persona,
    /// `Persona::accept_language()`, computed here so the engine never re-derives the
    /// q-values (one source of truth for the header).
    pub accept_language: String,
    pub vanta_launch: LaunchBinding,
}

/// Sign a launch config: `{"payload": "<persona + vanta_launch JSON>", "signature":
/// "<base64 Ed25519 over the payload bytes>"}`, the format engine patch 0002 verifies.
pub fn sign_launch(p: &Persona, binding: &LaunchBinding, key: &SigningKey) -> SignedConfig {
    let payload = serde_json::to_string(&LaunchPayload {
        persona: p.clone(),
        accept_language: p.accept_language(),
        vanta_launch: binding.clone(),
    })
    .expect("launch payload serializes");
    let sig = key.sign(payload.as_bytes());
    SignedConfig {
        payload,
        signature: STANDARD.encode(sig.to_bytes()),
    }
}

impl SignedConfig {
    /// The file the engine reads with `--vanta-config`.
    pub fn to_file_json(&self) -> String {
        serde_json::to_string(self).expect("signed config serializes")
    }
}

/// Value of `--vanta-pubkey`: the 32-byte Ed25519 public key, standard base64.
pub fn pubkey_b64(key: &VerifyingKey) -> String {
    STANDARD.encode(key.as_bytes())
}

pub fn new_signing_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

pub fn sign(p: &Persona, key: &SigningKey) -> SignedConfig {
    let payload = serde_json::to_string(p).expect("persona serializes");
    let sig = key.sign(payload.as_bytes());
    SignedConfig {
        payload,
        signature: STANDARD.encode(sig.to_bytes()),
    }
}

/// What the engine does at startup; returns the exit code it would use on failure.
pub fn verify_for_engine(
    cfg: &SignedConfig,
    pubkey: &VerifyingKey,
    engine: EngineVersion,
) -> std::result::Result<Persona, i32> {
    let sig_bytes = STANDARD
        .decode(&cfg.signature)
        .map_err(|_| exit_codes::BAD_CONFIG_SIGNATURE)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| exit_codes::BAD_CONFIG_SIGNATURE)?;
    pubkey
        .verify(cfg.payload.as_bytes(), &sig)
        .map_err(|_| exit_codes::BAD_CONFIG_SIGNATURE)?;
    let p: Persona =
        serde_json::from_str(&cfg.payload).map_err(|_| exit_codes::BAD_CONFIG_SIGNATURE)?;
    if p.engine != engine {
        return Err(exit_codes::VERSION_MISMATCH);
    }
    Ok(p)
}

/// App-side check before spawning the engine (C030 + all other rules).
pub fn preflight(p: &Persona, engine: EngineVersion) -> Result<()> {
    if p.engine != engine {
        return Err(VantaError::VersionMismatch {
            persona: p.engine.to_string(),
            engine: engine.to_string(),
        });
    }
    let res = crate::rules::check(p, engine);
    let f = crate::rules::failures(&res);
    if let Some(first) = f.first() {
        return Err(VantaError::Invalid(format!(
            "{} {}",
            first.id, first.message
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::builtin;
    const V: EngineVersion = EngineVersion::new(156, 0, 8078, 79);

    fn persona() -> Persona {
        Persona::from_device(&builtin()[0], V, 9, "en-US").unwrap()
    }

    #[test]
    fn sign_and_verify() {
        let k = new_signing_key();
        let cfg = sign(&persona(), &k);
        assert_eq!(
            verify_for_engine(&cfg, &k.verifying_key(), V).unwrap(),
            persona()
        );
    }

    #[test]
    fn tampered_payload_exit_86() {
        let k = new_signing_key();
        let mut cfg = sign(&persona(), &k);
        cfg.payload = cfg.payload.replace("Chrome/156", "Chrome/157");
        assert_eq!(verify_for_engine(&cfg, &k.verifying_key(), V), Err(86));
    }

    #[test]
    fn other_key_exit_86() {
        let cfg = sign(&persona(), &new_signing_key());
        assert_eq!(
            verify_for_engine(&cfg, &new_signing_key().verifying_key(), V),
            Err(86)
        );
    }

    #[test]
    fn version_mismatch_exit_87() {
        let k = new_signing_key();
        let cfg = sign(&persona(), &k);
        assert_eq!(
            verify_for_engine(
                &cfg,
                &k.verifying_key(),
                EngineVersion::new(156, 0, 8078, 82)
            ),
            Err(87)
        );
    }

    #[test]
    fn launch_payload_keeps_engine_at_top_level_and_verifies() {
        let k = new_signing_key();
        let b = LaunchBinding {
            profile_id: "p".into(),
            relay_port: 40123,
            issued_ms: 5,
        };
        let cfg = sign_launch(&persona(), &b, &k);
        let v: serde_json::Value = serde_json::from_str(&cfg.payload).unwrap();
        assert_eq!(v["engine"]["major"], 156);
        assert_eq!(v["engine"]["patch"], 79);
        assert_eq!(v["vanta_launch"]["relay_port"], 40123);
        assert_eq!(v["user_agent"], persona().user_agent);
        // The engine-side check still accepts it, and the payload round-trips.
        assert_eq!(
            verify_for_engine(&cfg, &k.verifying_key(), V).unwrap(),
            persona()
        );
        let back: LaunchPayload = serde_json::from_str(&cfg.payload).unwrap();
        assert_eq!(back.vanta_launch, b);
        assert_eq!(back.persona, persona());
        assert_eq!(back.accept_language, persona().accept_language());
        let file: serde_json::Value = serde_json::from_str(&cfg.to_file_json()).unwrap();
        assert!(file["payload"].is_string() && file["signature"].is_string());
        assert_eq!(
            STANDARD
                .decode(pubkey_b64(&k.verifying_key()))
                .unwrap()
                .len(),
            32
        );
    }

    #[test]
    fn preflight_blocks_mismatch_and_bad_rules() {
        assert!(preflight(&persona(), V).is_ok());
        assert!(matches!(
            preflight(&persona(), EngineVersion::new(157, 0, 0, 1)),
            Err(VantaError::VersionMismatch { .. })
        ));
        let mut p = persona();
        p.device_memory = 16.0;
        assert!(preflight(&p, V).unwrap_err().to_string().contains("C015"));
    }

    /// The fields engine patch 0003 (`components/vanta/persona.cc`, `PersonaFromDict`)
    /// requires, with their JSON types. Changing one of these is an engine interface
    /// change: update the patch and docs/persona-interface.md together.
    #[test]
    fn launch_payload_matches_engine_persona_contract() {
        use serde_json::Value;
        let k = new_signing_key();
        let b = LaunchBinding {
            profile_id: "p".into(),
            relay_port: 40123,
            issued_ms: 1_762_600_000_000,
        };
        let mut p = persona();
        p.apply_geo(
            crate::persona::Geo {
                country: "DE".into(),
                timezone: "Europe/Berlin".into(),
                latitude: 52.52,
                longitude: 13.405,
                accuracy_m: 5000,
            },
            None,
        );
        let cfg = sign_launch(&p, &b, &k);
        let v: Value = serde_json::from_str(&cfg.payload).unwrap();
        let is_int = |x: &Value| {
            x.as_i64()
                .is_some_and(|n| (0..=i32::MAX as i64).contains(&n))
        };
        let is_num = |x: &Value| x.is_number();
        let is_str = |x: &Value| x.is_string();
        let is_bool = |x: &Value| x.is_boolean();
        let is_str_list = |x: &Value| {
            x.as_array()
                .is_some_and(|a| a.iter().all(|e| e.is_string()))
        };
        let is_pair_list = |x: &Value| {
            x.as_array().is_some_and(|a| {
                a.iter().all(|e| {
                    e.as_array()
                        .is_some_and(|p| p.len() == 2 && p.iter().all(|s| s.is_string()))
                })
            })
        };
        let is_seed = |x: &Value| {
            x.as_str()
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()))
        };
        type Check<'a> = (&'a str, &'a dyn Fn(&Value) -> bool);
        let top: Vec<Check> = vec![
            ("schema", &is_int),
            ("os", &is_str),
            ("user_agent", &is_str),
            ("brand", &is_str),
            ("platform", &is_str),
            ("hardware_concurrency", &is_int),
            ("device_memory", &is_num),
            ("max_touch_points", &is_int),
            ("device_pixel_ratio", &is_num),
            ("fonts", &is_str_list),
            ("locale", &is_str),
            ("languages", &is_str_list),
            ("accept_language", &is_str),
            ("canvas", &is_str),
            ("webgl_image", &is_str),
            ("audio", &is_str),
            ("canvas_seed", &is_seed),
            ("audio_seed", &is_seed),
            ("clientrects_seed", &is_seed),
            ("webgl_seed", &is_seed),
            ("font_seed", &is_seed),
            ("webrtc_policy", &is_str),
        ];
        for (key, ok) in &top {
            assert!(ok(&v[*key]), "top-level {key}: {}", v[*key]);
        }
        for (key, ok) in [
            ("brands", &is_pair_list as &dyn Fn(&Value) -> bool),
            ("full_version_list", &is_pair_list),
            ("platform", &is_str),
            ("platform_version", &is_str),
            ("architecture", &is_str),
            ("bitness", &is_str),
            ("model", &is_str),
            ("mobile", &is_bool),
            ("wow64", &is_bool),
            ("form_factors", &is_str_list),
        ] {
            assert!(ok(&v["ua_ch"][key]), "ua_ch.{key}");
        }
        for key in [
            "width",
            "height",
            "avail_width",
            "avail_height",
            "color_depth",
        ] {
            assert!(is_int(&v["screen"][key]), "screen.{key}");
        }
        for key in ["vendor", "renderer", "webgpu_vendor", "webgpu_arch"] {
            assert!(is_str(&v["gpu"][key]), "gpu.{key}");
        }
        for key in ["audioinput", "audiooutput", "videoinput"] {
            assert!(is_int(&v["media_devices"][key]), "media_devices.{key}");
        }
        for (key, ok) in [
            ("country", &is_str as &dyn Fn(&Value) -> bool),
            ("timezone", &is_str),
            ("latitude", &is_num),
            ("longitude", &is_num),
            ("accuracy_m", &is_int),
        ] {
            assert!(ok(&v["geo"][key]), "geo.{key}");
        }
        assert!(matches!(v["os"].as_str(), Some("windows10" | "windows11")));
        assert_eq!(v["webrtc_policy"], "disable_non_proxied_udp");
        assert_eq!(v["accept_language"], "en-US,en;q=0.9");
        // Without a location, geo is null (the engine then reports no timezone).
        let cfg = sign_launch(&persona(), &b, &k);
        let v: Value = serde_json::from_str(&cfg.payload).unwrap();
        assert!(v["geo"].is_null());
    }
}
