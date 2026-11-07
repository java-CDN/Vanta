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
/// `vanta_launch`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LaunchPayload {
    #[serde(flatten)]
    pub persona: Persona,
    pub vanta_launch: LaunchBinding,
}

/// Sign a launch config: `{"payload": "<persona + vanta_launch JSON>", "signature":
/// "<base64 Ed25519 over the payload bytes>"}`, the format engine patch 0002 verifies.
pub fn sign_launch(p: &Persona, binding: &LaunchBinding, key: &SigningKey) -> SignedConfig {
    let payload = serde_json::to_string(&LaunchPayload {
        persona: p.clone(),
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
}
