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
