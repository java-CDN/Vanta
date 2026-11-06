use crate::Key;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use vanta_types::{Result, VantaError};
use zeroize::Zeroizing;

/// XChaCha20-Poly1305 ciphertext with its random 24-byte nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    #[serde(with = "crate::b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::b64")]
    pub ct: Vec<u8>,
}

impl Sealed {
    pub fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> Self {
        let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("encryption with a valid key cannot fail");
        Self {
            nonce: nonce.to_vec(),
            ct,
        }
    }

    pub fn open(&self, key: &Key, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if self.nonce.len() != 24 {
            return Err(VantaError::Crypto);
        }
        let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
        cipher
            .decrypt(
                XNonce::from_slice(&self.nonce),
                Payload { msg: &self.ct, aad },
            )
            .map(Zeroizing::new)
            .map_err(|_| VantaError::Crypto)
    }

    /// Compact binary form: nonce || ciphertext.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.nonce.clone();
        v.extend_from_slice(&self.ct);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 24 + 16 {
            return Err(VantaError::Crypto);
        }
        Ok(Self {
            nonce: b[..24].to_vec(),
            ct: b[24..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tamper_detected() {
        let k = Key::random();
        let mut s = Sealed::seal(&k, b"aad", b"hello");
        s.ct[0] ^= 1;
        assert!(s.open(&k, b"aad").is_err());
    }

    #[test]
    fn bytes_roundtrip() {
        let k = Key::random();
        let s = Sealed::seal(&k, b"", b"hello");
        let back = Sealed::from_bytes(&s.to_bytes()).unwrap();
        assert_eq!(&*back.open(&k, b"").unwrap(), b"hello");
        assert!(Sealed::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn nonces_differ() {
        let k = Key::random();
        assert_ne!(
            Sealed::seal(&k, b"", b"x").nonce,
            Sealed::seal(&k, b"", b"x").nonce
        );
    }
}
