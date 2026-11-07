//! vanta-vault: master password, vault key, per-profile keys (F06 Vault Lock).
//!
//! Key hierarchy
//! ```text
//! password --Argon2id--> password key --wraps--> vault key (random 32 B)
//! recovery key (random 32 B, printed once) --HKDF--> recovery wrap key --wraps--> vault key
//! vault key --HKDF "vanta/kek/v1"--> KEK --wraps (AAD = profile id)--> profile DEK (random 32 B)
//! ```
//! Deleting a profile's wrapped DEK makes its data unreadable at once.
//! Changing the password only re-wraps the vault key; no profile data is re-encrypted.

mod autolock;
mod sealed;

pub use autolock::{AutoLock, LockEvent, LockReason};
pub use sealed::Sealed;

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use vanta_types::{ProfileId, Result, VantaError};
use zeroize::{Zeroize, Zeroizing};

pub const KEY_LEN: usize = 32;
const INFO_KEK: &[u8] = b"vanta/kek/v1";
const INFO_RECOVERY: &[u8] = b"vanta/recovery/v1";
const INFO_LOG: &[u8] = b"vanta/log/v1";
const INFO_SECRETS: &[u8] = b"vanta/secrets/v1";
const AAD_SECRET: &str = "vanta/secret/";
const AAD_PW: &[u8] = b"vanta/vault-key/password";
const AAD_REC: &[u8] = b"vanta/vault-key/recovery";

/// Argon2id cost. Default = 64 MiB, 3 passes, 1 lane (about 0.5-1 s on a normal PC, by design).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

impl KdfParams {
    /// Cheap parameters for unit tests only.
    pub fn insecure_for_tests() -> Self {
        Self {
            m_cost_kib: 256,
            t_cost: 1,
            p_cost: 1,
        }
    }
}

/// What is stored on disk next to the database. Contains no secret in clear.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    pub format: u8,
    pub kdf: KdfParams,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    pub password_wrap: Sealed,
    pub recovery_wrap: Sealed,
}

impl VaultHeader {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("header serializes")
    }
    pub fn from_json(s: &str) -> Result<Self> {
        let h: Self = serde_json::from_str(s)
            .map_err(|e| VantaError::Invalid(format!("vault header: {e}")))?;
        if h.format != 1 {
            return Err(VantaError::Invalid(format!(
                "unknown vault format {}",
                h.format
            )));
        }
        Ok(h)
    }
}

/// 32-byte secret that wipes itself.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    pub fn random() -> Self {
        let mut k = [0u8; KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut k);
        Self(k)
    }
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
    fn from_slice(b: &[u8]) -> Result<Self> {
        if b.len() != KEY_LEN {
            return Err(VantaError::Crypto);
        }
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(b);
        Ok(Self(k))
    }
    fn derive(&self, info: &[u8]) -> Key {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut out = [0u8; KEY_LEN];
        hk.expand(info, &mut out)
            .expect("32 bytes is a valid HKDF length");
        Key(out)
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

/// Printed once at vault creation; groups of 4 base32 characters.
pub struct RecoveryKey(Zeroizing<String>);

impl RecoveryKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    fn encode(k: &Key) -> Self {
        let raw = data_encoding::BASE32_NOPAD.encode(k.as_bytes());
        let grouped: Vec<String> = raw
            .as_bytes()
            .chunks(4)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect();
        Self(Zeroizing::new(grouped.join("-")))
    }
    fn decode(s: &str) -> Result<Key> {
        let clean: Zeroizing<String> = Zeroizing::new(
            s.chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        let bytes = Zeroizing::new(
            data_encoding::BASE32_NOPAD
                .decode(clean.as_bytes())
                .map_err(|_| VantaError::Crypto)?,
        );
        Key::from_slice(&bytes)
    }
}

/// A profile's data-encryption key, wrapped by the KEK. Safe to store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKey(pub Sealed);

/// An unwrapped per-profile key. Encrypts that profile's config, cookies and snapshots.
#[derive(Debug, Clone)]
pub struct ProfileKey {
    id: ProfileId,
    key: Key,
}

impl ProfileKey {
    pub fn id(&self) -> ProfileId {
        self.id
    }
    /// Encrypt; `purpose` separates uses (e.g. "config", "cookies") so blobs cannot be swapped.
    pub fn seal(&self, purpose: &str, plaintext: &[u8]) -> Sealed {
        Sealed::seal(&self.key, &self.aad(purpose), plaintext)
    }
    pub fn open(&self, purpose: &str, sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
        sealed.open(&self.key, &self.aad(purpose))
    }
    fn aad(&self, purpose: &str) -> Vec<u8> {
        let mut a = Vec::with_capacity(16 + purpose.len());
        a.extend_from_slice(self.id.as_bytes());
        a.extend_from_slice(purpose.as_bytes());
        a
    }
}

struct Unlocked {
    vault_key: Key,
    kek: Key,
}

pub struct Vault {
    header: VaultHeader,
    unlocked: Option<Unlocked>,
}

fn password_key(password: &str, salt: &[u8], p: KdfParams) -> Result<Key> {
    let params = Params::new(p.m_cost_kib, p.t_cost, p.p_cost, Some(KEY_LEN))
        .map_err(|e| VantaError::Invalid(format!("kdf params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| VantaError::Invalid(format!("kdf: {e}")))?;
    let k = Key(out);
    out.zeroize();
    Ok(k)
}

impl Vault {
    /// Create a new vault. Returns it unlocked plus the recovery key to show the user once.
    pub fn create(password: &str, kdf: KdfParams) -> Result<(Self, RecoveryKey)> {
        if password.chars().count() < 8 {
            return Err(VantaError::Invalid(
                "master password must have at least 8 characters".into(),
            ));
        }
        let mut salt = vec![0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let vault_key = Key::random();
        let pw = password_key(password, &salt, kdf)?;
        let rec = Key::random();
        let header = VaultHeader {
            format: 1,
            kdf,
            salt,
            password_wrap: Sealed::seal(&pw, AAD_PW, vault_key.as_bytes()),
            recovery_wrap: Sealed::seal(&rec.derive(INFO_RECOVERY), AAD_REC, vault_key.as_bytes()),
        };
        let recovery = RecoveryKey::encode(&rec);
        let kek = vault_key.derive(INFO_KEK);
        Ok((
            Self {
                header,
                unlocked: Some(Unlocked { vault_key, kek }),
            },
            recovery,
        ))
    }

    /// Load from a stored header; starts locked.
    pub fn from_header(header: VaultHeader) -> Self {
        Self {
            header,
            unlocked: None,
        }
    }

    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked.is_some()
    }

    pub fn unlock(&mut self, password: &str) -> Result<()> {
        let pw = password_key(password, &self.header.salt, self.header.kdf)?;
        let raw = self.header.password_wrap.open(&pw, AAD_PW)?;
        self.set_unlocked(Key::from_slice(&raw)?);
        Ok(())
    }

    pub fn unlock_with_recovery(&mut self, recovery: &str) -> Result<()> {
        let rec = RecoveryKey::decode(recovery)?;
        let raw = self
            .header
            .recovery_wrap
            .open(&rec.derive(INFO_RECOVERY), AAD_REC)?;
        self.set_unlocked(Key::from_slice(&raw)?);
        Ok(())
    }

    fn set_unlocked(&mut self, vault_key: Key) {
        let kek = vault_key.derive(INFO_KEK);
        self.unlocked = Some(Unlocked { vault_key, kek });
    }

    /// Drop all keys from memory (they zeroize on drop).
    pub fn lock(&mut self) {
        self.unlocked = None;
    }

    fn keys(&self) -> Result<&Unlocked> {
        self.unlocked.as_ref().ok_or(VantaError::Locked)
    }

    /// Re-wrap the vault key under a new password (requires unlocked vault).
    pub fn change_password(&mut self, new_password: &str) -> Result<()> {
        if new_password.chars().count() < 8 {
            return Err(VantaError::Invalid(
                "master password must have at least 8 characters".into(),
            ));
        }
        let vk = self.keys()?.vault_key.clone();
        let mut salt = vec![0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let pw = password_key(new_password, &salt, self.header.kdf)?;
        self.header.salt = salt;
        self.header.password_wrap = Sealed::seal(&pw, AAD_PW, vk.as_bytes());
        Ok(())
    }

    /// New random key for a profile, returned both unwrapped (to use now) and wrapped (to store).
    pub fn new_profile_key(&self, id: ProfileId) -> Result<(ProfileKey, WrappedKey)> {
        let kek = &self.keys()?.kek;
        let key = Key::random();
        let wrapped = WrappedKey(Sealed::seal(kek, id.as_bytes(), key.as_bytes()));
        Ok((ProfileKey { id, key }, wrapped))
    }

    pub fn unwrap_profile_key(&self, id: ProfileId, wrapped: &WrappedKey) -> Result<ProfileKey> {
        let kek = &self.keys()?.kek;
        let raw = wrapped.0.open(kek, id.as_bytes())?;
        Ok(ProfileKey {
            id,
            key: Key::from_slice(&raw)?,
        })
    }

    /// Seal a vault secret (a proxy password, the launcher signing key, the activity-log
    /// head...). `reference` is the name the secret is stored under; it is bound into the
    /// AAD, so a sealed blob cannot be moved to another reference.
    pub fn seal_secret(&self, reference: &str, plaintext: &[u8]) -> Result<Sealed> {
        let k = self.keys()?.vault_key.derive(INFO_SECRETS);
        Ok(Sealed::seal(&k, &secret_aad(reference), plaintext))
    }

    /// Open a secret sealed with [`Vault::seal_secret`] under the same `reference`.
    pub fn open_secret(&self, reference: &str, sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
        let k = self.keys()?.vault_key.derive(INFO_SECRETS);
        sealed.open(&k, &secret_aad(reference))
    }

    /// Key for the encrypted, hash-chained activity log (F08).
    pub fn log_key(&self) -> Result<Key> {
        Ok(self.keys()?.vault_key.derive(INFO_LOG))
    }
}

fn secret_aad(reference: &str) -> Vec<u8> {
    let mut a = AAD_SECRET.as_bytes().to_vec();
    a.extend_from_slice(reference.as_bytes());
    a
}

mod b64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_vault() -> (Vault, RecoveryKey) {
        Vault::create("correct horse battery", KdfParams::insecure_for_tests()).unwrap()
    }

    #[test]
    fn create_lock_unlock() {
        let (mut v, _) = new_vault();
        assert!(v.is_unlocked());
        v.lock();
        assert!(!v.is_unlocked());
        assert!(matches!(
            v.new_profile_key(ProfileId::new()),
            Err(VantaError::Locked)
        ));
        v.unlock("correct horse battery").unwrap();
        assert!(v.is_unlocked());
    }

    #[test]
    fn wrong_password_fails() {
        let (mut v, _) = new_vault();
        v.lock();
        assert!(matches!(
            v.unlock("wrong password!"),
            Err(VantaError::Crypto)
        ));
        assert!(!v.is_unlocked());
    }

    #[test]
    fn short_password_rejected() {
        assert!(Vault::create("short", KdfParams::insecure_for_tests()).is_err());
    }

    #[test]
    fn header_roundtrip_has_no_plain_secret() {
        let (v, rec) = new_vault();
        let json = v.header().to_json();
        assert!(!json.contains("correct horse"));
        assert!(!json.contains(rec.as_str()));
        let mut v2 = Vault::from_header(VaultHeader::from_json(&json).unwrap());
        v2.unlock("correct horse battery").unwrap();
    }

    #[test]
    fn profile_key_survives_relock_and_header_reload() {
        let (mut v, _) = new_vault();
        let id = ProfileId::new();
        let (pk, wrapped) = v.new_profile_key(id).unwrap();
        let blob = pk.seal("config", b"{\"ua\":\"Chrome/156\"}");
        let json = v.header().to_json();
        v.lock();
        let mut v2 = Vault::from_header(VaultHeader::from_json(&json).unwrap());
        v2.unlock("correct horse battery").unwrap();
        let pk2 = v2.unwrap_profile_key(id, &wrapped).unwrap();
        assert_eq!(
            &*pk2.open("config", &blob).unwrap(),
            b"{\"ua\":\"Chrome/156\"}"
        );
    }

    #[test]
    fn wrapped_key_bound_to_profile_id() {
        let (v, _) = new_vault();
        let (_, wrapped) = v.new_profile_key(ProfileId::new()).unwrap();
        assert!(v.unwrap_profile_key(ProfileId::new(), &wrapped).is_err());
    }

    #[test]
    fn purpose_separation() {
        let (v, _) = new_vault();
        let (pk, _) = v.new_profile_key(ProfileId::new()).unwrap();
        let blob = pk.seal("cookies", b"x");
        assert!(pk.open("config", &blob).is_err());
    }

    #[test]
    fn recovery_key_unlocks_and_tolerates_formatting() {
        let (mut v, rec) = new_vault();
        v.lock();
        let messy = rec.as_str().to_lowercase().replace('-', " ");
        v.unlock_with_recovery(&messy).unwrap();
        assert!(v.is_unlocked());
        v.lock();
        assert!(v.unlock_with_recovery("AAAA-BBBB").is_err());
    }

    #[test]
    fn change_password_keeps_profile_data() {
        let (mut v, rec) = new_vault();
        let id = ProfileId::new();
        let (pk, wrapped) = v.new_profile_key(id).unwrap();
        let blob = pk.seal("config", b"data");
        v.change_password("a brand new password").unwrap();
        v.lock();
        assert!(v.unlock("correct horse battery").is_err());
        v.unlock("a brand new password").unwrap();
        assert_eq!(
            &*v.unwrap_profile_key(id, &wrapped)
                .unwrap()
                .open("config", &blob)
                .unwrap(),
            b"data"
        );
        v.lock();
        v.unlock_with_recovery(rec.as_str()).unwrap();
    }

    #[test]
    fn deleted_key_means_data_unreadable() {
        // Deleting the wrapped key is the shred: without it, a new key cannot open old data.
        let (v, _) = new_vault();
        let id = ProfileId::new();
        let (pk, _wrapped) = v.new_profile_key(id).unwrap();
        let blob = pk.seal("config", b"secret");
        drop(pk);
        let (other, _) = v.new_profile_key(id).unwrap();
        assert!(other.open("config", &blob).is_err());
    }

    #[test]
    fn secrets_bound_to_reference_and_need_unlock() {
        let (mut v, _) = new_vault();
        let s = v.seal_secret("proxy/a", b"hunter2").unwrap();
        assert_eq!(&*v.open_secret("proxy/a", &s).unwrap(), b"hunter2");
        assert!(v.open_secret("proxy/b", &s).is_err());
        let json = v.header().to_json();
        v.lock();
        assert!(matches!(
            v.open_secret("proxy/a", &s),
            Err(VantaError::Locked)
        ));
        assert!(matches!(v.seal_secret("x", b"y"), Err(VantaError::Locked)));
        let mut v2 = Vault::from_header(VaultHeader::from_json(&json).unwrap());
        v2.unlock("correct horse battery").unwrap();
        assert_eq!(&*v2.open_secret("proxy/a", &s).unwrap(), b"hunter2");
    }

    #[test]
    fn key_debug_is_redacted() {
        assert_eq!(format!("{:?}", Key::random()), "Key(<redacted>)");
    }

    #[test]
    fn default_kdf_is_64mib_3_passes() {
        let k = KdfParams::default();
        assert_eq!((k.m_cost_kib, k.t_cost, k.p_cost), (65536, 3, 1));
    }
}
