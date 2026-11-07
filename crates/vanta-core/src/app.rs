//! [`VantaApp`]: the one object the Tauri shell talks to.

use crate::deps::Deps;
use crate::dto::*;
use crate::error::{BlockReason, CoreError, CoreResult};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinHandle;
use vanta_fingerprint::config::{pubkey_b64, sign_launch, LaunchBinding};
use vanta_fingerprint::device::builtin;
use vanta_fingerprint::Persona;
use vanta_health::{evaluate, GuardSnapshot, HealthInput, HealthLab, LeakWatch, Outcome};
use vanta_launcher::{
    preflight, Block, EngineExit, EngineLaunch, EngineProcess, HealthGate, KillOnCloseJob,
    Preflight, ProcessTable, HEALTH_MAX_AGE_MS,
};
use vanta_log::{ActivityLog, LogFilter, LogKind};
use vanta_proxy::state::{now_ms, MAX_CHECK_AGE_MS};
use vanta_proxy::{
    check_assignment, parse_line, parse_list, probe, resolve_upstream, Credentials, DohProvider,
    GuardPolicy, ProxyEndpoint, ProxyScheme, ProxyState, Relay, RelayConfig, RelayEvent, Resolver,
    DEFAULT_HEARTBEAT,
};
use vanta_store::{HealthSummary, ProfileMeta, ProfileSecrets, ProxyRecord, Store};
use vanta_types::{EngineVersion, OsKind, ProfileId, ProfileStatus, VantaError};
use vanta_vault::{KdfParams, Sealed, Vault, VaultHeader, WrappedKey};

/// Vault secret holding the launcher's Ed25519 signing key (32-byte seed).
pub const SECRET_SIGNING_KEY: &str = "launcher/ed25519";
/// Vault secret holding the activity log's head hash.
pub const SECRET_LOG_HEAD: &str = "log/head";
const VAULT_FILE: &str = "vault.json";
const DB_FILE: &str = "vanta.db";
const LOG_FILE: &str = "activity.log";

/// The installed engine.
#[derive(Debug, Clone)]
pub struct EngineInfo {
    pub exe: PathBuf,
    /// The engine's version (`engine/VERSION`, R5). Personas are bound to it at launch.
    pub version: EngineVersion,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub data_dir: PathBuf,
    pub engine: EngineInfo,
    pub kdf: KdfParams,
    /// How long a fresh engine is watched for exit 86/87 before the launch counts as done.
    pub startup_window: Duration,
    /// How long a health run waits for the probe page's report.
    pub health_timeout: Duration,
    /// Proxy check / relay upstream connect timeout.
    pub proxy_timeout: Duration,
    /// Relay kill-switch heartbeat.
    pub heartbeat: Duration,
}

impl AppConfig {
    pub fn new(data_dir: impl Into<PathBuf>, engine: EngineInfo) -> Self {
        Self {
            data_dir: data_dir.into(),
            engine,
            kdf: KdfParams::default(),
            startup_window: Duration::from_secs(3),
            health_timeout: Duration::from_secs(30),
            proxy_timeout: Duration::from_secs(10),
            heartbeat: DEFAULT_HEARTBEAT,
        }
    }
}

/// Sealed per-profile config (purpose `config` under the profile key).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProfileConfig {
    persona: Persona,
    #[serde(default)]
    policy: GuardPolicy,
}

struct LogState {
    log: Option<ActivityLog>,
    /// Entries that arrived while the vault was locked; written at the next unlock.
    pending: Vec<(i64, LogKind, Option<ProfileId>, String)>,
}

/// One running engine and everything that lives exactly as long as it.
struct Running {
    /// Closing the last handle kills every process of the profile (kill-on-close).
    _job: Arc<KillOnCloseJob>,
    relay: Option<Relay>,
    events: JoinHandle<()>,
    config_path: PathBuf,
    stop_requested: bool,
}

impl Drop for Running {
    fn drop(&mut self) {
        // Relay::drop cuts every connection; the job handle closes after this.
        self.relay.take();
        self.events.abort();
        let _ = std::fs::remove_file(&self.config_path);
    }
}

struct Inner {
    cfg: AppConfig,
    deps: Deps,
    // Lock order: log > vault > store; procs and running are never held with another.
    log: Mutex<LogState>,
    vault: Mutex<Option<Vault>>,
    store: Mutex<Store>,
    procs: Mutex<ProcessTable>,
    running: Mutex<HashMap<ProfileId, Running>>,
}

/// The Vanta backend: profiles, proxies, vault, launches, health runs and the activity
/// log. Cheap to clone (shared state). Dropping the last clone closes every profile's Job
/// Object, so no engine outlives the app.
#[derive(Clone)]
pub struct VantaApp {
    inner: Arc<Inner>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn storage(what: &str, e: impl std::fmt::Display) -> CoreError {
    CoreError::Storage {
        message: format!("{what}: {e}"),
    }
}

/// What a launch or health run starts from.
struct Prepared {
    meta: ProfileMeta,
    persona: Persona,
    policy: GuardPolicy,
    proxy_id: String,
    endpoint: ProxyEndpoint,
    proxy_state: ProxyState,
    health: Option<HealthSummary>,
}

/// An engine that got past its start-up window.
struct Started {
    process: Box<dyn EngineProcess>,
    job: Arc<KillOnCloseJob>,
    relay: Relay,
    config_path: PathBuf,
}

enum Mode<'a> {
    Launch,
    Health {
        extra_args: Vec<String>,
        watch: &'a Arc<LeakWatch>,
    },
}

impl VantaApp {
    /// Open (or create) the data folder. Every profile starts `stopped`: no engine survives
    /// the app (Job Object kill-on-close).
    pub fn open(cfg: AppConfig, deps: Deps) -> CoreResult<Self> {
        std::fs::create_dir_all(&cfg.data_dir).map_err(|e| storage("data folder", e))?;
        let store = Store::open(cfg.data_dir.join(DB_FILE))?;
        store.reset_all_status()?;
        let vault = match std::fs::read_to_string(cfg.data_dir.join(VAULT_FILE)) {
            Ok(s) => Some(Vault::from_header(VaultHeader::from_json(&s)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(storage("vault header", e)),
        };
        Ok(Self {
            inner: Arc::new(Inner {
                cfg,
                deps,
                log: Mutex::new(LogState {
                    log: None,
                    pending: Vec::new(),
                }),
                vault: Mutex::new(vault),
                store: Mutex::new(store),
                procs: Mutex::new(ProcessTable::new()),
                running: Mutex::new(HashMap::new()),
            }),
        })
    }

    pub fn config(&self) -> &AppConfig {
        &self.inner.cfg
    }

    // ---- vault ---------------------------------------------------------------------

    pub fn is_initialized(&self) -> bool {
        lock(&self.inner.vault).is_some()
    }

    pub fn is_unlocked(&self) -> bool {
        lock(&self.inner.vault)
            .as_ref()
            .is_some_and(|v| v.is_unlocked())
    }

    /// First run: create the vault (unlocked), its signing key and the activity log.
    pub fn create_vault(&self, password: &str) -> CoreResult<VaultCreated> {
        let recovery = {
            let mut slot = lock(&self.inner.vault);
            if slot.is_some() {
                return Err(CoreError::AlreadyInitialized);
            }
            let (vault, recovery) = Vault::create(password, self.inner.cfg.kdf)?;
            self.write_header(&vault)?;
            *slot = Some(vault);
            recovery.as_str().to_string()
        };
        self.ensure_signing_key()?;
        let report = self.open_log()?;
        self.log(LogKind::VaultUnlock, None, "vault created");
        debug_assert_eq!(report, LogIntegrity::Ok);
        Ok(VaultCreated {
            recovery_key: recovery,
        })
    }

    pub fn unlock(&self, password: &str) -> CoreResult<UnlockReport> {
        self.with_vault_mut(|v| v.unlock(password))?;
        self.after_unlock("password")
    }

    pub fn unlock_with_recovery(&self, recovery_key: &str) -> CoreResult<UnlockReport> {
        self.with_vault_mut(|v| v.unlock_with_recovery(recovery_key))?;
        self.after_unlock("recovery key")
    }

    /// Lock: keys leave memory. Running profiles keep running; their events are logged at
    /// the next unlock.
    pub fn lock(&self) -> CoreResult<()> {
        self.log(LogKind::VaultLock, None, "locked by user");
        let mut st = lock(&self.inner.log);
        st.log = None;
        if let Some(v) = lock(&self.inner.vault).as_mut() {
            v.lock();
        }
        Ok(())
    }

    fn with_vault_mut(
        &self,
        f: impl FnOnce(&mut Vault) -> vanta_types::Result<()>,
    ) -> CoreResult<()> {
        let mut slot = lock(&self.inner.vault);
        let v = slot.as_mut().ok_or(CoreError::NotInitialized)?;
        f(v)?;
        Ok(())
    }

    fn after_unlock(&self, how: &str) -> CoreResult<UnlockReport> {
        self.ensure_signing_key()?;
        let migrated = self.migrate_legacy_proxies()?;
        let integrity = self.open_log()?;
        let mut detail = format!("unlocked with {how}");
        match &integrity {
            LogIntegrity::Ok => {}
            LogIntegrity::HeadMismatch { detail: d } | LogIntegrity::Unreadable { detail: d } => {
                detail.push_str(&format!("; activity log integrity: {d}"))
            }
        }
        if migrated > 0 {
            detail.push_str(&format!(
                "; {migrated} inline proxy password(s) moved into the vault"
            ));
        }
        self.log(LogKind::VaultUnlock, None, detail);
        Ok(UnlockReport {
            log_integrity: integrity,
            migrated_proxies: migrated,
        })
    }

    fn write_header(&self, vault: &Vault) -> CoreResult<()> {
        let path = self.inner.cfg.data_dir.join(VAULT_FILE);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, vault.header().to_json()).map_err(|e| storage("vault header", e))?;
        std::fs::rename(&tmp, &path).map_err(|e| storage("vault header", e))
    }

    fn seal(&self, reference: &str, plaintext: &[u8]) -> CoreResult<Vec<u8>> {
        let vault = lock(&self.inner.vault);
        let v = vault.as_ref().ok_or(CoreError::NotInitialized)?;
        Ok(v.seal_secret(reference, plaintext)?.to_bytes())
    }

    fn open_secret(&self, reference: &str) -> CoreResult<Option<zeroize::Zeroizing<Vec<u8>>>> {
        let blob = lock(&self.inner.store).get_secret(reference)?;
        let Some(blob) = blob else { return Ok(None) };
        let vault = lock(&self.inner.vault);
        let v = vault.as_ref().ok_or(CoreError::NotInitialized)?;
        Ok(Some(v.open_secret(reference, &Sealed::from_bytes(&blob)?)?))
    }

    fn require_unlocked(&self) -> CoreResult<()> {
        match lock(&self.inner.vault).as_ref() {
            None => Err(CoreError::NotInitialized),
            Some(v) if !v.is_unlocked() => Err(CoreError::Locked),
            Some(_) => Ok(()),
        }
    }

    fn ensure_signing_key(&self) -> CoreResult<()> {
        if lock(&self.inner.store)
            .get_secret(SECRET_SIGNING_KEY)?
            .is_some()
        {
            return Ok(());
        }
        let key = vanta_fingerprint::config::new_signing_key();
        let blob = self.seal(SECRET_SIGNING_KEY, key.as_bytes())?;
        lock(&self.inner.store).put_secret(SECRET_SIGNING_KEY, &blob)?;
        Ok(())
    }

    fn signing_key(&self) -> CoreResult<SigningKey> {
        let raw = self
            .open_secret(SECRET_SIGNING_KEY)?
            .ok_or_else(|| CoreError::Storage {
                message: "launcher signing key missing from the vault".into(),
            })?;
        let seed: [u8; 32] = raw.as_slice().try_into().map_err(|_| CoreError::Crypto)?;
        Ok(SigningKey::from_bytes(&seed))
    }

    // ---- activity log --------------------------------------------------------------

    /// Open the log with the vault's log key and check it against the head kept in the
    /// vault (detects entries removed from the end).
    fn open_log(&self) -> CoreResult<LogIntegrity> {
        let key = {
            let vault = lock(&self.inner.vault);
            vault.as_ref().ok_or(CoreError::NotInitialized)?.log_key()?
        };
        let path = self.inner.cfg.data_dir.join(LOG_FILE);
        let mut integrity = LogIntegrity::Ok;
        let log = match ActivityLog::open(&path, key.clone()) {
            Ok(log) => log,
            Err(e) => {
                let aside = path.with_extension(format!("unreadable-{}", now_ms()));
                std::fs::rename(&path, &aside).map_err(|e| storage("activity log", e))?;
                integrity = LogIntegrity::Unreadable {
                    detail: format!("{e}; kept as {}", aside.display()),
                };
                ActivityLog::open(&path, key)?
            }
        };
        if integrity == LogIntegrity::Ok {
            if let Some(head) = self.open_secret(SECRET_LOG_HEAD)? {
                let expected: [u8; 32] =
                    head.as_slice().try_into().map_err(|_| CoreError::Crypto)?;
                if let Err(e) = log.verify_head(&expected) {
                    integrity = LogIntegrity::HeadMismatch {
                        detail: e.to_string(),
                    };
                }
            } else if let Err(b) = log.verify_chain() {
                integrity = LogIntegrity::HeadMismatch {
                    detail: b.to_string(),
                };
            }
        }
        let mut st = lock(&self.inner.log);
        st.log = Some(log);
        let pending = std::mem::take(&mut st.pending);
        drop(st);
        self.log_batch(pending);
        let pruned = {
            let mut st = lock(&self.inner.log);
            st.log.as_mut().map(|l| l.prune(now_ms())).transpose()
        };
        if matches!(pruned, Ok(Some(n)) if n > 0) {
            self.store_log_head();
        }
        Ok(integrity)
    }

    fn log(&self, kind: LogKind, profile: Option<ProfileId>, detail: impl Into<String>) {
        self.log_batch(vec![(now_ms(), kind, profile, detail.into())]);
    }

    /// Append a batch, then keep the new head in the vault. While the vault is locked the
    /// entries wait in memory (they never hold secrets).
    fn log_batch(&self, batch: Vec<(i64, LogKind, Option<ProfileId>, String)>) {
        Inner::log_batch(&self.inner, batch)
    }

    fn store_log_head(&self) {
        Inner::store_log_head(&self.inner, &lock(&self.inner.log));
    }

    /// A page of the activity log, newest first.
    pub fn activity_log(&self, q: &LogQuery) -> CoreResult<LogPage> {
        self.require_unlocked()?;
        let st = lock(&self.inner.log);
        let log = st.log.as_ref().ok_or(CoreError::Locked)?;
        let filter = LogFilter {
            kinds: q.kinds.clone(),
            profile: q.profile,
            from_ms: q.from_ms,
            to_ms: q.to_ms,
        };
        let all = log.query(&filter);
        let limit = if q.limit == 0 { 100 } else { q.limit };
        Ok(LogPage {
            total: all.len(),
            entries: all
                .into_iter()
                .rev()
                .skip(q.offset)
                .take(limit)
                .cloned()
                .collect(),
        })
    }

    // ---- profiles ------------------------------------------------------------------

    pub fn list_profiles(
        &self,
        query: &str,
        limit: usize,
        offset: usize,
    ) -> CoreResult<ProfilePage> {
        let (items, total) = lock(&self.inner.store).search(query, limit.max(1), offset)?;
        Ok(ProfilePage { items, total })
    }

    pub fn folders(&self) -> CoreResult<Vec<(String, i64)>> {
        Ok(lock(&self.inner.store).folders()?)
    }

    pub fn get_profile(&self, id: ProfileId) -> CoreResult<ProfileDetail> {
        self.require_unlocked()?;
        let meta = lock(&self.inner.store).get(id)?;
        let cfg = self.load_config(id)?;
        let p = &cfg.persona;
        let health = lock(&self.inner.store).get_health(id)?;
        Ok(ProfileDetail {
            meta,
            persona: PersonaSummary {
                device_id: p.device_id.clone(),
                os: p.os,
                user_agent: p.user_agent.clone(),
                screen: format!("{}x{}", p.screen.width, p.screen.height),
                gpu: p.gpu.renderer.clone(),
                locale: p.locale.clone(),
                hardware_concurrency: p.hardware_concurrency,
                device_memory: p.device_memory,
            },
            health,
        })
    }

    fn new_persona(&self, os: Option<OsKind>, locale: &str, seed: u64) -> CoreResult<Persona> {
        Ok(Persona::generate(
            &builtin(),
            |d| !matches!(os, Some(o) if d.os_kind().ok() != Some(o)),
            self.inner.cfg.engine.version,
            seed,
            locale,
        )?)
    }

    pub fn create_profile(&self, new: NewProfile) -> CoreResult<ProfileMeta> {
        self.require_unlocked()?;
        if let Some(p) = &new.proxy_id {
            lock(&self.inner.store).get_proxy(p)?;
        }
        let locale = new.locale.clone().unwrap_or_else(|| "en-US".into());
        let seed = match &new.seed {
            Some(s) => parse_seed(s)?,
            None => rand::random(),
        };
        let persona = self.new_persona(new.os, &locale, seed)?;
        let mut meta = ProfileMeta::new(new.name, persona.os, now_ms());
        meta.folder = new.folder;
        meta.tags = new.tags;
        meta.notes = new.notes;
        meta.color = new.color;
        meta.proxy_id = new.proxy_id;
        let cfg = ProfileConfig {
            persona,
            policy: GuardPolicy::default(),
        };
        let (pk, wrapped) = {
            let vault = lock(&self.inner.vault);
            vault
                .as_ref()
                .ok_or(CoreError::NotInitialized)?
                .new_profile_key(meta.id)?
        };
        let json = serde_json::to_vec(&cfg).map_err(|e| storage("profile config", e))?;
        let secrets = ProfileSecrets {
            config: Some(pk.seal("config", &json).to_bytes()),
            wrapped_key: Some(wrapped.0.to_bytes()),
        };
        lock(&self.inner.store).insert(&meta, &secrets)?;
        Ok(lock(&self.inner.store).get(meta.id)?)
    }

    pub fn edit_profile(&self, id: ProfileId, edit: ProfileEdit) -> CoreResult<ProfileMeta> {
        let store = lock(&self.inner.store);
        let mut m = store.get(id)?;
        if let Some(v) = edit.name {
            m.name = v;
        }
        if let Some(v) = edit.folder {
            m.folder = v;
        }
        if let Some(v) = edit.tags {
            m.tags = v;
        }
        if let Some(v) = edit.notes {
            m.notes = v;
        }
        if let Some(v) = edit.color {
            m.color = v;
        }
        store.update_meta(&m)?;
        Ok(store.get(id)?)
    }

    /// Delete profiles: their engines are stopped first, then the row, sealed config and
    /// wrapped key go (crypto-shred) and the user-data folder is removed.
    pub fn delete_profiles(&self, ids: &[ProfileId]) -> CoreResult<usize> {
        for id in ids {
            if lock(&self.inner.running).contains_key(id) {
                let _ = self.stop_profile(*id);
            }
        }
        let n = lock(&self.inner.store).delete(ids)?;
        for id in ids {
            let _ = std::fs::remove_dir_all(self.user_data_dir(*id));
        }
        Ok(n)
    }

    /// Fingerprint Studio: the profile's persona bound to the installed engine, with the
    /// result of every consistency rule.
    pub fn fingerprint(&self, id: ProfileId) -> CoreResult<FingerprintView> {
        self.require_unlocked()?;
        let mut persona = self.load_config(id)?.persona;
        persona.bind_engine(self.inner.cfg.engine.version);
        Ok(fingerprint_view(&persona, self.inner.cfg.engine.version))
    }

    /// New Profile form: the persona `create_profile` will build for the same OS, locale
    /// and seed (hex). Nothing is stored.
    pub fn preview_fingerprint(
        &self,
        os: Option<OsKind>,
        locale: Option<&str>,
        seed: &str,
    ) -> CoreResult<FingerprintView> {
        let persona = self.new_persona(os, locale.unwrap_or("en-US"), parse_seed(seed)?)?;
        Ok(fingerprint_view(&persona, self.inner.cfg.engine.version))
    }

    /// The profile's Network Guard policy (kill switch and WebRTC rule are fixed).
    pub fn guard_policy(&self, id: ProfileId) -> CoreResult<GuardPolicy> {
        self.require_unlocked()?;
        Ok(self.load_config(id)?.policy)
    }

    /// Change the profile's DoH provider (the only configurable guard). Its health run no
    /// longer applies (the DNS checks ran against the old provider).
    pub fn set_doh_provider(&self, id: ProfileId, doh: DohProvider) -> CoreResult<GuardPolicy> {
        self.require_unlocked()?;
        let mut cfg = self.load_config(id)?;
        cfg.policy.doh = doh;
        self.save_config(id, &cfg)?;
        let store = lock(&self.inner.store);
        let mut m = store.get(id)?;
        m.health = 0;
        store.update_meta(&m)?;
        store.clear_health(id)?;
        Ok(cfg.policy)
    }

    /// Re-wrap the vault key under a new master password. The current password is checked
    /// on a copy of the header, so a wrong one changes nothing.
    pub fn change_password(&self, current: &str, new_password: &str) -> CoreResult<()> {
        self.require_unlocked()?;
        let mut slot = lock(&self.inner.vault);
        let v = slot.as_mut().ok_or(CoreError::NotInitialized)?;
        Vault::from_header(v.header().clone()).unlock(current)?;
        v.change_password(new_password)?;
        self.write_header(v)?;
        drop(slot);
        self.log(LogKind::VaultUnlock, None, "master password changed");
        Ok(())
    }

    /// New device and seeds for the profile (same locale and geo); its health run no
    /// longer applies.
    pub fn regenerate_fingerprint(
        &self,
        id: ProfileId,
        os: Option<OsKind>,
    ) -> CoreResult<ProfileMeta> {
        self.require_unlocked()?;
        let old = self.load_config(id)?;
        let mut persona = self.new_persona(os, &old.persona.locale, rand::random())?;
        persona.languages = old.persona.languages.clone();
        persona.geo = old.persona.geo.clone();
        self.save_config(
            id,
            &ProfileConfig {
                persona: persona.clone(),
                policy: old.policy,
            },
        )?;
        let store = lock(&self.inner.store);
        let mut m = store.get(id)?;
        m.os = persona.os;
        m.health = 0;
        store.update_meta(&m)?;
        store.clear_health(id)?;
        Ok(store.get(id)?)
    }

    fn profile_key(&self, id: ProfileId) -> CoreResult<(vanta_vault::ProfileKey, ProfileSecrets)> {
        let secrets = lock(&self.inner.store).secrets(id)?;
        let wrapped = secrets
            .wrapped_key
            .as_deref()
            .ok_or_else(|| CoreError::Storage {
                message: format!("profile {id} has no key"),
            })?;
        let wrapped = WrappedKey(Sealed::from_bytes(wrapped)?);
        let vault = lock(&self.inner.vault);
        let pk = vault
            .as_ref()
            .ok_or(CoreError::NotInitialized)?
            .unwrap_profile_key(id, &wrapped)?;
        Ok((pk, secrets))
    }

    fn load_config(&self, id: ProfileId) -> CoreResult<ProfileConfig> {
        let (pk, secrets) = self.profile_key(id)?;
        let blob = secrets.config.ok_or_else(|| CoreError::Storage {
            message: format!("profile {id} has no config"),
        })?;
        let json = pk.open("config", &Sealed::from_bytes(&blob)?)?;
        serde_json::from_slice(&json).map_err(|e| storage("profile config", e))
    }

    fn save_config(&self, id: ProfileId, cfg: &ProfileConfig) -> CoreResult<()> {
        let (pk, _) = self.profile_key(id)?;
        let json = serde_json::to_vec(cfg).map_err(|e| storage("profile config", e))?;
        lock(&self.inner.store).set_config(id, &pk.seal("config", &json).to_bytes())?;
        Ok(())
    }

    fn user_data_dir(&self, id: ProfileId) -> PathBuf {
        self.inner
            .cfg
            .data_dir
            .join("profiles")
            .join(id.to_string())
    }

    // ---- proxies -------------------------------------------------------------------

    fn proxy_view(r: &ProxyRecord) -> ProxyView {
        let state = serde_json::from_str(&r.state).unwrap_or(ProxyState::Unknown);
        let display = match &r.username {
            Some(u) => format!("{}://{u}:***@{}:{}", r.scheme, r.host, r.port),
            None => format!("{}://{}:{}", r.scheme, r.host, r.port),
        };
        ProxyView {
            id: r.id.clone(),
            scheme: r.scheme.clone(),
            host: r.host.clone(),
            port: r.port,
            username: r.username.clone(),
            has_password: r.secret_ref.is_some(),
            label: r.label.clone(),
            state,
            display,
        }
    }

    pub fn list_proxies(&self) -> CoreResult<Vec<ProxyView>> {
        Ok(lock(&self.inner.store)
            .list_proxies()?
            .iter()
            .map(Self::proxy_view)
            .collect())
    }

    /// Turn a parsed endpoint into a stored proxy: the password is sealed into the vault,
    /// the row keeps only its reference.
    fn proxy_record(&self, ep: &ProxyEndpoint) -> CoreResult<ProxyRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut secret_ref = None;
        if let Some(c) = &ep.auth {
            if !c.password().is_empty() {
                let r = format!("proxy/{id}");
                let blob = self.seal(&r, c.password().as_bytes())?;
                lock(&self.inner.store).put_secret(&r, &blob)?;
                secret_ref = Some(r);
            }
        }
        Ok(ProxyRecord {
            id,
            scheme: ep.scheme.as_str().into(),
            host: ep.host.clone(),
            port: ep.port,
            username: ep.auth.as_ref().map(|c| c.username.clone()),
            secret_ref,
            label: String::new(),
            state: serde_json::to_string(&ProxyState::Unknown).expect("state serializes"),
            created_ms: now_ms(),
        })
    }

    /// Bulk import (F04 grammar). Lines without a scheme take `default_scheme`.
    pub fn import_proxies(
        &self,
        text: &str,
        default_scheme: ProxyScheme,
    ) -> CoreResult<ImportResult> {
        self.require_unlocked()?;
        let report = parse_list(text, default_scheme);
        let mut records = Vec::new();
        for p in &report.proxies {
            records.push(self.proxy_record(&p.endpoint)?);
        }
        lock(&self.inner.store).insert_proxies(&records)?;
        Ok(ImportResult {
            added: records.iter().map(Self::proxy_view).collect(),
            errors: report
                .errors
                .into_iter()
                .map(|e| ImportLineError {
                    line: e.line,
                    message: e.message,
                })
                .collect(),
        })
    }

    pub fn delete_proxy(&self, proxy_id: &str) -> CoreResult<()> {
        Ok(lock(&self.inner.store).delete_proxy(proxy_id)?)
    }

    /// The endpoint with its password opened from the vault.
    fn endpoint(&self, r: &ProxyRecord) -> CoreResult<ProxyEndpoint> {
        let scheme = match r.scheme.as_str() {
            "http" => ProxyScheme::Http,
            "https" => ProxyScheme::Https,
            "socks5" => ProxyScheme::Socks5,
            s => {
                return Err(CoreError::Storage {
                    message: format!("proxy {} has unknown scheme {s}", r.id),
                })
            }
        };
        let auth = match (&r.username, &r.secret_ref) {
            (Some(u), Some(sr)) => {
                let pw = self.open_secret(sr)?.ok_or_else(|| CoreError::Storage {
                    message: format!("proxy {} password missing from the vault", r.id),
                })?;
                let pw = String::from_utf8(pw.to_vec()).map_err(|_| CoreError::Crypto)?;
                Some(Credentials::new(u.clone(), pw))
            }
            (Some(u), None) => Some(Credentials::new(u.clone(), "")),
            _ => None,
        };
        Ok(ProxyEndpoint::new(scheme, &r.host, r.port, auth))
    }

    /// Point a profile at a proxy (or none). Its health run no longer applies. Returns the
    /// other profiles that already exit through the same proxy (one proxy, one profile).
    pub fn assign_proxy(
        &self,
        profile: ProfileId,
        proxy_id: Option<&str>,
    ) -> CoreResult<AssignResult> {
        let shared_with = match proxy_id {
            None => vec![],
            Some(pid) => {
                let (rec, others) = {
                    let store = lock(&self.inner.store);
                    store.get(profile)?;
                    let rec = store.get_proxy(pid)?;
                    let mut others = Vec::new();
                    for (p, other) in store.assignments()? {
                        if let Ok(r) = store.get_proxy(&other) {
                            others.push((p, r));
                        }
                    }
                    (rec, others)
                };
                // Identity excludes the password, so no vault access is needed here.
                let ep = |r: &ProxyRecord| {
                    let scheme = match r.scheme.as_str() {
                        "http" => ProxyScheme::Http,
                        "https" => ProxyScheme::Https,
                        _ => ProxyScheme::Socks5,
                    };
                    ProxyEndpoint::new(
                        scheme,
                        &r.host,
                        r.port,
                        r.username.as_ref().map(|u| Credentials::new(u.clone(), "")),
                    )
                };
                let target = ep(&rec);
                let eps: Vec<(ProfileId, ProxyEndpoint)> =
                    others.iter().map(|(p, r)| (*p, ep(r))).collect();
                check_assignment(eps.iter().map(|(p, e)| (*p, e)), profile, &target)
                    .map(|w| w.other_profiles)
                    .unwrap_or_default()
            }
        };
        let store = lock(&self.inner.store);
        store.set_proxy_id(profile, proxy_id)?;
        store.clear_health(profile)?;
        Ok(AssignResult { shared_with })
    }

    async fn check_proxy(
        &self,
        proxy_id: &str,
        endpoint: &ProxyEndpoint,
        policy: &GuardPolicy,
    ) -> CoreResult<ProxyState> {
        let bootstrap = self.inner.deps.net.bootstrap(policy);
        let state = match resolve_upstream(endpoint, &*bootstrap).await {
            Ok(addr) => probe(endpoint, addr, self.inner.cfg.proxy_timeout).await,
            Err(_) => ProxyState::Offline {
                checked_ms: now_ms(),
                reason: vanta_proxy::OfflineReason::Unreachable,
            },
        };
        lock(&self.inner.store).set_proxy_state(
            proxy_id,
            &serde_json::to_string(&state).expect("state serializes"),
        )?;
        if let ProxyState::Offline { reason, .. } = state {
            self.log(
                LogKind::ProxyFailure,
                None,
                format!("proxy {endpoint} check failed: {reason}"),
            );
        }
        Ok(state)
    }

    /// Check a proxy now (reachability and, for SOCKS5, the login) and store the result.
    pub async fn test_proxy(&self, proxy_id: &str) -> CoreResult<ProxyView> {
        self.require_unlocked()?;
        let rec = lock(&self.inner.store).get_proxy(proxy_id)?;
        let ep = self.endpoint(&rec)?;
        self.check_proxy(proxy_id, &ep, &GuardPolicy::default())
            .await?;
        Ok(Self::proxy_view(
            &lock(&self.inner.store).get_proxy(proxy_id)?,
        ))
    }

    /// Schema-1 rows could hold an inline proxy line (with its password) in `proxy_id`.
    /// Move each into the Proxy Hub with its password sealed in the vault, then rewrite
    /// the database file so the old text is gone from free pages and the WAL.
    fn migrate_legacy_proxies(&self) -> CoreResult<usize> {
        let legacy = lock(&self.inner.store).legacy_inline_proxies()?;
        if legacy.is_empty() {
            return Ok(0);
        }
        let mut moved = 0;
        for (profile, raw) in legacy {
            match parse_line(raw.trim(), ProxyScheme::Socks5) {
                Ok(ep) => {
                    let rec = self.proxy_record(&ep)?;
                    let id = rec.id.clone();
                    let mut store = lock(&self.inner.store);
                    store.insert_proxies(&[rec])?;
                    store.set_proxy_id(profile, Some(&id))?;
                    moved += 1;
                }
                Err(_) => {
                    // Not a proxy line: drop the dangling value rather than keep text that
                    // might hold a secret.
                    lock(&self.inner.store).set_proxy_id(profile, None)?;
                }
            }
        }
        lock(&self.inner.store).compact()?;
        Ok(moved)
    }

    // ---- launch --------------------------------------------------------------------

    fn prepare(&self, id: ProfileId) -> CoreResult<Prepared> {
        self.require_unlocked()?;
        let meta = lock(&self.inner.store).get(id)?;
        let cfg = self.load_config(id)?;
        let mut persona = cfg.persona;
        // R5: the persona always claims exactly the installed engine (C030).
        persona.bind_engine(self.inner.cfg.engine.version);
        let proxy_id = meta.proxy_id.clone().ok_or_else(|| CoreError::Blocked {
            reasons: vec![BlockReason::no_proxy()],
        })?;
        let rec = lock(&self.inner.store).get_proxy(&proxy_id)?;
        let endpoint = self.endpoint(&rec)?;
        let proxy_state = serde_json::from_str(&rec.state).unwrap_or(ProxyState::Unknown);
        let health = lock(&self.inner.store).get_health(id)?;
        Ok(Prepared {
            meta,
            persona,
            policy: cfg.policy,
            proxy_id,
            endpoint,
            proxy_state,
            health,
        })
    }

    fn health_gate(&self, p: &Prepared, now: i64) -> HealthGate {
        match &p.health {
            None => HealthGate::Missing,
            // A report from another engine build or another proxy says nothing now.
            Some(h)
                if h.engine != self.inner.cfg.engine.version.to_string()
                    || h.proxy_id.as_deref() != Some(p.proxy_id.as_str()) =>
            {
                HealthGate::Missing
            }
            Some(h) if now - h.ts_ms > HEALTH_MAX_AGE_MS => HealthGate::Expired {
                age_ms: now - h.ts_ms,
            },
            Some(h) => HealthGate::Fresh { score: h.score },
        }
    }

    fn block(&self, id: ProfileId, reasons: Vec<BlockReason>) -> CoreError {
        lock(&self.inner.procs).mark_blocked(id);
        let _ = lock(&self.inner.store).set_status(id, ProfileStatus::Blocked, now_ms());
        self.log(
            LogKind::LaunchBlocked,
            Some(id),
            reasons
                .iter()
                .map(|r| r.code.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        );
        CoreError::Blocked { reasons }
    }

    /// Gate, relay, signed config, engine start. Shared by launch and health runs.
    async fn start_engine(&self, p: &Prepared, mode: Mode<'_>) -> CoreResult<Started> {
        let id = p.meta.id;
        let now = now_ms();
        let engine = self.inner.cfg.engine.version;

        // F02 rules (C001-C030) on the engine-bound persona.
        let mut rule_problem = None;
        if let Err(e) = vanta_fingerprint::config::preflight(&p.persona, engine) {
            rule_problem = Some(e.to_string());
        }

        // F04: proxy online and freshly checked; re-check when it is not.
        let mut proxy_state = p.proxy_state;
        if proxy_state.launch_gate(now, MAX_CHECK_AGE_MS).is_err() {
            proxy_state = self
                .check_proxy(&p.proxy_id, &p.endpoint, &p.policy)
                .await?;
        }

        // F05: the profile's own relay, accepting only its Job Object's processes.
        let job = Arc::new(KillOnCloseJob::new()?);
        let mut relay = None;
        if proxy_state.is_online() {
            let bootstrap = self.inner.deps.net.bootstrap(&p.policy);
            let addr = resolve_upstream(&p.endpoint, &*bootstrap).await?;
            let resolver: Arc<dyn Resolver> = match &mode {
                Mode::Health { watch, .. } => (*watch).clone(),
                Mode::Launch => self
                    .inner
                    .deps
                    .net
                    .relay_resolver(&p.policy, &p.endpoint, addr),
            };
            let mut rc = RelayConfig::new(p.endpoint.clone(), addr, resolver)
                .with_clients(self.inner.deps.clients.build(job.clone()));
            rc.policy = p.policy.clone();
            rc.connect_timeout = self.inner.cfg.proxy_timeout;
            rc.heartbeat = self.inner.cfg.heartbeat;
            relay = Some(Relay::start(rc).await?);
        }

        let health = match mode {
            Mode::Launch => self.health_gate(p, now),
            Mode::Health { .. } => HealthGate::NotRequired,
        };
        let gate = Preflight {
            proxy: proxy_state,
            proxy_max_age_ms: MAX_CHECK_AGE_MS,
            // Without a relay the proxy reason is already listed.
            relay_armed: !relay.as_ref().is_some_and(|r| r.is_tripped()),
            rules_passed: rule_problem.is_none(),
            health,
        };
        if let Err(blocks) = preflight(&gate, now) {
            let reasons = blocks
                .iter()
                .map(|b| match (b, &rule_problem) {
                    (Block::RulesFailed, Some(msg)) => {
                        BlockReason::new("rules_failed", format!("launch blocked: {msg}"))
                    }
                    _ => BlockReason::from_block(b),
                })
                .collect();
            return Err(self.block(id, reasons));
        }
        let relay = relay.expect("gate passed, so the proxy is online and the relay runs");

        // Signed launch config (engine patch 0002 format).
        let key = self.signing_key()?;
        let signed = sign_launch(
            &p.persona,
            &LaunchBinding {
                profile_id: id.to_string(),
                relay_port: relay.local_addr().port(),
                issued_ms: now,
            },
            &key,
        );
        let run_dir = self.inner.cfg.data_dir.join("run").join(id.to_string());
        std::fs::create_dir_all(&run_dir).map_err(|e| storage("run folder", e))?;
        let user_data = self.user_data_dir(id);
        std::fs::create_dir_all(&user_data).map_err(|e| storage("profile folder", e))?;
        let config_path = run_dir.join("launch.json");
        std::fs::write(&config_path, signed.to_file_json())
            .map_err(|e| storage("launch config", e))?;

        let launch = EngineLaunch {
            engine_exe: self.inner.cfg.engine.exe.clone(),
            user_data_dir: user_data,
            config_path: config_path.clone(),
            pubkey_b64: pubkey_b64(&key.verifying_key()),
            relay_proxy_url: relay.proxy_url(),
            policy: p.policy.clone(),
        };
        let mut args: Vec<OsString> = launch.args();
        if let Mode::Health { extra_args, .. } = &mode {
            args.extend(extra_args.iter().map(OsString::from));
        }
        let cleanup = |e: CoreError| {
            let _ = std::fs::remove_file(&config_path);
            e
        };
        let mut process = match self
            .inner
            .deps
            .spawner
            .spawn(&launch.engine_exe, &args, &job)
        {
            Ok(p) => p,
            Err(VantaError::Invalid(m)) if m.contains("only be launched on Windows") => {
                return Err(cleanup(CoreError::Unsupported { message: m }))
            }
            Err(e) => return Err(cleanup(e.into())),
        };

        // Watch the start-up window for the engine's own verdict (86/87).
        let deadline = tokio::time::Instant::now() + self.inner.cfg.startup_window;
        loop {
            match process.try_exit() {
                Ok(None) => {}
                Ok(Some(code)) => {
                    let err = match code.and_then(EngineExit::from_code) {
                        Some(EngineExit::BadConfigSignature) => CoreError::BadConfigSignature,
                        Some(EngineExit::VersionMismatch) => CoreError::VersionMismatch {
                            expected: engine.to_string(),
                        },
                        _ => CoreError::EngineExited { code },
                    };
                    let status = match err {
                        CoreError::EngineExited { .. } => ProfileStatus::Crashed,
                        _ => ProfileStatus::Blocked,
                    };
                    if status == ProfileStatus::Blocked {
                        lock(&self.inner.procs).mark_blocked(id);
                    }
                    let _ = lock(&self.inner.store).set_status(id, status, now_ms());
                    self.log(
                        if status == ProfileStatus::Blocked {
                            LogKind::LaunchBlocked
                        } else {
                            LogKind::ProfileCrash
                        },
                        Some(id),
                        err.to_string(),
                    );
                    return Err(cleanup(err));
                }
                Err(e) => return Err(cleanup(storage("engine process", e))),
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        Ok(Started {
            process,
            job,
            relay,
            config_path,
        })
    }

    /// Launch a profile: load it, open its proxy password from the vault, bind the
    /// persona to the engine (R5), start its relay (Job-Object clients only, kill switch
    /// armed), run the gate (proxy, guard, rules, health), sign the launch config and
    /// start the engine suspended inside the profile's Job Object.
    pub async fn launch_profile(&self, id: ProfileId) -> CoreResult<LaunchInfo> {
        if lock(&self.inner.running).contains_key(&id) {
            return Err(CoreError::AlreadyRunning);
        }
        let prepared = match self.prepare(id) {
            Err(CoreError::Blocked { reasons }) => return Err(self.block(id, reasons)),
            r => r?,
        };
        let started = self.start_engine(&prepared, Mode::Launch).await?;
        let pid = started.process.pid();
        let relay_port = started.relay.local_addr().port();
        let events = Inner::forward_relay_events(&self.inner, id, &started.relay);
        lock(&self.inner.procs).insert_boxed(id, started.process);
        lock(&self.inner.running).insert(
            id,
            Running {
                _job: started.job,
                relay: Some(started.relay),
                events,
                config_path: started.config_path,
                stop_requested: false,
            },
        );
        lock(&self.inner.store).set_status(id, ProfileStatus::Running, now_ms())?;
        self.log(
            LogKind::ProfileLaunch,
            Some(id),
            format!(
                "engine {} pid {pid}, relay 127.0.0.1:{relay_port}, proxy {}",
                self.inner.cfg.engine.version, prepared.endpoint
            ),
        );
        Ok(LaunchInfo {
            profile_id: id,
            pid,
            relay_port,
            engine_version: self.inner.cfg.engine.version.to_string(),
        })
    }

    /// Stop a running profile: kill its engine, close its relay and Job Object.
    pub fn stop_profile(&self, id: ProfileId) -> CoreResult<()> {
        let mut running = lock(&self.inner.running)
            .remove(&id)
            .ok_or(CoreError::NotRunning)?;
        running.stop_requested = true;
        let _ = lock(&self.inner.procs).stop(id);
        drop(running);
        lock(&self.inner.store).set_status(id, ProfileStatus::Stopped, now_ms())?;
        self.log(LogKind::ProfileStop, Some(id), "stopped by user");
        Ok(())
    }

    /// Reap ended engines and write their real status to the store: exit 0 or a user stop
    /// = `stopped`, 86/87 = `blocked`, anything else = `crashed`.
    pub fn poll_status(&self) -> Vec<StatusChange> {
        Inner::poll_status(&self.inner)
    }

    /// Run [`VantaApp::poll_status`] every `every` until the app is dropped.
    pub fn spawn_status_watcher(&self, every: Duration) -> JoinHandle<()> {
        let weak = Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            loop {
                tick.tick().await;
                let Some(inner) = weak.upgrade() else { break };
                Inner::poll_status(&inner);
            }
        })
    }

    /// Direct store access for this crate's tests.
    #[cfg(test)]
    pub(crate) fn store_for_tests(&self) -> MutexGuard<'_, Store> {
        lock(&self.inner.store)
    }

    pub fn running_profiles(&self) -> Vec<ProfileId> {
        lock(&self.inner.running).keys().copied().collect()
    }

    // ---- health --------------------------------------------------------------------

    /// F03: start the health lab, launch the engine (same flow: relay, signed config,
    /// suspended start in the job) with the lab's switches, collect, score, store the
    /// summary and log it.
    pub async fn run_health(&self, id: ProfileId) -> CoreResult<HealthResult> {
        if lock(&self.inner.running).contains_key(&id) {
            return Err(CoreError::AlreadyRunning);
        }
        let prepared = self.prepare(id)?;
        let mut input = HealthInput::new(prepared.persona.clone());
        let lab = HealthLab::start(&input).await?;
        let watch = {
            // The relay resolver for this run, wrapped so the DNS leak test sees each name.
            let bootstrap = self.inner.deps.net.bootstrap(&prepared.policy);
            let addr = match resolve_upstream(&prepared.endpoint, &*bootstrap).await {
                Ok(a) => a,
                Err(_) => "0.0.0.0:0".parse().expect("addr"),
            };
            Arc::new(LeakWatch::new(self.inner.deps.net.relay_resolver(
                &prepared.policy,
                &prepared.endpoint,
                addr,
            )))
        };
        let _ = lock(&self.inner.store).set_status(id, ProfileStatus::Starting, now_ms());
        let started = match self
            .start_engine(
                &prepared,
                Mode::Health {
                    extra_args: lab.engine_args(),
                    watch: &watch,
                },
            )
            .await
        {
            Ok(s) => s,
            Err(e) => {
                if !matches!(
                    e,
                    CoreError::Blocked { .. }
                        | CoreError::BadConfigSignature
                        | CoreError::VersionMismatch { .. }
                ) {
                    let _ =
                        lock(&self.inner.store).set_status(id, ProfileStatus::Stopped, now_ms());
                }
                return Err(e);
            }
        };
        input.guard = GuardSnapshot {
            proxy_reachable: true,
            relay_armed: !started.relay.is_tripped(),
            engine_uses_relay: true,
            doh_through_proxy: true,
            ..GuardSnapshot::default()
        };
        let input = lab
            .collect(input, &watch, self.inner.cfg.health_timeout)
            .await;
        let Started {
            mut process,
            job,
            relay,
            config_path,
        } = started;
        let _ = process.kill();
        let _ = process.wait_exit();
        relay.shutdown().await;
        drop(job);
        let _ = std::fs::remove_file(&config_path);

        let report = evaluate(&input);
        let summary = HealthSummary {
            profile_id: id,
            score: report.score,
            blocked: report.blocked,
            failing: report
                .results
                .iter()
                .filter(|r| r.outcome == Outcome::Fail)
                .map(|r| r.id.to_string())
                .collect(),
            engine: self.inner.cfg.engine.version.to_string(),
            proxy_id: Some(prepared.proxy_id.clone()),
            ts_ms: now_ms(),
        };
        {
            let mut store = lock(&self.inner.store);
            store.put_health(&summary)?;
            store.set_status(id, ProfileStatus::Stopped, now_ms())?;
        }
        self.log(
            LogKind::HealthRun,
            Some(id),
            format!(
                "score {}{}; failing: {}",
                summary.score,
                if summary.blocked {
                    " (blocks launch)"
                } else {
                    ""
                },
                if summary.failing.is_empty() {
                    "none".to_string()
                } else {
                    summary.failing.join(" ")
                }
            ),
        );
        Ok(HealthResult {
            problems: report
                .problems()
                .into_iter()
                .map(|r| CheckProblem {
                    id: r.id.into(),
                    title: r.title.into(),
                    outcome: format!("{:?}", r.outcome).to_lowercase(),
                    message: r.message.clone(),
                })
                .collect(),
            summary,
        })
    }
}

impl Inner {
    fn log_batch(this: &Arc<Inner>, batch: Vec<(i64, LogKind, Option<ProfileId>, String)>) {
        if batch.is_empty() {
            return;
        }
        let mut st = lock(&this.log);
        let Some(log) = st.log.as_mut() else {
            st.pending.extend(batch);
            return;
        };
        for (ts, kind, profile, detail) in batch {
            let _ = log.append(ts, kind, profile, detail);
        }
        Self::store_log_head(this, &st);
    }

    /// Keep the log's head in the vault (sealed), so a truncated log is caught at unlock.
    fn store_log_head(this: &Arc<Inner>, st: &LogState) {
        let Some(log) = st.log.as_ref() else { return };
        let head = log.head();
        let sealed = {
            let vault = lock(&this.vault);
            match vault
                .as_ref()
                .map(|v| v.seal_secret(SECRET_LOG_HEAD, &head))
            {
                Some(Ok(s)) => s,
                _ => return,
            }
        };
        let _ = lock(&this.store).put_secret(SECRET_LOG_HEAD, &sealed.to_bytes());
    }

    /// Relay events -> activity log, one batch per wake-up.
    fn forward_relay_events(this: &Arc<Inner>, id: ProfileId, relay: &Relay) -> JoinHandle<()> {
        let mut rx = relay.events();
        let weak: Weak<Inner> = Arc::downgrade(this);
        tokio::spawn(async move {
            loop {
                let first = match rx.recv().await {
                    Ok(ev) => Some(ev),
                    Err(RecvError::Lagged(n)) => {
                        let Some(inner) = weak.upgrade() else { break };
                        Inner::log_batch(
                            &inner,
                            vec![(
                                now_ms(),
                                LogKind::BlockedEvent,
                                Some(id),
                                format!("{n} relay events dropped (log too slow)"),
                            )],
                        );
                        None
                    }
                    Err(RecvError::Closed) => break,
                };
                let mut batch: Vec<RelayEvent> = first.into_iter().collect();
                while let Ok(ev) = rx.try_recv() {
                    batch.push(ev);
                }
                let Some(inner) = weak.upgrade() else { break };
                let ts = now_ms();
                Inner::log_batch(
                    &inner,
                    batch
                        .into_iter()
                        .map(|ev| match ev {
                            RelayEvent::Blocked { target, reason } => (
                                ts,
                                LogKind::BlockedEvent,
                                Some(id),
                                format!("{reason}: {target}"),
                            ),
                            RelayEvent::Tripped { reason } => (
                                ts,
                                LogKind::KillSwitch,
                                Some(id),
                                format!("kill switch tripped: {reason}"),
                            ),
                            RelayEvent::Rearmed => (
                                ts,
                                LogKind::ProxyReconnect,
                                Some(id),
                                "proxy reachable again, kill switch re-armed".into(),
                            ),
                        })
                        .collect(),
                );
            }
        })
    }

    fn poll_status(this: &Arc<Inner>) -> Vec<StatusChange> {
        let ended = lock(&this.procs).poll_exits();
        let mut changes = Vec::new();
        for (id, code) in ended {
            let running = lock(&this.running).remove(&id);
            let requested = running.as_ref().is_some_and(|r| r.stop_requested);
            drop(running); // relay, job (kills leftovers) and config file go now
            let status = match code {
                _ if requested => ProfileStatus::Stopped,
                Some(0) => ProfileStatus::Stopped,
                Some(c)
                    if matches!(
                        EngineExit::from_code(c),
                        Some(EngineExit::BadConfigSignature | EngineExit::VersionMismatch)
                    ) =>
                {
                    ProfileStatus::Blocked
                }
                _ => ProfileStatus::Crashed,
            };
            let _ = lock(&this.store).set_status(id, status, now_ms());
            let (kind, detail) = match status {
                ProfileStatus::Stopped => (
                    LogKind::ProfileStop,
                    format!("engine exited (code {code:?})"),
                ),
                ProfileStatus::Blocked => (
                    LogKind::LaunchBlocked,
                    format!(
                        "engine refused its config: {}",
                        code.and_then(vanta_launcher::exit_reason).unwrap_or("?")
                    ),
                ),
                _ => (
                    LogKind::ProfileCrash,
                    format!("engine crashed (code {code:?})"),
                ),
            };
            Inner::log_batch(this, vec![(now_ms(), kind, Some(id), detail)]);
            changes.push(StatusChange {
                profile_id: id,
                status,
                exit_code: code,
            });
        }
        changes
    }
}

/// Where the app keeps a profile's launch config while it runs (for tests and support).
fn parse_seed(s: &str) -> CoreResult<u64> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.is_empty() || t.len() > 16 {
        return Err(CoreError::Invalid {
            message: format!("seed '{s}' is not a 64-bit hex value"),
        });
    }
    u64::from_str_radix(t, 16).map_err(|_| CoreError::Invalid {
        message: format!("seed '{s}' is not a 64-bit hex value"),
    })
}

fn fingerprint_view(p: &Persona, installed: EngineVersion) -> FingerprintView {
    use vanta_fingerprint::rules::{check, Level};
    FingerprintView {
        device_id: p.device_id.clone(),
        os: p.os,
        engine: p.engine.to_string(),
        user_agent: p.user_agent.clone(),
        sec_ch_ua: p.sec_ch_ua(),
        navigator_platform: p.platform.clone(),
        ua_platform: p.ua_ch.platform.clone(),
        platform_version: p.ua_ch.platform_version.clone(),
        architecture: p.ua_ch.architecture.clone(),
        bitness: p.ua_ch.bitness.clone(),
        screen_width: p.screen.width,
        screen_height: p.screen.height,
        avail_width: p.screen.avail_width,
        avail_height: p.screen.avail_height,
        color_depth: p.screen.color_depth,
        device_pixel_ratio: p.device_pixel_ratio,
        hardware_concurrency: p.hardware_concurrency,
        device_memory: p.device_memory,
        max_touch_points: p.max_touch_points,
        gpu_vendor: p.gpu.vendor.clone(),
        gpu_renderer: p.gpu.renderer.clone(),
        webgpu_vendor: p.gpu.webgpu_vendor.clone(),
        webgpu_arch: p.gpu.webgpu_arch.clone(),
        fonts: p.fonts.clone(),
        microphones: p.media_devices.audioinput,
        cameras: p.media_devices.videoinput,
        speakers: p.media_devices.audiooutput,
        locale: p.locale.clone(),
        languages: p.languages.clone(),
        accept_language: p.accept_language(),
        timezone: p.geo.as_ref().map(|g| g.timezone.clone()),
        country: p.geo.as_ref().map(|g| g.country.clone()),
        latitude: p.geo.as_ref().map(|g| g.latitude),
        longitude: p.geo.as_ref().map(|g| g.longitude),
        canvas: p.canvas,
        webgl_image: p.webgl_image,
        audio: p.audio,
        webrtc_policy: p.webrtc_policy.clone(),
        seed_prefix: format!("{:016X}", p.seed)[..4].to_string(),
        rules: check(p, installed)
            .into_iter()
            .map(|r| RuleView {
                id: r.id.to_string(),
                level: match r.level {
                    Level::Pass => "pass",
                    Level::Note => "note",
                    Level::Fail => "fail",
                }
                .into(),
                message: r.message,
            })
            .collect(),
    }
}

pub fn launch_config_path(data_dir: &Path, id: ProfileId) -> PathBuf {
    data_dir
        .join("run")
        .join(id.to_string())
        .join("launch.json")
}
