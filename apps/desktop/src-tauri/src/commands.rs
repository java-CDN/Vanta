//! Tauri commands: thin wrappers over `vanta_core::VantaApp`. Blocking work runs on the
//! blocking pool; the async core calls (launch, health run, proxy test) are driven there
//! too with `block_on`, so the IPC thread never waits on disk, Argon2 or the network.
//! Errors are `CoreError` values (serialized with a `kind` tag for the UI).

use crate::events;
use crate::settings::Settings;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use tauri::{AppHandle, Emitter, State};
use vanta_core::*;
use vanta_proxy::{DohProvider, GuardPolicy, ProxyScheme};
use vanta_store::ProfileMeta;
use vanta_types::{OsKind, ProfileId};
use vanta_vault::{AutoLock, LockEvent};
use zeroize::Zeroizing;

type R<T> = Result<T, CoreError>;

/// Everything the window shares. `app` is cheap to clone (shared state inside).
pub struct Shell {
    pub app: VantaApp,
    pub settings: Mutex<Settings>,
    pub settings_path: PathBuf,
    pub autolock: Mutex<AutoLock>,
    pub log_integrity: Mutex<Option<LogIntegrity>>,
    /// Last activity-log sequence number pushed to the UI.
    pub log_seq: Mutex<Option<u64>>,
    pub engine_path: PathBuf,
    pub data_dir: PathBuf,
}

pub fn held<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn join_err(e: impl std::fmt::Display) -> CoreError {
    CoreError::Storage {
        message: format!("background task failed: {e}"),
    }
}

/// Run blocking core work off the IPC thread.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> R<T> + Send + 'static) -> R<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(join_err)?
}

/// Drive an async core call on a blocking thread (inside the runtime context, so the
/// relay and health-lab tasks it spawns live on the app's runtime).
async fn drive<T, F, Fut>(app: VantaApp, f: F) -> R<T>
where
    T: Send + 'static,
    F: FnOnce(VantaApp) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = R<T>>,
{
    tauri::async_runtime::spawn_blocking(move || tauri::async_runtime::block_on(f(app)))
        .await
        .map_err(join_err)?
}

impl Shell {
    fn after_unlock(&self, r: &UnlockReport) {
        *held(&self.log_integrity) = Some(r.log_integrity.clone());
        *held(&self.log_seq) = None;
        held(&self.autolock).reset(now_ms());
    }
}

// ---- app & vault -------------------------------------------------------------------

#[derive(Serialize)]
pub struct AppInfo {
    app_version: String,
    initialized: bool,
    unlocked: bool,
    engine_version: String,
    engine_path: String,
    engine_found: bool,
    data_dir: String,
    log_integrity: Option<LogIntegrity>,
    mock: bool,
}

#[tauri::command]
pub fn app_info(app: AppHandle, s: State<'_, Shell>) -> AppInfo {
    AppInfo {
        app_version: app.package_info().version.to_string(),
        initialized: s.app.is_initialized(),
        unlocked: s.app.is_unlocked(),
        engine_version: s.app.config().engine.version.to_string(),
        engine_path: s.engine_path.display().to_string(),
        engine_found: s.engine_path.is_file(),
        data_dir: s.data_dir.display().to_string(),
        log_integrity: held(&s.log_integrity).clone(),
        mock: false,
    }
}

#[tauri::command]
pub async fn create_vault(s: State<'_, Shell>, password: String) -> R<VaultCreated> {
    let pw = Zeroizing::new(password);
    if pw.chars().count() < 12 {
        return Err(CoreError::Invalid {
            message: "use at least 12 characters for the master password".into(),
        });
    }
    let app = s.app.clone();
    let r = blocking(move || app.create_vault(&pw)).await?;
    s.after_unlock(&UnlockReport {
        log_integrity: LogIntegrity::Ok,
        migrated_proxies: 0,
    });
    Ok(r)
}

#[tauri::command]
pub async fn unlock(s: State<'_, Shell>, password: String) -> R<UnlockReport> {
    let pw = Zeroizing::new(password);
    let app = s.app.clone();
    let r = blocking(move || app.unlock(&pw)).await?;
    s.after_unlock(&r);
    Ok(r)
}

#[tauri::command]
pub async fn unlock_with_recovery(s: State<'_, Shell>, recovery_key: String) -> R<UnlockReport> {
    let key = Zeroizing::new(recovery_key);
    let app = s.app.clone();
    let r = blocking(move || app.unlock_with_recovery(key.trim())).await?;
    s.after_unlock(&r);
    Ok(r)
}

#[tauri::command]
pub async fn lock(s: State<'_, Shell>) -> R<()> {
    let app = s.app.clone();
    blocking(move || app.lock()).await
}

#[tauri::command]
pub async fn change_password(s: State<'_, Shell>, current: String, new_password: String) -> R<()> {
    let (cur, new) = (Zeroizing::new(current), Zeroizing::new(new_password));
    if new.chars().count() < 12 {
        return Err(CoreError::Invalid {
            message: "use at least 12 characters for the new master password".into(),
        });
    }
    let app = s.app.clone();
    blocking(move || app.change_password(&cur, &new)).await
}

// ---- profiles ----------------------------------------------------------------------

#[tauri::command]
pub async fn list_profiles(
    s: State<'_, Shell>,
    query: String,
    limit: usize,
    offset: usize,
) -> R<ProfilePage> {
    let app = s.app.clone();
    blocking(move || app.list_profiles(&query, limit, offset)).await
}

#[tauri::command]
pub async fn folders(s: State<'_, Shell>) -> R<Vec<(String, i64)>> {
    let app = s.app.clone();
    blocking(move || app.folders()).await
}

#[tauri::command]
pub async fn get_profile(s: State<'_, Shell>, id: ProfileId) -> R<ProfileDetail> {
    let app = s.app.clone();
    blocking(move || app.get_profile(id)).await
}

#[tauri::command]
pub async fn create_profile(s: State<'_, Shell>, profile: NewProfile) -> R<ProfileMeta> {
    let app = s.app.clone();
    blocking(move || app.create_profile(profile)).await
}

#[tauri::command]
pub async fn edit_profile(s: State<'_, Shell>, id: ProfileId, edit: ProfileEdit) -> R<ProfileMeta> {
    let app = s.app.clone();
    blocking(move || app.edit_profile(id, edit)).await
}

#[tauri::command]
pub async fn delete_profiles(s: State<'_, Shell>, ids: Vec<ProfileId>) -> R<usize> {
    let app = s.app.clone();
    blocking(move || app.delete_profiles(&ids)).await
}

#[tauri::command]
pub async fn fingerprint(s: State<'_, Shell>, id: ProfileId) -> R<FingerprintView> {
    let app = s.app.clone();
    blocking(move || app.fingerprint(id)).await
}

#[tauri::command]
pub async fn preview_fingerprint(
    s: State<'_, Shell>,
    os: Option<OsKind>,
    locale: Option<String>,
    seed: String,
) -> R<FingerprintView> {
    let app = s.app.clone();
    blocking(move || app.preview_fingerprint(os, locale.as_deref(), &seed)).await
}

#[tauri::command]
pub async fn regenerate_fingerprint(
    s: State<'_, Shell>,
    id: ProfileId,
    os: Option<OsKind>,
) -> R<ProfileMeta> {
    let app = s.app.clone();
    blocking(move || app.regenerate_fingerprint(id, os)).await
}

// ---- proxies -----------------------------------------------------------------------

#[tauri::command]
pub async fn list_proxies(s: State<'_, Shell>) -> R<Vec<ProxyView>> {
    let app = s.app.clone();
    blocking(move || app.list_proxies()).await
}

#[tauri::command]
pub async fn import_proxies(
    s: State<'_, Shell>,
    text: String,
    default_scheme: ProxyScheme,
) -> R<ImportResult> {
    // The pasted list holds passwords: wipe our copy when done.
    let text = Zeroizing::new(text);
    let app = s.app.clone();
    blocking(move || app.import_proxies(&text, default_scheme)).await
}

#[tauri::command]
pub async fn delete_proxy(s: State<'_, Shell>, proxy_id: String) -> R<()> {
    let app = s.app.clone();
    blocking(move || app.delete_proxy(&proxy_id)).await
}

#[tauri::command]
pub async fn assign_proxy(
    s: State<'_, Shell>,
    profile_id: ProfileId,
    proxy_id: Option<String>,
) -> R<AssignResult> {
    let app = s.app.clone();
    blocking(move || app.assign_proxy(profile_id, proxy_id.as_deref())).await
}

#[tauri::command]
pub async fn test_proxy(s: State<'_, Shell>, proxy_id: String) -> R<ProxyView> {
    drive(s.app.clone(), move |app| async move {
        app.test_proxy(&proxy_id).await
    })
    .await
}

// ---- launch & health ---------------------------------------------------------------

#[tauri::command]
pub async fn launch_profile(
    handle: AppHandle,
    s: State<'_, Shell>,
    id: ProfileId,
) -> R<LaunchInfo> {
    let r = drive(s.app.clone(), move |app| async move {
        app.launch_profile(id).await
    })
    .await;
    events::status_now(&handle, id, &r);
    r
}

#[tauri::command]
pub async fn stop_profile(handle: AppHandle, s: State<'_, Shell>, id: ProfileId) -> R<()> {
    let app = s.app.clone();
    blocking(move || app.stop_profile(id)).await?;
    let _ = handle.emit(
        events::STATUS,
        vec![StatusChange {
            profile_id: id,
            status: vanta_types::ProfileStatus::Stopped,
            exit_code: None,
        }],
    );
    Ok(())
}

#[tauri::command]
pub fn running_profiles(s: State<'_, Shell>) -> Vec<ProfileId> {
    s.app.running_profiles()
}

#[tauri::command]
pub async fn run_health(s: State<'_, Shell>, id: ProfileId) -> R<HealthResult> {
    drive(
        s.app.clone(),
        move |app| async move { app.run_health(id).await },
    )
    .await
}

// ---- network guard -----------------------------------------------------------------

#[tauri::command]
pub async fn guard_policy(s: State<'_, Shell>, id: ProfileId) -> R<GuardPolicy> {
    let app = s.app.clone();
    blocking(move || app.guard_policy(id)).await
}

#[tauri::command]
pub async fn set_doh_provider(
    s: State<'_, Shell>,
    id: ProfileId,
    doh: DohProvider,
) -> R<GuardPolicy> {
    let app = s.app.clone();
    blocking(move || app.set_doh_provider(id, doh)).await
}

// ---- activity log ------------------------------------------------------------------

#[tauri::command]
pub async fn activity_log(s: State<'_, Shell>, query: LogQuery) -> R<LogPage> {
    let app = s.app.clone();
    blocking(move || app.activity_log(&query)).await
}

// ---- settings, idle lock, quit -----------------------------------------------------

#[tauri::command]
pub fn get_settings(s: State<'_, Shell>) -> Settings {
    held(&s.settings).clone()
}

#[tauri::command]
pub fn set_settings(s: State<'_, Shell>, settings: Settings) -> R<Settings> {
    let mut settings = settings;
    settings.engine_path = settings
        .engine_path
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty());
    settings.validate()?;
    settings.save(&s.settings_path)?;
    {
        let mut al = held(&s.autolock);
        al.set_idle_minutes(settings.autolock_minutes);
        al.reset(now_ms());
    }
    *held(&s.settings) = settings.clone();
    Ok(settings)
}

/// Keyboard/mouse activity inside the window (the UI throttles it).
#[tauri::command]
pub fn report_activity(s: State<'_, Shell>) {
    held(&s.autolock).on_event(LockEvent::Activity { now_ms: now_ms() });
}

/// Exit: dropping the app closes every profile's Job Object, which ends its engine.
#[tauri::command]
pub fn quit_app(handle: AppHandle, s: State<'_, Shell>) {
    let _ = s.app.lock();
    handle.exit(0);
}
