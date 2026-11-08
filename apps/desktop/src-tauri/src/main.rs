//! Vanta desktop shell (Tauri 2). The window shows `ui/` and talks to `vanta_core::VantaApp`
//! only through the commands in `commands.rs`. No updater, no telemetry, no remote content,
//! one instance per user.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod events;
mod paths;
mod settings;

use commands::{now_ms, Shell};
use std::sync::Mutex;
use tauri::{Emitter, Manager, WindowEvent};
use vanta_core::{verify_engine_dir, AppConfig, Deps, EngineCheck, EngineInfo, VantaApp};
use vanta_vault::AutoLock;

fn open_shell(handle: &tauri::AppHandle) -> Result<Shell, Box<dyn std::error::Error>> {
    let local = paths::local_app_data(|| {
        handle
            .path()
            .local_data_dir()
            .unwrap_or_else(|_| std::env::temp_dir())
    });
    let data_dir = local.join("Vanta");
    std::fs::create_dir_all(&data_dir)?;
    let settings_path = data_dir.join("settings.json");
    let settings = settings::Settings::load(&settings_path);
    let resource_dir = handle.path().resource_dir().ok();
    let engine_path = paths::choose_engine(
        settings.engine_path.as_deref(),
        &local,
        resource_dir.as_deref(),
    );
    let engine = EngineInfo {
        exe: engine_path.clone(),
        version: paths::engine_version(&engine_path),
    };
    let mut cfg = AppConfig::new(&data_dir, engine);
    cfg.ip_echo_url = settings.echo_url();
    cfg.ip_info_url = settings.info_url();
    cfg.speed_test_url = settings.speed_url();
    let app = VantaApp::open(cfg, Deps::production()).map_err(|e| e.to_string())?;
    check_engine(&app, &engine_path);
    Ok(Shell {
        app,
        autolock: Mutex::new(AutoLock::new(settings.autolock_minutes, now_ms())),
        settings: Mutex::new(settings),
        settings_path,
        log_integrity: Mutex::new(None),
        log_seq: Mutex::new(None),
        engine_path,
        data_dir,
    })
}

/// An engine shipped with the installer has a `SHA256SUMS` next to it: check every listed
/// file in the background (the engine is a few hundred MB) and refuse launches until the
/// check has passed. Without `SHA256SUMS` nothing changes.
fn check_engine(app: &VantaApp, exe: &std::path::Path) {
    let Some(dir) = exe.parent().map(|d| d.to_path_buf()) else {
        return;
    };
    if !dir.join(vanta_core::engine_check::ENGINE_SUMS).is_file() {
        return;
    }
    app.set_engine_check(EngineCheck::Pending);
    let app = app.clone();
    std::thread::spawn(move || app.set_engine_check(verify_engine_dir(&dir)));
}

fn main() {
    tauri::Builder::default()
        // First: a second start focuses the running window instead (one vault, one owner).
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .setup(|app| {
            let shell = open_shell(app.handle())?;
            app.manage(shell);
            events::spawn_loops(app.handle());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let running = window.state::<Shell>().app.running_profiles().len();
                if running > 0 {
                    // The UI asks first; `quit_app` exits, which ends every engine.
                    api.prevent_close();
                    let _ = window.emit(events::CLOSE_REQUESTED, events::CloseRequest { running });
                } else {
                    let _ = window.state::<Shell>().app.lock();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::create_vault,
            commands::unlock,
            commands::unlock_with_recovery,
            commands::lock,
            commands::change_password,
            commands::list_profiles,
            commands::folders,
            commands::get_profile,
            commands::create_profile,
            commands::edit_profile,
            commands::delete_profiles,
            commands::fingerprint,
            commands::preview_fingerprint,
            commands::regenerate_fingerprint,
            commands::list_proxies,
            commands::import_proxies,
            commands::add_proxy,
            commands::edit_proxy,
            commands::preview_preset,
            commands::delete_proxy,
            commands::assign_proxy,
            commands::test_proxy,
            commands::inspect_proxy,
            commands::launch_profile,
            commands::stop_profile,
            commands::running_profiles,
            commands::run_health,
            commands::guard_policy,
            commands::set_doh_provider,
            commands::activity_log,
            commands::get_settings,
            commands::set_settings,
            commands::report_activity,
            commands::quit_app,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Vanta");
}
