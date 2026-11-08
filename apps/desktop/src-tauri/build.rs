/// Every command the UI may call (keep in sync with `src/commands.rs` and
/// `capabilities/default.json`). Each becomes an `allow-<command>` permission; the main
/// window gets exactly these, so no other command and no core window, fs or shell API is
/// reachable from the webview.
const COMMANDS: &[&str] = &[
    "app_info",
    "create_vault",
    "unlock",
    "unlock_with_recovery",
    "lock",
    "change_password",
    "list_profiles",
    "folders",
    "get_profile",
    "create_profile",
    "edit_profile",
    "delete_profiles",
    "fingerprint",
    "preview_fingerprint",
    "regenerate_fingerprint",
    "list_proxies",
    "import_proxies",
    "add_proxy",
    "edit_proxy",
    "preview_preset",
    "delete_proxy",
    "assign_proxy",
    "test_proxy",
    "inspect_proxy",
    "launch_profile",
    "stop_profile",
    "running_profiles",
    "run_health",
    "guard_policy",
    "set_doh_provider",
    "activity_log",
    "get_settings",
    "set_settings",
    "report_activity",
    "quit_app",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("tauri build");
}
