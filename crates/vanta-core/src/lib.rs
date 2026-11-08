//! vanta-core: the orchestration layer the Tauri shell calls ([`VantaApp`]).
//!
//! It wires the other crates together; it adds no new security mechanism of its own.
//!
//! **Launch** ([`VantaApp::launch_profile`]):
//! 1. load the profile; open its sealed config with the profile key (vault);
//! 2. open the proxy password from the vault (the store keeps only a reference);
//! 3. `Persona::bind_engine` to the installed engine version (R5, C030);
//! 4. check the proxy when its last check is not fresh (F04);
//! 5. start the profile's relay on `127.0.0.1:<random>` with its `GuardPolicy`, the
//!    fail-closed kill switch and `AllowedClients::process_tree(JobAuthorizer)` over a new
//!    per-profile `KillOnCloseJob` (F05);
//! 6. run the gate (`vanta_launcher::preflight`): proxy, relay armed, rules C001–C030, and
//!    the last health report (missing, expired, other engine or other proxy = blocked);
//! 7. sign the launch config (Ed25519 key sealed in the vault; persona + relay port, in
//!    the format engine patch 0002 verifies) and write it for `--vanta-config`;
//! 8. start the engine `CREATE_SUSPENDED`, assign it to the job, resume it
//!    (`vanta_launcher::spawn_in_job`); exits 86/87 in the start-up window become
//!    [`CoreError::BadConfigSignature`] / [`CoreError::VersionMismatch`];
//! 9. after [`MAX_FAILED_LAUNCHES`] failed launches in a row (gate block, exit 86/87, end in
//!    the start-up window) the next one needs the user's confirmation
//!    ([`CoreError::ConfirmRequired`], [`VantaApp::launch_profile_confirmed`]); a successful
//!    launch resets the count.
//!
//! **Status**: [`VantaApp::poll_status`] (or [`VantaApp::spawn_status_watcher`]) reaps
//! engines and writes `running/stopped/crashed/blocked` to the store. Dropping the app
//! closes every job, which kills every engine process.
//!
//! **Activity log**: launches, stops, crashes, blocks, health runs, proxy failures and
//! every relay event (blocked request, kill switch, reconnect) go to `vanta-log`. After
//! each batch the log head is sealed into the vault; each unlock verifies it
//! ([`LogIntegrity`]), which catches entries cut from the end.
//!
//! **Health** ([`VantaApp::run_health`]): measure the exit IP through the profile's proxy
//! and the PC's own addresses (for comparison only; [`IpEcho`]), health lab, the same
//! launch flow with the lab's switches, collect, score, store the summary, log it.
//!
//! Test seams: [`EngineSpawner`] (the engine process), [`NetFactory`] (DoH), [`IpEcho`]
//! (exit and host IP) and, in this crate's own tests only, a custom relay client policy. Release builds can only use
//! [`RelayClients::ProcessTree`].

mod app;
mod deps;
mod dto;
mod error;

pub use app::{
    launch_config_path, AppConfig, EngineInfo, VantaApp, MAX_FAILED_LAUNCHES, SECRET_LOG_HEAD,
    SECRET_SIGNING_KEY,
};
pub use deps::{
    Deps, DohNet, EngineSpawner, HttpsIpEcho, IpEcho, NetFactory, OsSpawner, RelayClients,
};
pub use dto::*;
pub use error::{BlockReason, CoreError, CoreResult};

#[cfg(test)]
mod tests;
