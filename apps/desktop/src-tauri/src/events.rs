//! Events pushed to the UI (names mirror `ui/src/api/tauri.ts` EVENTS) and the background
//! loops that produce them: engine status, new activity-log entries, idle auto-lock.

use crate::commands::{held, now_ms, Shell};
use serde::Serialize;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};
use vanta_core::{CoreError, LaunchInfo, LogQuery, StatusChange};
use vanta_types::{ProfileId, ProfileStatus};
use vanta_vault::{LockEvent, LockReason};

pub const STATUS: &str = "vanta://status";
pub const LOG: &str = "vanta://log";
pub const LOCKED: &str = "vanta://locked";
pub const CLOSE_REQUESTED: &str = "vanta://close-requested";

#[derive(Clone, Serialize)]
pub struct Locked {
    pub reason: &'static str,
}

#[derive(Clone, Serialize)]
pub struct CloseRequest {
    pub running: usize,
}

/// Status right after a launch attempt (the watcher only reports engines that ended).
pub fn status_now(h: &AppHandle, id: ProfileId, r: &Result<LaunchInfo, CoreError>) {
    let status = match r {
        Ok(_) => ProfileStatus::Running,
        Err(
            CoreError::Blocked { .. }
            | CoreError::BadConfigSignature
            | CoreError::VersionMismatch { .. },
        ) => ProfileStatus::Blocked,
        Err(_) => ProfileStatus::Stopped,
    };
    let _ = h.emit(
        STATUS,
        vec![StatusChange {
            profile_id: id,
            status,
            exit_code: None,
        }],
    );
}

/// Engine exits (crash, user closed the window, 86/87) → `running/stopped/crashed/blocked`
/// within a second.
async fn status_loop(h: AppHandle) {
    let mut tick = tokio_interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        let app = h.state::<Shell>().app.clone();
        let changes = tauri::async_runtime::spawn_blocking(move || app.poll_status())
            .await
            .unwrap_or_default();
        if !changes.is_empty() {
            let _ = h.emit(STATUS, changes);
        }
    }
}

/// New activity-log entries (relay blocks, kill switch, crashes…) while unlocked.
async fn log_loop(h: AppHandle) {
    let mut tick = tokio_interval(Duration::from_secs(2));
    loop {
        tick.tick().await;
        let s = h.state::<Shell>();
        if !s.app.is_unlocked() {
            continue;
        }
        let app = s.app.clone();
        let page = tauri::async_runtime::spawn_blocking(move || {
            app.activity_log(&LogQuery {
                limit: 50,
                ..Default::default()
            })
        })
        .await;
        let Ok(Ok(page)) = page else { continue };
        let newest = page.entries.first().map(|e| e.seq);
        let mut last = held(&s.log_seq);
        let fresh: Vec<_> = match *last {
            // First look after an unlock: remember where we are, push nothing.
            None => vec![],
            Some(seen) => page
                .entries
                .into_iter()
                .rev()
                .filter(|e| e.seq > seen)
                .collect(),
        };
        if newest.is_some() {
            *last = newest;
        } else if last.is_none() {
            *last = Some(0);
        }
        drop(last);
        if !fresh.is_empty() {
            let _ = h.emit(LOG, fresh);
        }
    }
}

/// Idle auto-lock (Settings › Security & vault). The UI reports activity; the timer runs
/// here so a stalled webview still locks.
async fn autolock_loop(h: AppHandle) {
    let mut tick = tokio_interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        let s = h.state::<Shell>();
        if !s.app.is_unlocked() {
            continue;
        }
        let due = held(&s.autolock).on_event(LockEvent::Tick { now_ms: now_ms() });
        if due == Some(LockReason::Idle) {
            let app = s.app.clone();
            let _ = tauri::async_runtime::spawn_blocking(move || app.lock()).await;
            let _ = h.emit(LOCKED, Locked { reason: "idle" });
        }
    }
}

fn tokio_interval(d: Duration) -> tokio::time::Interval {
    let mut i = tokio::time::interval(d);
    i.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    i
}

pub fn spawn_loops(h: &AppHandle) {
    tauri::async_runtime::spawn(status_loop(h.clone()));
    tauri::async_runtime::spawn(log_loop(h.clone()));
    tauri::async_runtime::spawn(autolock_loop(h.clone()));
}
