//! vanta-launcher (skeleton): the launch gate, the engine command line, real process
//! status, and a Job Object that kills every profile process when the app exits.
//!
//! - [`preflight`] decides whether a profile may launch: proxy online and freshly checked
//!   (F04), Network Guard relay armed (F05), consistency rules passed (F02), health score
//!   at least [`MIN_HEALTH_SCORE`] (F03). Any failure makes the profile `Blocked`.
//! - [`EngineLaunch`] builds the `vanta-chromium.exe` command line: signed config
//!   (`--vanta-config`, `--vanta-pubkey`), the relay as the only proxy, the WebRTC policy and
//!   QUIC off. It never adds `--remote-debugging-*` (no CDP, Master Plan v3).
//! - [`ProcessTable`] reports status from the real child process (never guessed), which is
//!   what `vanta-store::Store::set_status` is fed with. It holds any [`EngineProcess`]
//!   (a real [`Child`], or a test double).
//! - [`spawn_in_job`]: on Windows the engine is created `CREATE_SUSPENDED`, assigned to the
//!   profile's [`KillOnCloseJob`] and only then resumed, so not a single instruction of the
//!   engine (and no child it spawns) runs outside the job. Other hosts get an error.
//! - [`KillOnCloseJob`]: on Windows a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`;
//!   elsewhere (developer builds only) a no-op. Use one job per profile: it is also the
//!   profile's engine process tree for the relay's client check ([`JobAuthorizer`],
//!   [`relay_clients`]), since every child the engine spawns inherits the job.
//!
//! The orchestration (relay per launch, signed config, status watcher, activity log) lives
//! in `vanta-core`.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Arc;
use vanta_proxy::{AllowedClients, ClientAuthorizer, GuardPolicy, LaunchBlock, ProxyState};
use vanta_types::{exit_codes, ProfileId, ProfileStatus, Result, VantaError};

mod host_gpu;
pub use host_gpu::host_gpu_vendor_id;

/// A health score below this blocks launch (F03).
pub const MIN_HEALTH_SCORE: u8 = 60;

/// Everything the gate looks at for one profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preflight {
    pub proxy: ProxyState,
    /// Max age of the proxy check (see `vanta_proxy::state::MAX_CHECK_AGE_MS`).
    pub proxy_max_age_ms: i64,
    /// The profile's Network Guard relay is running and its kill switch is armed.
    pub relay_armed: bool,
    /// Rules C001–C030 have no Fail.
    pub rules_passed: bool,
    /// The profile's last health run (F03).
    pub health: HealthGate,
}

/// What the gate knows about the profile's last health run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthGate {
    /// A health report younger than the maximum age, for this engine and this proxy.
    Fresh { score: u8 },
    /// No health run yet (or it was invalidated by a proxy/fingerprint/engine change).
    Missing,
    /// The last report is older than the maximum age.
    Expired { age_ms: i64 },
    /// The launch *is* the health run; it cannot require one.
    NotRequired,
}

/// A health report older than this must be renewed before launch (7 days).
pub const HEALTH_MAX_AGE_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// One reason a launch is blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Block {
    Proxy(LaunchBlock),
    GuardNotArmed,
    RulesFailed,
    HealthTooLow { score: u8 },
    HealthMissing,
    HealthExpired { age_ms: i64 },
}

impl std::fmt::Display for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Block::Proxy(b) => b.fmt(f),
            Block::GuardNotArmed => f.write_str("launch blocked: Network Guard is not armed"),
            Block::RulesFailed => f.write_str("launch blocked: a consistency rule fails"),
            Block::HealthTooLow { score } => {
                write!(
                    f,
                    "launch blocked: health score {score} is below {MIN_HEALTH_SCORE}"
                )
            }
            Block::HealthMissing => {
                f.write_str("launch blocked: run a health check for this profile first")
            }
            Block::HealthExpired { age_ms } => write!(
                f,
                "launch blocked: last health check is {} days old, run it again",
                age_ms / 86_400_000
            ),
        }
    }
}

/// The launch gate. Returns every reason at once so the UI can list them.
pub fn preflight(p: &Preflight, now_ms: i64) -> std::result::Result<(), Vec<Block>> {
    let mut blocks = Vec::new();
    if let Err(b) = p.proxy.launch_gate(now_ms, p.proxy_max_age_ms) {
        blocks.push(Block::Proxy(b));
    }
    if !p.relay_armed {
        blocks.push(Block::GuardNotArmed);
    }
    if !p.rules_passed {
        blocks.push(Block::RulesFailed);
    }
    match p.health {
        HealthGate::Fresh { score } if score < MIN_HEALTH_SCORE => {
            blocks.push(Block::HealthTooLow { score })
        }
        HealthGate::Fresh { .. } | HealthGate::NotRequired => {}
        HealthGate::Missing => blocks.push(Block::HealthMissing),
        HealthGate::Expired { age_ms } => blocks.push(Block::HealthExpired { age_ms }),
    }
    if blocks.is_empty() {
        Ok(())
    } else {
        Err(blocks)
    }
}

/// Meaning of an engine exit code that Vanta defines (86/87/88).
pub fn exit_reason(code: i32) -> Option<&'static str> {
    match code {
        exit_codes::BAD_CONFIG_SIGNATURE => Some("launch config signature invalid"),
        exit_codes::VERSION_MISMATCH => Some("persona version does not match the engine (C030)"),
        exit_codes::ISOLATION_BROKEN => Some("profile isolation broken"),
        _ => None,
    }
}

/// Typed meaning of an engine exit code that Vanta defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineExit {
    BadConfigSignature,
    VersionMismatch,
    IsolationBroken,
}

impl EngineExit {
    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            exit_codes::BAD_CONFIG_SIGNATURE => Some(Self::BadConfigSignature),
            exit_codes::VERSION_MISMATCH => Some(Self::VersionMismatch),
            exit_codes::ISOLATION_BROKEN => Some(Self::IsolationBroken),
            _ => None,
        }
    }
}

/// Inputs for one engine start.
#[derive(Debug, Clone)]
pub struct EngineLaunch {
    pub engine_exe: PathBuf,
    pub user_data_dir: PathBuf,
    /// Signed config JSON written by `vanta-fingerprint`.
    pub config_path: PathBuf,
    /// Launcher Ed25519 public key, standard base64.
    pub pubkey_b64: String,
    /// `Relay::proxy_url()` of this profile's relay.
    pub relay_proxy_url: String,
    pub policy: GuardPolicy,
}

impl EngineLaunch {
    pub fn args(&self) -> Vec<OsString> {
        let mut a: Vec<OsString> = Vec::new();
        let mut kv = |k: &str, v: &std::path::Path| {
            let mut s = OsString::from(k);
            s.push(v.as_os_str());
            a.push(s);
        };
        kv("--user-data-dir=", &self.user_data_dir);
        kv("--vanta-config=", &self.config_path);
        a.push(format!("--vanta-pubkey={}", self.pubkey_b64).into());
        for x in self.policy.engine_args(&self.relay_proxy_url) {
            a.push(x.into());
        }
        a.push("--no-first-run".into());
        a.push("--no-default-browser-check".into());
        a
    }

    pub fn command(&self) -> Command {
        let mut c = Command::new(&self.engine_exe);
        c.args(self.args());
        c
    }
}

/// A running engine process: a real [`Child`] in production, a double in tests.
pub trait EngineProcess: Send {
    fn pid(&self) -> u32;
    /// `Ok(None)` while running, `Ok(Some(code))` once it ended (`None` code = killed by a
    /// signal / no code).
    fn try_exit(&mut self) -> std::io::Result<Option<Option<i32>>>;
    /// Terminate it (the profile's job also goes when its handle closes).
    fn kill(&mut self) -> std::io::Result<()>;
    /// Wait for it to end.
    fn wait_exit(&mut self) -> std::io::Result<Option<i32>>;
}

impl EngineProcess for Child {
    fn pid(&self) -> u32 {
        self.id()
    }
    fn try_exit(&mut self) -> std::io::Result<Option<Option<i32>>> {
        Ok(self.try_wait()?.map(|st| st.code()))
    }
    fn kill(&mut self) -> std::io::Result<()> {
        Child::kill(self)
    }
    fn wait_exit(&mut self) -> std::io::Result<Option<i32>> {
        Ok(self.wait()?.code())
    }
}

/// Live profile processes. Status is read from the OS, never assumed.
#[derive(Default)]
pub struct ProcessTable {
    procs: HashMap<ProfileId, Box<dyn EngineProcess>>,
    blocked: HashSet<ProfileId>,
}

impl ProcessTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Track a started engine process.
    pub fn insert(&mut self, id: ProfileId, child: impl EngineProcess + 'static) {
        self.insert_boxed(id, Box::new(child));
    }

    pub fn insert_boxed(&mut self, id: ProfileId, child: Box<dyn EngineProcess>) {
        self.blocked.remove(&id);
        self.procs.insert(id, child);
    }

    /// Record that the gate blocked this profile.
    pub fn mark_blocked(&mut self, id: ProfileId) {
        self.blocked.insert(id);
    }

    pub fn clear_blocked(&mut self, id: ProfileId) {
        self.blocked.remove(&id);
    }

    /// Whether a live process is tracked for `id` (without reaping it).
    pub fn contains(&self, id: ProfileId) -> bool {
        self.procs.contains_key(&id)
    }

    /// PID of the profile's engine, if tracked.
    pub fn pid(&self, id: ProfileId) -> Option<u32> {
        self.procs.get(&id).map(|p| p.pid())
    }

    /// Current status. An exited process is removed and reported `Stopped`.
    pub fn status(&mut self, id: ProfileId) -> ProfileStatus {
        if let Some(child) = self.procs.get_mut(&id) {
            match child.try_exit() {
                Ok(None) => return ProfileStatus::Running,
                _ => {
                    self.procs.remove(&id);
                }
            }
        }
        if self.blocked.contains(&id) {
            ProfileStatus::Blocked
        } else {
            ProfileStatus::Stopped
        }
    }

    /// Reap exited processes: `(profile, exit code)` for each one that ended.
    pub fn poll_exits(&mut self) -> Vec<(ProfileId, Option<i32>)> {
        let mut ended = Vec::new();
        self.procs.retain(|id, child| match child.try_exit() {
            Ok(None) => true,
            Ok(Some(code)) => {
                ended.push((*id, code));
                false
            }
            Err(_) => {
                ended.push((*id, None));
                false
            }
        });
        ended
    }

    /// Kill a profile's process and wait for it.
    pub fn stop(&mut self, id: ProfileId) -> Result<()> {
        let mut child = self
            .procs
            .remove(&id)
            .ok_or_else(|| VantaError::NotFound(format!("running profile {id}")))?;
        let _ = child.kill();
        child
            .wait_exit()
            .map(|_| ())
            .map_err(|e| VantaError::Storage(format!("wait for profile process: {e}")))
    }

    pub fn running(&self) -> impl Iterator<Item = ProfileId> + '_ {
        self.procs.keys().copied()
    }
}

#[cfg(windows)]
mod job {
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;
    use vanta_types::{Result, VantaError};
    use windows_sys::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    /// Spawn `cmd` suspended, put it in `job`, then resume its (only) thread. On any
    /// failure the child is killed and never runs.
    pub fn spawn_in_job(mut cmd: std::process::Command, job: &KillOnCloseJob) -> Result<Child> {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
        cmd.creation_flags(CREATE_SUSPENDED);
        let mut child = cmd
            .spawn()
            .map_err(|e| VantaError::Storage(format!("start engine: {e}")))?;
        let fail = |child: &mut Child, e: VantaError| {
            let _ = child.kill();
            let _ = child.wait();
            e
        };
        if let Err(e) = job.assign(&child) {
            return Err(fail(&mut child, e));
        }
        if let Err(e) = resume_threads(child.id()) {
            return Err(fail(&mut child, e));
        }
        Ok(child)
    }

    /// Resume every thread of `pid` (a process created suspended has exactly one).
    fn resume_threads(pid: u32) -> Result<()> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows_sys::Win32::System::Threading::{
            OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
        };
        // SAFETY: a system-wide thread snapshot; the handle is checked and closed below.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return Err(last_error("CreateToolhelp32Snapshot"));
        }
        // SAFETY: zeroed THREADENTRY32 with dwSize set is what Thread32First expects.
        let mut te: THREADENTRY32 = unsafe { std::mem::zeroed() };
        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut resumed = 0;
        let mut err = None;
        // SAFETY: `snap` is a valid snapshot handle and `te` a writable entry.
        let mut more = unsafe { Thread32First(snap, &mut te) } != 0;
        while more {
            if te.th32OwnerProcessID == pid {
                // SAFETY: plain thread id; a null result is handled.
                let th = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, te.th32ThreadID) };
                if th.is_null() {
                    err = Some(last_error("OpenThread"));
                } else {
                    // SAFETY: `th` is a valid thread handle we opened and close once.
                    let prev = unsafe { ResumeThread(th) };
                    unsafe { CloseHandle(th) };
                    if prev == u32::MAX {
                        err = Some(last_error("ResumeThread"));
                    } else {
                        resumed += 1;
                    }
                }
            }
            // SAFETY: as above.
            more = unsafe { Thread32Next(snap, &mut te) } != 0;
        }
        // SAFETY: we own the snapshot handle and close it once.
        unsafe { CloseHandle(snap) };
        match (resumed, err) {
            (0, Some(e)) => Err(e),
            (0, None) => Err(VantaError::Storage(format!(
                "engine process {pid} has no thread to resume"
            ))),
            _ => Ok(()),
        }
    }

    /// Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: when the app exits (or this
    /// value is dropped) Windows terminates every process assigned to it.
    pub struct KillOnCloseJob(HANDLE);

    // SAFETY: a job handle may be used and closed from any thread.
    unsafe impl Send for KillOnCloseJob {}
    unsafe impl Sync for KillOnCloseJob {}

    fn last_error(what: &str) -> VantaError {
        VantaError::Storage(format!("{what}: {}", std::io::Error::last_os_error()))
    }

    impl KillOnCloseJob {
        pub fn new() -> Result<Self> {
            // SAFETY: null attributes and name create an anonymous job.
            let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if h.is_null() {
                return Err(last_error("CreateJobObjectW"));
            }
            let job = Self(h);
            // SAFETY: a zeroed JOBOBJECT_EXTENDED_LIMIT_INFORMATION is valid; we pass its
            // exact size.
            let ok = unsafe {
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const std::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if ok == 0 {
                return Err(last_error("SetInformationJobObject"));
            }
            Ok(job)
        }

        pub fn assign(&self, child: &Child) -> Result<()> {
            // SAFETY: both handles are valid for the duration of the call.
            let ok = unsafe { AssignProcessToJobObject(self.0, child.as_raw_handle() as HANDLE) };
            if ok == 0 {
                return Err(last_error("AssignProcessToJobObject"));
            }
            Ok(())
        }

        /// Whether process `pid` is in this job (`IsProcessInJob`). A process that cannot
        /// be opened (gone, or no access) is reported as not in the job.
        pub fn contains_pid(&self, pid: u32) -> bool {
            // SAFETY: OpenProcess with a plain PID; a null result is handled.
            let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
            if h.is_null() {
                return false;
            }
            let mut inside: BOOL = 0;
            // SAFETY: `h` and the job handle are valid; `inside` is a writable BOOL.
            let ok = unsafe { IsProcessInJob(h, self.0, &mut inside) };
            // SAFETY: we opened `h` above and close it once.
            unsafe { CloseHandle(h) };
            ok != 0 && inside != 0
        }
    }

    impl Drop for KillOnCloseJob {
        fn drop(&mut self) {
            // SAFETY: we own the handle and close it once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(not(windows))]
mod job {
    use std::process::Child;
    use vanta_types::{Result, VantaError};

    /// Engines run on Windows only: elsewhere there is no suspended start and no Job
    /// Object, so launching is refused instead of running the engine unconfined.
    pub fn spawn_in_job(_cmd: std::process::Command, _job: &KillOnCloseJob) -> Result<Child> {
        Err(VantaError::Invalid(
            "the engine can only be launched on Windows (suspended start + Job Object)".into(),
        ))
    }

    /// Developer builds on non-Windows hosts: no Job Objects, nothing is enforced.
    /// Vanta ships for Windows only, where the real implementation is used.
    pub struct KillOnCloseJob(());

    impl KillOnCloseJob {
        pub fn new() -> Result<Self> {
            Ok(Self(()))
        }

        pub fn assign(&self, _child: &Child) -> Result<()> {
            Ok(())
        }

        /// No Job Objects here: membership is unknown, reported as not in the job.
        pub fn contains_pid(&self, _pid: u32) -> bool {
            false
        }
    }
}

pub use job::{spawn_in_job, KillOnCloseJob};

/// [`ClientAuthorizer`] backed by a profile's Job Object: a relay client is accepted only
/// when its owning process is in the job (the engine and every process it spawned).
#[derive(Clone)]
pub struct JobAuthorizer {
    job: Arc<KillOnCloseJob>,
}

impl JobAuthorizer {
    pub fn new(job: Arc<KillOnCloseJob>) -> Self {
        Self { job }
    }
}

impl ClientAuthorizer for JobAuthorizer {
    fn allow(&self, pid: u32) -> bool {
        self.job.contains_pid(pid)
    }
}

/// The relay client policy for a profile: on Windows only processes in the profile's job
/// may use its relay, and a client whose PID cannot be found is refused. Pass the result to
/// `vanta_proxy::RelayConfig::with_clients`.
pub fn relay_clients(job: Arc<KillOnCloseJob>) -> AllowedClients {
    AllowedClients::process_tree(Arc::new(JobAuthorizer::new(job)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    use vanta_proxy::OfflineReason;

    const NOW: i64 = 1_800_000_000_000;

    fn good() -> Preflight {
        Preflight {
            proxy: ProxyState::Online {
                checked_ms: NOW - 1000,
                latency_ms: 50,
            },
            proxy_max_age_ms: 300_000,
            relay_armed: true,
            rules_passed: true,
            health: HealthGate::Fresh { score: 90 },
        }
    }

    #[test]
    fn gate_passes_when_everything_is_green() {
        assert_eq!(preflight(&good(), NOW), Ok(()));
        let health_run = Preflight {
            health: HealthGate::NotRequired,
            ..good()
        };
        assert_eq!(preflight(&health_run, NOW), Ok(()));
    }

    #[test]
    fn missing_or_expired_health_blocks() {
        let p = Preflight {
            health: HealthGate::Missing,
            ..good()
        };
        assert_eq!(preflight(&p, NOW), Err(vec![Block::HealthMissing]));
        let p = Preflight {
            health: HealthGate::Expired {
                age_ms: 8 * 86_400_000,
            },
            ..good()
        };
        let b = preflight(&p, NOW).unwrap_err();
        assert!(b[0].to_string().contains("8 days"), "{}", b[0]);
    }

    #[test]
    fn exit_codes_are_typed() {
        assert_eq!(
            EngineExit::from_code(86),
            Some(EngineExit::BadConfigSignature)
        );
        assert_eq!(EngineExit::from_code(87), Some(EngineExit::VersionMismatch));
        assert_eq!(EngineExit::from_code(88), Some(EngineExit::IsolationBroken));
        assert_eq!(EngineExit::from_code(1), None);
    }

    #[test]
    fn offline_proxy_blocks_launch() {
        let p = Preflight {
            proxy: ProxyState::Offline {
                checked_ms: NOW,
                reason: OfflineReason::Unreachable,
            },
            ..good()
        };
        assert_eq!(
            preflight(&p, NOW),
            Err(vec![Block::Proxy(LaunchBlock::ProxyOffline(
                OfflineReason::Unreachable
            ))])
        );
    }

    #[test]
    fn every_reason_is_listed() {
        let p = Preflight {
            proxy: ProxyState::Unknown,
            proxy_max_age_ms: 300_000,
            relay_armed: false,
            rules_passed: false,
            health: HealthGate::Fresh { score: 59 },
        };
        let b = preflight(&p, NOW).unwrap_err();
        assert_eq!(
            b,
            vec![
                Block::Proxy(LaunchBlock::ProxyUnchecked),
                Block::GuardNotArmed,
                Block::RulesFailed,
                Block::HealthTooLow { score: 59 }
            ]
        );
        assert!(b[3].to_string().contains("below 60"));
    }

    #[test]
    fn exit_codes_explained() {
        assert!(exit_reason(87).unwrap().contains("C030"));
        assert!(exit_reason(86).is_some() && exit_reason(88).is_some());
        assert_eq!(exit_reason(0), None);
    }

    #[test]
    fn engine_args_have_relay_and_no_cdp() {
        let l = EngineLaunch {
            engine_exe: "vanta-chromium.exe".into(),
            user_data_dir: "profiles/p1".into(),
            config_path: "profiles/p1/config.json".into(),
            pubkey_b64: "AAAA".into(),
            relay_proxy_url: "socks5://127.0.0.1:40001".into(),
            policy: GuardPolicy::default(),
        };
        let args: Vec<String> = l
            .args()
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        assert!(args.contains(&"--proxy-server=socks5://127.0.0.1:40001".to_string()));
        assert!(args.contains(&"--vanta-pubkey=AAAA".to_string()));
        assert!(args.iter().any(|a| a.starts_with("--vanta-config=")));
        assert!(args
            .iter()
            .any(|a| a == "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"));
        assert!(!args.iter().any(|a| a.contains("remote-debugging")));
        assert_eq!(l.command().get_args().count(), args.len());
    }

    fn long_running() -> Command {
        let mut c = if cfg!(windows) {
            let mut c = Command::new("ping");
            c.args(["-n", "30", "127.0.0.1"]);
            c
        } else {
            let mut c = Command::new("sleep");
            c.arg("30");
            c
        };
        c.stdout(Stdio::null()).stderr(Stdio::null());
        c
    }

    #[test]
    fn status_follows_the_real_process() {
        let id = ProfileId::new();
        let mut t = ProcessTable::new();
        assert_eq!(t.status(id), ProfileStatus::Stopped);
        t.mark_blocked(id);
        assert_eq!(t.status(id), ProfileStatus::Blocked);
        t.insert(id, long_running().spawn().unwrap());
        assert_eq!(t.status(id), ProfileStatus::Running);
        assert_eq!(t.running().count(), 1);
        t.stop(id).unwrap();
        assert_eq!(t.status(id), ProfileStatus::Stopped);
        assert!(t.stop(id).is_err());
    }

    #[test]
    fn poll_reports_exits() {
        let id = ProfileId::new();
        let mut t = ProcessTable::new();
        let quick = if cfg!(windows) {
            let mut c = Command::new("cmd");
            c.args(["/C", "exit 87"]);
            c
        } else {
            let mut c = Command::new("sh");
            c.args(["-c", "exit 87"]);
            c
        };
        t.insert(id, { quick }.spawn().unwrap());
        let start = Instant::now();
        loop {
            let ended = t.poll_exits();
            if !ended.is_empty() {
                assert_eq!(ended, vec![(id, Some(87))]);
                break;
            }
            assert!(start.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(t.status(id), ProfileStatus::Stopped);
    }

    #[test]
    fn job_authorizer_accepts_only_job_members() {
        let job = Arc::new(KillOnCloseJob::new().unwrap());
        let auth = JobAuthorizer::new(job.clone());
        // This test process was never assigned to the job.
        assert!(!auth.allow(std::process::id()));
        let mut child = long_running().spawn().unwrap();
        job.assign(&child).unwrap();
        // Membership is real on Windows; non-Windows hosts have no jobs and say no.
        assert_eq!(auth.allow(child.id()), cfg!(windows));
        assert!(!auth.allow(0xFFFF_FFF0), "unknown PIDs are never members");
        let _ = child.kill();
        let _ = child.wait();
        assert!(matches!(
            relay_clients(job),
            AllowedClients::ProcessTree {
                unknown: vanta_proxy::UnknownPid::Deny,
                ..
            }
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn spawn_in_job_is_refused_off_windows() {
        let job = KillOnCloseJob::new().unwrap();
        let e = spawn_in_job(long_running(), &job).unwrap_err();
        assert!(e.to_string().contains("Windows"), "{e}");
    }

    /// The fix for the child-process race: the engine is created suspended, put into the
    /// job, then resumed. `cmd /c ping` must therefore have its grandchild (ping) in the job
    /// too, and the whole tree must die when the job handle closes.
    #[cfg(windows)]
    #[test]
    fn suspended_spawn_puts_child_and_grandchild_in_the_job() {
        let job = Arc::new(KillOnCloseJob::new().unwrap());
        let mut cmd = Command::new("cmd.exe");
        cmd.args(["/c", "ping -n 3 127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = spawn_in_job(cmd, &job).unwrap();
        assert!(job.contains_pid(child.id()), "child is in the job");
        // The grandchild (ping.exe) is started by cmd after the resume.
        let start = Instant::now();
        let grandchild = loop {
            if let Some(pid) = winproc::child_of(child.id(), "ping.exe") {
                break pid;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "ping.exe never started"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(job.contains_pid(grandchild), "grandchild inherited the job");
        drop(job); // closes the handle: kill-on-close ends the whole tree
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            assert!(start.elapsed() < Duration::from_secs(10), "tree not killed");
            std::thread::sleep(Duration::from_millis(20));
        }
        let start = Instant::now();
        while winproc::alive(grandchild) {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "grandchild survived"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[cfg(windows)]
    #[test]
    fn suspended_spawn_runs_the_program_to_completion() {
        let job = KillOnCloseJob::new().unwrap();
        let mut cmd = Command::new("cmd.exe");
        cmd.args(["/c", "exit 87"]);
        let mut child = spawn_in_job(cmd, &job).unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(87), "resumed and ran");
    }

    #[cfg(windows)]
    mod winproc {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        /// PID of a live child of `parent` whose image name is `exe` (case-insensitive).
        pub fn child_of(parent: u32, exe: &str) -> Option<u32> {
            procs()
                .into_iter()
                .find(|(_, ppid, name)| *ppid == parent && name.eq_ignore_ascii_case(exe))
                .map(|(pid, _, _)| pid)
        }

        pub fn alive(pid: u32) -> bool {
            procs().iter().any(|(p, _, _)| *p == pid)
        }

        fn procs() -> Vec<(u32, u32, String)> {
            let mut out = Vec::new();
            // SAFETY: process snapshot; handle checked and closed below.
            let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
            if snap == INVALID_HANDLE_VALUE {
                return out;
            }
            // SAFETY: zeroed entry with dwSize set, as Process32FirstW requires.
            let mut pe: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
            pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            // SAFETY: valid snapshot and writable entry.
            let mut more = unsafe { Process32FirstW(snap, &mut pe) } != 0;
            while more {
                let len = pe.szExeFile.iter().position(|c| *c == 0).unwrap_or(0);
                let name = String::from_utf16_lossy(&pe.szExeFile[..len]);
                out.push((pe.th32ProcessID, pe.th32ParentProcessID, name));
                // SAFETY: as above.
                more = unsafe { Process32NextW(snap, &mut pe) } != 0;
            }
            // SAFETY: we own the snapshot handle.
            unsafe { CloseHandle(snap) };
            out
        }
    }

    #[test]
    fn job_kills_assigned_process_on_drop() {
        let mut child = long_running().spawn().unwrap();
        {
            let job = KillOnCloseJob::new().unwrap();
            job.assign(&child).unwrap();
        } // the job handle closes here
        if cfg!(windows) {
            let start = Instant::now();
            while child.try_wait().unwrap().is_none() {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "job did not kill the process"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        } else {
            // No Job Objects here: the process is still ours to clean up.
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
