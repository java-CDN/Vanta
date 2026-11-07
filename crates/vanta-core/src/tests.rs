//! End-to-end tests of the orchestration with in-process doubles only: a mock engine that
//! performs exactly the checks of engine patch 0002, a mock SOCKS5 upstream with a login,
//! a mock DoH resolver and an injected PID lookup. No outbound network.

use crate::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::HashSet;
use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use vanta_launcher::{EngineProcess, KillOnCloseJob};
use vanta_log::LogKind;
use vanta_proxy::doh::BoxFuture;
use vanta_proxy::net::NetResult;
use vanta_proxy::{
    AllowedClients, GuardPolicy, PidLookup, ProxyEndpoint, ProxyScheme, ProxyState, Resolver,
    UnknownPid,
};
use vanta_store::HealthSummary;
use vanta_types::{EngineVersion, ProfileId, ProfileStatus};
use vanta_vault::KdfParams;

const ENGINE: EngineVersion = EngineVersion::new(156, 0, 8078, 79);
const USER: &str = "alice";
const PASSWORD: &str = "S3cret-Proxy-Passw0rd-7781";

// ---- mock SOCKS5 upstream (RFC 1928 + RFC 1929 login) ---------------------------------

struct Upstream {
    addr: SocketAddr,
    targets: Arc<Mutex<Vec<String>>>,
    logins: Arc<Mutex<Vec<(String, String)>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn upstream(user: &'static str, pass: &'static str) -> Upstream {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = l.local_addr().unwrap();
    let targets = Arc::new(Mutex::new(Vec::new()));
    let logins = Arc::new(Mutex::new(Vec::new()));
    let (t, lg) = (targets.clone(), logins.clone());
    let task = tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { break };
            let (t, lg) = (t.clone(), lg.clone());
            tokio::spawn(async move {
                let _ = serve_socks(s, user, pass, t, lg).await;
            });
        }
    });
    Upstream {
        addr,
        targets,
        logins,
        task,
    }
}

async fn serve_socks(
    mut s: TcpStream,
    user: &str,
    pass: &str,
    targets: Arc<Mutex<Vec<String>>>,
    logins: Arc<Mutex<Vec<(String, String)>>>,
) -> std::io::Result<()> {
    let mut h = [0u8; 2];
    s.read_exact(&mut h).await?;
    let mut m = vec![0u8; h[1] as usize];
    s.read_exact(&mut m).await?;
    if !m.contains(&2) {
        s.write_all(&[5, 0xFF]).await?;
        return Ok(());
    }
    s.write_all(&[5, 2]).await?;
    let mut v = [0u8; 2];
    s.read_exact(&mut v).await?;
    let mut u = vec![0u8; v[1] as usize];
    s.read_exact(&mut u).await?;
    let mut pl = [0u8; 1];
    s.read_exact(&mut pl).await?;
    let mut p = vec![0u8; pl[0] as usize];
    s.read_exact(&mut p).await?;
    let (u, p) = (
        String::from_utf8_lossy(&u).into_owned(),
        String::from_utf8_lossy(&p).into_owned(),
    );
    let ok = u == user && p == pass;
    logins.lock().unwrap().push((u, p));
    s.write_all(&[1, if ok { 0 } else { 1 }]).await?;
    if !ok {
        return Ok(());
    }
    let mut r = [0u8; 4];
    if s.read_exact(&mut r).await.is_err() {
        return Ok(()); // heartbeat: login only
    }
    let target = match r[3] {
        1 => {
            let mut a = [0u8; 6];
            s.read_exact(&mut a).await?;
            format!(
                "{}:{}",
                Ipv4Addr::new(a[0], a[1], a[2], a[3]),
                u16::from_be_bytes([a[4], a[5]])
            )
        }
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut n = vec![0u8; l[0] as usize + 2];
            s.read_exact(&mut n).await?;
            let port = u16::from_be_bytes([n[n.len() - 2], n[n.len() - 1]]);
            format!("{}:{port}", String::from_utf8_lossy(&n[..n.len() - 2]))
        }
        _ => return Ok(()),
    };
    targets.lock().unwrap().push(target);
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let (mut rd, mut wr) = s.into_split();
    tokio::io::copy(&mut rd, &mut wr).await?;
    Ok(())
}

// ---- mock resolver ---------------------------------------------------------------------

struct MockDoh;
impl Resolver for MockDoh {
    fn resolve<'a>(&'a self, _host: &'a str) -> BoxFuture<'a, NetResult<Vec<Ipv4Addr>>> {
        Box::pin(async { Ok(vec![Ipv4Addr::new(203, 0, 113, 7)]) })
    }
}

struct MockNet;
impl NetFactory for MockNet {
    fn bootstrap(&self, _: &GuardPolicy) -> Arc<dyn Resolver> {
        Arc::new(MockDoh)
    }
    fn relay_resolver(
        &self,
        _: &GuardPolicy,
        _: &ProxyEndpoint,
        _: SocketAddr,
    ) -> Arc<dyn Resolver> {
        Arc::new(MockDoh)
    }
}

// ---- mock engine: engine patch 0002, step by step ------------------------------------

type ExitSlot = Arc<Mutex<Option<Option<i32>>>>;

struct MockProc {
    pid: u32,
    exit: ExitSlot,
}

impl EngineProcess for MockProc {
    fn pid(&self) -> u32 {
        self.pid
    }
    fn try_exit(&mut self) -> std::io::Result<Option<Option<i32>>> {
        Ok(*self.exit.lock().unwrap())
    }
    fn kill(&mut self) -> std::io::Result<()> {
        let mut e = self.exit.lock().unwrap();
        if e.is_none() {
            *e = Some(Some(1));
        }
        Ok(())
    }
    fn wait_exit(&mut self) -> std::io::Result<Option<i32>> {
        Ok(self.exit.lock().unwrap().flatten())
    }
}

struct Spawn {
    pid: u32,
    args: Vec<String>,
    exit: ExitSlot,
}

struct MockEngine {
    /// The engine binary's own version (what `version_info::GetVersion()` returns).
    own_version: EngineVersion,
    /// Simulates a launcher key the engine does not accept.
    replace_pubkey: Option<String>,
    next_pid: AtomicU32,
    members: Arc<Mutex<HashSet<u32>>>,
    spawns: Mutex<Vec<Spawn>>,
}

impl MockEngine {
    fn new(own_version: EngineVersion) -> Self {
        Self {
            own_version,
            replace_pubkey: None,
            next_pid: AtomicU32::new(4000),
            members: Arc::new(Mutex::new(HashSet::new())),
            spawns: Mutex::new(Vec::new()),
        }
    }
    fn last(&self) -> (u32, Vec<String>, ExitSlot) {
        let s = self.spawns.lock().unwrap();
        let l = s.last().expect("engine was spawned");
        (l.pid, l.args.clone(), l.exit.clone())
    }
    fn count(&self) -> usize {
        self.spawns.lock().unwrap().len()
    }
}

fn arg(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .find_map(|a| a.strip_prefix(key).map(String::from))
}

/// `vanta::VerifyLaunchConfig` (engine/patches/vanta/0002) in Rust. `None` = continue.
fn verify_like_engine_patch_0002(args: &[String], own: EngineVersion) -> Option<i32> {
    const BAD: i32 = 86;
    const MISMATCH: i32 = 87;
    let path = arg(args, "--vanta-config=")?;
    // 1. read {"payload": ..., "signature": ...}
    let Ok(file) = std::fs::read(&path) else {
        return Some(BAD);
    };
    if file.len() > 1024 * 1024 {
        return Some(BAD);
    }
    let Ok(serde_json::Value::Object(outer)) = serde_json::from_slice(&file) else {
        return Some(BAD);
    };
    let (Some(payload), Some(sig_b64)) = (
        outer.get("payload").and_then(|v| v.as_str()),
        outer.get("signature").and_then(|v| v.as_str()),
    ) else {
        return Some(BAD);
    };
    // 2. Ed25519 over the exact payload bytes
    let Ok(sig) = STANDARD.decode(sig_b64) else {
        return Some(BAD);
    };
    let Ok(sig) = <[u8; 64]>::try_from(sig.as_slice()) else {
        return Some(BAD);
    };
    let Some(Ok(pk)) = arg(args, "--vanta-pubkey=").map(|k| STANDARD.decode(k)) else {
        return Some(BAD);
    };
    let Ok(pk) = <[u8; 32]>::try_from(pk.as_slice()) else {
        return Some(BAD);
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return Some(BAD);
    };
    if vk
        .verify(payload.as_bytes(), &Signature::from_bytes(&sig))
        .is_err()
    {
        return Some(BAD);
    }
    // 3. version lock
    let Ok(serde_json::Value::Object(persona)) = serde_json::from_str(payload) else {
        return Some(BAD);
    };
    let Some(serde_json::Value::Object(engine)) = persona.get("engine") else {
        return Some(BAD);
    };
    let mut wanted = Vec::new();
    for part in ["major", "minor", "build", "patch"] {
        match engine.get(part).and_then(|v| v.as_i64()) {
            Some(v) if v >= 0 => wanted.push(v as u32),
            _ => return Some(BAD),
        }
    }
    if wanted != [own.major, own.minor, own.build, own.patch] {
        return Some(MISMATCH);
    }
    None
}

impl EngineSpawner for MockEngine {
    fn spawn(
        &self,
        _exe: &Path,
        args: &[OsString],
        _job: &KillOnCloseJob,
    ) -> vanta_types::Result<Box<dyn EngineProcess>> {
        let mut args: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        if let Some(k) = &self.replace_pubkey {
            for a in args.iter_mut() {
                if a.starts_with("--vanta-pubkey=") {
                    *a = format!("--vanta-pubkey={k}");
                }
            }
        }
        let pid = self.next_pid.fetch_add(1, Ordering::SeqCst);
        let exit: ExitSlot = Arc::new(Mutex::new(
            verify_like_engine_patch_0002(&args, self.own_version).map(Some),
        ));
        self.members.lock().unwrap().insert(pid);
        self.spawns.lock().unwrap().push(Spawn {
            pid,
            args,
            exit: exit.clone(),
        });
        Ok(Box::new(MockProc { pid, exit }))
    }
}

/// The OS connection table, as the test says: every relay client "is" this PID.
struct FakeLookup(Arc<AtomicU32>);
impl PidLookup for FakeLookup {
    fn owning_pid(&self, c: SocketAddr, s: SocketAddr) -> Option<u32> {
        assert!(c.ip().is_loopback() && s.ip().is_loopback());
        match self.0.load(Ordering::SeqCst) {
            0 => None,
            p => Some(p),
        }
    }
}

// ---- fixture -------------------------------------------------------------------------

struct Env {
    dir: PathBuf,
    app: VantaApp,
    engine: Arc<MockEngine>,
    client_pid: Arc<AtomicU32>,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn config(dir: &Path) -> AppConfig {
    let mut cfg = AppConfig::new(
        dir,
        EngineInfo {
            exe: dir.join("vanta-chromium.exe"),
            version: ENGINE,
        },
    );
    cfg.kdf = KdfParams::insecure_for_tests();
    cfg.startup_window = Duration::from_millis(150);
    cfg.health_timeout = Duration::from_millis(300);
    cfg.proxy_timeout = Duration::from_secs(2);
    cfg.heartbeat = Duration::from_millis(200);
    cfg
}

fn deps(engine: Arc<MockEngine>, client_pid: Arc<AtomicU32>) -> Deps {
    let members = engine.members.clone();
    Deps {
        spawner: engine,
        net: Arc::new(MockNet),
        // Same shape as production (process tree, unknown PIDs refused), with the job
        // membership answered by the mock engine and the PID by the test.
        clients: RelayClients::Custom(Arc::new(move |_job: Arc<KillOnCloseJob>| {
            let members = members.clone();
            AllowedClients::ProcessTree {
                authorizer: Arc::new(move |pid: u32| members.lock().unwrap().contains(&pid)),
                lookup: Arc::new(FakeLookup(client_pid.clone())),
                unknown: UnknownPid::Deny,
            }
        })),
    }
}

fn env_with(engine: MockEngine, dir: Option<PathBuf>) -> Env {
    let dir = dir.unwrap_or_else(|| {
        std::env::temp_dir().join(format!("vanta-core-test-{}", uuid::Uuid::new_v4()))
    });
    let engine = Arc::new(engine);
    let client_pid = Arc::new(AtomicU32::new(0));
    let app = VantaApp::open(config(&dir), deps(engine.clone(), client_pid.clone())).unwrap();
    Env {
        dir,
        app,
        engine,
        client_pid,
    }
}

fn env() -> Env {
    env_with(MockEngine::new(ENGINE), None)
}

const MASTER: &str = "correct horse battery";

/// Vault, one proxy (the mock upstream), one profile using it.
fn setup(e: &Env, up: &Upstream) -> (ProfileId, String) {
    if !e.app.is_initialized() {
        e.app.create_vault(MASTER).unwrap();
    }
    let imp = e
        .app
        .import_proxies(
            &format!("socks5://{USER}:{PASSWORD}@127.0.0.1:{}", up.addr.port()),
            ProxyScheme::Socks5,
        )
        .unwrap();
    assert_eq!(imp.added.len(), 1, "{:?}", imp.errors);
    let proxy = imp.added[0].id.clone();
    let p = e
        .app
        .create_profile(NewProfile {
            name: format!("p-{}", uuid::Uuid::new_v4()),
            proxy_id: Some(proxy.clone()),
            ..Default::default()
        })
        .unwrap();
    (p.id, proxy)
}

fn fresh_health(e: &Env, id: ProfileId, proxy: &str, score: u8) {
    e.app
        .store_for_tests()
        .put_health(&HealthSummary {
            profile_id: id,
            score,
            blocked: score < 60,
            failing: vec![],
            engine: ENGINE.to_string(),
            proxy_id: Some(proxy.into()),
            ts_ms: vanta_proxy::state::now_ms(),
        })
        .unwrap();
}

fn status(e: &Env, id: ProfileId) -> ProfileStatus {
    e.app.store_for_tests().get(id).unwrap().status
}

fn log_kinds(e: &Env, id: ProfileId) -> Vec<LogKind> {
    let mut v: Vec<LogKind> = e
        .app
        .activity_log(&LogQuery {
            profile: Some(id),
            limit: 1000,
            ..Default::default()
        })
        .unwrap()
        .entries
        .into_iter()
        .map(|x| x.kind)
        .collect();
    v.reverse();
    v
}

async fn wait_until(mut f: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    while !f() {
        // Generous: on Windows a refused connect takes about 2 s.
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "condition never became true"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// SOCKS5 CONNECT to an IPv4 target through the relay, like the engine would.
async fn through_relay(port: u16) -> Option<TcpStream> {
    let mut c = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.ok()?;
    c.write_all(&[5, 1, 0]).await.ok()?;
    let mut g = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(2), c.read_exact(&mut g))
        .await
        .ok()?
        .ok()?;
    c.write_all(&[5, 1, 0, 1, 203, 0, 113, 7, 1, 187])
        .await
        .ok()?;
    let mut r = [0u8; 10];
    c.read_exact(&mut r).await.ok()?;
    (r[1] == 0).then_some(c)
}

fn codes(e: &CoreError) -> Vec<String> {
    match e {
        CoreError::Blocked { reasons } => reasons.iter().map(|r| r.code.clone()).collect(),
        other => panic!("expected Blocked, got {other:?}"),
    }
}

fn db_bytes(dir: &Path) -> Vec<u8> {
    let mut all = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_file() {
            all.extend(std::fs::read(&p).unwrap());
        }
    }
    all
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

// ---- tests ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn happy_path_launch_relay_status_and_log() {
    let up = upstream(USER, PASSWORD).await;
    let e = env();
    let (id, proxy) = setup(&e, &up);
    let v = e.app.test_proxy(&proxy).await.unwrap();
    assert!(
        matches!(v.state, ProxyState::Online { .. }),
        "{:?}",
        v.state
    );
    fresh_health(&e, id, &proxy, 92);

    let info = e.app.launch_profile(id).await.unwrap();
    assert_eq!(info.engine_version, "156.0.8078.79");
    assert_eq!(status(&e, id), ProfileStatus::Running);
    assert!(e
        .app
        .store_for_tests()
        .get(id)
        .unwrap()
        .last_opened_ms
        .is_some());

    // The engine got the relay as its only proxy, the signed config and no CDP.
    let (pid, args, exit) = e.engine.last();
    assert_eq!(pid, info.pid);
    assert!(args.contains(&format!(
        "--proxy-server=socks5://127.0.0.1:{}",
        info.relay_port
    )));
    assert!(args.iter().any(|a| a == "--disable-quic"));
    assert!(!args.iter().any(|a| a.contains("remote-debugging")));
    let cfg_path = arg(&args, "--vanta-config=").unwrap();
    assert_eq!(
        PathBuf::from(&cfg_path),
        launch_config_path(&e.dir, id),
        "config is where the app says"
    );
    let file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
    let payload: serde_json::Value =
        serde_json::from_str(file["payload"].as_str().unwrap()).unwrap();
    assert_eq!(payload["vanta_launch"]["relay_port"], info.relay_port);
    assert_eq!(payload["vanta_launch"]["profile_id"], id.to_string());
    assert_eq!(payload["engine"]["build"], 8078);
    assert!(!contains(file.to_string().as_bytes(), PASSWORD));

    // The engine's own connection goes through, with the vault-held password upstream.
    e.client_pid.store(info.pid, Ordering::SeqCst);
    let mut c = through_relay(info.relay_port)
        .await
        .expect("engine allowed");
    c.write_all(b"ping").await.unwrap();
    let mut b = [0u8; 4];
    c.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"ping");
    assert!(up
        .targets
        .lock()
        .unwrap()
        .contains(&"203.0.113.7:443".to_string()));
    assert!(up
        .logins
        .lock()
        .unwrap()
        .iter()
        .all(|(u, p)| u == USER && p == PASSWORD));

    // Second launch while running is refused.
    assert!(matches!(
        e.app.launch_profile(id).await,
        Err(CoreError::AlreadyRunning)
    ));

    // The engine crashes: the watcher writes the real status and cleans up.
    *exit.lock().unwrap() = Some(Some(3));
    let changes = e.app.poll_status();
    assert_eq!(
        changes,
        vec![StatusChange {
            profile_id: id,
            status: ProfileStatus::Crashed,
            exit_code: Some(3)
        }]
    );
    assert_eq!(status(&e, id), ProfileStatus::Crashed);
    assert!(!Path::new(&cfg_path).exists(), "launch config removed");
    assert!(e.app.running_profiles().is_empty());
    assert!(
        through_relay(info.relay_port).await.is_none(),
        "relay closed"
    );

    // Launch again, then a user stop.
    let info2 = e.app.launch_profile(id).await.unwrap();
    assert_ne!(info2.relay_port, 0);
    e.app.stop_profile(id).unwrap();
    assert_eq!(status(&e, id), ProfileStatus::Stopped);
    assert!(matches!(e.app.stop_profile(id), Err(CoreError::NotRunning)));

    // A clean exit (user closed the browser) is "stopped" through the watcher.
    e.app.launch_profile(id).await.unwrap();
    *e.engine.last().2.lock().unwrap() = Some(Some(0));
    let w = e.app.spawn_status_watcher(Duration::from_millis(20));
    wait_until(|| status(&e, id) == ProfileStatus::Stopped).await;
    w.abort();

    let kinds = log_kinds(&e, id);
    for k in [
        LogKind::ProfileLaunch,
        LogKind::ProfileCrash,
        LogKind::ProfileStop,
    ] {
        assert!(kinds.contains(&k), "{k:?} missing from {kinds:?}");
    }
    e.app.activity_log(&LogQuery::default()).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_version_mismatch_exit_87_blocks() {
    let up = upstream(USER, PASSWORD).await;
    let e = env_with(MockEngine::new(EngineVersion::new(156, 0, 8078, 82)), None);
    let (id, proxy) = setup(&e, &up);
    fresh_health(&e, id, &proxy, 90);
    let err = e.app.launch_profile(id).await.unwrap_err();
    assert!(
        matches!(&err, CoreError::VersionMismatch { expected } if expected == "156.0.8078.79"),
        "{err:?}"
    );
    assert_eq!(status(&e, id), ProfileStatus::Blocked);
    assert!(e.app.running_profiles().is_empty());
    assert!(log_kinds(&e, id).contains(&LogKind::LaunchBlocked));
    let json = serde_json::to_value(&err).unwrap();
    assert_eq!(json["kind"], "version_mismatch");
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_signature_exit_86_is_typed() {
    let up = upstream(USER, PASSWORD).await;
    let mut eng = MockEngine::new(ENGINE);
    eng.replace_pubkey = Some(
        STANDARD.encode(
            vanta_fingerprint::config::new_signing_key()
                .verifying_key()
                .as_bytes(),
        ),
    );
    let e = env_with(eng, None);
    let (id, proxy) = setup(&e, &up);
    fresh_health(&e, id, &proxy, 90);
    let err = e.app.launch_profile(id).await.unwrap_err();
    assert!(matches!(err, CoreError::BadConfigSignature), "{err:?}");
    assert_eq!(status(&e, id), ProfileStatus::Blocked);
}

#[tokio::test(flavor = "multi_thread")]
async fn health_run_below_60_blocks_launch() {
    let up = upstream(USER, PASSWORD).await;
    let e = env();
    let (id, _) = setup(&e, &up);
    // The mock engine never loads the probe page, so the run has no browser evidence.
    let r = e.app.run_health(id).await.unwrap();
    assert!(r.summary.score < 60, "score {}", r.summary.score);
    assert!(r.summary.blocked);
    assert!(!r.summary.failing.is_empty());
    assert!(!r.problems.is_empty());
    assert_eq!(e.engine.count(), 1, "the health run launched the engine");
    let (_, args, exit) = e.engine.last();
    assert!(args
        .iter()
        .any(|a| a.starts_with("--ignore-certificate-errors-spki-list=")));
    assert!(args
        .iter()
        .any(|a| a.starts_with("https://vanta-health.localhost:")));
    assert!(
        exit.lock().unwrap().is_some(),
        "engine stopped after the run"
    );
    assert_eq!(status(&e, id), ProfileStatus::Stopped);
    let stored = e.app.store_for_tests().get_health(id).unwrap().unwrap();
    assert_eq!(stored.score, r.summary.score);
    assert_eq!(
        e.app.store_for_tests().get(id).unwrap().health,
        r.summary.score
    );
    assert!(log_kinds(&e, id).contains(&LogKind::HealthRun));

    let err = e.app.launch_profile(id).await.unwrap_err();
    assert_eq!(codes(&err), ["health_too_low"]);
    assert_eq!(status(&e, id), ProfileStatus::Blocked);
    assert_eq!(e.engine.count(), 1, "no engine for a blocked launch");
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_expired_or_foreign_health_blocks() {
    let up = upstream(USER, PASSWORD).await;
    let e = env();
    let (id, proxy) = setup(&e, &up);
    assert_eq!(
        codes(&e.app.launch_profile(id).await.unwrap_err()),
        ["health_missing"]
    );
    // Expired.
    let mut h = HealthSummary {
        profile_id: id,
        score: 95,
        blocked: false,
        failing: vec![],
        engine: ENGINE.to_string(),
        proxy_id: Some(proxy.clone()),
        ts_ms: vanta_proxy::state::now_ms() - vanta_launcher::HEALTH_MAX_AGE_MS - 60_000,
    };
    e.app.store_for_tests().put_health(&h).unwrap();
    assert_eq!(
        codes(&e.app.launch_profile(id).await.unwrap_err()),
        ["health_expired"]
    );
    // Another engine build.
    h.ts_ms = vanta_proxy::state::now_ms();
    h.engine = "156.0.8078.73".into();
    e.app.store_for_tests().put_health(&h).unwrap();
    assert_eq!(
        codes(&e.app.launch_profile(id).await.unwrap_err()),
        ["health_missing"]
    );
    // A fresh report, then a new proxy assignment invalidates it.
    fresh_health(&e, id, &proxy, 95);
    let other = e
        .app
        .import_proxies("198.51.100.20:1080", ProxyScheme::Socks5)
        .unwrap()
        .added[0]
        .id
        .clone();
    e.app.assign_proxy(id, Some(&other)).unwrap();
    assert!(e.app.store_for_tests().get_health(id).unwrap().is_none());
    assert_eq!(e.engine.count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_proxy_blocks_and_no_relay_or_engine_starts() {
    let e = env();
    let dead = {
        let l = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        l.local_addr().unwrap().port()
    }; // listener dropped: nothing listens there
    e.app.create_vault(MASTER).unwrap();
    let proxy = e
        .app
        .import_proxies(
            &format!("socks5://{USER}:{PASSWORD}@127.0.0.1:{dead}"),
            ProxyScheme::Socks5,
        )
        .unwrap()
        .added[0]
        .id
        .clone();
    let p = e
        .app
        .create_profile(NewProfile {
            name: "offline".into(),
            proxy_id: Some(proxy.clone()),
            ..Default::default()
        })
        .unwrap();
    fresh_health(&e, p.id, &proxy, 90);
    let err = e.app.launch_profile(p.id).await.unwrap_err();
    assert_eq!(codes(&err), ["proxy_offline"]);
    assert_eq!(status(&e, p.id), ProfileStatus::Blocked);
    assert_eq!(e.engine.count(), 0);
    let v = e.app.list_proxies().unwrap();
    assert!(matches!(v[0].state, ProxyState::Offline { .. }));
    let all = e.app.activity_log(&LogQuery::default()).unwrap();
    assert!(all
        .entries
        .iter()
        .any(|x| x.kind == LogKind::ProxyFailure && !x.detail.contains(PASSWORD)));
    // A profile with no proxy never launches either.
    let bare = e
        .app
        .create_profile(NewProfile {
            name: "no-proxy".into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        codes(&e.app.launch_profile(bare.id).await.unwrap_err()),
        ["no_proxy"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_rejects_a_process_outside_the_profile_job() {
    let up = upstream(USER, PASSWORD).await;
    let e = env();
    let (id, proxy) = setup(&e, &up);
    fresh_health(&e, id, &proxy, 90);
    let info = e.app.launch_profile(id).await.unwrap();
    let before = up.targets.lock().unwrap().len();

    // Another local process (not in the profile's job) tries the relay.
    e.client_pid.store(999, Ordering::SeqCst);
    assert!(through_relay(info.relay_port).await.is_none());
    // A client whose PID cannot be found is refused too (production: unknown = deny).
    e.client_pid.store(0, Ordering::SeqCst);
    assert!(through_relay(info.relay_port).await.is_none());
    assert_eq!(
        up.targets.lock().unwrap().len(),
        before,
        "nothing went upstream"
    );

    let blocked = |e: &Env| {
        e.app
            .activity_log(&LogQuery {
                kinds: vec![LogKind::BlockedEvent],
                ..Default::default()
            })
            .unwrap()
            .entries
    };
    wait_until(|| blocked(&e).len() >= 2).await;
    let b = blocked(&e);
    assert!(b.iter().any(|x| x.detail.contains("pid 999")), "{b:?}");
    assert!(b.iter().any(|x| x.detail.contains("pid unknown")), "{b:?}");
    assert!(b.iter().all(|x| x.profile == Some(id)));

    // The engine itself still gets through.
    e.client_pid.store(info.pid, Ordering::SeqCst);
    assert!(through_relay(info.relay_port).await.is_some());
    e.app.stop_profile(id).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn kill_switch_trip_is_logged() {
    let up = upstream(USER, PASSWORD).await;
    let e = env();
    let (id, proxy) = setup(&e, &up);
    fresh_health(&e, id, &proxy, 90);
    e.app.launch_profile(id).await.unwrap();
    drop(up); // the proxy goes away; the heartbeat trips the kill switch
    wait_until(|| log_kinds(&e, id).contains(&LogKind::KillSwitch)).await;
    e.app.stop_profile(id).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn activity_log_head_mismatch_is_detected_at_unlock() {
    let dir = std::env::temp_dir().join(format!("vanta-core-test-{}", uuid::Uuid::new_v4()));
    {
        let e = env_with(MockEngine::new(ENGINE), Some(dir.clone()));
        e.app.create_vault(MASTER).unwrap();
        e.app
            .create_profile(NewProfile {
                name: "a".into(),
                ..Default::default()
            })
            .unwrap();
        e.app.lock().unwrap();
        // Untouched log: unlock verifies it against the head kept in the vault.
        let r = e.app.unlock(MASTER).unwrap();
        assert_eq!(r.log_integrity, LogIntegrity::Ok);
        e.app.lock().unwrap();
        assert!(matches!(
            e.app.activity_log(&LogQuery::default()),
            Err(CoreError::Locked)
        ));
        std::mem::forget(e); // keep the folder for the second half
    }
    // Cut the last frame off the log file (tail truncation keeps the chain valid).
    let path = dir.join("activity.log");
    let data = std::fs::read(&path).unwrap();
    let mut frames = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let len = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as usize;
        frames.push(i);
        i += 4 + len;
    }
    assert!(frames.len() >= 3, "anchor + entries");
    std::fs::write(&path, &data[..*frames.last().unwrap()]).unwrap();

    let e = env_with(MockEngine::new(ENGINE), Some(dir));
    let r = e.app.unlock(MASTER).unwrap();
    match &r.log_integrity {
        LogIntegrity::HeadMismatch { detail } => assert!(detail.contains("head"), "{detail}"),
        other => panic!("truncation not detected: {other:?}"),
    }
    // The finding is itself logged.
    let last = e.app.activity_log(&LogQuery::default()).unwrap().entries[0].clone();
    assert_eq!(last.kind, LogKind::VaultUnlock);
    assert!(last.detail.contains("integrity"), "{}", last.detail);
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_password_is_never_plaintext_in_the_data_folder() {
    let up = upstream(USER, PASSWORD).await;
    let e = env();
    let (id, proxy) = setup(&e, &up);
    fresh_health(&e, id, &proxy, 90);
    e.app.launch_profile(id).await.unwrap();
    e.app.stop_profile(id).unwrap();
    let rec = e.app.store_for_tests().get_proxy(&proxy).unwrap();
    assert_eq!(
        rec.secret_ref.as_deref(),
        Some(format!("proxy/{proxy}").as_str())
    );
    assert_eq!(rec.username.as_deref(), Some(USER));
    let view = &e.app.list_proxies().unwrap()[0];
    assert!(view.has_password && !view.display.contains(PASSWORD));
    assert!(!serde_json::to_string(view).unwrap().contains(PASSWORD));
    let bytes = db_bytes(&e.dir);
    assert!(
        contains(&bytes, USER),
        "sanity: the folder holds the user name"
    );
    assert!(!contains(&bytes, PASSWORD), "password found in clear");
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_inline_proxy_moves_into_the_vault_on_unlock() {
    const LEGACY_PW: &str = "Legacy-Inline-Pw-55120";
    let up = upstream("bob", LEGACY_PW).await;
    let e = env();
    e.app.create_vault(MASTER).unwrap();
    let p = e
        .app
        .create_profile(NewProfile {
            name: "legacy".into(),
            ..Default::default()
        })
        .unwrap();
    // A schema-1 row: the whole proxy line, password included, in `proxy_id`.
    let line = format!("socks5://bob:{LEGACY_PW}@127.0.0.1:{}", up.addr.port());
    e.app
        .store_for_tests()
        .set_proxy_id(p.id, Some(&line))
        .unwrap();
    assert!(
        contains(&db_bytes(&e.dir), LEGACY_PW),
        "sanity: the legacy row holds the password in clear"
    );
    e.app.lock().unwrap();

    let r = e.app.unlock(MASTER).unwrap();
    assert_eq!(r.migrated_proxies, 1);
    let meta = e.app.store_for_tests().get(p.id).unwrap();
    let pid = meta.proxy_id.unwrap();
    assert!(!pid.contains(LEGACY_PW));
    assert!(e
        .app
        .store_for_tests()
        .legacy_inline_proxies()
        .unwrap()
        .is_empty());
    // The password works from the vault.
    let v = e.app.test_proxy(&pid).await.unwrap();
    assert!(
        matches!(v.state, ProxyState::Online { .. }),
        "{:?}",
        v.state
    );
    assert!(
        !contains(&db_bytes(&e.dir), LEGACY_PW),
        "legacy password left in the db"
    );
    // Idempotent.
    e.app.lock().unwrap();
    assert_eq!(e.app.unlock(MASTER).unwrap().migrated_proxies, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn profile_crud_fingerprint_and_assignment_warnings() {
    let e = env();
    assert!(matches!(
        e.app.create_profile(NewProfile::default()),
        Err(CoreError::NotInitialized)
    ));
    e.app.create_vault(MASTER).unwrap();
    assert!(matches!(
        e.app.create_vault(MASTER),
        Err(CoreError::AlreadyInitialized)
    ));
    let a = e
        .app
        .create_profile(NewProfile {
            name: "shop-de-01".into(),
            tags: vec!["shop".into()],
            os: Some(vanta_types::OsKind::Windows11),
            locale: Some("de-DE".into()),
            ..Default::default()
        })
        .unwrap();
    let b = e
        .app
        .create_profile(NewProfile {
            name: "shop-de-02".into(),
            ..Default::default()
        })
        .unwrap();
    let d = e.app.get_profile(a.id).unwrap();
    assert_eq!(d.persona.os, vanta_types::OsKind::Windows11);
    assert_eq!(d.persona.locale, "de-DE");
    assert!(d.persona.user_agent.contains("Chrome/156.0.0.0"));
    let page = e.app.list_profiles("tag:shop", 50, 0).unwrap();
    assert_eq!(page.total, 1);

    let edited = e
        .app
        .edit_profile(
            a.id,
            ProfileEdit {
                folder: Some("E-commerce".into()),
                notes: Some("main".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(edited.folder, "E-commerce");

    let before = e.app.get_profile(a.id).unwrap().persona;
    let mut changed = false;
    for _ in 0..5 {
        e.app.regenerate_fingerprint(a.id, None).unwrap();
        let after = e.app.get_profile(a.id).unwrap().persona;
        assert_eq!(after.locale, "de-DE", "locale kept");
        if after.device_id != before.device_id || after.screen != before.screen {
            changed = true;
            break;
        }
    }
    assert!(changed, "regenerate never produced another device");

    let px = e
        .app
        .import_proxies(
            "socks5://u:p@198.51.100.9:1080\nnot a proxy",
            ProxyScheme::Socks5,
        )
        .unwrap();
    assert_eq!((px.added.len(), px.errors.len()), (1, 1));
    assert_eq!(px.errors[0].line, 2);
    let pid = px.added[0].id.clone();
    assert!(e
        .app
        .assign_proxy(a.id, Some(&pid))
        .unwrap()
        .shared_with
        .is_empty());
    assert_eq!(
        e.app.assign_proxy(b.id, Some(&pid)).unwrap().shared_with,
        vec![a.id]
    );
    e.app.delete_proxy(&pid).unwrap();
    assert_eq!(e.app.store_for_tests().get(a.id).unwrap().proxy_id, None);

    assert_eq!(e.app.delete_profiles(&[a.id, b.id]).unwrap(), 2);
    assert_eq!(e.app.list_profiles("", 50, 0).unwrap().total, 0);
    assert!(matches!(
        e.app.get_profile(a.id),
        Err(CoreError::NotFound { .. })
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn locked_vault_refuses_work() {
    let up = upstream(USER, PASSWORD).await;
    let e = env();
    let (id, _) = setup(&e, &up);
    e.app.lock().unwrap();
    assert!(!e.app.is_unlocked());
    assert!(matches!(
        e.app.launch_profile(id).await,
        Err(CoreError::Locked)
    ));
    assert!(matches!(e.app.run_health(id).await, Err(CoreError::Locked)));
    assert!(matches!(
        e.app.unlock("wrong password!"),
        Err(CoreError::Crypto)
    ));
    e.app.unlock(MASTER).unwrap();
    // Unchanged: still only a proxy check away from the health gate.
    assert_eq!(
        codes(&e.app.launch_profile(id).await.unwrap_err()),
        ["health_missing"]
    );
}

#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread")]
async fn real_spawner_is_refused_off_windows() {
    let up = upstream(USER, PASSWORD).await;
    let dir = std::env::temp_dir().join(format!("vanta-core-test-{}", uuid::Uuid::new_v4()));
    let client_pid = Arc::new(AtomicU32::new(0));
    let mut d = deps(Arc::new(MockEngine::new(ENGINE)), client_pid);
    d.spawner = Arc::new(OsSpawner);
    let app = VantaApp::open(config(&dir), d).unwrap();
    let e = Env {
        dir,
        app,
        engine: Arc::new(MockEngine::new(ENGINE)),
        client_pid: Arc::new(AtomicU32::new(0)),
    };
    let (id, proxy) = setup(&e, &up);
    fresh_health(&e, id, &proxy, 90);
    let err = e.app.launch_profile(id).await.unwrap_err();
    assert!(matches!(err, CoreError::Unsupported { .. }), "{err:?}");
    assert!(!launch_config_path(&e.dir, id).exists());
}

#[test]
fn production_relay_policy_is_job_process_tree_with_unknown_denied() {
    let d = Deps::production();
    assert!(matches!(d.clients, RelayClients::ProcessTree));
    let job = Arc::new(KillOnCloseJob::new().unwrap());
    assert!(matches!(
        d.clients.build(job),
        AllowedClients::ProcessTree {
            unknown: UnknownPid::Deny,
            ..
        }
    ));
}

#[test]
fn errors_and_dtos_serialize_for_the_ui() {
    let e = CoreError::Blocked {
        reasons: vec![BlockReason::no_proxy()],
    };
    let v = serde_json::to_value(&e).unwrap();
    assert_eq!(v["kind"], "blocked");
    assert_eq!(v["reasons"][0]["code"], "no_proxy");
    assert!(e.to_string().contains("no proxy"));
    let v = serde_json::to_value(CoreError::EngineExited { code: Some(3) }).unwrap();
    assert_eq!(v["kind"], "engine_exited");
    let q: LogQuery = serde_json::from_str(r#"{"kinds":["kill_switch"],"limit":5}"#).unwrap();
    assert_eq!(q.kinds, vec![LogKind::KillSwitch]);
    let n: NewProfile = serde_json::from_str(r#"{"name":"x","os":"windows10"}"#).unwrap();
    assert_eq!(n.os, Some(vanta_types::OsKind::Windows10));
}

#[test]
fn app_futures_are_send_for_the_tauri_runtime() {
    fn send<T: Send>(_: &T) {}
    let e = env();
    let id = ProfileId::new();
    let f1 = e.app.launch_profile(id);
    send(&f1);
    let f2 = e.app.run_health(id);
    send(&f2);
    let f3 = e.app.test_proxy("x");
    send(&f3);
}
