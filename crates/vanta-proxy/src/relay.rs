//! Network Guard local relay (F05).
//!
//! The engine only knows `socks5://127.0.0.1:<ephemeral>`. For each client connection the
//! relay:
//!
//! 1. refuses at once if the kill switch is tripped;
//! 2. reads the request (SOCKS5 CONNECT, or HTTP `CONNECT`; SOCKS5 UDP ASSOCIATE is
//!    refused, which is how non-proxied UDP is blocked);
//! 3. resolves a host name with the injected [`Resolver`] (DoH through the proxy, never the
//!    system resolver) and refuses IPv6, LAN and other non-public targets;
//! 4. opens the upstream tunnel (SOCKS5 or HTTP(S) CONNECT) **before** telling the client
//!    the connection succeeded, so no client byte is accepted without a live tunnel;
//! 5. pumps bytes until either side closes.
//!
//! Before step 1 the client itself is checked against [`RelayConfig::clients`]
//! ([`AllowedClients`]): on Windows the relay looks up the PID that owns the client's end of
//! the connection and accepts it only when that process belongs to the profile's engine
//! (its Job Object). Chromium cannot authenticate to SOCKS5, so this is how other local
//! processes are kept off the profile's proxy. A refused client is closed at once, before a
//! single byte is read, and reported as [`RelayEvent::Blocked`].
//!
//! Kill switch (fail closed, cannot be disabled): a heartbeat checks the upstream proxy
//! every `heartbeat` interval (TCP connect, TLS for https, SOCKS5 greeting + login). When
//! the proxy fails, or a tunnel fails because the proxy is down, the switch trips: every
//! open client connection is cut and new ones are refused. There is no direct fallback
//! anywhere in this module. The switch re-arms when the heartbeat succeeds again.
//!
//! The heartbeat defaults to [`DEFAULT_HEARTBEAT`] (5 s). Every heartbeat is a fresh
//! connection and, for SOCKS5 with a login, a fresh authentication at the provider.
//! Residential providers count and rate-limit these (a 1 s heartbeat is 86,400 logins per
//! profile per day, which trips provider abuse limits and can rotate a sticky session).
//! Detection does not depend on the heartbeat alone: a tunnel read error or a failed tunnel
//! setup (proxy down) trips the switch at once, and when the proxy dies the open tunnels
//! close with it, so live traffic still stops well inside the F05 1 s budget. The heartbeat
//! only bounds how long an *idle* relay takes to notice. It stays configurable.
//!
//! Every block and kill-switch change is published as a [`RelayEvent`] for the activity
//! log (F08).

use crate::clients::{AllowedClients, ClientVerdict};
use crate::doh::Resolver;
use crate::endpoint::ProxyEndpoint;
use crate::guard::{is_blocked_ip, GuardPolicy};
use crate::net::{
    connect_proxy, open_tunnel, read_http_head, read_socks_addr, BoxStream, NetError, TargetAddr,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, watch, Notify};
use tokio::task::JoinHandle;
use vanta_types::{Result, VantaError};

/// Relay configuration for one profile.
#[derive(Clone)]
pub struct RelayConfig {
    pub upstream: ProxyEndpoint,
    /// The upstream proxy's address (see [`resolve_upstream`]).
    pub upstream_addr: SocketAddr,
    /// Resolver for target host names; production uses DoH routed through the proxy.
    pub resolver: Arc<dyn Resolver>,
    pub policy: GuardPolicy,
    pub connect_timeout: Duration,
    /// Kill-switch heartbeat interval (default [`DEFAULT_HEARTBEAT`]; see the module docs
    /// for why it is not 1 s).
    pub heartbeat: Duration,
    /// Which local processes may use the relay (default [`AllowedClients::Any`]; the
    /// launcher sets [`AllowedClients::ProcessTree`] with the profile's Job Object).
    pub clients: AllowedClients,
}

/// Default kill-switch heartbeat: 5 s, so provider login rate limits are not hit.
pub const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(5);

impl RelayConfig {
    pub fn new(
        upstream: ProxyEndpoint,
        upstream_addr: SocketAddr,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self {
            upstream,
            upstream_addr,
            resolver,
            policy: GuardPolicy::default(),
            connect_timeout: Duration::from_secs(10),
            heartbeat: DEFAULT_HEARTBEAT,
            clients: AllowedClients::Any,
        }
    }

    /// Set the client policy.
    pub fn with_clients(mut self, clients: AllowedClients) -> Self {
        self.clients = clients;
        self
    }
}

/// Resolve the proxy's own address: an IP literal as is, a host name through `bootstrap`
/// (a [`crate::doh::DohResolver`] with [`crate::doh::DohRoute::Direct`]). Never system DNS.
pub async fn resolve_upstream(
    proxy: &ProxyEndpoint,
    bootstrap: &dyn Resolver,
) -> Result<SocketAddr> {
    if let Some(ip) = proxy.ip() {
        return Ok(SocketAddr::new(ip, proxy.port));
    }
    let ips = bootstrap.resolve(&proxy.host).await?;
    ips.first()
        .map(|ip| SocketAddr::new(IpAddr::V4(*ip), proxy.port))
        .ok_or_else(|| VantaError::Network(format!("proxy host {} has no address", proxy.host)))
}

/// Kill-switch state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardState {
    Armed,
    Tripped { reason: String },
}

/// What the relay reports to the activity log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayEvent {
    /// A request was refused by policy (UDP, IPv6, LAN, plain HTTP, a local process that
    /// is not this profile's engine...). For a refused client `target` is
    /// `client <addr> (pid <n>)`.
    Blocked {
        target: String,
        reason: &'static str,
    },
    /// The upstream proxy failed; all connections were cut.
    Tripped { reason: String },
    /// The upstream proxy is back.
    Rearmed,
}

struct Shared {
    cfg: RelayConfig,
    addr: SocketAddr,
    state: watch::Sender<GuardState>,
    shutdown: watch::Sender<bool>,
    events: broadcast::Sender<RelayEvent>,
    check_now: Notify,
}

impl Shared {
    fn tripped(&self) -> bool {
        matches!(*self.state.borrow(), GuardState::Tripped { .. })
    }

    fn trip(&self, reason: String) {
        let changed = self.state.send_if_modified(|s| {
            if matches!(s, GuardState::Armed) {
                *s = GuardState::Tripped {
                    reason: reason.clone(),
                };
                true
            } else {
                false
            }
        });
        if changed {
            let _ = self.events.send(RelayEvent::Tripped { reason });
        }
    }

    fn rearm(&self) {
        let changed = self.state.send_if_modified(|s| {
            if matches!(s, GuardState::Tripped { .. }) {
                *s = GuardState::Armed;
                true
            } else {
                false
            }
        });
        if changed {
            let _ = self.events.send(RelayEvent::Rearmed);
        }
    }

    fn blocked(&self, target: String, reason: &'static str) {
        let _ = self.events.send(RelayEvent::Blocked { target, reason });
    }
}

/// A running relay. Dropping it without [`Relay::shutdown`] also stops it.
pub struct Relay {
    addr: SocketAddr,
    shared: Arc<Shared>,
    tasks: Vec<JoinHandle<()>>,
}

impl Relay {
    /// Bind `127.0.0.1:0` and start serving. The upstream proxy is checked first: a relay
    /// whose proxy is down starts tripped.
    pub async fn start(cfg: RelayConfig) -> Result<Relay> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|e| VantaError::Network(format!("relay bind: {e}")))?;
        let addr = listener
            .local_addr()
            .map_err(|e| VantaError::Network(format!("relay addr: {e}")))?;
        let initial =
            match connect_proxy(&cfg.upstream, cfg.upstream_addr, cfg.connect_timeout).await {
                Ok(_) => GuardState::Armed,
                Err(e) => GuardState::Tripped {
                    reason: e.to_string(),
                },
            };
        let (events, _) = broadcast::channel(256);
        let shared = Arc::new(Shared {
            cfg,
            addr,
            state: watch::channel(initial).0,
            shutdown: watch::channel(false).0,
            events,
            check_now: Notify::new(),
        });
        // Subscribe before spawning so a shutdown sent right after start is never missed.
        let accept = tokio::spawn(accept_loop(
            listener,
            shared.clone(),
            shared.shutdown.subscribe(),
        ));
        let heartbeat = tokio::spawn(heartbeat_loop(shared.clone(), shared.shutdown.subscribe()));
        Ok(Relay {
            addr,
            shared,
            tasks: vec![accept, heartbeat],
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Value for the engine's `--proxy-server`.
    pub fn proxy_url(&self) -> String {
        format!("socks5://{}", self.addr)
    }

    pub fn state(&self) -> GuardState {
        self.shared.state.borrow().clone()
    }

    pub fn is_tripped(&self) -> bool {
        self.shared.tripped()
    }

    pub fn watch_state(&self) -> watch::Receiver<GuardState> {
        self.shared.state.subscribe()
    }

    pub fn events(&self) -> broadcast::Receiver<RelayEvent> {
        self.shared.events.subscribe()
    }

    /// Stop accepting, cut every open connection and wait for the relay tasks.
    pub async fn shutdown(mut self) {
        self.shared.shutdown.send_replace(true);
        for t in self.tasks.drain(..) {
            let _ = t.await;
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.shared.shutdown.send_replace(true);
        for t in &self.tasks {
            t.abort();
        }
    }
}

async fn accept_loop(listener: TcpListener, shared: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            r = listener.accept() => {
                let Ok((client, peer)) = r else { continue };
                let _ = client.set_nodelay(true);
                let sh = shared.clone();
                tokio::spawn(async move {
                    if authorize(&sh, peer).await {
                        handle_client(client, sh).await
                    }
                    // else: dropped unread, the client sees the connection close.
                });
            }
        }
    }
}

/// Check the client against the relay's [`AllowedClients`] policy. The OS lookup is a
/// blocking call, so it runs on the blocking pool.
async fn authorize(shared: &Arc<Shared>, peer: SocketAddr) -> bool {
    if matches!(shared.cfg.clients, AllowedClients::Any) {
        return true;
    }
    let policy = shared.cfg.clients.clone();
    let server = shared.addr;
    let verdict = tokio::task::spawn_blocking(move || policy.check(peer, server))
        .await
        .unwrap_or(ClientVerdict::UnknownProcess);
    if let Some(reason) = verdict.reason() {
        let who = match verdict {
            ClientVerdict::NotInProcessTree { pid } => format!("client {peer} (pid {pid})"),
            _ => format!("client {peer} (pid unknown)"),
        };
        shared.blocked(who, reason);
        return false;
    }
    true
}

async fn heartbeat_loop(shared: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    let cfg = &shared.cfg;
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = tokio::time::sleep(cfg.heartbeat) => {}
            _ = shared.check_now.notified() => {}
        }
        let timeout = cfg
            .connect_timeout
            .min(cfg.heartbeat * 2)
            .max(Duration::from_millis(200));
        match connect_proxy(&cfg.upstream, cfg.upstream_addr, timeout).await {
            Ok(_) => shared.rearm(),
            Err(e) => shared.trip(e.to_string()),
        }
    }
}

const SOCKS_OK: u8 = 0;
const SOCKS_GENERAL_FAILURE: u8 = 1;
const SOCKS_NOT_ALLOWED: u8 = 2;
const SOCKS_HOST_UNREACHABLE: u8 = 4;
const SOCKS_CMD_NOT_SUPPORTED: u8 = 7;

enum Request {
    Socks(TargetAddr),
    Http(TargetAddr),
}

async fn socks_reply(c: &mut TcpStream, code: u8) {
    let _ = c.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await;
}

async fn http_reply(c: &mut TcpStream, status: &str) {
    let _ = c
        .write_all(
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await;
}

async fn refuse(c: &mut TcpStream, req: &Request, socks: u8, http: &str) {
    match req {
        Request::Socks(_) => socks_reply(c, socks).await,
        Request::Http(_) => http_reply(c, http).await,
    }
}

/// Read the client's request. `None` means the client was already answered and dropped.
async fn read_request(c: &mut TcpStream, shared: &Shared) -> Option<Request> {
    let first = c.read_u8().await.ok()?;
    if first == 5 {
        let n = c.read_u8().await.ok()? as usize;
        let mut methods = vec![0u8; n];
        c.read_exact(&mut methods).await.ok()?;
        if !methods.contains(&0) {
            let _ = c.write_all(&[5, 0xFF]).await;
            return None;
        }
        c.write_all(&[5, 0]).await.ok()?;
        let mut h = [0u8; 3];
        c.read_exact(&mut h).await.ok()?;
        let target = read_socks_addr(c).await.ok()?;
        match h[1] {
            1 => Some(Request::Socks(target)),
            3 => {
                shared.blocked(target.to_string(), "UDP ASSOCIATE (non-proxied UDP)");
                socks_reply(c, SOCKS_CMD_NOT_SUPPORTED).await;
                None
            }
            _ => {
                shared.blocked(target.to_string(), "unsupported SOCKS5 command");
                socks_reply(c, SOCKS_CMD_NOT_SUPPORTED).await;
                None
            }
        }
    } else {
        let mut head = vec![first];
        let rest = read_http_head(c).await.ok()?;
        head.extend_from_slice(rest.as_bytes());
        let head = String::from_utf8(head).ok()?;
        let mut parts = head.lines().next().unwrap_or("").split_whitespace();
        let (method, authority) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        if !method.eq_ignore_ascii_case("CONNECT") {
            shared.blocked(method.to_string(), "plain HTTP proxying is not offered");
            http_reply(c, "405 Method Not Allowed").await;
            return None;
        }
        let target = parse_authority(authority);
        if target.is_none() {
            http_reply(c, "400 Bad Request").await;
        }
        target.map(Request::Http)
    }
}

fn parse_authority(a: &str) -> Option<TargetAddr> {
    if let Ok(sa) = a.parse::<SocketAddr>() {
        return Some(TargetAddr::Ip(sa));
    }
    let (h, p) = a.rsplit_once(':')?;
    let port: u16 = p.parse().ok().filter(|p| *p != 0)?;
    Some(TargetAddr::Domain(h.to_string(), port))
}

/// Resolve and police the target. Err carries (socks code, http status, reason).
async fn resolve_target(
    target: &TargetAddr,
    shared: &Shared,
) -> std::result::Result<SocketAddr, (u8, &'static str, &'static str)> {
    let (ip, port) = match target {
        TargetAddr::Ip(sa) => (sa.ip(), sa.port()),
        TargetAddr::Domain(h, port) => {
            if let Ok(ip) = h.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
                (ip, *port)
            } else {
                let lower = h.to_ascii_lowercase();
                if lower == "localhost"
                    || lower.ends_with(".localhost")
                    || lower.ends_with(".local")
                {
                    return Err((SOCKS_NOT_ALLOWED, "403 Forbidden", "local host name"));
                }
                let ips = shared.cfg.resolver.resolve(h).await.map_err(|_| {
                    (
                        SOCKS_HOST_UNREACHABLE,
                        "502 Bad Gateway",
                        "DoH lookup failed",
                    )
                })?;
                let ip = ips
                    .into_iter()
                    .find(|ip| !is_blocked_ip(IpAddr::V4(*ip)))
                    .ok_or((
                        SOCKS_NOT_ALLOWED,
                        "403 Forbidden",
                        "name resolves to a blocked address",
                    ))?;
                (IpAddr::V4(ip), *port)
            }
        }
    };
    if is_blocked_ip(ip) {
        let reason = if ip.is_ipv6() {
            "IPv6 target"
        } else {
            "LAN or reserved target"
        };
        return Err((SOCKS_NOT_ALLOWED, "403 Forbidden", reason));
    }
    Ok(SocketAddr::new(ip, port))
}

async fn handle_client(mut client: TcpStream, shared: Arc<Shared>) {
    if shared.tripped() {
        return; // kill switch: refuse immediately
    }
    let Some(req) = read_request(&mut client, &shared).await else {
        return;
    };
    let target = match &req {
        Request::Socks(t) | Request::Http(t) => t.clone(),
    };
    let ip_target = match resolve_target(&target, &shared).await {
        Ok(sa) => sa,
        Err((socks, http, reason)) => {
            if socks == SOCKS_NOT_ALLOWED {
                shared.blocked(target.to_string(), reason);
            }
            refuse(&mut client, &req, socks, http).await;
            return;
        }
    };
    if shared.tripped() {
        refuse(
            &mut client,
            &req,
            SOCKS_GENERAL_FAILURE,
            "503 Service Unavailable",
        )
        .await;
        return;
    }
    let cfg = &shared.cfg;
    let upstream = match open_tunnel(
        &cfg.upstream,
        cfg.upstream_addr,
        &TargetAddr::Ip(ip_target),
        cfg.connect_timeout,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            if e.proxy_down() {
                shared.trip(e.to_string());
            }
            let socks = match e {
                NetError::Refused(c) if c < 256 => c as u8,
                _ => SOCKS_GENERAL_FAILURE,
            };
            refuse(&mut client, &req, socks, "502 Bad Gateway").await;
            return;
        }
    };
    // Tunnel is live: only now tell the client it may send bytes.
    let ok = match &req {
        Request::Socks(_) => {
            client
                .write_all(&[5, SOCKS_OK, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
        }
        Request::Http(_) => {
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
        }
    };
    if ok.is_err() {
        return;
    }
    pump(client, upstream, &shared).await;
}

/// Copy bytes both ways. Ends (dropping both sockets) when the upstream side closes or
/// errors, the kill switch trips, or the relay shuts down. A client half-close is passed on
/// and the response is still delivered.
async fn pump(client: TcpStream, upstream: BoxStream, shared: &Shared) {
    let mut state = shared.state.subscribe();
    let mut stop = shared.shutdown.subscribe();
    if shared.tripped() || *stop.borrow() {
        return;
    }
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = tokio::io::split(upstream);
    let up_to_client = async {
        let r = tokio::io::copy(&mut ur, &mut cw).await;
        if r.is_err() {
            // Could be the proxy dying under us: check it right away.
            shared.check_now.notify_one();
        }
    };
    let client_to_up = async {
        let _ = tokio::io::copy(&mut cr, &mut uw).await;
        let _ = uw.shutdown().await;
        std::future::pending::<()>().await
    };
    let killed = async {
        loop {
            if state.changed().await.is_err() {
                return;
            }
            if matches!(*state.borrow(), GuardState::Tripped { .. }) {
                return;
            }
        }
    };
    tokio::select! {
        _ = up_to_client => {}
        _ = client_to_up => {}
        _ = killed => {}
        _ = stop.changed() => {}
    }
    // Dropping the halves closes both sockets.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clients::{PidLookup, SystemPidLookup, UnknownPid};
    use crate::doh::BoxFuture;
    use crate::endpoint::{Credentials, ProxyScheme};
    use crate::net::NetResult;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use tokio::task::JoinSet;

    /// Resolver that records every name asked and answers from a fixed table.
    #[derive(Default)]
    struct MockDoh {
        asked: Mutex<Vec<String>>,
        table: Vec<(&'static str, Ipv4Addr)>,
    }

    impl Resolver for MockDoh {
        fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, NetResult<Vec<Ipv4Addr>>> {
            Box::pin(async move {
                self.asked.lock().unwrap().push(host.to_string());
                Ok(self
                    .table
                    .iter()
                    .filter(|(h, _)| *h == host)
                    .map(|(_, ip)| *ip)
                    .collect())
            })
        }
    }

    /// In-process upstream proxy (SOCKS5 with login, or HTTP CONNECT). After the tunnel is
    /// set up it echoes bytes back. `down` makes it drop every new connection.
    struct MockUpstream {
        addr: SocketAddr,
        targets: Arc<Mutex<Vec<TargetAddr>>>,
        down: Arc<AtomicBool>,
        task: JoinHandle<()>,
    }

    impl MockUpstream {
        async fn start(scheme: ProxyScheme) -> Self {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            let targets = Arc::new(Mutex::new(Vec::new()));
            let down = Arc::new(AtomicBool::new(false));
            let (t, d) = (targets.clone(), down.clone());
            let task = tokio::spawn(async move {
                let mut conns = JoinSet::new();
                loop {
                    let (s, _) = l.accept().await.unwrap();
                    if d.load(Ordering::SeqCst) {
                        drop(s);
                        continue;
                    }
                    let t = t.clone();
                    conns.spawn(async move {
                        let _ = serve(s, scheme, t).await;
                    });
                }
                // `conns` (and every tunnel) is dropped when this task is aborted.
            });
            Self {
                addr,
                targets,
                down,
                task,
            }
        }

        fn endpoint(&self, scheme: ProxyScheme) -> ProxyEndpoint {
            ProxyEndpoint::new(
                scheme,
                "127.0.0.1",
                self.addr.port(),
                Some(Credentials::new("user", "pass")),
            )
        }
    }

    async fn serve(
        mut s: TcpStream,
        scheme: ProxyScheme,
        targets: Arc<Mutex<Vec<TargetAddr>>>,
    ) -> NetResult<()> {
        match scheme {
            ProxyScheme::Socks5 => {
                let mut g = [0u8; 2];
                s.read_exact(&mut g).await?;
                let mut m = vec![0u8; g[1] as usize];
                s.read_exact(&mut m).await?;
                if !m.contains(&2) {
                    s.write_all(&[5, 0xFF]).await?;
                    return Ok(());
                }
                s.write_all(&[5, 2]).await?;
                let _v = s.read_u8().await?;
                let ul = s.read_u8().await? as usize;
                let mut u = vec![0u8; ul];
                s.read_exact(&mut u).await?;
                let pl = s.read_u8().await? as usize;
                let mut p = vec![0u8; pl];
                s.read_exact(&mut p).await?;
                let ok = u == b"user" && p == b"pass";
                s.write_all(&[1, if ok { 0 } else { 1 }]).await?;
                if !ok {
                    return Ok(());
                }
                let mut h = [0u8; 3];
                s.read_exact(&mut h).await?;
                let t = read_socks_addr(&mut s).await?;
                targets.lock().unwrap().push(t);
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            }
            _ => {
                let head = read_http_head(&mut s).await?;
                assert!(head.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"));
                let auth = head.split_whitespace().nth(1).unwrap().to_string();
                targets
                    .lock()
                    .unwrap()
                    .push(parse_authority(&auth).unwrap());
                s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
            }
        }
        let (mut r, mut w) = s.into_split();
        tokio::io::copy(&mut r, &mut w).await?;
        Ok(())
    }

    fn mock_doh() -> Arc<MockDoh> {
        Arc::new(MockDoh {
            asked: Mutex::new(Vec::new()),
            table: vec![
                ("example.test", Ipv4Addr::new(203, 0, 113, 7)),
                ("lan.test", Ipv4Addr::new(192, 168, 0, 10)),
            ],
        })
    }

    async fn relay_for(up: &MockUpstream, scheme: ProxyScheme, doh: Arc<MockDoh>) -> Relay {
        let mut cfg = RelayConfig::new(up.endpoint(scheme), up.addr, doh);
        cfg.connect_timeout = Duration::from_secs(2);
        cfg.heartbeat = Duration::from_millis(100);
        Relay::start(cfg).await.unwrap()
    }

    /// SOCKS5 CONNECT through the relay; returns the reply code (0xEE when the relay closed
    /// the connection without a reply) and the stream.
    async fn socks_connect(relay: SocketAddr, target: &TargetAddr) -> (u8, TcpStream) {
        let mut c = TcpStream::connect(relay).await.unwrap();
        let code = async {
            c.write_all(&[5, 1, 0]).await?;
            let mut g = [0u8; 2];
            c.read_exact(&mut g).await?;
            assert_eq!(g, [5, 0]);
            let mut req = vec![5, 1, 0];
            crate::net::encode_socks_addr(&mut req, target).unwrap();
            c.write_all(&req).await?;
            let mut r = [0u8; 10];
            c.read_exact(&mut r).await?;
            Ok::<u8, std::io::Error>(r[1])
        }
        .await
        .unwrap_or(0xEE);
        (code, c)
    }

    async fn echo_ok(c: &mut TcpStream) {
        c.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(3), c.read_exact(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&b, b"ping");
    }

    async fn wait_until(mut f: impl FnMut() -> bool) {
        for _ in 0..100 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("condition not reached in 2 s");
    }

    #[tokio::test]
    async fn binds_loopback_and_reports_url() {
        let up = MockUpstream::start(ProxyScheme::Socks5).await;
        let relay = relay_for(&up, ProxyScheme::Socks5, mock_doh()).await;
        assert!(relay.local_addr().ip().is_loopback());
        assert_ne!(relay.local_addr().port(), 0);
        assert_eq!(
            relay.proxy_url(),
            format!("socks5://{}", relay.local_addr())
        );
        assert_eq!(relay.state(), GuardState::Armed);
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn hostname_resolved_via_doh_and_ip_sent_upstream() {
        let up = MockUpstream::start(ProxyScheme::Socks5).await;
        let doh = mock_doh();
        let relay = relay_for(&up, ProxyScheme::Socks5, doh.clone()).await;
        let (code, mut c) = socks_connect(
            relay.local_addr(),
            &TargetAddr::Domain("example.test".into(), 443),
        )
        .await;
        assert_eq!(code, 0);
        echo_ok(&mut c).await;
        assert_eq!(*doh.asked.lock().unwrap(), ["example.test"]);
        // The upstream got the DoH answer as an IPv4 literal, not the host name.
        assert_eq!(
            *up.targets.lock().unwrap(),
            [TargetAddr::Ip("203.0.113.7:443".parse().unwrap())]
        );
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn http_connect_client_and_http_upstream() {
        let up = MockUpstream::start(ProxyScheme::Http).await;
        let relay = relay_for(&up, ProxyScheme::Http, mock_doh()).await;
        let mut c = TcpStream::connect(relay.local_addr()).await.unwrap();
        c.write_all(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
            .await
            .unwrap();
        let head = read_http_head(&mut c).await.unwrap();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        echo_ok(&mut c).await;
        assert_eq!(
            *up.targets.lock().unwrap(),
            [TargetAddr::Ip("203.0.113.7:443".parse().unwrap())]
        );
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn plain_http_is_refused() {
        let up = MockUpstream::start(ProxyScheme::Socks5).await;
        let relay = relay_for(&up, ProxyScheme::Socks5, mock_doh()).await;
        let mut c = TcpStream::connect(relay.local_addr()).await.unwrap();
        c.write_all(b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .unwrap();
        let head = read_http_head(&mut c).await.unwrap();
        assert!(head.starts_with("HTTP/1.1 405"));
        assert!(up.targets.lock().unwrap().is_empty());
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn lan_ipv6_and_udp_are_blocked_and_reported() {
        let up = MockUpstream::start(ProxyScheme::Socks5).await;
        let relay = relay_for(&up, ProxyScheme::Socks5, mock_doh()).await;
        let mut ev = relay.events();
        for t in [
            TargetAddr::Ip("192.168.1.1:80".parse().unwrap()),
            TargetAddr::Ip("127.0.0.1:22".parse().unwrap()),
            TargetAddr::Ip("[2606:4700::1111]:443".parse().unwrap()),
            TargetAddr::Domain("lan.test".into(), 80),
            TargetAddr::Domain("localhost".into(), 80),
        ] {
            let (code, _) = socks_connect(relay.local_addr(), &t).await;
            assert_eq!(code, SOCKS_NOT_ALLOWED, "{t}");
            assert!(matches!(
                ev.recv().await.unwrap(),
                RelayEvent::Blocked { .. }
            ));
        }
        // UDP ASSOCIATE: refused with "command not supported".
        let mut c = TcpStream::connect(relay.local_addr()).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        c.read_exact(&mut [0u8; 2]).await.unwrap();
        c.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        let mut r = [0u8; 10];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(r[1], SOCKS_CMD_NOT_SUPPORTED);
        match ev.recv().await.unwrap() {
            RelayEvent::Blocked { reason, .. } => assert!(reason.contains("UDP")),
            other => panic!("{other:?}"),
        }
        assert!(
            up.targets.lock().unwrap().is_empty(),
            "nothing reached the upstream"
        );
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn kill_switch_cuts_clients_when_upstream_drops() {
        let up = MockUpstream::start(ProxyScheme::Socks5).await;
        let relay = relay_for(&up, ProxyScheme::Socks5, mock_doh()).await;
        let mut ev = relay.events();
        let (code, mut c) = socks_connect(
            relay.local_addr(),
            &TargetAddr::Domain("example.test".into(), 443),
        )
        .await;
        assert_eq!(code, 0);
        echo_ok(&mut c).await;

        // Kill the upstream proxy: listener and every tunnel socket go away.
        up.task.abort();
        let _ = up.task.await;

        // The open client connection is cut within the 1 s budget.
        let mut b = [0u8; 16];
        let r = tokio::time::timeout(Duration::from_secs(1), c.read(&mut b)).await;
        match r {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            other => panic!("client not cut: {other:?}"),
        }
        // The switch trips and new connections are refused, never sent direct.
        wait_until(|| relay.is_tripped()).await;
        assert!(matches!(
            ev.recv().await.unwrap(),
            RelayEvent::Tripped { .. }
        ));
        let (code, _) = socks_connect(
            relay.local_addr(),
            &TargetAddr::Domain("example.test".into(), 443),
        )
        .await;
        assert_ne!(code, 0);
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn kill_switch_cuts_idle_tunnel_and_rearms() {
        let up = MockUpstream::start(ProxyScheme::Socks5).await;
        let relay = relay_for(&up, ProxyScheme::Socks5, mock_doh()).await;
        let (code, mut c) = socks_connect(
            relay.local_addr(),
            &TargetAddr::Domain("example.test".into(), 443),
        )
        .await;
        assert_eq!(code, 0);
        echo_ok(&mut c).await;

        // Proxy stops serving new connections (the existing tunnel stays open on its side):
        // the heartbeat trips the switch and the relay cuts the live client anyway.
        up.down.store(true, Ordering::SeqCst);
        wait_until(|| relay.is_tripped()).await;
        let mut b = [0u8; 4];
        let r = tokio::time::timeout(Duration::from_secs(1), c.read(&mut b)).await;
        assert!(matches!(r, Ok(Ok(0)) | Ok(Err(_))), "client not cut: {r:?}");

        // Proxy back: the switch re-arms and traffic flows again.
        up.down.store(false, Ordering::SeqCst);
        wait_until(|| !relay.is_tripped()).await;
        let (code, mut c2) = socks_connect(
            relay.local_addr(),
            &TargetAddr::Domain("example.test".into(), 443),
        )
        .await;
        assert_eq!(code, 0);
        echo_ok(&mut c2).await;
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn starts_tripped_when_upstream_is_down() {
        let up = MockUpstream::start(ProxyScheme::Socks5).await;
        up.down.store(true, Ordering::SeqCst);
        let relay = relay_for(&up, ProxyScheme::Socks5, mock_doh()).await;
        assert!(relay.is_tripped());
        let answer = socks_greeting(relay.local_addr()).await;
        assert!(answer.is_none(), "tripped relay must not answer");
        relay.shutdown().await;
    }

    /// Greeting only; `None` when the relay closes without answering.
    async fn socks_greeting(relay: SocketAddr) -> Option<[u8; 2]> {
        let mut c = TcpStream::connect(relay).await.unwrap();
        let _ = c.write_all(&[5, 1, 0]).await;
        let mut g = [0u8; 2];
        match tokio::time::timeout(Duration::from_secs(2), c.read_exact(&mut g)).await {
            Ok(Ok(_)) => Some(g),
            _ => None,
        }
    }

    #[tokio::test]
    async fn wrong_login_trips_and_refuses() {
        let up = MockUpstream::start(ProxyScheme::Socks5).await;
        let mut ep = up.endpoint(ProxyScheme::Socks5);
        ep.auth = Some(Credentials::new("user", "WRONG"));
        let mut cfg = RelayConfig::new(ep, up.addr, mock_doh());
        cfg.heartbeat = Duration::from_millis(100);
        let relay = Relay::start(cfg).await.unwrap();
        assert!(
            matches!(relay.state(), GuardState::Tripped { reason } if !reason.contains("WRONG"))
        );
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_cuts_open_connections() {
        let up = MockUpstream::start(ProxyScheme::Socks5).await;
        let relay = relay_for(&up, ProxyScheme::Socks5, mock_doh()).await;
        let (_, mut c) = socks_connect(
            relay.local_addr(),
            &TargetAddr::Domain("example.test".into(), 443),
        )
        .await;
        echo_ok(&mut c).await;
        relay.shutdown().await;
        let r = tokio::time::timeout(Duration::from_secs(1), c.read(&mut [0u8; 4])).await;
        assert!(matches!(r, Ok(Ok(0)) | Ok(Err(_))), "{r:?}");
    }

    #[test]
    fn heartbeat_defaults_to_five_seconds_and_stays_configurable() {
        let ep = ProxyEndpoint::new(ProxyScheme::Socks5, "127.0.0.1", 1080, None);
        let cfg = RelayConfig::new(ep, "127.0.0.1:1080".parse().unwrap(), mock_doh());
        assert_eq!(cfg.heartbeat, Duration::from_secs(5));
        assert_eq!(DEFAULT_HEARTBEAT, Duration::from_secs(5));
        assert!(matches!(cfg.clients, AllowedClients::Any));
        let mut cfg = cfg;
        cfg.heartbeat = Duration::from_millis(250);
        assert_eq!(cfg.heartbeat, Duration::from_millis(250));
    }

    #[tokio::test]
    async fn default_heartbeat_still_cuts_live_traffic_within_one_second() {
        let up = MockUpstream::start(ProxyScheme::Socks5).await;
        let mut cfg = RelayConfig::new(up.endpoint(ProxyScheme::Socks5), up.addr, mock_doh());
        cfg.connect_timeout = Duration::from_secs(2);
        assert_eq!(cfg.heartbeat, DEFAULT_HEARTBEAT);
        let relay = Relay::start(cfg).await.unwrap();
        let target = TargetAddr::Domain("example.test".into(), 443);
        let (code, mut c) = socks_connect(relay.local_addr(), &target).await;
        assert_eq!(code, 0);
        echo_ok(&mut c).await;
        up.task.abort();
        let _ = up.task.await;
        let t0 = std::time::Instant::now();
        let r = tokio::time::timeout(Duration::from_secs(1), c.read(&mut [0u8; 4])).await;
        assert!(matches!(r, Ok(Ok(0)) | Ok(Err(_))), "client not cut: {r:?}");
        // The next request fails to open a tunnel, which trips the switch at once instead
        // of waiting for the 5 s heartbeat.
        let (code, _) = socks_connect(relay.local_addr(), &target).await;
        assert_ne!(code, 0);
        assert!(relay.is_tripped());
        // Tripped by the failed tunnel, well before the first 5 s heartbeat. (Windows takes
        // about 2 s to report a refused loopback connect, so allow for that.)
        assert!(
            t0.elapsed() < DEFAULT_HEARTBEAT - Duration::from_millis(500),
            "{:?}",
            t0.elapsed()
        );
        relay.shutdown().await;
    }

    /// PID lookup injected by the tests: always answers `pid`.
    struct FakeLookup(Option<u32>);
    impl PidLookup for FakeLookup {
        fn owning_pid(&self, client: SocketAddr, server: SocketAddr) -> Option<u32> {
            assert!(client.ip().is_loopback() && server.ip().is_loopback());
            self.0
        }
    }

    async fn relay_with_clients(up: &MockUpstream, clients: AllowedClients) -> Relay {
        let mut cfg = RelayConfig::new(up.endpoint(ProxyScheme::Socks5), up.addr, mock_doh())
            .with_clients(clients);
        cfg.connect_timeout = Duration::from_secs(2);
        cfg.heartbeat = Duration::from_millis(100);
        Relay::start(cfg).await.unwrap()
    }

    fn engine_tree(pid: Option<u32>, unknown: UnknownPid) -> AllowedClients {
        AllowedClients::ProcessTree {
            authorizer: Arc::new(|p: u32| p == 4242),
            lookup: Arc::new(FakeLookup(pid)),
            unknown,
        }
    }

    #[tokio::test]
    async fn authorized_engine_process_may_use_the_relay() {
        let up = MockUpstream::start(ProxyScheme::Socks5).await;
        let relay = relay_with_clients(&up, engine_tree(Some(4242), UnknownPid::Deny)).await;
        let (code, mut c) = socks_connect(
            relay.local_addr(),
            &TargetAddr::Domain("example.test".into(), 443),
        )
        .await;
        assert_eq!(code, 0);
        echo_ok(&mut c).await;
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn foreign_process_is_refused_and_reported() {
        let up = MockUpstream::start(ProxyScheme::Socks5).await;
        let relay = relay_with_clients(&up, engine_tree(Some(999), UnknownPid::Allow)).await;
        let mut ev = relay.events();
        assert!(socks_greeting(relay.local_addr()).await.is_none());
        match ev.recv().await.unwrap() {
            RelayEvent::Blocked { target, reason } => {
                assert!(target.contains("pid 999"), "{target}");
                assert!(reason.contains("not part of the profile"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
        assert!(up.targets.lock().unwrap().is_empty());
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn unknown_pid_is_decided_by_policy() {
        let up = MockUpstream::start(ProxyScheme::Socks5).await;
        let deny = relay_with_clients(&up, engine_tree(None, UnknownPid::Deny)).await;
        let mut ev = deny.events();
        assert!(socks_greeting(deny.local_addr()).await.is_none());
        match ev.recv().await.unwrap() {
            RelayEvent::Blocked { target, reason } => {
                assert!(target.contains("pid unknown"));
                assert!(reason.contains("could not be identified"));
            }
            other => panic!("{other:?}"),
        }
        deny.shutdown().await;
        let allow = relay_with_clients(&up, engine_tree(None, UnknownPid::Allow)).await;
        assert_eq!(socks_greeting(allow.local_addr()).await, Some([5, 0]));
        allow.shutdown().await;
    }

    /// Real OS lookup. On Windows the owning PID of the test's own connection is this
    /// process: allowed when authorized, refused when not. Elsewhere the lookup has no
    /// table, so the unknown-PID policy decides.
    #[tokio::test]
    async fn system_lookup_identifies_this_process() {
        let me = std::process::id();
        let up = MockUpstream::start(ProxyScheme::Socks5).await;
        let mine = AllowedClients::ProcessTree {
            authorizer: Arc::new(move |p: u32| p == me),
            lookup: Arc::new(SystemPidLookup),
            unknown: UnknownPid::Deny,
        };
        let not_mine = AllowedClients::ProcessTree {
            authorizer: Arc::new(move |p: u32| p != me),
            lookup: Arc::new(SystemPidLookup),
            unknown: UnknownPid::Deny,
        };
        let ok = relay_with_clients(&up, mine).await;
        let refused = relay_with_clients(&up, not_mine).await;
        let mut ev = refused.events();
        if cfg!(windows) {
            assert_eq!(socks_greeting(ok.local_addr()).await, Some([5, 0]));
            assert!(socks_greeting(refused.local_addr()).await.is_none());
            match ev.recv().await.unwrap() {
                RelayEvent::Blocked { target, .. } => {
                    assert!(target.contains(&format!("pid {me}")), "{target}")
                }
                other => panic!("{other:?}"),
            }
        } else {
            assert!(socks_greeting(ok.local_addr()).await.is_none());
            assert!(socks_greeting(refused.local_addr()).await.is_none());
        }
        ok.shutdown().await;
        refused.shutdown().await;
    }

    #[tokio::test]
    async fn upstream_resolution_never_uses_system_dns() {
        let doh = mock_doh();
        let ep = ProxyEndpoint::new(ProxyScheme::Socks5, "example.test", 1080, None);
        let sa = resolve_upstream(&ep, &*doh).await.unwrap();
        assert_eq!(sa, "203.0.113.7:1080".parse().unwrap());
        let lit = ProxyEndpoint::new(ProxyScheme::Socks5, "198.51.100.2", 1080, None);
        assert_eq!(
            resolve_upstream(&lit, &*doh).await.unwrap(),
            "198.51.100.2:1080".parse().unwrap()
        );
        assert_eq!(*doh.asked.lock().unwrap(), ["example.test"]);
        let none = ProxyEndpoint::new(ProxyScheme::Socks5, "missing.test", 1080, None);
        assert!(resolve_upstream(&none, &*doh).await.is_err());
    }
}
