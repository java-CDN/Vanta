//! What the orchestration needs from the outside world, as traits, so tests can inject
//! an in-process engine and resolver. Production values: [`Deps::production`].

use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use vanta_launcher::{relay_clients, spawn_in_job, EngineProcess, KillOnCloseJob};
use vanta_proxy::doh::BoxFuture;
use vanta_proxy::echo::{exit_ip_via_proxy, host_ip_direct, primary_local_ip};
use vanta_proxy::inspect::{
    ip_info_via_proxy, speed_via_proxy, udp_check, Check, IpInfo, SpeedResult, UdpResult,
    SPEED_MAX_BYTES,
};
use vanta_proxy::net::NetResult;
use vanta_proxy::{
    AllowedClients, DohResolver, DohRoute, EchoUrl, GuardPolicy, ProxyEndpoint, Resolver,
};
use vanta_types::Result;

/// Starts the engine. Production: [`OsSpawner`] (suspended, in the job, then resumed).
pub trait EngineSpawner: Send + Sync {
    fn spawn(
        &self,
        exe: &Path,
        args: &[OsString],
        job: &KillOnCloseJob,
    ) -> Result<Box<dyn EngineProcess>>;
}

/// The real engine process: `CREATE_SUSPENDED`, assigned to the profile's Job Object,
/// then resumed (`vanta_launcher::spawn_in_job`). Refused off Windows.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsSpawner;

impl EngineSpawner for OsSpawner {
    fn spawn(
        &self,
        exe: &Path,
        args: &[OsString],
        job: &KillOnCloseJob,
    ) -> Result<Box<dyn EngineProcess>> {
        let mut cmd = Command::new(exe);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Ok(Box::new(spawn_in_job(cmd, job)?))
    }
}

/// Name resolution for the relay. Never the system resolver.
pub trait NetFactory: Send + Sync {
    /// Resolves the proxy's own host name (DoH, direct to the provider).
    fn bootstrap(&self, policy: &GuardPolicy) -> Arc<dyn Resolver>;
    /// Resolves the engine's target names (DoH routed through the proxy).
    fn relay_resolver(
        &self,
        policy: &GuardPolicy,
        proxy: &ProxyEndpoint,
        proxy_addr: SocketAddr,
    ) -> Arc<dyn Resolver>;
}

/// Production resolvers: `vanta_proxy::DohResolver` with the profile's DoH provider.
#[derive(Debug, Clone, Copy)]
pub struct DohNet {
    pub timeout: Duration,
}

impl Default for DohNet {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
        }
    }
}

impl NetFactory for DohNet {
    fn bootstrap(&self, policy: &GuardPolicy) -> Arc<dyn Resolver> {
        Arc::new(DohResolver::new(
            policy.doh.clone(),
            DohRoute::Direct,
            self.timeout,
        ))
    }
    fn relay_resolver(
        &self,
        policy: &GuardPolicy,
        proxy: &ProxyEndpoint,
        proxy_addr: SocketAddr,
    ) -> Arc<dyn Resolver> {
        Arc::new(DohResolver::new(
            policy.doh.clone(),
            DohRoute::ViaProxy {
                proxy: proxy.clone(),
                addr: proxy_addr,
            },
            self.timeout,
        ))
    }
}

/// IP measurements for a health run (F03). Production: [`HttpsIpEcho`].
pub trait IpEcho: Send + Sync {
    /// The profile's exit IP: the echo endpoint asked through the upstream proxy
    /// (resolved to `proxy_addr`).
    fn exit_ip<'a>(
        &'a self,
        url: &'a EchoUrl,
        proxy: &'a ProxyEndpoint,
        proxy_addr: SocketAddr,
        timeout: Duration,
    ) -> BoxFuture<'a, NetResult<IpAddr>>;
    /// The PC's own addresses, for comparison only: its public IP from a direct request to
    /// the echo endpoint (host name resolved with `resolver`) and its local address on the
    /// default route. Empty when nothing could be measured.
    fn host_ips<'a>(
        &'a self,
        url: &'a EchoUrl,
        resolver: Arc<dyn Resolver>,
        timeout: Duration,
    ) -> BoxFuture<'a, Vec<IpAddr>>;
}

/// The real IP echo over HTTPS (`vanta_proxy::echo`).
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpsIpEcho;

impl IpEcho for HttpsIpEcho {
    fn exit_ip<'a>(
        &'a self,
        url: &'a EchoUrl,
        proxy: &'a ProxyEndpoint,
        proxy_addr: SocketAddr,
        timeout: Duration,
    ) -> BoxFuture<'a, NetResult<IpAddr>> {
        Box::pin(exit_ip_via_proxy(url, proxy, proxy_addr, timeout))
    }

    fn host_ips<'a>(
        &'a self,
        url: &'a EchoUrl,
        resolver: Arc<dyn Resolver>,
        timeout: Duration,
    ) -> BoxFuture<'a, Vec<IpAddr>> {
        Box::pin(async move {
            let mut ips = Vec::new();
            let public = host_ip_direct(url, &*resolver, timeout).await.ok();
            ips.extend(public);
            // Route lookup only (no packet): towards the echo answer, else a public anchor.
            let toward = public.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)));
            if let Some(local) = primary_local_ip(toward) {
                if !ips.contains(&local) {
                    ips.push(local);
                }
            }
            ips
        })
    }
}

/// The Proxy Hub's extended checks (`vanta_proxy::inspect`). Every call goes through
/// `proxy` (resolved to `proxy_addr`). Production: [`ProxyInspector`]. Blocklist lookups use
/// [`NetFactory::relay_resolver`] (DoH through the proxy).
pub trait ProxyChecker: Send + Sync {
    /// Exit IP, ASN, organisation and country from the IP information endpoint.
    fn ip_info<'a>(
        &'a self,
        url: &'a EchoUrl,
        proxy: &'a ProxyEndpoint,
        proxy_addr: SocketAddr,
        timeout: Duration,
    ) -> BoxFuture<'a, NetResult<IpInfo>>;
    /// Bounded timed download.
    fn speed<'a>(
        &'a self,
        url: &'a EchoUrl,
        proxy: &'a ProxyEndpoint,
        proxy_addr: SocketAddr,
        timeout: Duration,
    ) -> BoxFuture<'a, NetResult<SpeedResult>>;
    /// SOCKS5 UDP ASSOCIATE support.
    fn udp<'a>(
        &'a self,
        proxy: &'a ProxyEndpoint,
        proxy_addr: SocketAddr,
        timeout: Duration,
    ) -> BoxFuture<'a, Check<UdpResult>>;
}

/// The real checks over HTTPS / SOCKS5 (`vanta_proxy::inspect`).
#[derive(Debug, Clone, Copy, Default)]
pub struct ProxyInspector;

impl ProxyChecker for ProxyInspector {
    fn ip_info<'a>(
        &'a self,
        url: &'a EchoUrl,
        proxy: &'a ProxyEndpoint,
        proxy_addr: SocketAddr,
        timeout: Duration,
    ) -> BoxFuture<'a, NetResult<IpInfo>> {
        Box::pin(ip_info_via_proxy(url, proxy, proxy_addr, timeout))
    }

    fn speed<'a>(
        &'a self,
        url: &'a EchoUrl,
        proxy: &'a ProxyEndpoint,
        proxy_addr: SocketAddr,
        timeout: Duration,
    ) -> BoxFuture<'a, NetResult<SpeedResult>> {
        Box::pin(speed_via_proxy(
            url,
            proxy,
            proxy_addr,
            timeout,
            SPEED_MAX_BYTES,
        ))
    }

    fn udp<'a>(
        &'a self,
        proxy: &'a ProxyEndpoint,
        proxy_addr: SocketAddr,
        timeout: Duration,
    ) -> BoxFuture<'a, Check<UdpResult>> {
        Box::pin(udp_check(proxy, proxy_addr, timeout))
    }
}

/// Who may use a profile's relay.
#[derive(Clone)]
pub enum RelayClients {
    /// Production and the only value release builds can name: a client is accepted only
    /// when the OS connection table says its process is in the profile's Job Object;
    /// unknown PIDs are refused.
    ProcessTree,
    /// Developer hosts only (feature `dev-any-client`): any local process.
    #[cfg(feature = "dev-any-client")]
    DevAnyClient,
    /// Tests: build the policy from the profile's job.
    #[cfg(test)]
    Custom(Arc<dyn Fn(Arc<KillOnCloseJob>) -> AllowedClients + Send + Sync>),
}

impl RelayClients {
    pub fn build(&self, job: Arc<KillOnCloseJob>) -> AllowedClients {
        match self {
            RelayClients::ProcessTree => relay_clients(job),
            #[cfg(feature = "dev-any-client")]
            RelayClients::DevAnyClient => AllowedClients::Any,
            #[cfg(test)]
            RelayClients::Custom(f) => f(job),
        }
    }
}

/// Everything injectable.
#[derive(Clone)]
pub struct Deps {
    pub spawner: Arc<dyn EngineSpawner>,
    pub net: Arc<dyn NetFactory>,
    pub clients: RelayClients,
    pub ip_echo: Arc<dyn IpEcho>,
    pub checker: Arc<dyn ProxyChecker>,
}

impl Deps {
    pub fn production() -> Self {
        Self {
            spawner: Arc::new(OsSpawner),
            net: Arc::new(DohNet::default()),
            clients: RelayClients::ProcessTree,
            ip_echo: Arc::new(HttpsIpEcho),
            checker: Arc::new(ProxyInspector),
        }
    }
}
