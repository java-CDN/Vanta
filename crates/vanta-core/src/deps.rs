//! What the orchestration needs from the outside world, as traits, so tests can inject
//! an in-process engine and resolver. Production values: [`Deps::production`].

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use vanta_launcher::{relay_clients, spawn_in_job, EngineProcess, KillOnCloseJob};
use vanta_proxy::{AllowedClients, DohResolver, DohRoute, GuardPolicy, ProxyEndpoint, Resolver};
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
}

impl Deps {
    pub fn production() -> Self {
        Self {
            spawner: Arc::new(OsSpawner),
            net: Arc::new(DohNet::default()),
            clients: RelayClients::ProcessTree,
        }
    }
}
