//! vanta-proxy: Proxy Hub (F04) and the Network Guard local relay (F05).
//!
//! - [`endpoint`]: proxy endpoints and the bulk-import line grammar (`host:port`,
//!   `host:port:user:pass`, `user:pass@host:port`, `scheme://user:pass@host:port`).
//! - [`provider`]: username grammars for Bright Data, SOAX, Geonode, DataImpulse, Webshare
//!   and Thordata with a deterministic sticky session per profile.
//! - [`assign`]: "one proxy, one profile" warning as a pure function.
//! - [`state`]: online/offline state, the launch gate (enforced by `vanta-launcher`), the
//!   reachability probe and the SOCKS5 UDP ASSOCIATE capability probe.
//! - [`guard`]: Network Guard policy; kill switch and WebRTC rule have no "off" value.
//! - [`doh`]: DNS-over-HTTPS resolver (RFC 8484) behind the [`doh::Resolver`] trait.
//! - [`clients`]: who may use the relay (owning PID of the client connection checked
//!   against the profile's engine process tree; Windows `GetExtendedTcpTable`).
//! - [`echo`]: IP echo for health runs: the exit IP through the proxy, the PC's own public
//!   IP over a direct connection (compared only, never sent elsewhere or logged).
//! - [`relay`]: the tokio relay on `127.0.0.1:<ephemeral>` the engine points at, with the
//!   fail-closed kill switch.
//!
//! Local-only: the only outbound connections are to the user's configured proxy, the DoH
//! provider and, during a health run, the configured IP echo endpoint. TLS is rustls with the ring provider (no OpenSSL).

pub mod assign;
pub mod clients;
pub mod doh;
pub mod echo;
pub mod endpoint;
pub mod guard;
pub mod net;
pub mod provider;
pub mod relay;
pub mod state;

pub use assign::{check_assignment, shared_proxies, ProxyIdentity, SharedProxyWarning};
pub use clients::{
    AllowAll, AllowedClients, ClientAuthorizer, ClientVerdict, PidLookup, SystemPidLookup,
    UnknownPid,
};
pub use doh::{DohProvider, DohResolver, DohRoute, Resolver};
pub use echo::{EchoUrl, DEFAULT_IP_ECHO_URL};
pub use endpoint::{parse_line, parse_list, Credentials, ImportReport, ProxyEndpoint, ProxyScheme};
pub use guard::{GuardPolicy, KillSwitch, WebRtcPolicy};
pub use provider::{
    build_username, build_username_for, session_id, session_id_for, Provider, ProviderPreset,
    ProviderSpec, SessionKey, SessionParams, PROVIDER_PRESETS_VERIFIED_LIVE,
};
pub use relay::{resolve_upstream, GuardState, Relay, RelayConfig, RelayEvent, DEFAULT_HEARTBEAT};
pub use state::{probe, udp_associate_probe, LaunchBlock, OfflineReason, ProxyState, UdpSupport};
