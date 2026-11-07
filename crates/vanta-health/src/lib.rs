//! vanta-health: the local Health Check (F03).
//!
//! Everything runs on the user's PC; nothing is sent anywhere.
//!
//! - [`reflector`]: HTTPS reflector on `127.0.0.1` (rustls + ring, self-signed certificate
//!   generated at start with rcgen). It parses the raw TLS ClientHello itself
//!   ([`tls`], JA4), the HTTP/2 client start ([`h2`]: SETTINGS order, WINDOW_UPDATE,
//!   pseudo-header order) and HTTP/1.1 header order, serves the probe page and receives
//!   its report.
//! - [`stun`]: STUN Binding responder on `127.0.0.1/udp` (XOR-MAPPED-ADDRESS); a request
//!   reaching it means WebRTC sent raw UDP outside the proxy.
//! - [`dns`]: DNS leak test hook around the relay's `vanta_proxy::Resolver`.
//! - [`probe`]: the probe page (static HTML + inline JS, no external fetch, no CDP) and
//!   its JSON report.
//! - [`checks`]: 56 checks H01–H56 in the prototype's 8 areas, each a pure function of
//!   [`HealthInput`].
//! - [`report`]: weighted 0–100 score; any critical Fail caps it at 40; below 60 the launch
//!   is blocked (`vanta_launcher::MIN_HEALTH_SCORE`).
//! - [`lab`]: starts the reflector, STUN responder and leak test for one run and collects
//!   their captures.
//! - [`testkit`]: a fully consistent run for a persona, the baseline tests break.

pub mod checks;
pub mod dns;
pub mod h2;
pub mod input;
pub mod lab;
pub mod probe;
pub mod reflector;
pub mod report;
pub mod stun;
pub mod testkit;
pub mod tls;

pub use checks::{run_all, Area, CheckResult, Outcome, Severity, CHECKS};
pub use dns::{DnsLeakResult, DnsLeakTest, LeakWatch};
pub use input::{AsnKind, ExitInfo, GuardSnapshot, HealthInput, NetReference, TlsCapture};
pub use lab::HealthLab;
pub use probe::ProbeReport;
pub use reflector::{Captures, Reflector, ReflectorConfig};
pub use report::{evaluate, HealthReport, CRITICAL_CAP, LAUNCH_THRESHOLD};
pub use stun::StunResponder;
