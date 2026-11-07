//! Who may use a profile's local relay (F05).
//!
//! Chromium cannot authenticate to a SOCKS5 proxy, so the relay on `127.0.0.1:<port>` cannot
//! ask its client for a password. Without a check, any local process (another profile's
//! engine, malware, a curious tool) could use the relay and exit through this profile's
//! proxy. Instead the relay asks the OS which process owns the client end of every accepted
//! TCP connection and accepts it only when that process belongs to the profile's engine
//! process tree.
//!
//! - [`PidLookup`] maps the client's local endpoint to its owning PID. On Windows
//!   [`SystemPidLookup`] reads `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL, AF_INET)`;
//!   elsewhere it returns `None` (developer builds only).
//! - [`ClientAuthorizer`] answers "is this PID part of the profile's engine tree?". The
//!   launcher implements it with the profile's Job Object (`IsProcessInJob`), which every
//!   child the engine spawns inherits. [`AllowAll`] is for tests and developer hosts.
//! - [`AllowedClients`] combines the two and decides what happens when the PID cannot be
//!   found ([`UnknownPid`]).

use std::net::SocketAddr;
use std::sync::Arc;

/// Decides whether a process may use the relay.
pub trait ClientAuthorizer: Send + Sync {
    fn allow(&self, pid: u32) -> bool;
}

/// Accepts every PID (tests, non-Windows developer hosts).
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl ClientAuthorizer for AllowAll {
    fn allow(&self, _pid: u32) -> bool {
        true
    }
}

impl<F: Fn(u32) -> bool + Send + Sync> ClientAuthorizer for F {
    fn allow(&self, pid: u32) -> bool {
        self(pid)
    }
}

/// Finds the PID that owns a TCP connection.
pub trait PidLookup: Send + Sync {
    /// `client` is the client's local endpoint (the relay's `peer_addr`), `server` the
    /// relay's listening address. `None` when the OS cannot tell.
    fn owning_pid(&self, client: SocketAddr, server: SocketAddr) -> Option<u32>;
}

/// The operating system's connection table. Windows only; `None` elsewhere.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemPidLookup;

impl PidLookup for SystemPidLookup {
    fn owning_pid(&self, client: SocketAddr, server: SocketAddr) -> Option<u32> {
        owning_pid(client, server)
    }
}

/// What to do when the client's PID cannot be determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnknownPid {
    /// Refuse the client (production on Windows).
    #[default]
    Deny,
    /// Accept the client (developer hosts without a connection table).
    Allow,
}

/// The relay's client policy.
#[derive(Clone, Default)]
pub enum AllowedClients {
    /// Any local process may connect. Only for tests and developer hosts; the launcher
    /// always sets [`AllowedClients::ProcessTree`] on Windows.
    #[default]
    Any,
    /// Only processes the authorizer accepts.
    ProcessTree {
        authorizer: Arc<dyn ClientAuthorizer>,
        lookup: Arc<dyn PidLookup>,
        unknown: UnknownPid,
    },
}

impl std::fmt::Debug for AllowedClients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AllowedClients::Any => f.write_str("Any"),
            AllowedClients::ProcessTree { unknown, .. } => f
                .debug_struct("ProcessTree")
                .field("unknown", unknown)
                .finish_non_exhaustive(),
        }
    }
}

/// Outcome of checking one client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientVerdict {
    Allowed {
        pid: Option<u32>,
    },
    /// The PID was found and the authorizer refused it.
    NotInProcessTree {
        pid: u32,
    },
    /// The PID could not be found and the policy denies unknown clients.
    UnknownProcess,
}

impl ClientVerdict {
    pub fn allowed(&self) -> bool {
        matches!(self, ClientVerdict::Allowed { .. })
    }

    /// Log-friendly reason for a refusal (`None` when allowed).
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            ClientVerdict::Allowed { .. } => None,
            ClientVerdict::NotInProcessTree { .. } => {
                Some("client process is not part of the profile's engine")
            }
            ClientVerdict::UnknownProcess => Some("client process could not be identified"),
        }
    }
}

impl AllowedClients {
    /// Production policy: the system connection table, unknown clients refused.
    pub fn process_tree(authorizer: Arc<dyn ClientAuthorizer>) -> Self {
        AllowedClients::ProcessTree {
            authorizer,
            lookup: Arc::new(SystemPidLookup),
            unknown: UnknownPid::Deny,
        }
    }

    /// Check one accepted connection. Blocking (reads the OS connection table).
    pub fn check(&self, client: SocketAddr, server: SocketAddr) -> ClientVerdict {
        match self {
            AllowedClients::Any => ClientVerdict::Allowed { pid: None },
            AllowedClients::ProcessTree {
                authorizer,
                lookup,
                unknown,
            } => match lookup.owning_pid(client, server) {
                Some(pid) if authorizer.allow(pid) => ClientVerdict::Allowed { pid: Some(pid) },
                Some(pid) => ClientVerdict::NotInProcessTree { pid },
                None if *unknown == UnknownPid::Allow => ClientVerdict::Allowed { pid: None },
                None => ClientVerdict::UnknownProcess,
            },
        }
    }
}

/// PID owning the IPv4 TCP connection `client -> server`, from the OS connection table.
#[cfg(windows)]
pub fn owning_pid(client: SocketAddr, server: SocketAddr) -> Option<u32> {
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let (SocketAddr::V4(c), SocketAddr::V4(s)) = (client, server) else {
        return None;
    };
    let mut size: u32 = 0;
    let mut buf: Vec<u64> = Vec::new();
    let mut filled = false;
    // The table can grow between the size query and the read: retry a few times.
    for _ in 0..4 {
        let ptr = if buf.is_empty() {
            std::ptr::null_mut()
        } else {
            buf.as_mut_ptr() as *mut std::ffi::c_void
        };
        // SAFETY: `ptr` is null (size query) or points at `size` writable bytes.
        let rc = unsafe {
            GetExtendedTcpTable(
                ptr,
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc == NO_ERROR && !buf.is_empty() {
            filled = true;
            break;
        }
        if rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR {
            return None;
        }
        // u64 elements keep the buffer 8-byte aligned; add slack for new rows.
        buf = vec![0u64; (size as usize + 1024).div_ceil(8)];
        size = (buf.len() * 8) as u32;
    }
    if !filled {
        return None;
    }
    let base = buf.as_ptr() as *const u8;
    // SAFETY: on NO_ERROR the buffer starts with MIB_TCPTABLE_OWNER_PID: a u32 count
    // followed by `count` rows (rows start at offset 4; each field is a u32).
    let count = unsafe { std::ptr::read_unaligned(base as *const u32) } as usize;
    let max = (buf.len() * 8 - 4) / std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
    let rows = base.wrapping_add(4) as *const MIB_TCPROW_OWNER_PID;
    let want_ip = u32::from_ne_bytes(c.ip().octets());
    let want_srv_ip = u32::from_ne_bytes(s.ip().octets());
    for i in 0..count.min(max) {
        // SAFETY: i < count and i < max, so the row lies inside the buffer.
        let r = unsafe { std::ptr::read_unaligned(rows.add(i)) };
        let lport = u16::from_be((r.dwLocalPort & 0xFFFF) as u16);
        let rport = u16::from_be((r.dwRemotePort & 0xFFFF) as u16);
        if r.dwLocalAddr == want_ip
            && lport == c.port()
            && r.dwRemoteAddr == want_srv_ip
            && rport == s.port()
        {
            return Some(r.dwOwningPid);
        }
    }
    None
}

/// Non-Windows hosts have no owner-PID connection table here; the policy decides.
#[cfg(not(windows))]
pub fn owning_pid(_client: SocketAddr, _server: SocketAddr) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedPid(Option<u32>);
    impl PidLookup for FixedPid {
        fn owning_pid(&self, _c: SocketAddr, _s: SocketAddr) -> Option<u32> {
            self.0
        }
    }

    fn addrs() -> (SocketAddr, SocketAddr) {
        (
            "127.0.0.1:50000".parse().unwrap(),
            "127.0.0.1:40000".parse().unwrap(),
        )
    }

    fn tree(pid: Option<u32>, unknown: UnknownPid) -> AllowedClients {
        AllowedClients::ProcessTree {
            authorizer: Arc::new(|p: u32| p == 42),
            lookup: Arc::new(FixedPid(pid)),
            unknown,
        }
    }

    #[test]
    fn any_allows_everything() {
        let (c, s) = addrs();
        assert!(AllowedClients::Any.check(c, s).allowed());
        assert!(AllowAll.allow(1));
    }

    #[test]
    fn process_tree_allows_member_and_denies_stranger() {
        let (c, s) = addrs();
        assert_eq!(
            tree(Some(42), UnknownPid::Deny).check(c, s),
            ClientVerdict::Allowed { pid: Some(42) }
        );
        let v = tree(Some(7), UnknownPid::Allow).check(c, s);
        assert_eq!(v, ClientVerdict::NotInProcessTree { pid: 7 });
        assert!(v.reason().unwrap().contains("not part"));
    }

    #[test]
    fn unknown_pid_follows_policy() {
        let (c, s) = addrs();
        assert_eq!(
            tree(None, UnknownPid::Deny).check(c, s),
            ClientVerdict::UnknownProcess
        );
        assert!(tree(None, UnknownPid::Allow).check(c, s).allowed());
        assert_eq!(UnknownPid::default(), UnknownPid::Deny);
    }

    #[test]
    fn ipv6_or_unknown_connection_has_no_pid() {
        let v6: SocketAddr = "[::1]:5".parse().unwrap();
        assert_eq!(owning_pid(v6, v6), None);
        // A connection that does not exist is never attributed to anyone.
        assert_eq!(
            owning_pid(
                "127.0.0.1:1".parse().unwrap(),
                "127.0.0.1:2".parse().unwrap()
            ),
            None
        );
    }
}
