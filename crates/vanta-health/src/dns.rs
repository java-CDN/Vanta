//! DNS leak test hook.
//!
//! The profile's relay resolves every host name with its [`Resolver`] (DoH through the
//! proxy). [`LeakWatch`] wraps that resolver and records each name it is asked for. A
//! health run generates unique, never-before-seen names under [`LEAK_SUFFIX`]
//! ([`DnsLeakTest::new`]); the probe page requests them through the relay. If DNS goes
//! through DoH, every unique name shows up at the watch. A name that does not show up was
//! resolved somewhere else (the system resolver, a local cache, the engine itself) or
//! never reached the relay, and either way DNS is not provably going through DoH.
//!
//! The names end in a reserved `.invalid` suffix (RFC 6761), so even a leaked query
//! reveals nothing and resolves nowhere.

use rand::RngCore;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use vanta_proxy::doh::BoxFuture;
use vanta_proxy::net::NetResult;
use vanta_proxy::Resolver;

pub const LEAK_SUFFIX: &str = "leak.vanta.invalid";

/// Resolver wrapper that records every name before passing it to the inner resolver.
pub struct LeakWatch {
    inner: Arc<dyn Resolver>,
    seen: Mutex<Vec<String>>,
}

impl LeakWatch {
    pub fn new(inner: Arc<dyn Resolver>) -> Self {
        Self {
            inner,
            seen: Mutex::new(Vec::new()),
        }
    }

    /// Names asked so far, lower-cased, in order.
    pub fn seen(&self) -> Vec<String> {
        self.seen.lock().expect("leak watch").clone()
    }
}

impl Resolver for LeakWatch {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, NetResult<Vec<Ipv4Addr>>> {
        self.seen
            .lock()
            .expect("leak watch")
            .push(host.to_ascii_lowercase());
        self.inner.resolve(host)
    }
}

/// One leak test: a set of unique names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsLeakTest {
    pub names: Vec<String>,
}

/// Result of a leak test, an input of the health checks.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct DnsLeakResult {
    /// Unique names the page asked for.
    pub expected: usize,
    /// Names the DoH resolver saw.
    pub via_doh: usize,
    /// Names that never reached DoH.
    pub missing: Vec<String>,
}

impl DnsLeakResult {
    pub fn all_via_doh(&self) -> bool {
        self.expected > 0 && self.missing.is_empty()
    }
}

impl DnsLeakTest {
    /// `n` random names such as `k3h9x2m4q7z1.leak.vanta.invalid`.
    pub fn new(n: usize) -> Self {
        let mut rng = rand::thread_rng();
        let names = (0..n)
            .map(|_| {
                let mut b = [0u8; 8];
                rng.fill_bytes(&mut b);
                let label: String = b.iter().map(|x| format!("{x:02x}")).collect();
                format!("{label}.{LEAK_SUFFIX}")
            })
            .collect();
        Self { names }
    }

    /// Compare the test's names with what the DoH watch saw.
    pub fn evaluate(&self, watch: &LeakWatch) -> DnsLeakResult {
        let seen = watch.seen();
        let missing: Vec<String> = self
            .names
            .iter()
            .filter(|n| !seen.contains(&n.to_ascii_lowercase()))
            .cloned()
            .collect();
        DnsLeakResult {
            expected: self.names.len(),
            via_doh: self.names.len() - missing.len(),
            missing,
        }
    }

    /// Ask every name through `resolver` directly (the relay's own path). Used when the
    /// engine is not involved, e.g. to confirm the relay's resolver is the DoH watch.
    pub async fn run_through(&self, resolver: &dyn Resolver) {
        for n in &self.names {
            // NXDOMAIN is expected for these names; only the lookup itself matters.
            let _ = resolver.resolve(n).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock DoH: answers nothing (NXDOMAIN-like), counts calls.
    struct MockDoh(Mutex<usize>);
    impl Resolver for MockDoh {
        fn resolve<'a>(&'a self, _h: &'a str) -> BoxFuture<'a, NetResult<Vec<Ipv4Addr>>> {
            *self.0.lock().unwrap() += 1;
            Box::pin(async { Ok(vec![]) })
        }
    }

    #[tokio::test]
    async fn names_through_doh_pass() {
        let doh = Arc::new(MockDoh(Mutex::new(0)));
        let watch = LeakWatch::new(doh.clone());
        let t = DnsLeakTest::new(4);
        assert_eq!(t.names.len(), 4);
        assert!(t.names.iter().all(|n| n.ends_with(".leak.vanta.invalid")));
        t.run_through(&watch).await;
        let r = t.evaluate(&watch);
        assert!(r.all_via_doh(), "{r:?}");
        assert_eq!(r.via_doh, 4);
        assert_eq!(*doh.0.lock().unwrap(), 4, "inner resolver was used");
    }

    #[tokio::test]
    async fn names_resolved_elsewhere_are_missing() {
        let watch = LeakWatch::new(Arc::new(MockDoh(Mutex::new(0))));
        let t = DnsLeakTest::new(3);
        // Only one name reaches DoH; the others were resolved by someone else.
        let _ = watch.resolve(&t.names[0].to_uppercase()).await;
        let r = t.evaluate(&watch);
        assert!(!r.all_via_doh());
        assert_eq!(r.missing.len(), 2);
        assert_eq!(r.via_doh, 1);
        assert!(
            !DnsLeakResult::default().all_via_doh(),
            "no test is no pass"
        );
    }

    #[test]
    fn names_are_unique() {
        let t = DnsLeakTest::new(50);
        let mut v = t.names.clone();
        v.sort();
        v.dedup();
        assert_eq!(v.len(), 50);
    }
}
