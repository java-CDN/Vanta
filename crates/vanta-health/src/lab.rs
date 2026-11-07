//! One health run's local services: reflector, STUN responder and DNS leak test.

use crate::checks::fonts_to_test;
use crate::dns::{DnsLeakTest, LeakWatch};
use crate::input::HealthInput;
use crate::reflector::{Reflector, ReflectorConfig};
use crate::stun::StunResponder;
use rand::RngCore;
use std::time::Duration;
use vanta_types::Result;

/// Number of unique names in a leak test.
pub const DNS_TEST_NAMES: usize = 3;

pub struct HealthLab {
    pub reflector: Reflector,
    pub stun: StunResponder,
    pub dns: DnsLeakTest,
    pub token: String,
}

impl HealthLab {
    /// Start the STUN responder and the reflector for `input`'s persona.
    pub async fn start(input: &HealthInput) -> Result<Self> {
        let mut t = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut t);
        let token: String = t.iter().map(|b| format!("{b:02x}")).collect();
        let stun = StunResponder::start().await?;
        let dns = DnsLeakTest::new(DNS_TEST_NAMES);
        let reflector = Reflector::start(ReflectorConfig {
            token: token.clone(),
            stun: Some(stun.local_addr()),
            fonts: fonts_to_test(input),
            dns_names: dns.names.clone(),
        })
        .await?;
        Ok(Self {
            reflector,
            stun,
            dns,
            token,
        })
    }

    /// Extra engine switches for the health run: trust exactly the reflector's key, and
    /// open the probe page.
    pub fn engine_args(&self) -> Vec<String> {
        vec![
            format!(
                "--ignore-certificate-errors-spki-list={}",
                self.reflector.spki_pin()
            ),
            self.reflector.page_url(),
        ]
    }

    /// Wait for the page's report (up to `timeout`), then fill `input` with every capture.
    /// `watch` is the relay's resolver wrapper for this run.
    pub async fn collect(
        self,
        mut input: HealthInput,
        watch: &LeakWatch,
        timeout: Duration,
    ) -> HealthInput {
        let _ = self.reflector.wait_for_report(timeout).await;
        input = input.with_captures(&self.reflector.captures(), &self.token);
        input.stun = self.stun.requests();
        input.dns = Some(self.dns.evaluate(watch));
        self.reflector.shutdown().await;
        self.stun.shutdown().await;
        input
    }
}
