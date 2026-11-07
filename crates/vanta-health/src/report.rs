//! Scoring: 0–100, weighted by severity; a critical Fail caps the score at 40; a score
//! below 60 blocks launch.

use crate::checks::{run_all, Area, CheckResult, Outcome, Severity};
use crate::input::HealthInput;
use serde::Serialize;

/// Highest score possible while any critical check fails.
pub const CRITICAL_CAP: u8 = 40;
/// Scores below this block launch (same value as `vanta_launcher::MIN_HEALTH_SCORE`).
pub const LAUNCH_THRESHOLD: u8 = 60;

/// Points a result takes off 100.
pub fn penalty(sev: Severity, out: Outcome) -> u32 {
    match (sev, out) {
        (_, Outcome::Pass) => 0,
        (Severity::Critical, Outcome::Fail) => 15,
        (Severity::Critical, Outcome::Warn) => 5,
        (Severity::Warn, Outcome::Fail) => 8,
        (Severity::Warn, Outcome::Warn) => 3,
        (Severity::Info, Outcome::Fail) => 3,
        (Severity::Info, Outcome::Warn) => 1,
    }
}

/// Outcome of one health run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthReport {
    pub score: u8,
    pub results: Vec<CheckResult>,
    /// `score < LAUNCH_THRESHOLD`.
    pub blocked: bool,
}

impl HealthReport {
    pub fn from_results(results: Vec<CheckResult>) -> Self {
        let lost: u32 = results.iter().map(|r| penalty(r.severity, r.outcome)).sum();
        let mut score = 100u32.saturating_sub(lost) as u8;
        if results
            .iter()
            .any(|r| r.severity == Severity::Critical && r.outcome == Outcome::Fail)
        {
            score = score.min(CRITICAL_CAP);
        }
        Self {
            score,
            blocked: score < LAUNCH_THRESHOLD,
            results,
        }
    }

    /// Ids of failed critical checks.
    pub fn critical_failures(&self) -> Vec<&'static str> {
        self.results
            .iter()
            .filter(|r| r.severity == Severity::Critical && r.outcome == Outcome::Fail)
            .map(|r| r.id)
            .collect()
    }

    /// Results that are not Pass, worst first.
    pub fn problems(&self) -> Vec<&CheckResult> {
        let mut v: Vec<&CheckResult> = self
            .results
            .iter()
            .filter(|r| r.outcome != Outcome::Pass)
            .collect();
        v.sort_by_key(|r| std::cmp::Reverse(penalty(r.severity, r.outcome)));
        v
    }

    pub fn result(&self, id: &str) -> Option<&CheckResult> {
        self.results.iter().find(|r| r.id == id || r.key == id)
    }

    /// (area, passed, total) per area.
    pub fn by_area(&self) -> Vec<(Area, usize, usize)> {
        Area::ALL
            .iter()
            .map(|a| {
                let in_area = self.results.iter().filter(|r| r.area == *a);
                let total = in_area.clone().count();
                let ok = in_area.filter(|r| r.outcome == Outcome::Pass).count();
                (*a, ok, total)
            })
            .collect()
    }

    /// Value for `vanta_launcher::Preflight::health_score`.
    pub fn preflight_score(&self) -> Option<u8> {
        Some(self.score)
    }
}

/// Run all 56 checks and score them.
pub fn evaluate(input: &HealthInput) -> HealthReport {
    HealthReport::from_results(run_all(input))
}
