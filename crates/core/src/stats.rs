//! Reads the per-CPU ingress and egress counters and names them for the CLI.

use anyhow::Result;

use crate::maps::open_pinned;
use crate::percpu_sum;

/// Ingress reason names, index-aligned with enum sf_reason.
pub const REASONS: [&str; 27] = [
    "pass_non_dns",
    "pass_tcp",
    "pass_frag",
    "pass_calm",
    "pass_t0",
    "pass_t1",
    "pass_t2",
    "pass_allow",
    "pass_fixed",
    "drop_deny",
    "drop_banned",
    "drop_malformed",
    "drop_source",
    "drop_prefix",
    "drop_pool",
    "drop_heavy",
    "tx_slip",
    "shadow_drop",
    "promote_t1",
    "promote_denied",
    "ban_issued",
    "cost_units",
    "queries",
    "queries_t0",
    "queries_t1",
    "queries_t2",
    "cookie_ok",
];

/// Egress observer counter names, index-aligned with enum sf_obs.
pub const OBS: [&str; 5] = ["resp", "nxdomain", "servfail", "tcp_resp", "proofs"];

/// One snapshot of the ingress counters.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    /// Each counter by reason index.
    pub c: Vec<u64>,
}

impl Stats {
    /// Reads every ingress counter from sf_stats.
    pub fn read() -> Result<Stats> {
        let map = open_pinned("sf_stats")?;
        let mut c = Vec::with_capacity(REASONS.len());
        for i in 0..REASONS.len() as u32 {
            c.push(percpu_sum(&map, i)?);
        }
        Ok(Stats { c })
    }

    /// Value of one named counter, or 0 if the name is unknown.
    pub fn get(&self, name: &str) -> u64 {
        REASONS
            .iter()
            .position(|n| *n == name)
            .and_then(|i| self.c.get(i).copied())
            .unwrap_or(0)
    }

    /// Total queries admitted across all tiers (pass_t0..t2 plus calm/fixed).
    pub fn admitted(&self) -> u64 {
        [
            "pass_calm",
            "pass_t0",
            "pass_t1",
            "pass_t2",
            "pass_fixed",
            "pass_allow",
        ]
        .iter()
        .map(|n| self.get(n))
        .sum()
    }

    /// Total queries dropped or slipped.
    pub fn blocked(&self) -> u64 {
        [
            "drop_deny",
            "drop_banned",
            "drop_malformed",
            "drop_source",
            "drop_prefix",
            "drop_pool",
            "drop_heavy",
            "tx_slip",
        ]
        .iter()
        .map(|n| self.get(n))
        .sum()
    }
}

/// One snapshot of the egress observer counters.
#[derive(Debug, Clone, Default)]
pub struct ObsStats {
    /// Each observer counter by index.
    pub c: Vec<u64>,
}

impl ObsStats {
    /// Reads every observer counter from sf_obs.
    pub fn read() -> Result<ObsStats> {
        let map = open_pinned("sf_obs")?;
        let mut c = Vec::with_capacity(OBS.len());
        for i in 0..OBS.len() as u32 {
            c.push(percpu_sum(&map, i)?);
        }
        Ok(ObsStats { c })
    }

    /// Value of one named observer counter.
    pub fn get(&self, name: &str) -> u64 {
        OBS.iter()
            .position(|n| *n == name)
            .and_then(|i| self.c.get(i).copied())
            .unwrap_or(0)
    }

    /// Fraction of responses that were NXDOMAIN, 0 when there are none.
    pub fn nxdomain_ratio(&self) -> f64 {
        let resp = self.get("resp");
        if resp == 0 {
            0.0
        } else {
            self.get("nxdomain") as f64 / resp as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_count_matches_enum() {
        // enum sf_reason has SF_REASON_MAX entries before the sentinel.
        assert_eq!(REASONS.len(), 27);
    }

    #[test]
    fn obs_count_matches_enum() {
        assert_eq!(OBS.len(), 5);
    }

    #[test]
    fn admitted_sums_named() {
        let mut s = Stats {
            c: vec![0; REASONS.len()],
        };
        s.c[REASONS.iter().position(|n| *n == "pass_t2").unwrap()] = 7;
        assert_eq!(s.admitted(), 7);
    }
}
