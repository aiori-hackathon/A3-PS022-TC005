//! Runtime policy: human-facing rates in `Policy`, packed to the 184-byte datapath `Config`.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// Number of trust tiers (T0 unknown, T1 returning, T2 proven).
pub const TIERS: usize = 3;

/// Admission algorithm selector, mirroring enum sf_algo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Algo {
    /// Segfault's trust-tiered, cost-weighted admission.
    Segfault,
    /// Fixed-threshold per-source + global baseline.
    Fixed,
}

impl Algo {
    /// Datapath integer value.
    pub fn raw(self) -> u32 {
        match self {
            Algo::Segfault => 0,
            Algo::Fixed => 1,
        }
    }
}

/// Defense mode, mirroring enum sf_mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Admit all, learn who returns politely.
    Calm,
    /// Enforce tier budgets and prefix fairness.
    Guard,
    /// Reserve capacity for proven clients; slip or drop unknown excess.
    Siege,
}

impl Mode {
    /// Datapath integer value.
    pub fn raw(self) -> u32 {
        match self {
            Mode::Calm => 0,
            Mode::Guard => 1,
            Mode::Siege => 2,
        }
    }

    /// Name for logs and the CLI.
    pub fn name(self) -> &'static str {
        match self {
            Mode::Calm => "calm",
            Mode::Guard => "guard",
            Mode::Siege => "siege",
        }
    }

    /// Parses a mode name.
    pub fn parse(s: &str) -> Result<Mode> {
        Ok(match s {
            "calm" => Mode::Calm,
            "guard" => Mode::Guard,
            "siege" => Mode::Siege,
            other => bail!("unknown mode '{other}'"),
        })
    }
}

/// Operator-facing policy in queries/sec and bursts, loaded from segfault.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Measured server capacity in queries/sec; pools are shares of it.
    pub capacity_qps: f64,
    /// Share of capacity reserved for proven (T2) clients, 0..1.
    pub proven_share: f64,
    /// Share of the remainder the unknown (T0) pool may use, 0..1.
    pub unknown_share: f64,
    /// Per-source query rate for returning sources (qps).
    pub src_qps: f64,
    /// Per-source burst allowance (queries).
    pub src_burst: f64,
    /// Per-prefix query rate (qps), shared across a /24 or /48.
    pub prefix_qps: f64,
    /// Per-prefix burst allowance (queries).
    pub prefix_burst: f64,
    /// Promotions per second from unknown to returning.
    pub promote_qps: f64,
    /// Promotion burst allowance.
    pub promote_burst: f64,
    /// Sketch count over the window above which an unknown source is "heavy".
    pub heavy_threshold: u32,
    /// Min/max sketch count for a well-behaved source eligible for promotion.
    pub promote_min: u32,
    /// Max sketch count for promotion.
    pub promote_max: u32,
    /// Strikes before a returning source is banned.
    pub strikes_ban: u32,
    /// Ban duration (seconds).
    pub ban_secs: f64,
    /// Proven-tier TTL (seconds).
    pub proven_ttl_secs: f64,
    /// Cost multipliers for ANY, DO-bit and large-response query types.
    pub cost_any: u32,
    /// Cost multiplier for the DNSSEC DO bit.
    pub cost_do: u32,
    /// Cost multiplier for large-response qtypes (TXT, DNSKEY, ...).
    pub cost_big: u32,
    /// Slip ratio: 1 in k over-budget unknown queries gets a TC reply (0 disables).
    pub slip_k: u32,
    /// Learn (promote) while in CALM mode.
    pub learn_in_calm: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            capacity_qps: 20000.0,
            proven_share: 0.5,
            unknown_share: 0.3,
            src_qps: 50.0,
            src_burst: 100.0,
            prefix_qps: 2000.0,
            prefix_burst: 4000.0,
            promote_qps: 200.0,
            promote_burst: 400.0,
            heavy_threshold: 2000,
            promote_min: 2,
            promote_max: 400,
            strikes_ban: 20,
            ban_secs: 30.0,
            proven_ttl_secs: 300.0,
            cost_any: 8,
            cost_do: 2,
            cost_big: 3,
            slip_k: 4,
            learn_in_calm: true,
        }
    }
}

/// ns per unit for a token-bucket rate; 0 rate means "no limit" (inc 0).
fn inc_ns(qps: f64) -> u64 {
    if qps <= 0.0 {
        0
    } else {
        (1_000_000_000.0 / qps).round() as u64
    }
}

/// burst as a time budget: burst units times the per-unit increment.
fn burst_ns(qps: f64, burst: f64) -> u64 {
    (inc_ns(qps) as f64 * burst).round() as u64
}

/// Packed datapath config; field order matches struct sf_config exactly.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub algo: u32,
    pub mode: u32,
    pub shadow: u32,
    pub slip_k: u32,
    pub epoch: u32,
    pub t0_heavy: u32,
    pub promote_min: u32,
    pub promote_max: u32,
    pub strikes_ban: u32,
    pub cost_any: u32,
    pub cost_do: u32,
    pub cost_big: u32,
    pub learn_in_calm: u32,
    pub pool_ns: [u64; TIERS],
    pub pool_burst_ns: [u64; TIERS],
    pub src_ns: [u64; TIERS],
    pub src_burst_ns: u64,
    pub pfx_ns: u64,
    pub pfx_burst_ns: u64,
    pub promo_ns: u64,
    pub promo_burst_ns: u64,
    pub ban_ns: u64,
    pub t2_ttl_ns: u64,
}

impl Config {
    /// Builds a datapath config from an operator policy, algorithm and mode.
    pub fn from_policy(p: &Policy, algo: Algo, mode: Mode, shadow: bool, epoch: u32) -> Config {
        let cap = p.capacity_qps.max(1.0);
        let proven = cap * p.proven_share.clamp(0.0, 1.0);
        let rest = (cap - proven).max(0.0);
        let unknown = rest * p.unknown_share.clamp(0.0, 1.0);
        let returning = (rest - unknown).max(cap * 0.05);
        // SIEGE squeezes unknown (T0) and per-source hard while leaving proven (T2) untouched,
        // so a flood of many low-rate unknown sources cannot crowd out clients that have proven themselves.
        let (t0_scale, src_scale, pfx_scale) = match mode {
            Mode::Siege => (0.25, 0.5, 0.5),
            _ => (1.0, 1.0, 1.0),
        };
        // Pools are indexed by tier: T0 unknown, T1 returning, T2 proven.
        let pool_qps = [unknown * t0_scale, returning, proven];
        let mut pool_ns = [0u64; TIERS];
        let mut pool_burst_ns = [0u64; TIERS];
        for t in 0..TIERS {
            pool_ns[t] = inc_ns(pool_qps[t]);
            pool_burst_ns[t] = burst_ns(pool_qps[t], pool_qps[t] * 0.2 + 50.0);
        }
        // Per-source rate: unknown sources have no T1 entry, so index T1 is the one used.
        let mut src_ns = [0u64; TIERS];
        src_ns[1] = inc_ns(p.src_qps * src_scale);
        src_ns[2] = inc_ns(p.src_qps * 4.0);
        Config {
            algo: algo.raw(),
            mode: mode.raw(),
            shadow: shadow as u32,
            slip_k: p.slip_k,
            epoch,
            t0_heavy: p.heavy_threshold,
            promote_min: p.promote_min,
            promote_max: p.promote_max,
            strikes_ban: p.strikes_ban,
            cost_any: p.cost_any,
            cost_do: p.cost_do,
            cost_big: p.cost_big,
            learn_in_calm: p.learn_in_calm as u32,
            pool_ns,
            pool_burst_ns,
            src_ns,
            src_burst_ns: burst_ns(p.src_qps, p.src_burst),
            pfx_ns: inc_ns(p.prefix_qps * pfx_scale),
            pfx_burst_ns: burst_ns(p.prefix_qps, p.prefix_burst),
            promo_ns: inc_ns(p.promote_qps),
            promo_burst_ns: burst_ns(p.promote_qps, p.promote_burst),
            ban_ns: (p.ban_secs * 1e9) as u64,
            t2_ttl_ns: (p.proven_ttl_secs * 1e9) as u64,
        }
    }

    /// Serializes to the 184-byte little-endian layout the datapath expects.
    pub fn to_bytes(&self) -> [u8; crate::CONFIG_SIZE] {
        let mut b = [0u8; crate::CONFIG_SIZE];
        let mut o = 0usize;
        let w32 = |b: &mut [u8], o: &mut usize, v: u32| {
            b[*o..*o + 4].copy_from_slice(&v.to_le_bytes());
            *o += 4;
        };
        for v in [
            self.algo,
            self.mode,
            self.shadow,
            self.slip_k,
            self.epoch,
            self.t0_heavy,
            self.promote_min,
            self.promote_max,
            self.strikes_ban,
            self.cost_any,
            self.cost_do,
            self.cost_big,
            self.learn_in_calm,
            0,
        ] {
            w32(&mut b, &mut o, v);
        }
        let w64 = |b: &mut [u8], o: &mut usize, v: u64| {
            b[*o..*o + 8].copy_from_slice(&v.to_le_bytes());
            *o += 8;
        };
        for v in self.pool_ns {
            w64(&mut b, &mut o, v);
        }
        for v in self.pool_burst_ns {
            w64(&mut b, &mut o, v);
        }
        for v in self.src_ns {
            w64(&mut b, &mut o, v);
        }
        for v in [
            self.src_burst_ns,
            self.pfx_ns,
            self.pfx_burst_ns,
            self.promo_ns,
            self.promo_burst_ns,
            self.ban_ns,
            self.t2_ttl_ns,
        ] {
            w64(&mut b, &mut o, v);
        }
        debug_assert_eq!(o, crate::CONFIG_SIZE);
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_is_184_bytes() {
        let c = Config::from_policy(&Policy::default(), Algo::Segfault, Mode::Guard, false, 0);
        assert_eq!(c.to_bytes().len(), 184);
    }

    #[test]
    fn higher_rate_is_smaller_increment() {
        assert!(inc_ns(100.0) < inc_ns(10.0));
        assert_eq!(inc_ns(0.0), 0);
    }

    #[test]
    fn proven_pool_gets_its_share() {
        let p = Policy::default();
        let c = Config::from_policy(&p, Algo::Segfault, Mode::Siege, false, 1);
        // Proven share is largest here, so its per-unit increment is smallest.
        assert!(c.pool_ns[2] < c.pool_ns[0]);
    }

    #[test]
    fn siege_throttles_unknown_not_proven() {
        let p = Policy::default();
        let guard = Config::from_policy(&p, Algo::Segfault, Mode::Guard, false, 1);
        let siege = Config::from_policy(&p, Algo::Segfault, Mode::Siege, false, 1);
        // SIEGE slows the unknown pool and per-source (larger ns per unit) ...
        assert!(siege.pool_ns[0] > guard.pool_ns[0]);
        assert!(siege.src_ns[1] > guard.src_ns[1]);
        assert!(siege.pfx_ns > guard.pfx_ns);
        // ... but leaves the proven pool untouched.
        assert_eq!(siege.pool_ns[2], guard.pool_ns[2]);
    }

    #[test]
    fn mode_round_trips() {
        assert_eq!(Mode::parse("siege").unwrap().raw(), 2);
    }
}
