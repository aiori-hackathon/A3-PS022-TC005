//! Benchmark runner and report writer (filled in Part 6).

/// Filters compared in every benchmark run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Baseline {
    /// No filtering at all.
    None,
    /// nftables meter + limit with the same thresholds.
    Nftables,
    /// Segfault XDP, drop only.
    XdpDrop,
    /// Segfault XDP, drop plus TC-slip.
    XdpSlip,
}

impl Baseline {
    /// Every baseline in bench order.
    pub const ALL: [Baseline; 4] = [
        Baseline::None,
        Baseline::Nftables,
        Baseline::XdpDrop,
        Baseline::XdpSlip,
    ];

    /// CLI name of the baseline.
    pub fn name(self) -> &'static str {
        match self {
            Baseline::None => "none",
            Baseline::Nftables => "nftables",
            Baseline::XdpDrop => "xdp-drop",
            Baseline::XdpSlip => "xdp-slip",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_baselines() {
        assert_eq!(Baseline::ALL.len(), 4);
        assert_eq!(Baseline::XdpSlip.name(), "xdp-slip");
    }
}
