//! Synthetic DNS flood generator (filled in Part 5).

/// The three PS-022 load scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// A: one source at max rate.
    Single,
    /// B: many spoofed sources, each under the per-source limit.
    Distributed,
    /// C: on/off bursts of random-subdomain queries.
    Pulse,
}

impl Scenario {
    /// Every scenario in bench order.
    pub const ALL: [Scenario; 3] = [Scenario::Single, Scenario::Distributed, Scenario::Pulse];

    /// CLI name of the scenario.
    pub fn name(self) -> &'static str {
        match self {
            Scenario::Single => "single",
            Scenario::Distributed => "distributed",
            Scenario::Pulse => "pulse",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique() {
        let names: Vec<_> = Scenario::ALL.iter().map(|s| s.name()).collect();
        assert_eq!(names, ["single", "distributed", "pulse"]);
    }
}
