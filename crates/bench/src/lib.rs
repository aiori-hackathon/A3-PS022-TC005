//! Benchmark model: baselines, one result row per (baseline, scenario), CSV and SVG output.
#![allow(clippy::write_with_newline)]

use std::fmt::Write as _;

/// Filters compared in every benchmark run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Baseline {
    /// No filtering at all.
    None,
    /// nftables meter + limit at prerouting.
    Nftables,
    /// nftables at the netdev ingress hook with conntrack off.
    NftablesNetdev,
    /// A plain fixed-threshold per-source + global XDP limiter (the typical rival design).
    FixedXdp,
    /// Segfault: trust-tiered, cost-weighted XDP.
    Segfault,
}

impl Baseline {
    /// Every baseline in bench order.
    pub const ALL: [Baseline; 5] = [
        Baseline::None,
        Baseline::Nftables,
        Baseline::NftablesNetdev,
        Baseline::FixedXdp,
        Baseline::Segfault,
    ];

    /// CLI/CSV name of the baseline.
    pub fn name(self) -> &'static str {
        match self {
            Baseline::None => "none",
            Baseline::Nftables => "nftables",
            Baseline::NftablesNetdev => "nftables-netdev",
            Baseline::FixedXdp => "fixed-xdp",
            Baseline::Segfault => "segfault",
        }
    }

    /// Human label for charts.
    pub fn label(self) -> &'static str {
        match self {
            Baseline::None => "No filter",
            Baseline::Nftables => "nftables",
            Baseline::NftablesNetdev => "nftables (netdev)",
            Baseline::FixedXdp => "Fixed XDP",
            Baseline::Segfault => "Segfault",
        }
    }

    /// Parses a baseline name.
    pub fn parse(s: &str) -> Option<Baseline> {
        Baseline::ALL.into_iter().find(|b| b.name() == s)
    }
}

/// One measured row: a (baseline, scenario) pair with its goodput and latency.
#[derive(Debug, Clone)]
pub struct Row {
    pub baseline: String,
    pub scenario: String,
    pub flood_pps: u64,
    pub goodput: f64,
    pub collateral: f64,
    pub p50_us: u64,
    pub p99_us: u64,
    pub probe_sent: u64,
    pub probe_ok: u64,
    pub admitted: u64,
    pub blocked: u64,
}

/// Parses a `RESULT ...` line emitted by segfault-gen into a partial row.
pub fn parse_result(line: &str, baseline: &str) -> Option<Row> {
    if !line.starts_with("RESULT ") {
        return None;
    }
    let mut f = std::collections::HashMap::new();
    for tok in line.split_whitespace().skip(1) {
        if let Some((k, v)) = tok.split_once('=') {
            f.insert(k.to_string(), v.to_string());
        }
    }
    Some(Row {
        baseline: baseline.to_string(),
        scenario: f.get("scenario")?.clone(),
        flood_pps: f.get("flood_pps")?.parse().ok()?,
        goodput: f.get("goodput")?.parse().ok()?,
        collateral: f.get("collateral")?.parse().ok()?,
        p50_us: f.get("p50_us")?.parse().ok()?,
        p99_us: f.get("p99_us")?.parse().ok()?,
        probe_sent: f
            .get("probe_sent")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        probe_ok: f.get("probe_ok").and_then(|v| v.parse().ok()).unwrap_or(0),
        admitted: 0,
        blocked: 0,
    })
}

/// Serializes rows as CSV with a header.
pub fn to_csv(rows: &[Row]) -> String {
    let mut s = String::from(
        "baseline,scenario,flood_pps,goodput,collateral,p50_us,p99_us,probe_sent,probe_ok,admitted,blocked\n",
    );
    for r in rows {
        let _ = writeln!(
            s,
            "{},{},{},{:.4},{:.4},{},{},{},{},{},{}",
            r.baseline,
            r.scenario,
            r.flood_pps,
            r.goodput,
            r.collateral,
            r.p50_us,
            r.p99_us,
            r.probe_sent,
            r.probe_ok,
            r.admitted,
            r.blocked
        );
    }
    s
}

/// Draws a grouped bar chart of legitimate p99 latency (log scale, lower is better) as an SVG.
pub fn latency_svg(rows: &[Row]) -> String {
    let scenarios: Vec<String> = dedup(rows.iter().map(|r| r.scenario.clone()));
    let baselines: Vec<String> = dedup(rows.iter().map(|r| r.baseline.clone()));
    let (w, h) = (900.0, 460.0);
    let (ml, mr, mt, mb) = (70.0, 180.0, 40.0, 70.0);
    let pw = w - ml - mr;
    let ph = h - mt - mb;
    let gw = pw / scenarios.len().max(1) as f64;
    let bw = (gw * 0.8) / baselines.len().max(1) as f64;
    let colors = ["#9aa0a6", "#5b8ff9", "#2f6fb0", "#f2994a", "#27ae60"];
    // Log scale from 10us to 1s (1e1..1e6 microseconds).
    let (lmin, lmax) = (1.0f64, 6.0f64);
    let logpos = |us: u64| -> f64 {
        let v = (us.max(1) as f64).log10().clamp(lmin, lmax);
        (v - lmin) / (lmax - lmin)
    };
    let mut s = format!(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {w} {h}' font-family='system-ui,sans-serif'>\n\
         <rect width='{w}' height='{h}' fill='white'/>\n\
         <text x='{ml}' y='22' font-size='16' font-weight='600'>Legitimate query p99 latency under attack (log scale — lower is better)</text>\n"
    );
    for (i, label) in ["10us", "100us", "1ms", "10ms", "100ms", "1s"]
        .iter()
        .enumerate()
    {
        let frac = i as f64 / 5.0;
        let y = mt + ph * (1.0 - frac);
        let _ = write!(
            s,
            "<line x1='{ml}' y1='{y:.1}' x2='{:.1}' y2='{y:.1}' stroke='#eee'/>\
             <text x='{:.1}' y='{:.1}' font-size='11' text-anchor='end' fill='#666'>{label}</text>\n",
            ml + pw,
            ml - 6.0,
            y + 4.0
        );
    }
    for (si, sc) in scenarios.iter().enumerate() {
        let gx = ml + si as f64 * gw;
        let _ = write!(
            s,
            "<text x='{:.1}' y='{:.1}' font-size='12' text-anchor='middle'>{sc}</text>\n",
            gx + gw / 2.0,
            mt + ph + 20.0
        );
        for (bi, bl) in baselines.iter().enumerate() {
            let us = rows
                .iter()
                .find(|r| &r.scenario == sc && &r.baseline == bl)
                .map(|r| r.p99_us)
                .unwrap_or(0);
            let x = gx + gw * 0.1 + bi as f64 * bw;
            let bh = ph * logpos(us);
            let y = mt + ph - bh;
            let _ = write!(
                s,
                "<rect x='{x:.1}' y='{y:.1}' width='{:.1}' height='{bh:.1}' fill='{}'/>\n",
                bw * 0.92,
                colors[bi % colors.len()]
            );
        }
    }
    for (bi, bl) in baselines.iter().enumerate() {
        let y = mt + bi as f64 * 22.0;
        let _ = write!(
            s,
            "<rect x='{:.1}' y='{y:.1}' width='14' height='14' fill='{}'/>\
             <text x='{:.1}' y='{:.1}' font-size='12'>{bl}</text>\n",
            w - mr + 10.0,
            colors[bi % colors.len()],
            w - mr + 30.0,
            y + 12.0
        );
    }
    s.push_str("</svg>\n");
    s
}

/// Draws a grouped bar chart of legitimate goodput by scenario and baseline as a standalone SVG.
pub fn goodput_svg(rows: &[Row]) -> String {
    let scenarios: Vec<String> = dedup(rows.iter().map(|r| r.scenario.clone()));
    let baselines: Vec<String> = dedup(rows.iter().map(|r| r.baseline.clone()));
    let (w, h) = (900.0, 460.0);
    let (ml, mr, mt, mb) = (60.0, 180.0, 40.0, 70.0);
    let pw = w - ml - mr;
    let ph = h - mt - mb;
    let gw = pw / scenarios.len().max(1) as f64;
    let bw = (gw * 0.8) / baselines.len().max(1) as f64;
    let colors = ["#9aa0a6", "#5b8ff9", "#2f6fb0", "#f2994a", "#27ae60"];

    let mut s = format!(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {w} {h}' font-family='system-ui,sans-serif'>\n\
         <rect width='{w}' height='{h}' fill='white'/>\n\
         <text x='{tx}' y='22' font-size='16' font-weight='600'>Legitimate goodput under attack (1.0 = all real queries answered)</text>\n",
        tx = ml
    );
    // Y gridlines at 0, .25, .5, .75, 1.0.
    for i in 0..=4 {
        let frac = i as f64 / 4.0;
        let y = mt + ph * (1.0 - frac);
        let _ = write!(
            s,
            "<line x1='{ml}' y1='{y:.1}' x2='{:.1}' y2='{y:.1}' stroke='#eee'/>\
                <text x='{:.1}' y='{:.1}' font-size='11' text-anchor='end' fill='#666'>{:.2}</text>\n",
            ml + pw,
            ml - 6.0,
            y + 4.0,
            frac
        );
    }
    for (si, sc) in scenarios.iter().enumerate() {
        let gx = ml + si as f64 * gw;
        let _ = write!(
            s,
            "<text x='{:.1}' y='{:.1}' font-size='12' text-anchor='middle'>{}</text>\n",
            gx + gw / 2.0,
            mt + ph + 20.0,
            sc
        );
        for (bi, bl) in baselines.iter().enumerate() {
            let val = rows
                .iter()
                .find(|r| &r.scenario == sc && &r.baseline == bl)
                .map(|r| r.goodput)
                .unwrap_or(0.0);
            let x = gx + gw * 0.1 + bi as f64 * bw;
            let bh = ph * val.clamp(0.0, 1.0);
            let y = mt + ph - bh;
            let _ = write!(
                s,
                "<rect x='{x:.1}' y='{y:.1}' width='{:.1}' height='{bh:.1}' fill='{}'/>\n",
                bw * 0.92,
                colors[bi % colors.len()]
            );
        }
    }
    // Legend.
    for (bi, bl) in baselines.iter().enumerate() {
        let y = mt + bi as f64 * 22.0;
        let _ = write!(
            s,
            "<rect x='{:.1}' y='{y:.1}' width='14' height='14' fill='{}'/>\
                <text x='{:.1}' y='{:.1}' font-size='12'>{}</text>\n",
            w - mr + 10.0,
            colors[bi % colors.len()],
            w - mr + 30.0,
            y + 12.0,
            bl
        );
    }
    s.push_str("</svg>\n");
    s
}

/// Stable de-dup preserving first-seen order.
fn dedup(it: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = Vec::new();
    for x in it {
        if !seen.contains(&x) {
            seen.push(x);
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_baselines() {
        assert_eq!(Baseline::ALL.len(), 5);
        assert_eq!(Baseline::Segfault.name(), "segfault");
    }

    #[test]
    fn parses_a_result_line() {
        let line = "RESULT scenario=single flood_pps=50000 flood_sent=1 probe_sent=100 \
                    probe_ok=98 goodput=0.9800 collateral=0.0200 p50_us=300 p99_us=900";
        let r = parse_result(line, "segfault").unwrap();
        assert_eq!(r.scenario, "single");
        assert_eq!(r.flood_pps, 50000);
        assert!((r.goodput - 0.98).abs() < 1e-6);
        assert_eq!(r.p99_us, 900);
    }

    #[test]
    fn csv_has_header_and_rows() {
        let rows = vec![Row {
            baseline: "segfault".into(),
            scenario: "pulse".into(),
            flood_pps: 1000,
            goodput: 0.99,
            collateral: 0.01,
            p50_us: 10,
            p99_us: 20,
            probe_sent: 6,
            probe_ok: 5,
            admitted: 5,
            blocked: 1,
        }];
        let csv = to_csv(&rows);
        assert!(csv.starts_with("baseline,scenario"));
        assert!(csv.contains("segfault,pulse,1000"));
    }

    #[test]
    fn latency_svg_wellformed() {
        let rows = vec![Row {
            baseline: "segfault".into(),
            scenario: "distributed".into(),
            flood_pps: 1,
            goodput: 1.0,
            collateral: 0.0,
            p50_us: 100,
            p99_us: 3000,
            probe_sent: 700,
            probe_ok: 700,
            admitted: 0,
            blocked: 0,
        }];
        assert!(latency_svg(&rows).starts_with("<svg"));
    }

    #[test]
    fn svg_is_wellformed() {
        let rows = vec![Row {
            baseline: "none".into(),
            scenario: "single".into(),
            flood_pps: 1,
            goodput: 0.2,
            collateral: 0.8,
            p50_us: 1,
            p99_us: 1,
            probe_sent: 1,
            probe_ok: 0,
            admitted: 0,
            blocked: 0,
        }];
        let svg = goodput_svg(&rows);
        assert!(svg.starts_with("<svg"));
        assert!(svg.trim_end().ends_with("</svg>"));
    }
}
