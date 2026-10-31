//! segfault-bench: turns a directory of raw run outputs into results.csv, goodput.svg and report.md.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use segfault_bench::{Row, goodput_svg, latency_svg, parse_result, to_csv};

#[derive(Parser)]
#[command(
    name = "segfault-bench",
    version,
    about = "Summarize Segfault benchmark runs"
)]
struct Cli {
    /// Directory of raw run files named <baseline>-<scenario>.txt (holding a RESULT line).
    raw: PathBuf,
    /// Output directory for results.csv, goodput.svg and report.md.
    #[arg(short, long, default_value = "results")]
    out: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    fs::create_dir_all(&cli.out)?;
    let mut rows: Vec<Row> = Vec::new();

    for entry in fs::read_dir(&cli.raw).with_context(|| format!("read {}", cli.raw.display()))? {
        let path = entry?.path();
        if path.extension().map(|e| e != "txt").unwrap_or(true) {
            continue;
        }
        let stem = path.file_stem().unwrap().to_string_lossy().to_string();
        let baseline = stem.split('-').next().unwrap_or(&stem).to_string();
        let text = fs::read_to_string(&path)?;
        for line in text.lines() {
            let bl = baseline_of(&stem).unwrap_or_else(|| baseline.clone());
            if let Some(row) = parse_result(line, &bl) {
                rows.push(row);
            }
        }
    }
    let mut rows = aggregate(rows);
    rows.sort_by(|a, b| {
        (a.scenario.clone(), a.baseline.clone()).cmp(&(b.scenario.clone(), b.baseline.clone()))
    });

    let csv = to_csv(&rows);
    fs::write(cli.out.join("results.csv"), &csv)?;
    fs::write(cli.out.join("goodput.svg"), goodput_svg(&rows))?;
    fs::write(cli.out.join("latency.svg"), latency_svg(&rows))?;
    fs::write(cli.out.join("report.md"), report(&rows))?;
    println!(
        "wrote {} rows to {}/: results.csv, latency.svg, goodput.svg, report.md",
        rows.len(),
        cli.out.display()
    );
    Ok(())
}

/// Collapses repeated runs of the same (baseline, scenario) into one row of per-field medians.
fn aggregate(rows: Vec<Row>) -> Vec<Row> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<(String, String), Vec<Row>> = BTreeMap::new();
    for r in rows {
        groups
            .entry((r.baseline.clone(), r.scenario.clone()))
            .or_default()
            .push(r);
    }
    let med_u64 = |v: &mut Vec<u64>| -> u64 {
        v.sort_unstable();
        v.get(v.len() / 2).copied().unwrap_or(0)
    };
    let med_f64 = |v: &mut Vec<f64>| -> f64 {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v.get(v.len() / 2).copied().unwrap_or(0.0)
    };
    let mut out = Vec::new();
    for ((baseline, scenario), g) in groups {
        out.push(Row {
            baseline,
            scenario,
            flood_pps: g[0].flood_pps,
            goodput: med_f64(&mut g.iter().map(|r| r.goodput).collect()),
            collateral: med_f64(&mut g.iter().map(|r| r.collateral).collect()),
            p50_us: med_u64(&mut g.iter().map(|r| r.p50_us).collect()),
            p99_us: med_u64(&mut g.iter().map(|r| r.p99_us).collect()),
            probe_sent: med_u64(&mut g.iter().map(|r| r.probe_sent).collect()),
            probe_ok: med_u64(&mut g.iter().map(|r| r.probe_ok).collect()),
            admitted: 0,
            blocked: 0,
        });
    }
    out
}

/// Extracts a known baseline name from a file stem like "nftables-netdev-single".
fn baseline_of(stem: &str) -> Option<String> {
    for b in [
        "none",
        "nftables-netdev",
        "nftables",
        "fixed-xdp",
        "segfault",
    ] {
        if stem.starts_with(b) {
            return Some(b.to_string());
        }
    }
    None
}

/// Builds a Markdown report leading with latency and throughput (the metrics that separate the baselines).
fn report(rows: &[Row]) -> String {
    let mut s = String::from("# Segfault benchmark results\n\n");
    s.push_str(
        "A legitimate client sends DNS queries throughout each attack. Because a real resolver ",
    );
    s.push_str("falls back to TCP, almost every query *eventually* succeeds under every baseline — so the ");
    s.push_str("story is **latency and throughput**, not success rate.\n\n");
    s.push_str("- **p99 latency**: how slow the real client's queries get under attack (lower is better).\n");
    s.push_str("- **Throughput**: legitimate queries the client completed during the run (higher is better).\n\n");
    s.push_str("![Legitimate p99 latency under attack](latency.svg)\n\n");
    s.push_str("| Scenario | Baseline | p50 (us) | p99 (us) | Legit done | Goodput |\n");
    s.push_str("|---|---|---:|---:|---:|---:|\n");
    for r in rows {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {:.3} |\n",
            r.scenario, r.baseline, r.p50_us, r.p99_us, r.probe_ok, r.goodput
        ));
    }
    s.push_str("\n![Goodput under attack](goodput.svg)\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_prefix_matches_longest() {
        assert_eq!(
            baseline_of("nftables-netdev-pulse").as_deref(),
            Some("nftables-netdev")
        );
        assert_eq!(baseline_of("nftables-single").as_deref(), Some("nftables"));
        assert_eq!(
            baseline_of("segfault-adaptive").as_deref(),
            Some("segfault")
        );
    }
}
