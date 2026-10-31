//! segfault-gen: drives flood scenarios and the legitimate prober against the lab server.

mod flood;
mod flood6;

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use segfault_gen::{Scenario, probe};

/// Parses an optional 32-hex-char cookie secret.
fn parse_secret(hex: Option<String>) -> Result<Option<[u8; 16]>> {
    match hex {
        None => Ok(None),
        Some(h) => {
            let h = h.trim();
            if h.len() != 32 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
                bail!("cookie-secret must be 32 hex chars");
            }
            let mut k = [0u8; 16];
            for i in 0..16 {
                k[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
            }
            Ok(Some(k))
        }
    }
}

#[derive(Parser)]
#[command(name = "segfault-gen", version, about = "Segfault lab load generator")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a flood plus a concurrent legitimate prober and print goodput.
    Run {
        /// Server IP (the target VM's lab address).
        #[arg(long)]
        server: IpAddr,
        /// Scenario: single, distributed, pulse, adaptive, prefix-spoof, water-torture.
        #[arg(long)]
        scenario: String,
        /// Flood packets per second.
        #[arg(long, default_value_t = 50000)]
        pps: u64,
        /// Legitimate prober queries per second.
        #[arg(long, default_value_t = 200)]
        probe_qps: u32,
        /// Run duration in seconds.
        #[arg(long, default_value_t = 20)]
        secs: u64,
        /// Deterministic seed.
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Per-source pps the adaptive attacker keeps each flow under.
        #[arg(long, default_value_t = 45)]
        adaptive_src_pps: u64,
        /// Number of parallel sender threads (raise to push past one thread's pps ceiling).
        #[arg(long, default_value_t = 1)]
        threads: u64,
    },
    /// Ramp load to find the server's knee capacity (suggests capacity_qps for segfault.toml).
    Calibrate {
        #[arg(long)]
        server: IpAddr,
        /// Highest qps to try.
        #[arg(long, default_value_t = 50000)]
        max_qps: u32,
        /// Seconds per step.
        #[arg(long, default_value_t = 2)]
        step_secs: u64,
    },
    /// Run only the legitimate prober (baseline goodput, no attack).
    Probe {
        #[arg(long)]
        server: IpAddr,
        #[arg(long, default_value_t = 200)]
        qps: u32,
        #[arg(long, default_value_t = 20)]
        secs: u64,
        /// If set (32 hex chars), send a valid RFC 9018 cookie with every query.
        #[arg(long)]
        cookie_secret: Option<String>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Calibrate {
            server,
            max_qps,
            step_secs,
        } => calibrate(server, max_qps, step_secs),
        Cmd::Run {
            server,
            scenario,
            pps,
            probe_qps,
            secs,
            seed,
            adaptive_src_pps,
            threads,
        } => {
            let sc = Scenario::parse(&scenario)
                .ok_or_else(|| anyhow::anyhow!("unknown scenario '{scenario}'"))?;
            run(
                server,
                sc,
                pps,
                probe_qps,
                secs,
                seed,
                adaptive_src_pps,
                threads,
            )
        }
        Cmd::Probe {
            server,
            qps,
            secs,
            cookie_secret,
        } => {
            let stop = Arc::new(AtomicBool::new(false));
            let secret = parse_secret(cookie_secret)?;
            let r =
                segfault_gen::probe_cookie(server, qps, Duration::from_secs(secs), stop, secret)?;
            println!(
                "probe: sent={} ok={} lost={} success={:.3} p50={}us p99={}us",
                r.sent,
                r.ok_udp + r.ok_tcp,
                r.lost,
                r.success_rate(),
                r.pct_us(0.5),
                r.pct_us(0.99)
            );
            Ok(())
        }
    }
}

/// Ramps offered load in steps and reports the highest rate the server serves cleanly.
fn calibrate(server: IpAddr, max_qps: u32, step_secs: u64) -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let mut knee = 0u32;
    let mut qps = 1000u32;
    println!("calibrating {server} (success >= 0.99 and p99 < 20ms is 'clean')");
    while qps <= max_qps {
        let r = probe(server, qps, Duration::from_secs(step_secs), stop.clone())?;
        let p99 = r.pct_us(0.99);
        let clean = r.success_rate() >= 0.99 && p99 < 20_000;
        println!(
            "  {qps:>6} qps -> success {:.3}, p99 {}us {}",
            r.success_rate(),
            p99,
            if clean { "OK" } else { "<-- knee" }
        );
        if clean {
            knee = qps;
        } else {
            break;
        }
        qps = (qps as f64 * 1.5) as u32;
    }
    println!(
        "suggested capacity_qps = {} (set it in configs/segfault.toml)",
        knee.max(1000)
    );
    Ok(())
}

/// Launches the flood and prober together, prints a one-line result for the bench to parse.
#[allow(clippy::too_many_arguments)]
fn run(
    server: IpAddr,
    sc: Scenario,
    pps: u64,
    probe_qps: u32,
    secs: u64,
    seed: u64,
    asp: u64,
    threads: u64,
) -> Result<()> {
    // Refuse to run a "no-attack" benchmark silently when the flood cannot be sent.
    flood::preflight(server)?;
    let dur = Duration::from_secs(secs);
    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicU64::new(0));

    let fstop = stop.clone();
    let fsent = sent.clone();
    let fh =
        thread::spawn(move || flood::flood(server, sc, pps, dur, seed, asp, threads, fsent, fstop));

    // Give the flood a 1s head start so the controller is already reacting.
    thread::sleep(Duration::from_secs(1));
    let probe_dur = dur.saturating_sub(Duration::from_secs(1));
    let r = probe(server, probe_qps, probe_dur, stop.clone())?;

    stop.store(true, Ordering::Relaxed);
    let flooded = match fh.join() {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => bail!("flood failed: {e:#}"),
        Err(_) => bail!("flood thread panicked"),
    };

    println!(
        "RESULT scenario={} flood_pps={} flood_sent={} probe_sent={} probe_ok={} \
         goodput={:.4} collateral={:.4} p50_us={} p99_us={}",
        sc.name(),
        pps,
        flooded,
        r.sent,
        r.ok_udp + r.ok_tcp,
        r.success_rate(),
        1.0 - r.success_rate(),
        r.pct_us(0.5),
        r.pct_us(0.99)
    );
    Ok(())
}
