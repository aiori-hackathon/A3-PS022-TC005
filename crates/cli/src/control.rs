//! Controller loop: watches the observer, moves between CALM/GUARD/SIEGE, rotates the sketch epoch.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use segfault_core::config::{Config, Mode};
use segfault_core::stats::{ObsStats, Stats};
use segfault_core::{Algo, Policy, maps};

/// Reads config, flips only the mode field, writes it back (used by `segfault mode`).
pub fn set_mode_only(mode: Mode) -> Result<()> {
    // The controller owns the full config; here we rebuild from defaults-free current policy.
    // Simford: read the pinned config bytes, patch the mode word, write back.
    let map = maps::open_pinned("sf_cfg")?;
    use libbpf_rs::{MapCore, MapFlags};
    if let Some(v) = map.lookup(&0u32.to_ne_bytes(), MapFlags::ANY)? {
        let mut b = v;
        b[4..8].copy_from_slice(&mode.raw().to_le_bytes());
        map.update(&0u32.to_ne_bytes(), &b, MapFlags::ANY)?;
    }
    Ok(())
}

/// Installs a Ctrl-C handler that flips the flag.
fn on_signal(flag: Arc<AtomicBool>) {
    let f = flag.clone();
    let _ = ctrlc_lite(move || f.store(true, Ordering::Relaxed));
}

/// Minimal SIGINT/SIGTERM handler without extra crates.
fn ctrlc_lite<F: Fn() + Send + Sync + 'static>(f: F) -> Result<()> {
    use std::sync::OnceLock;
    static CB: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();
    let _ = CB.set(Box::new(f));
    extern "C" fn handler(_sig: libc::c_int) {
        if let Some(cb) = CB.get() {
            cb();
        }
    }
    unsafe {
        libc::signal(libc::SIGINT, handler as *const () as usize);
        libc::signal(libc::SIGTERM, handler as *const () as usize);
    }
    Ok(())
}

/// Runs the controller until `seconds` elapse (0 = until signalled).
pub fn run(policy: Policy, algo: Algo, shadow: bool, seconds: u64) -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    on_signal(stop.clone());

    let cap = policy.capacity_qps.max(1.0);
    let mut mode = Mode::Guard;
    let mut epoch = 1u32;
    let mut stable_since = Instant::now();
    let mut last = Stats::read().unwrap_or_default();
    let mut last_t = Instant::now();
    let start = Instant::now();
    let tick = Duration::from_millis(500);
    println!(
        "controller: capacity={:.0} qps, tick 500ms (Ctrl-C to detach)",
        cap
    );

    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(tick);
        if seconds > 0 && start.elapsed() >= Duration::from_secs(seconds) {
            break;
        }
        let now = Stats::read().unwrap_or_default();
        let obs = ObsStats::read().unwrap_or_default();
        let dt = last_t.elapsed().as_secs_f64().max(1e-3);
        let admit_rate = (now.admitted().saturating_sub(last.admitted())) as f64 / dt;
        let block_rate = (now.blocked().saturating_sub(last.blocked())) as f64 / dt;
        let ratio = response_ratio(&obs);

        let want = decide(mode, admit_rate, block_rate, cap, ratio, &mut stable_since);
        if want != mode {
            let total = admit_rate + block_rate;
            println!(
                "mode {} -> {} (admit={:.0}qps, dropping {:.0}% of {:.0}k pps, resp_ratio={:.2})",
                mode.name(),
                want.name(),
                admit_rate,
                100.0 * block_rate / total.max(1.0),
                total / 1000.0,
                ratio
            );
            mode = want;
            stable_since = Instant::now();
        }

        // Rotate the sketch window roughly every 5s so estimates track recent traffic.
        if start.elapsed().as_secs().is_multiple_of(5) {
            epoch = epoch.wrapping_add(1);
        }
        refresh_zone_costs(&policy);

        let cfg = Config::from_policy(&policy, algo, mode, shadow, epoch);
        let _ = maps::write_config(&cfg);
        last = now;
        last_t = Instant::now();
    }
    println!("controller stopped; datapath stays attached (run `segfault down` to remove)");
    Ok(())
}

/// Response ratio proxy: 1.0 when there is no evidence of failure.
fn response_ratio(obs: &ObsStats) -> f64 {
    let resp = obs.get("resp");
    if resp == 0 {
        return 1.0;
    }
    let bad = obs.get("servfail");
    1.0 - (bad as f64 / resp as f64)
}

/// Mode state machine with hysteresis: escalate fast, de-escalate only after 10s stable.
/// Attack is signalled by server errors (ratio) OR by how much offered traffic we are dropping.
fn decide(
    cur: Mode,
    admit: f64,
    blocked: f64,
    cap: f64,
    ratio: f64,
    stable_since: &mut Instant,
) -> Mode {
    let load = admit / cap;
    let total = admit + blocked;
    let drop_frac = if total > 1.0 { blocked / total } else { 0.0 };
    // Dropping most of the offered traffic is itself proof of a volumetric flood.
    let busy = load >= 0.7 || drop_frac > 0.2 || ratio < 0.98;
    let under_attack = drop_frac > 0.6 || ratio < 0.85;
    let escalate = match cur {
        Mode::Calm => busy.then_some(Mode::Guard),
        Mode::Guard => under_attack.then_some(Mode::Siege),
        Mode::Siege => None,
    };
    if let Some(up) = escalate {
        return up;
    }
    let calm_ok = load < 0.5 && drop_frac < 0.05 && ratio >= 0.99;
    let guard_ok = drop_frac < 0.15 && ratio >= 0.95;
    let settled = stable_since.elapsed() >= Duration::from_secs(10);
    match cur {
        Mode::Siege if settled && guard_ok => Mode::Guard,
        Mode::Guard if settled && calm_ok => Mode::Calm,
        _ => {
            if !matches!(cur, Mode::Calm) && !calm_ok {
                *stable_since = Instant::now();
            }
            cur
        }
    }
}

/// Reads per-zone response stats and raises the cost multiplier for zones with high NXDOMAIN.
fn refresh_zone_costs(policy: &Policy) {
    use libbpf_rs::{MapCore, MapFlags};
    let Ok(stats) = maps::open_pinned("sf_zone_stats") else {
        return;
    };
    for key in stats.keys() {
        if let Ok(Some(v)) = stats.lookup(&key, MapFlags::ANY) {
            if v.len() < 16 {
                continue;
            }
            let resp = u64::from_ne_bytes(v[0..8].try_into().unwrap());
            let nx = u64::from_ne_bytes(v[8..16].try_into().unwrap());
            if resp < 50 {
                continue;
            }
            let nx_ratio = nx as f64 / resp as f64;
            // Heavy NXDOMAIN implies a random-subdomain flood: make those zones cost more.
            let mult = if nx_ratio > 0.5 {
                policy.cost_big.max(4)
            } else if nx_ratio > 0.2 {
                2
            } else {
                1
            };
            if let Ok(zc) = maps::open_pinned("sf_zone_cost") {
                let zone = u32::from_ne_bytes(key[0..4].try_into().unwrap_or([0; 4]));
                let _ = zc.update(&zone.to_ne_bytes(), &mult.to_ne_bytes(), MapFlags::ANY);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalates_to_siege_when_dropping_most_traffic() {
        let mut t = Instant::now();
        // Admitting a little, dropping a lot (volumetric flood) -> SIEGE, even with a healthy ratio.
        let m = decide(Mode::Guard, 2_000.0, 180_000.0, 20_000.0, 1.0, &mut t);
        assert_eq!(m, Mode::Siege);
    }

    #[test]
    fn stays_guard_when_quiet() {
        let mut t = Instant::now();
        let m = decide(Mode::Guard, 1_000.0, 10.0, 20_000.0, 1.0, &mut t);
        assert_eq!(m, Mode::Guard);
    }
}
