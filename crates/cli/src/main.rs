//! segfault: load, attach and steer the DNS-aware XDP rate limiter and read its state.
#![allow(unsafe_code)]

mod attach;
mod control;
mod observe;

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use segfault_core::{
    Algo, Mode, Policy,
    maps::{self, is_loaded},
    stats::{OBS, ObsStats, REASONS, Stats},
};

/// Embedded datapath object, built by `make bpf` before the Rust crates.
const BPF_OBJ: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/bpf/segfault.bpf.o"
));

#[derive(Parser)]
#[command(
    name = "segfault",
    version,
    about = "DNS-aware XDP rate limiter for query floods"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check the host for XDP, bpffs and tools.
    Doctor,
    /// Attach the datapath to an interface and run the controller.
    Up(UpArgs),
    /// Detach everything and remove pinned state.
    Down {
        /// Interface the datapath is attached to.
        #[arg(short, long)]
        iface: String,
    },
    /// Print the live counters once.
    Stats {
        /// Emit the raw counters as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Explain the current verdict for one source IP.
    Why {
        /// Source address to look up.
        ip: IpAddr,
    },
    /// Set the defense mode by hand (calm, guard, siege).
    Mode {
        /// Mode name.
        mode: String,
    },
    /// Write the config for an algorithm/mode without attaching (used by the bench).
    Config(ConfigArgs),
    /// Set the RFC 9018 DNS-cookie secret (32 hex chars) shared with the resolver.
    CookieSecret {
        /// 16-byte secret as 32 hex characters.
        hex: String,
    },
    /// Live full-screen counter view.
    Top,
    /// Serve Prometheus /metrics and a web dashboard on localhost.
    Serve {
        /// TCP port to listen on.
        #[arg(long, default_value_t = 9108)]
        port: u16,
    },
}

#[derive(Parser)]
struct UpArgs {
    /// Interface to protect (e.g. eth1).
    #[arg(short, long)]
    iface: String,
    /// Algorithm: segfault or fixed (the baseline).
    #[arg(long, default_value = "segfault")]
    algo: String,
    /// Starting mode.
    #[arg(long, default_value = "guard")]
    mode: String,
    /// Policy file; defaults are used when absent.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Shadow mode: run the logic, drop nothing.
    #[arg(long)]
    shadow: bool,
    /// Attach and write config, then exit instead of running the controller.
    #[arg(long)]
    no_control: bool,
    /// Stop the controller after this many seconds (0 = run until signalled).
    #[arg(long, default_value_t = 0)]
    seconds: u64,
}

#[derive(Parser)]
struct ConfigArgs {
    #[arg(long, default_value = "segfault")]
    algo: String,
    #[arg(long, default_value = "guard")]
    mode: String,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    shadow: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Doctor => doctor(),
        Cmd::Up(a) => up(a),
        Cmd::Down { iface } => down(&iface),
        Cmd::Stats { json } => stats(json),
        Cmd::Why { ip } => why(ip),
        Cmd::Mode { mode } => set_mode(&mode),
        Cmd::Config(a) => write_config_only(a),
        Cmd::CookieSecret { hex } => set_cookie_secret(&hex),
        Cmd::Top => observe::top(),
        Cmd::Serve { port } => observe::serve(port),
    }
}

/// `cookie-secret`: install the shared cookie secret and enable the cookie proof path.
fn set_cookie_secret(hex: &str) -> Result<()> {
    if !is_loaded() {
        bail!("datapath not attached");
    }
    let key = segfault_core::parse_hex16(hex)?;
    maps::write_secret(&key, true)?;
    println!("cookie secret installed; valid RFC 9018 cookies now promote straight to proven (T2)");
    Ok(())
}

/// Loads a policy from a file or returns defaults.
fn load_policy(path: &Option<PathBuf>) -> Result<Policy> {
    match path {
        Some(p) => {
            let text =
                std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
            Ok(toml::from_str(&text).context("parse policy toml")?)
        }
        None => Ok(Policy::default()),
    }
}

/// Parses an algorithm name.
fn parse_algo(s: &str) -> Result<Algo> {
    Ok(match s {
        "segfault" => Algo::Segfault,
        "fixed" => Algo::Fixed,
        other => bail!("unknown algo '{other}'"),
    })
}

/// `doctor`: quick environment check.
fn doctor() -> Result<()> {
    let bpffs = std::path::Path::new("/sys/fs/bpf").exists();
    println!("bpffs mounted : {}", yesno(bpffs));
    println!("pin dir       : {}", segfault_core::PIN_DIR);
    println!(
        "datapath      : {}",
        if is_loaded() {
            "attached"
        } else {
            "not attached"
        }
    );
    println!("bpf object    : {} bytes embedded", BPF_OBJ.len());
    Ok(())
}

/// `up`: attach and (unless --no-control) run the controller loop.
fn up(a: UpArgs) -> Result<()> {
    let algo = parse_algo(&a.algo)?;
    let mode = Mode::parse(&a.mode)?;
    let policy = load_policy(&a.config)?;
    attach::attach(&a.iface, BPF_OBJ)?;
    let cfg = segfault_core::config::Config::from_policy(&policy, algo, mode, a.shadow, 1);
    maps::write_config(&cfg)?;
    println!(
        "segfault up on {} algo={} mode={} shadow={}",
        a.iface,
        a.algo,
        mode.name(),
        a.shadow
    );
    if a.no_control {
        return Ok(());
    }
    control::run(policy, algo, a.shadow, a.seconds)
}

/// `down`: detach and clean up.
fn down(iface: &str) -> Result<()> {
    attach::detach(iface)?;
    maps::unpin_all()?;
    println!("segfault down on {iface}");
    Ok(())
}

/// `stats`: one snapshot.
fn stats(json: bool) -> Result<()> {
    if !is_loaded() {
        bail!("datapath not attached; run `segfault up` first");
    }
    let s = Stats::read()?;
    let o = ObsStats::read()?;
    if json {
        print!("{{\"ingress\":{{");
        for (i, name) in REASONS.iter().enumerate() {
            print!("{}\"{}\":{}", if i == 0 { "" } else { "," }, name, s.c[i]);
        }
        print!("}},\"egress\":{{");
        for (i, name) in OBS.iter().enumerate() {
            print!("{}\"{}\":{}", if i == 0 { "" } else { "," }, name, o.c[i]);
        }
        println!("}}}}");
        return Ok(());
    }
    println!("queries total : {}", s.get("queries"));
    println!(
        "  by tier     : t0={} t1={} t2={}",
        s.get("queries_t0"),
        s.get("queries_t1"),
        s.get("queries_t2")
    );
    println!("admitted      : {}", s.admitted());
    println!("blocked       : {}", s.blocked());
    println!(
        "  drops       : source={} prefix={} pool={} heavy={} banned={} deny={} malformed={}",
        s.get("drop_source"),
        s.get("drop_prefix"),
        s.get("drop_pool"),
        s.get("drop_heavy"),
        s.get("drop_banned"),
        s.get("drop_deny"),
        s.get("drop_malformed")
    );
    println!("  slips (TX)  : {}", s.get("tx_slip"));
    println!(
        "promotions    : t1={} denied={}",
        s.get("promote_t1"),
        s.get("promote_denied")
    );
    println!("bans issued   : {}", s.get("ban_issued"));
    println!("cost units    : {}", s.get("cost_units"));
    println!(
        "observer      : resp={} nxdomain={} servfail={} tcp_proofs={}",
        o.get("resp"),
        o.get("nxdomain"),
        o.get("servfail"),
        o.get("proofs")
    );
    println!("nxdomain ratio: {:.3}", o.nxdomain_ratio());
    Ok(())
}

/// `why`: explain a source's current standing.
fn why(ip: IpAddr) -> Result<()> {
    if !is_loaded() {
        bail!("datapath not attached");
    }
    if maps::is_proven(ip)? {
        println!(
            "{ip}: tier T2 (proven) — proven return path (valid DNS cookie or TCP after a slip); served from the proven pool"
        );
        return Ok(());
    }
    match maps::source_state(ip)? {
        Some((strikes, queries, banned)) => {
            println!("{ip}: tier T1 (returning) — promoted from unknown");
            println!("  queries seen : {queries}");
            println!("  strikes      : {strikes}");
            println!("  banned now   : {}", yesno(banned));
            println!(
                "  limited by   : its own per-source bucket, then its /24 or /48 prefix, then the T1 pool"
            );
        }
        None => {
            println!("{ip}: tier T0 (unknown) — no per-source state is kept");
            println!("  tracked in the Count-Min sketch only; shares the small unknown pool");
            println!(
                "  to earn trust: answer a slip over TCP (→T2) or keep a steady low rate (→T1)"
            );
        }
    }
    Ok(())
}

/// `mode`: set the mode live.
fn set_mode(mode: &str) -> Result<()> {
    if !is_loaded() {
        bail!("datapath not attached");
    }
    let m = Mode::parse(mode)?;
    control::set_mode_only(m)?;
    println!("mode set to {}", m.name());
    Ok(())
}

/// `config`: write config without attaching (bench helper).
fn write_config_only(a: ConfigArgs) -> Result<()> {
    if !is_loaded() {
        bail!("datapath not attached");
    }
    let policy = load_policy(&a.config)?;
    let cfg = segfault_core::config::Config::from_policy(
        &policy,
        parse_algo(&a.algo)?,
        Mode::parse(&a.mode)?,
        a.shadow,
        1,
    );
    maps::write_config(&cfg)?;
    println!("config written: algo={} mode={}", a.algo, a.mode);
    Ok(())
}

/// Formats a bool for the CLI.
fn yesno(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}
