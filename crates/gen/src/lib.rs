//! Synthetic DNS load: flood scenarios A-E and a legitimate prober that falls back to TCP.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

pub mod cookie;

/// The load scenarios; A-C are from PS-022, D-F are Segfault's own red-team cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// A: one source at max rate.
    Single,
    /// B: many spoofed sources, each under the per-source limit.
    Distributed,
    /// C: on/off bursts of random-subdomain queries.
    Pulse,
    /// D: an adaptive attacker holding just under a fixed per-source threshold.
    Adaptive,
    /// E: attacker spoofing addresses inside the legitimate client's own prefix.
    PrefixSpoof,
    /// F: sustained random-subdomain (water-torture) flood that forces NXDOMAIN work.
    WaterTorture,
}

impl Scenario {
    /// Every scenario in bench order.
    pub const ALL: [Scenario; 6] = [
        Scenario::Single,
        Scenario::Distributed,
        Scenario::Pulse,
        Scenario::Adaptive,
        Scenario::PrefixSpoof,
        Scenario::WaterTorture,
    ];

    /// CLI name of the scenario.
    pub fn name(self) -> &'static str {
        match self {
            Scenario::Single => "single",
            Scenario::Distributed => "distributed",
            Scenario::Pulse => "pulse",
            Scenario::Adaptive => "adaptive",
            Scenario::PrefixSpoof => "prefix-spoof",
            Scenario::WaterTorture => "water-torture",
        }
    }

    /// Parses a scenario name.
    pub fn parse(s: &str) -> Option<Scenario> {
        Scenario::ALL.into_iter().find(|x| x.name() == s)
    }
}

/// A tiny xorshift PRNG; deterministic so every bench run uses the same traffic.
pub struct Rng(u64);

impl Rng {
    /// Seeds the generator.
    pub fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }

    /// Next 64-bit value.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Value in 0..n.
    pub fn below(&mut self, n: u32) -> u32 {
        (self.next() % n as u64) as u32
    }
}

/// Encodes a DNS query for `qname`/A into buf and returns its length.
pub fn encode_query(buf: &mut [u8], id: u16, qname: &str) -> usize {
    buf[0] = (id >> 8) as u8;
    buf[1] = id as u8;
    buf[2] = 0x01; // RD
    buf[3] = 0x00;
    buf[4] = 0x00;
    buf[5] = 0x01; // QDCOUNT 1
    buf[6..12].fill(0);
    let mut o = 12;
    for label in qname
        .trim_end_matches('.')
        .split('.')
        .filter(|s| !s.is_empty())
    {
        let l = label.len().min(63);
        buf[o] = l as u8;
        o += 1;
        buf[o..o + l].copy_from_slice(&label.as_bytes()[..l]);
        o += l;
    }
    buf[o] = 0;
    o += 1;
    buf[o..o + 2].copy_from_slice(&[0x00, 0x01]); // QTYPE A
    buf[o + 2..o + 4].copy_from_slice(&[0x00, 0x01]); // QCLASS IN
    o + 4
}

/// Encodes a query for `qname`/A that also carries an EDNS COOKIE option; returns its length.
pub fn encode_query_cookie(buf: &mut [u8], id: u16, qname: &str, cookie: &[u8]) -> usize {
    let mut o = encode_query(buf, id, qname);
    buf[11] = 1; // ARCOUNT = 1 (the OPT RR)
    buf[o] = 0; // OPT name = root
    buf[o + 1..o + 3].copy_from_slice(&[0x00, 0x29]); // type OPT (41)
    buf[o + 3..o + 5].copy_from_slice(&[0x10, 0x00]); // UDP size 4096
    buf[o + 5..o + 9].copy_from_slice(&[0, 0, 0, 0]); // ext-rcode/version/flags
    let rdlen = 4 + cookie.len();
    buf[o + 9..o + 11].copy_from_slice(&(rdlen as u16).to_be_bytes());
    o += 11;
    buf[o..o + 2].copy_from_slice(&[0x00, 0x0a]); // option code COOKIE (10)
    buf[o + 2..o + 4].copy_from_slice(&(cookie.len() as u16).to_be_bytes());
    o += 4;
    buf[o..o + cookie.len()].copy_from_slice(cookie);
    o + cookie.len()
}

/// Result of one legitimate-prober run.
#[derive(Debug, Clone, Default)]
pub struct ProbeResult {
    /// Queries sent.
    pub sent: u64,
    /// Answers received over UDP.
    pub ok_udp: u64,
    /// Answers received after falling back to TCP (counts as success).
    pub ok_tcp: u64,
    /// Queries that got no answer on either transport.
    pub lost: u64,
    /// Observed latencies in microseconds for successful queries.
    pub latencies_us: Vec<u64>,
}

impl ProbeResult {
    /// Success rate across all sent queries.
    pub fn success_rate(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            (self.ok_udp + self.ok_tcp) as f64 / self.sent as f64
        }
    }

    /// Latency percentile in microseconds (p in 0..1).
    pub fn pct_us(&self, p: f64) -> u64 {
        if self.latencies_us.is_empty() {
            return 0;
        }
        let mut v = self.latencies_us.clone();
        v.sort_unstable();
        let i = ((v.len() as f64 - 1.0) * p).round() as usize;
        v[i]
    }
}

/// Runs a legitimate client: one UDP query per interval, TCP retry on timeout or truncation.
pub fn probe(
    server: IpAddr,
    qps: u32,
    dur: Duration,
    stop: Arc<AtomicBool>,
) -> Result<ProbeResult> {
    probe_cookie(server, qps, dur, stop, None)
}

/// Legitimate prober; when `cookie_secret` is set, every query carries a valid RFC 9018 cookie.
pub fn probe_cookie(
    server: IpAddr,
    qps: u32,
    dur: Duration,
    stop: Arc<AtomicBool>,
    cookie_secret: Option<[u8; 16]>,
) -> Result<ProbeResult> {
    let bind = if server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind).context("bind prober udp")?;
    sock.set_read_timeout(Some(Duration::from_millis(200)))?;
    let dst = SocketAddr::new(server, 53);
    sock.connect(dst).ok();
    let local_ip = sock.local_addr().map(|a| a.ip()).unwrap_or(server);
    let gap = Duration::from_micros(1_000_000 / qps.max(1) as u64);
    let mut res = ProbeResult::default();
    let mut buf = [0u8; 512];
    let mut rbuf = [0u8; 1500];
    let start = Instant::now();
    let mut id: u16 = 0x1000;

    while start.elapsed() < dur && !stop.load(Ordering::Relaxed) {
        let tick = Instant::now();
        id = id.wrapping_add(1);
        let name = format!("legit-{id:04x}.lab.test");
        let n = match cookie_secret {
            Some(secret) => {
                let cc = (id as u64).to_le_bytes();
                let ck = cookie::build_cookie(&secret, local_ip, cc, 1);
                encode_query_cookie(&mut buf, id, &name, &ck)
            }
            None => encode_query(&mut buf, id, &name),
        };
        res.sent += 1;
        let t0 = Instant::now();
        sock.send(&buf[..n]).ok();
        match sock.recv(&mut rbuf) {
            Ok(len) if len >= 3 => {
                let truncated = rbuf[2] & 0x02 != 0;
                if truncated {
                    if tcp_query(server, &buf[..n]).unwrap_or(false) {
                        res.ok_tcp += 1;
                        res.latencies_us.push(t0.elapsed().as_micros() as u64);
                    } else {
                        res.lost += 1;
                    }
                } else {
                    res.ok_udp += 1;
                    res.latencies_us.push(t0.elapsed().as_micros() as u64);
                }
            }
            _ => {
                // No UDP answer: try TCP before giving up (models a real resolver).
                if tcp_query(server, &buf[..n]).unwrap_or(false) {
                    res.ok_tcp += 1;
                    res.latencies_us.push(t0.elapsed().as_micros() as u64);
                } else {
                    res.lost += 1;
                }
            }
        }
        if let Some(rem) = gap.checked_sub(tick.elapsed()) {
            std::thread::sleep(rem);
        }
    }
    Ok(res)
}

/// Sends one query over TCP/53 with a 2-byte length prefix; true if an answer came back.
fn tcp_query(server: IpAddr, msg: &[u8]) -> Result<bool> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let mut s =
        TcpStream::connect_timeout(&SocketAddr::new(server, 53), Duration::from_millis(400))?;
    s.set_read_timeout(Some(Duration::from_millis(600)))?;
    s.set_write_timeout(Some(Duration::from_millis(400)))?;
    let len = (msg.len() as u16).to_be_bytes();
    s.write_all(&len)?;
    s.write_all(msg)?;
    let mut hdr = [0u8; 2];
    if s.read_exact(&mut hdr).is_err() {
        return Ok(false);
    }
    let rlen = u16::from_be_bytes(hdr) as usize;
    let mut r = vec![0u8; rlen.min(4096)];
    Ok(s.read(&mut r).map(|n| n >= 3).unwrap_or(false))
}

/// A flood run's totals.
#[derive(Debug, Clone, Default)]
pub struct FloodResult {
    /// Query packets sent.
    pub sent: u64,
}

/// Builds the QNAME for a flood query under the given scenario.
pub fn flood_qname(sc: Scenario, rng: &mut Rng, i: u64) -> String {
    match sc {
        // Random subdomains under flood.test return NXDOMAIN, triggering the zone-cost repricing.
        Scenario::Pulse | Scenario::WaterTorture => {
            format!("r{:08x}{:08x}.flood.test", rng.next() as u32, i as u32)
        }
        _ => "flood.test".to_string(),
    }
}

/// Returns the IPv4 source a spoofed flood packet should claim, by scenario.
/// Real spoofing needs raw sockets/root; the bench harness documents when it is simulated.
pub fn flood_src(sc: Scenario, legit_prefix: Ipv4Addr, rng: &mut Rng) -> Ipv4Addr {
    let o = legit_prefix.octets();
    match sc {
        Scenario::Distributed | Scenario::WaterTorture => {
            Ipv4Addr::new(203, 0, rng.below(254) as u8 + 1, rng.below(254) as u8 + 1)
        }
        Scenario::PrefixSpoof => Ipv4Addr::new(o[0], o[1], o[2], rng.below(254) as u8 + 1),
        _ => Ipv4Addr::new(198, 51, 100, 10),
    }
}

/// Returns the IPv6 source a spoofed flood packet should claim, by scenario (mirrors flood_src).
pub fn flood_src6(sc: Scenario, server6: Ipv6Addr, rng: &mut Rng) -> Ipv6Addr {
    let mut r16 = || rng.next() as u16;
    match sc {
        // Spoof inside the server's own /64 so per-prefix limiting would punish the real client.
        Scenario::PrefixSpoof => {
            let s = server6.segments();
            Ipv6Addr::new(s[0], s[1], s[2], s[3], r16(), r16(), r16(), r16())
        }
        // Random documentation-range (2001:db8::/32) sources: a simulated IPv6 botnet.
        Scenario::Distributed | Scenario::WaterTorture => {
            Ipv6Addr::new(0x2001, 0x0db8, r16(), r16(), r16(), r16(), r16(), r16())
        }
        _ => Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x10),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique() {
        let names: Vec<_> = Scenario::ALL.iter().map(|s| s.name()).collect();
        assert_eq!(names.len(), 6);
        let mut d = names.clone();
        d.sort_unstable();
        d.dedup();
        assert_eq!(d.len(), 6);
    }

    #[test]
    fn water_torture_names_vary_and_hit_flood_zone() {
        let mut r = Rng::new(9);
        let a = flood_qname(Scenario::WaterTorture, &mut r, 1);
        let b = flood_qname(Scenario::WaterTorture, &mut r, 2);
        assert_ne!(a, b);
        assert!(a.ends_with(".flood.test"));
    }

    #[test]
    fn prefix_spoof_v6_stays_in_prefix() {
        let mut r = Rng::new(5);
        let server = "fd53::10".parse().unwrap();
        let ip = flood_src6(Scenario::PrefixSpoof, server, &mut r);
        assert_eq!(
            &ip.segments()[..4],
            &"fd53::".parse::<Ipv6Addr>().unwrap().segments()[..4]
        );
    }

    #[test]
    fn query_encodes_qdcount_one() {
        let mut b = [0u8; 512];
        let n = encode_query(&mut b, 0x1234, "legit-0001.lab.test");
        assert_eq!(b[5], 1);
        assert_eq!(b[0], 0x12);
        assert!(n > 12);
    }

    #[test]
    fn pulse_names_vary() {
        let mut r = Rng::new(7);
        let a = flood_qname(Scenario::Pulse, &mut r, 1);
        let b = flood_qname(Scenario::Pulse, &mut r, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn prefix_spoof_stays_in_prefix() {
        let mut r = Rng::new(3);
        let ip = flood_src(Scenario::PrefixSpoof, Ipv4Addr::new(10, 53, 0, 20), &mut r);
        let o = ip.octets();
        assert_eq!(&o[..3], &[10, 53, 0]);
    }

    #[test]
    fn probe_success_rate_math() {
        let r = ProbeResult {
            sent: 10,
            ok_udp: 7,
            ok_tcp: 1,
            lost: 2,
            latencies_us: vec![],
        };
        assert!((r.success_rate() - 0.8).abs() < 1e-9);
    }
}
