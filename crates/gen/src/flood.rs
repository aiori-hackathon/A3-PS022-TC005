//! Flood sender: plain UDP for real-source scenarios, raw IPv4 sockets to spoof source addresses.
#![allow(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use segfault_gen::{Rng, Scenario, encode_query, flood_qname, flood_src};

/// One's-complement 16-bit checksum over a byte slice.
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | data[i + 1] as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

/// Builds an IPv4 + UDP + DNS packet with a spoofed source into out; returns length.
fn build_raw(out: &mut [u8], src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dns: &[u8]) -> usize {
    let udp_len = 8 + dns.len();
    let tot = 20 + udp_len;
    out[0] = 0x45;
    out[1] = 0;
    out[2..4].copy_from_slice(&(tot as u16).to_be_bytes());
    out[4..6].copy_from_slice(&0u16.to_be_bytes());
    out[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    out[8] = 64;
    out[9] = 17; // UDP
    out[10..12].copy_from_slice(&0u16.to_be_bytes());
    out[12..16].copy_from_slice(&src.octets());
    out[16..20].copy_from_slice(&dst.octets());
    let ic = checksum(&out[..20]);
    out[10..12].copy_from_slice(&ic.to_be_bytes());
    out[20..22].copy_from_slice(&sport.to_be_bytes());
    out[22..24].copy_from_slice(&53u16.to_be_bytes());
    out[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    out[26..28].copy_from_slice(&0u16.to_be_bytes()); // checksum 0 = unchecked for IPv4 UDP
    out[28..28 + dns.len()].copy_from_slice(dns);
    tot
}

/// Opens a raw IPv4 socket with IP_HDRINCL for spoofed sends (needs CAP_NET_RAW / root).
fn open_raw() -> Result<i32> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("raw socket (need sudo)");
    }
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    Ok(fd)
}

/// Fails fast if this process cannot open a raw socket (spoofing needs CAP_NET_RAW).
pub fn check_raw() -> Result<()> {
    let fd = open_raw()
        .context("cannot spoof: run `sudo setcap cap_net_raw+ep <segfault-gen>` or use sudo")?;
    unsafe { libc::close(fd) };
    Ok(())
}

/// Family-aware preflight: verify the flood can actually be sent before the bench trusts a run.
pub fn preflight(server: IpAddr) -> Result<()> {
    match server {
        IpAddr::V4(_) => check_raw(),
        IpAddr::V6(a) => crate::flood6::check(a),
    }
}

/// Sends a raw packet to dst.
fn send_raw(fd: i32, pkt: &[u8], dst: Ipv4Addr) -> isize {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_addr.s_addr = u32::from_ne_bytes(dst.octets());
    unsafe {
        libc::sendto(
            fd,
            pkt.as_ptr() as *const libc::c_void,
            pkt.len(),
            0,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    }
}

/// Dispatches the flood across `threads` sender threads (each at pps/threads) by server family.
#[allow(clippy::too_many_arguments)]
pub fn flood(
    server: IpAddr,
    sc: Scenario,
    pps: u64,
    dur: Duration,
    seed: u64,
    adaptive_src_pps: u64,
    threads: u64,
    sent: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) -> Result<u64> {
    let n = threads.max(1);
    let per = (pps / n).max(1);
    let mut handles = Vec::new();
    for t in 0..n {
        let sent = sent.clone();
        let stop = stop.clone();
        let tseed = seed.wrapping_add(t.wrapping_mul(0x9e3779b97f4a7c15));
        handles.push(std::thread::spawn(move || match server {
            IpAddr::V4(dst) => flood_v4(dst, sc, per, dur, tseed, adaptive_src_pps, sent, stop),
            IpAddr::V6(dst) => {
                crate::flood6::flood6(dst, sc, per, dur, tseed, adaptive_src_pps, sent, stop)
            }
        }));
    }
    let mut total = 0u64;
    for h in handles {
        total += h.join().ok().and_then(|r| r.ok()).unwrap_or(0);
    }
    Ok(total)
}

/// Runs one IPv4 flood at a target pps for a duration; returns packets sent.
#[allow(clippy::too_many_arguments)]
fn flood_v4(
    dst: Ipv4Addr,
    sc: Scenario,
    pps: u64,
    dur: Duration,
    seed: u64,
    adaptive_src_pps: u64,
    sent: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) -> Result<u64> {
    let legit_prefix = Ipv4Addr::new(dst.octets()[0], dst.octets()[1], dst.octets()[2], 0);
    let mut rng = Rng::new(seed);
    let mut dnsbuf = [0u8; 512];
    let mut raw = [0u8; 600];

    // Every scenario spoofs a distinct attacker source, so the attacker is never the legit client.
    let rawfd = open_raw()?;

    // Adaptive attacker: spread the flood over enough sources that each stays under the per-source limit.
    let distinct = (pps / adaptive_src_pps.max(1)).max(1);

    let start = Instant::now();
    let mut i = 0u64;
    let mut local = 0u64;

    while start.elapsed() < dur && !stop.load(Ordering::Relaxed) {
        // Pace to the target pps: if ahead of schedule, wait briefly (accurate at any rate).
        if local >= (pps as f64 * start.elapsed().as_secs_f64()) as u64 {
            std::thread::sleep(Duration::from_micros(100));
            continue;
        }
        let name = flood_qname(sc, &mut rng, i);
        let id = rng.next() as u16;
        let n = encode_query(&mut dnsbuf, id, &name);

        // Adaptive rotates over many sources; the others use flood_src's per-scenario address.
        let src = if sc == Scenario::Adaptive {
            let k = (i % distinct) as u32;
            Ipv4Addr::new(198, 51, 1 + (k / 254) as u8, 1 + (k % 254) as u8)
        } else {
            flood_src(sc, legit_prefix, &mut rng)
        };
        let sport = 1024 + (rng.next() as u16 % 60000);
        let len = build_raw(&mut raw, src, dst, sport, &dnsbuf[..n]);
        send_raw(rawfd, &raw[..len], dst);

        local += 1;
        sent.fetch_add(1, Ordering::Relaxed);
        i += 1;
    }
    unsafe { libc::close(rawfd) };
    Ok(local)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_known_header() {
        // IP header with checksum field zeroed should produce a non-zero complement.
        let hdr = [
            0x45u8, 0, 0, 0x3c, 0, 0, 0x40, 0, 0x40, 0x11, 0, 0, 10, 53, 0, 20, 10, 53, 0, 10,
        ];
        assert_ne!(checksum(&hdr), 0);
    }

    #[test]
    fn raw_packet_has_ip_and_udp() {
        let mut out = [0u8; 600];
        let dns = [0u8; 30];
        let n = build_raw(
            &mut out,
            Ipv4Addr::new(203, 0, 1, 2),
            Ipv4Addr::new(10, 53, 0, 10),
            5000,
            &dns,
        );
        assert_eq!(n, 20 + 8 + 30);
        assert_eq!(out[9], 17);
        assert_eq!(&out[12..16], &[203, 0, 1, 2]);
        assert_eq!(u16::from_be_bytes([out[22], out[23]]), 53);
    }
}
