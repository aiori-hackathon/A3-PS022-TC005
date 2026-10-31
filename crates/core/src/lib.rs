//! Shared control-plane types for Segfault: config layout, map access, stats and policy presets.

use std::collections::BTreeMap;
use std::mem::size_of;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use libbpf_rs::{MapCore, MapFlags};

pub mod config;
pub mod maps;
pub mod stats;

pub use config::{Algo, Config, Mode, Policy, TIERS};
pub use maps::Maps;
pub use stats::{OBS, ObsStats, REASONS, Stats};

/// Directory where Segfault pins its maps and bpf_link.
pub const PIN_DIR: &str = "/sys/fs/bpf/segfault";

/// Default config file name.
pub const CONFIG_FILE: &str = "segfault.toml";

/// UDP port the datapath inspects.
pub const DNS_PORT: u16 = 53;

/// Version string shared by every Segfault binary.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Pin path for one named object under the Segfault pin directory.
pub fn pin_path(name: &str) -> PathBuf {
    Path::new(PIN_DIR).join(name)
}

/// Encodes an IP as the 16-byte IPv4-mapped form the datapath stores.
pub fn addr_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => {
            let mut a = [0u8; 16];
            a[10] = 0xff;
            a[11] = 0xff;
            a[12..].copy_from_slice(&v4.octets());
            a
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Decodes a 16-byte datapath address back to an IP.
pub fn addr_from_bytes(a: &[u8; 16]) -> IpAddr {
    if a[..10] == [0u8; 10] && a[10] == 0xff && a[11] == 0xff {
        IpAddr::from([a[12], a[13], a[14], a[15]])
    } else {
        IpAddr::from(*a)
    }
}

/// Reads one little-endian u64 from a byte slice at an offset.
pub(crate) fn rd_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// Reads one little-endian u32 from a byte slice at an offset.
pub(crate) fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

/// Sums a per-CPU u64 array value returned by a BPF map lookup.
pub(crate) fn sum_percpu(vals: &[Vec<u8>]) -> u64 {
    vals.iter()
        .map(|v| rd_u64(v, 0))
        .fold(0u64, u64::wrapping_add)
}

/// Looks one key up in a per-CPU map and sums its values, or 0 when absent.
pub(crate) fn percpu_sum(map: &libbpf_rs::MapHandle, key: u32) -> Result<u64> {
    let k = key.to_ne_bytes();
    match map.lookup_percpu(&k, MapFlags::ANY)? {
        Some(v) => Ok(sum_percpu(&v)),
        None => Ok(0),
    }
}

/// Asserts a map value size matches a Rust struct, to catch layout drift early.
pub(crate) fn check_value_size(map: &libbpf_rs::MapHandle, want: usize) -> Result<()> {
    let got = map.value_size() as usize;
    if got != want {
        bail!(
            "map {:?} value size {} != expected {}",
            map.name(),
            got,
            want
        );
    }
    Ok(())
}

/// A tier/zone cost multiplier table keyed by zone hash, used by the controller.
pub type ZoneCosts = BTreeMap<u32, u32>;

/// FNV-1a zone hash matching the datapath (last two labels, lowercased).
pub fn zone_hash(name: &str) -> u32 {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = name.split('.').filter(|s| !s.is_empty()).collect();
    let (mut h, mut hz) = (2166136261u32, 2166136261u32);
    let mut started = false;
    let mut zone_on = false;
    for (li, label) in labels.iter().enumerate() {
        if li > 0 {
            zone_on = started;
        }
        for &c in label.as_bytes() {
            let c = c.to_ascii_lowercase();
            h = (h ^ c as u32).wrapping_mul(16777619);
            if zone_on {
                hz = (hz ^ c as u32).wrapping_mul(16777619);
            }
        }
        started = true;
        let _ = li;
    }
    if zone_on { hz } else { h }
}

/// Ensures the pin directory exists.
pub fn ensure_pin_dir() -> Result<()> {
    std::fs::create_dir_all(PIN_DIR).with_context(|| format!("create pin dir {PIN_DIR}"))?;
    Ok(())
}

/// Parses a 32-char hex string into a 16-byte key.
pub fn parse_hex16(hex: &str) -> Result<[u8; 16]> {
    let h = hex.trim();
    if h.len() != 32 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        bail!("cookie secret must be 32 hex chars (16 bytes)");
    }
    let mut k = [0u8; 16];
    for i in 0..16 {
        k[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
    }
    Ok(k)
}

/// Size of the datapath config struct, mirrored in config.rs.
pub const CONFIG_SIZE: usize = 184;
const _: () = assert!(CONFIG_SIZE == 184);

/// Size of one per-source value, mirrored by sf_src in C.
pub const SRC_SIZE: usize = size_of::<u64>() * 4 + size_of::<u32>() * 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_dir_is_under_bpffs() {
        assert!(PIN_DIR.starts_with("/sys/fs/bpf/"));
    }

    #[test]
    fn version_is_set() {
        assert!(!version().is_empty());
    }

    #[test]
    fn v4_round_trips_mapped() {
        let ip: IpAddr = "10.53.0.20".parse().unwrap();
        let b = addr_bytes(ip);
        assert_eq!(b[10], 0xff);
        assert_eq!(b[11], 0xff);
        assert_eq!(addr_from_bytes(&b), ip);
    }

    #[test]
    fn v6_round_trips() {
        let ip: IpAddr = "fd53::20".parse().unwrap();
        assert_eq!(addr_from_bytes(&addr_bytes(ip)), ip);
    }
}
