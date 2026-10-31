//! Loads the Segfault BPF object, pins its maps, attaches XDP + tc, and exposes map handles.

use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use libbpf_rs::{MapCore, MapFlags, MapHandle, Object, ObjectBuilder};

use crate::config::Config;
use crate::{PIN_DIR, ensure_pin_dir, pin_path};

/// Pool bucket indices in sf_pools, matching the C defines.
pub const POOL_PROMO: u32 = 3;
pub const POOL_FIXED: u32 = 4;

/// Opened Segfault object; keeping it alive keeps the loaded programs resident.
pub struct Maps {
    _obj: Object,
}

/// Opens one pinned map by name, erroring if it is absent.
pub fn open_pinned(name: &str) -> Result<MapHandle> {
    let path = pin_path(name);
    MapHandle::from_pinned_path(&path)
        .with_context(|| format!("open pinned map {}", path.display()))
}

/// True if the datapath is currently loaded (its config map is pinned).
pub fn is_loaded() -> bool {
    pin_path("sf_cfg").exists()
}

impl Maps {
    /// Loads the BPF object from a path, pinning every persistent map under PIN_DIR.
    pub fn load(obj_path: &Path) -> Result<Maps> {
        ensure_pin_dir()?;
        let mut builder = ObjectBuilder::default();
        let mut open = builder
            .open_file(obj_path)
            .with_context(|| format!("open {}", obj_path.display()))?;
        for mut m in open.maps_mut() {
            let name = m.name().to_string_lossy().to_string();
            // Scratch maps (per-CPU buffers, slip counter) are not pinned.
            if name.starts_with("sf_") && name != "sf_buf" && name != "sf_slip_ctr" {
                m.set_pin_path(Path::new(PIN_DIR).join(&name))
                    .with_context(|| format!("set pin path for {name}"))?;
            }
        }
        let obj = open.load().context("load/verify BPF object")?;
        Ok(Maps { _obj: obj })
    }

    /// Keeps the loaded object alive; borrow nothing, read state via pinned paths.
    pub fn keep(self) -> Object {
        self._obj
    }
}

/// Writes the config into sf_cfg slot 0.
pub fn write_config(cfg: &Config) -> Result<()> {
    let map = open_pinned("sf_cfg")?;
    crate::check_value_size(&map, crate::CONFIG_SIZE)?;
    map.update(&0u32.to_ne_bytes(), &cfg.to_bytes(), MapFlags::ANY)
        .context("write sf_cfg")?;
    Ok(())
}

/// Reads one u64 pool bucket (raw TAT value; mostly for diagnostics).
pub fn read_pool(idx: u32) -> Result<u64> {
    let map = open_pinned("sf_pools")?;
    match map.lookup(&idx.to_ne_bytes(), MapFlags::ANY)? {
        Some(v) => Ok(u64::from_ne_bytes(v[..8].try_into().unwrap())),
        None => Ok(0),
    }
}

/// Adds one IP to the allow or deny LPM list at /128 (or the mapped /32 host).
pub fn list_add(deny: bool, ip: IpAddr) -> Result<()> {
    let map = open_pinned(if deny { "sf_deny" } else { "sf_allow" })?;
    let mut key = Vec::with_capacity(20);
    key.extend_from_slice(&128u32.to_ne_bytes());
    key.extend_from_slice(&crate::addr_bytes(ip));
    map.update(&key, &1u32.to_ne_bytes(), MapFlags::ANY)
        .context("add to list")?;
    Ok(())
}

/// Sets a zone cost multiplier by domain name (controller refreshes these live).
pub fn set_zone_cost(name: &str, mult: u32) -> Result<()> {
    let map = open_pinned("sf_zone_cost")?;
    let key = crate::zone_hash(name);
    map.update(&key.to_ne_bytes(), &mult.to_ne_bytes(), MapFlags::ANY)
        .context("set zone cost")?;
    Ok(())
}

/// Looks up a source's state in T1 and returns (strikes, queries, banned) if present.
pub fn source_state(ip: IpAddr) -> Result<Option<(u32, u32, bool)>> {
    let map = open_pinned("sf_t1")?;
    let key = crate::addr_bytes(ip);
    match map.lookup(&key, MapFlags::ANY)? {
        Some(v) => {
            if v.len() < crate::SRC_SIZE {
                bail!("sf_t1 value too small");
            }
            let ban_until = crate::rd_u64(&v, 24);
            let strikes = crate::rd_u32(&v, 32);
            let queries = crate::rd_u32(&v, 36);
            Ok(Some((strikes, queries, ban_until != 0)))
        }
        None => Ok(None),
    }
}

/// Returns true if an IP currently has a live proven (T2) entry.
pub fn is_proven(ip: IpAddr) -> Result<bool> {
    let map = open_pinned("sf_t2")?;
    Ok(map.lookup(&crate::addr_bytes(ip), MapFlags::ANY)?.is_some())
}

/// Writes the 16-byte DNS-cookie secret and enables cookie validation.
pub fn write_secret(key: &[u8; 16], enabled: bool) -> Result<()> {
    let map = open_pinned("sf_secret")?;
    let mut v = vec![0u8; 24];
    v[..16].copy_from_slice(key);
    v[16..20].copy_from_slice(&(enabled as u32).to_ne_bytes());
    map.update(&0u32.to_ne_bytes(), &v, MapFlags::ANY)
        .context("write sf_secret")?;
    Ok(())
}

/// Unpins every Segfault map, detaching the datapath state.
pub fn unpin_all() -> Result<()> {
    let dir = Path::new(PIN_DIR);
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let _ = std::fs::remove_file(&path);
    }
    Ok(())
}
