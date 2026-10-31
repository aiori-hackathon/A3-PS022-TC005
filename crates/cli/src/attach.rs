//! Attaches and detaches the XDP program and the tc-egress observer, keeping maps pinned.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::path::Path;

use anyhow::{Context, Result, bail};
use libbpf_rs::{Object, ObjectBuilder, TC_EGRESS, TcHookBuilder, Xdp, XdpFlags};
use std::os::fd::AsFd;

use segfault_core::{PIN_DIR, ensure_pin_dir};

/// Resolves an interface name to its index.
pub fn ifindex(name: &str) -> Result<i32> {
    let c = CString::new(name)?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        bail!("no interface named '{name}'");
    }
    Ok(idx as i32)
}

/// Loads the embedded object, pinning persistent maps; returns the live Object.
fn load(obj_bytes: &[u8]) -> Result<Object> {
    ensure_pin_dir()?;
    let mut builder = ObjectBuilder::default();
    let mut open = builder
        .open_memory(obj_bytes)
        .context("open embedded object")?;
    for mut m in open.maps_mut() {
        let name = m.name().to_string_lossy().to_string();
        if name.starts_with("sf_") && name != "sf_buf" && name != "sf_slip_ctr" {
            let path = Path::new(PIN_DIR).join(&name);
            // Reuse an already-pinned map so state survives a controller restart.
            if path.exists() {
                m.reuse_pinned_map(&path).ok();
            } else {
                m.set_pin_path(&path).ok();
            }
        }
    }
    open.load().context("load/verify BPF object")
}

/// Attaches XDP (native if the driver allows, else generic) and the tc egress observer.
pub fn attach(iface: &str, obj_bytes: &[u8]) -> Result<()> {
    let idx = ifindex(iface)?;
    let obj = load(obj_bytes)?;

    let xdp_prog = obj
        .progs()
        .find(|p| p.name().to_string_lossy() == "segfault_xdp")
        .context("segfault_xdp missing")?;
    let tc_prog = obj
        .progs()
        .find(|p| p.name().to_string_lossy() == "segfault_tc")
        .context("segfault_tc missing")?;

    // Clear any XDP program left over from a previous run so the mode is never ambiguous.
    let _ = detach_xdp(idx);

    // XDP: try native/driver mode, fall back to generic (SKB) mode.
    let xdp = Xdp::new(xdp_prog.as_fd());
    if xdp.attach(idx, XdpFlags::DRV_MODE).is_err() {
        xdp.attach(idx, XdpFlags::SKB_MODE)
            .context("attach XDP (native and generic both failed)")?;
        eprintln!(
            "note: attached XDP in generic mode (no native XDP — on hv_netvsc run: ethtool -K <iface> lro off gro off)"
        );
    }

    // tc clsact egress hook for the observer.
    let mut hook = TcHookBuilder::new(tc_prog.as_fd())
        .ifindex(idx)
        .replace(true)
        .handle(1)
        .priority(1)
        .hook(TC_EGRESS);
    hook.create().ok(); // clsact may already exist; ignore.
    hook.attach().context("attach tc egress observer")?;

    // Programs stay attached in the kernel after this object drops.
    std::mem::forget(obj);
    Ok(())
}

/// Detaches the XDP program and removes the tc clsact qdisc (and the observer with it).
pub fn detach(iface: &str) -> Result<()> {
    let idx = ifindex(iface)?;
    let _ = detach_xdp(idx);
    // Removing the clsact qdisc takes the egress observer filter down cleanly.
    let _ = std::process::Command::new("tc")
        .args(["qdisc", "del", "dev", iface, "clsact"])
        .status();
    Ok(())
}

/// Removes any XDP program from an interface, whatever mode it was attached in.
fn detach_xdp(idx: i32) -> Result<()> {
    // A program attached in a specific mode only detaches with that mode's flag, so try each.
    const XDP_FLAGS_SKB_MODE: u32 = 2;
    const XDP_FLAGS_DRV_MODE: u32 = 4;
    unsafe {
        libbpf_sys::bpf_xdp_detach(idx, XDP_FLAGS_DRV_MODE, std::ptr::null());
        libbpf_sys::bpf_xdp_detach(idx, XDP_FLAGS_SKB_MODE, std::ptr::null());
        libbpf_sys::bpf_xdp_detach(idx, 0, std::ptr::null());
    }
    Ok(())
}
