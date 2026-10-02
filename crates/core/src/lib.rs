//! Shared control-plane constants and types for Segfault.

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
}
