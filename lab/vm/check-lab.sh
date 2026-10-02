#!/usr/bin/env bash
# Checks that this lab VM is ready for Segfault: peer reachability, XDP driver, toolchain.
set -uo pipefail

role="${1:-}"
iface="${2:-enp0s8}"
case "$role" in
target) peer=10.53.0.20 peer6=fd53::20 ;;
gen) peer=10.53.0.10 peer6=fd53::10 ;;
*)
	echo "usage: $0 <target|gen> [iface]" >&2
	exit 1
	;;
esac

fails=0
ok() { printf '  [ok]   %s\n' "$1"; }
bad() {
	printf '  [fail] %s\n' "$1"
	fails=$((fails + 1))
}
info() { printf '  [info] %s\n' "$1"; }
# Runs a command quietly and reports it as ok or fail.
probe() {
	local label="$1"
	shift
	if "$@" >/dev/null 2>&1; then ok "$label"; else bad "$label"; fi
}

echo "== segfault lab check ($role, $iface)"
info "kernel $(uname -r)"

probe "ping $peer" ping -c 2 -W 1 -I "$iface" "$peer"
probe "ping $peer6" ping -6 -c 2 -W 1 -I "$iface" "$peer6"

driver="$(ethtool -i "$iface" 2>/dev/null | awk '/^driver:/{print $2}')"
case "$driver" in
virtio_net | ixgbe | i40e | ice | mlx5_core | veth) ok "driver $driver supports native XDP" ;;
"") bad "cannot read driver for $iface" ;;
*) info "driver $driver: expect generic XDP mode" ;;
esac

probe "bpffs mounted" mountpoint -q /sys/fs/bpf
probe "clang" clang --version
probe "bpftool" bpftool version
probe "cargo" cargo --version
if [[ "$role" == "target" ]]; then
	probe "unbound" command -v unbound
else
	probe "dnsperf" command -v dnsperf
fi

if ((fails)); then
	echo "== $fails check(s) failed"
	exit 1
fi
echo "== all checks passed"
