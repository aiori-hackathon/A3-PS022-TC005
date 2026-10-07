#!/usr/bin/env bash
# Installs the Segfault build and lab toolchain on Ubuntu 24.04 or Kali/Debian (roles: target, gen, all, ci).
set -euo pipefail

role="${1:-all}"
case "$role" in
target | gen | all | ci) ;;
*)
	echo "usage: $0 [target|gen|all|ci]" >&2
	exit 1
	;;
esac

if [[ $EUID -ne 0 ]]; then
	exec sudo -E bash "$0" "$@"
fi

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
user="${SUDO_USER:-root}"

# shellcheck source=/dev/null
. /etc/os-release
distro="${ID:-unknown}"
case "$distro" in
ubuntu)
	if [[ "${VERSION_ID:-}" != "24.04" ]]; then
		echo "warning: tested on Ubuntu 24.04, found ${PRETTY_NAME:-unknown}" >&2
	fi
	;;
kali | debian) echo "==> ${PRETTY_NAME:-$distro}: using Debian package names" ;;
*) echo "warning: untested distro ${PRETTY_NAME:-unknown}" >&2 ;;
esac

export DEBIAN_FRONTEND=noninteractive
pkgs=(build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config linux-libc-dev
	iproute2 ethtool tcpdump bind9-dnsutils git curl ca-certificates jq clang-format shellcheck)

# bpftool ships in linux-tools on Ubuntu and as its own package on Kali/Debian.
if [[ "$role" != "ci" ]]; then
	if [[ "$distro" == "ubuntu" ]]; then
		pkgs+=(linux-tools-common linux-tools-generic)
		if apt-cache show "linux-tools-$(uname -r)" >/dev/null 2>&1; then
			pkgs+=("linux-tools-$(uname -r)")
		fi
	else
		pkgs+=(bpftool)
	fi
fi
[[ "$role" == "target" || "$role" == "all" ]] && pkgs+=(unbound nftables)
[[ "$role" == "gen" || "$role" == "all" ]] && pkgs+=(dnsperf)

echo "==> apt: ${#pkgs[@]} packages for role '$role'"
apt-get update -q
apt-get install -y -q --no-install-recommends "${pkgs[@]}"

# Mount bpffs if the distro has not already.
if ! mountpoint -q /sys/fs/bpf; then
	mount -t bpf bpf /sys/fs/bpf
fi

# Rust goes to the invoking user, pinned by rust-toolchain.toml.
echo "==> rust for user '$user'"
sudo -u "$user" -H bash -s -- "$repo" <<'RUST'
set -euo pipefail
if [[ ! -x "$HOME/.cargo/bin/rustup" ]] && ! command -v rustup >/dev/null; then
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
fi
export PATH="$HOME/.cargo/bin:$PATH"
cd "$1"
rustup toolchain install
rustc --version
RUST

echo "==> versions"
clang --version | head -n1
bpftool version 2>/dev/null | head -n1 || echo "bpftool: not available for kernel $(uname -r)"
echo "done: open a new shell (or 'source ~/.cargo/env') then run 'make build'"
