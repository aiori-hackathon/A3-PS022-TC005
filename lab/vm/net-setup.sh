#!/usr/bin/env bash
# Gives this VM its static IPv4 and IPv6 address on the isolated lab network.
set -euo pipefail

role="${1:-}"
iface="${2:-enp0s8}"
case "$role" in
target) v4=10.53.0.10 v6=fd53::10 host=segfault-target ;;
gen) v4=10.53.0.20 v6=fd53::20 host=segfault-gen ;;
*)
	echo "usage: $0 <target|gen> [iface]" >&2
	exit 1
	;;
esac

if [[ $EUID -ne 0 ]]; then
	exec sudo bash "$0" "$@"
fi

if ! ip link show "$iface" >/dev/null 2>&1; then
	echo "no interface '$iface'; pick the lab NIC from 'ip -br link'" >&2
	exit 1
fi

# Netplan on Ubuntu, NetworkManager on Kali/Debian; only the lab NIC is touched.
if command -v netplan >/dev/null 2>&1; then
	conf=/etc/netplan/60-segfault-lab.yaml
	cat >"$conf" <<NETPLAN
network:
  version: 2
  ethernets:
    $iface:
      dhcp4: false
      dhcp6: false
      accept-ra: false
      addresses: [$v4/24, "$v6/64"]
NETPLAN
	chmod 600 "$conf"
	netplan apply
	hostnamectl set-hostname "$host"
elif command -v nmcli >/dev/null 2>&1; then
	nmcli connection delete segfault-lab >/dev/null 2>&1 || true
	nmcli connection add type ethernet ifname "$iface" con-name segfault-lab \
		connection.autoconnect yes connection.autoconnect-priority 100 \
		ipv4.method manual ipv4.addresses "$v4/24" ipv4.never-default yes \
		ipv6.method manual ipv6.addresses "$v6/64" ipv6.never-default yes ipv6.addr-gen-mode eui64
	nmcli connection up segfault-lab
	echo "hostname left as $(hostname) (NetworkManager host)"
else
	echo "neither netplan nor nmcli found" >&2
	exit 1
fi

sed -i '/# segfault-lab$/d' /etc/hosts
printf '%s\n' \
	"10.53.0.10 segfault-target # segfault-lab" \
	"10.53.0.20 segfault-gen # segfault-lab" \
	"fd53::10 segfault-target6 # segfault-lab" \
	"fd53::20 segfault-gen6 # segfault-lab" >>/etc/hosts

ip -br addr show "$iface"
