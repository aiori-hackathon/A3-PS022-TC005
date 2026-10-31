#!/usr/bin/env bash
# Stronger baseline: nftables at the netdev ingress hook with conntrack off (closest to XDP).
set -euo pipefail
IFACE="${1:-eth1}"
SRC_QPS="${2:-50}"
GLOBAL_QPS="${3:-20000}"
sudo nft delete table netdev segfault_nd 2>/dev/null || true
sudo nft -f - <<NFT
table netdev segfault_nd {
    chain ingress {
        type filter hook ingress device ${IFACE} priority -500; policy accept;
        udp dport 53 meter persrc6 { ip saddr limit rate over ${SRC_QPS}/second } drop
        udp dport 53 limit rate over ${GLOBAL_QPS}/second drop
    }
}
NFT
echo "nftables netdev-ingress baseline up on ${IFACE}"
