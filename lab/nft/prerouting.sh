#!/usr/bin/env bash
# Baseline: nftables rate limit at the inet prerouting hook (after sk_buff allocation).
set -euo pipefail
SRC_QPS="${1:-50}"
GLOBAL_QPS="${2:-20000}"
sudo nft delete table inet segfault_bl 2>/dev/null || true
sudo nft -f - <<NFT
table inet segfault_bl {
    set floodsrc { type ipv4_addr; flags dynamic, timeout; size 65535; }
    chain pre {
        type filter hook prerouting priority -300; policy accept;
        udp dport 53 meter persrc { ip saddr limit rate over ${SRC_QPS}/second } drop
        udp dport 53 limit rate over ${GLOBAL_QPS}/second drop
    }
}
NFT
echo "nftables prerouting baseline up (src=${SRC_QPS}/s global=${GLOBAL_QPS}/s)"
