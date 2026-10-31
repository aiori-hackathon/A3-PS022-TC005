#!/usr/bin/env bash
# Removes both nftables baselines.
sudo nft delete table inet segfault_bl 2>/dev/null || true
sudo nft delete table netdev segfault_nd 2>/dev/null || true
echo "nftables baselines removed"
