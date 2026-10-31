#!/usr/bin/env bash
# Restores the normal lab resolver (local-static flood.test) after a realistic water-torture run.
set -euo pipefail
sudo pkill -f 'unbound -c' 2>/dev/null || true
sleep 1
sudo unbound -c lab/dns/unbound.conf
echo "normal resolver(:53) restored; check: dig @10.53.0.10 legit.lab.test +short"
