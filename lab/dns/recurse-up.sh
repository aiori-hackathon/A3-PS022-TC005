#!/usr/bin/env bash
# Starts the realistic water-torture lab: a local authoritative for flood.test (:5353) plus the
# main resolver that recurses to it. Run from the repo root on the target VM. Needs sudo.
set -euo pipefail
sudo pkill -f 'unbound -c' 2>/dev/null || true
sleep 1
sudo unbound -c lab/dns/unbound-auth.conf
sudo unbound -c lab/dns/unbound-recurse.conf
sleep 1
echo "auth(:5353) + recursive resolver(:53) up"
echo "legit check:  dig @10.53.0.10 legit.lab.test +short   (expect 10.53.0.100)"
echo "recurse check: dig @10.53.0.10 r$RANDOM$RANDOM.flood.test   (expect status: NXDOMAIN)"
