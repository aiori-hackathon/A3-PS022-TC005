#!/usr/bin/env bash
# Orchestrates the full matrix: each baseline x each scenario, driving the gen VM over SSH.
# Run on the TARGET VM. Needs passwordless SSH to the gen VM (see docs/lab-setup.md).
set -uo pipefail

IFACE="${IFACE:-eth1}"
GEN_HOST="${GEN_HOST:-kali@kali.mshome.net}"
SERVER_IP="${SERVER_IP:-10.53.0.10}"
GEN_BIN="${GEN_BIN:-/home/kali/segfault-local/target/release/segfault-gen}"
SF="${SF:-sudo ./target/release/segfault}"
PPS="${PPS:-200000}"
SECS="${SECS:-20}"
PROBE_QPS="${PROBE_QPS:-200}"
OUT="${OUT:-results/raw}"
REPEATS="${REPEATS:-3}"
# Override with e.g. SCENARIOS="adaptive" for a quick check.
# Set SERVER_IP=fd53::10 (and GEN_BIN on an IPv6-reachable gen) to benchmark over IPv6.
read -r -a SCENARIOS <<< "${SCENARIOS:-single distributed pulse adaptive prefix-spoof water-torture}"
mkdir -p "$OUT"
echo "segfault bench: scenarios=[${SCENARIOS[*]}] repeats=$REPEATS secs=$SECS gen=$GEN_HOST"

# Preflight: the generator must actually be able to send the (spoofed) flood, or every number is meaningless.
pre=$(ssh "$GEN_HOST" "$GEN_BIN run --server $SERVER_IP --scenario single --pps 1000 --probe-qps 10 --secs 2" 2>&1)
if ! grep -q 'flood_sent=[1-9]' <<< "$pre"; then
    echo "PREFLIGHT FAILED: the generator on $GEN_HOST sent no flood packets."
    echo "$pre" | tail -3
    echo "Fix on the Kali VM:  sudo setcap cap_net_raw+ep $GEN_BIN"
    exit 1
fi
echo "preflight ok: $(grep -o 'flood_sent=[0-9]*' <<< "$pre")"

# One (baseline, scenario): sets up the filter, runs the gen, saves the RESULT line + stats.
run_one() {
    local baseline="$1" scenario="$2"
    echo ">>> $baseline / $scenario"
    # Segfault runs its live controller (CALM/GUARD/SIEGE) for the whole set of repeats;
    # the fixed-xdp baseline stays static, representing the rivals' fixed-threshold design.
    local total=$(( REPEATS * (SECS + 4) + 8 ))
    case "$baseline" in
        none)            bash lab/nft/down.sh >/dev/null; $SF down -i "$IFACE" >/dev/null 2>&1 ;;
        nftables)        $SF down -i "$IFACE" >/dev/null 2>&1; bash lab/nft/prerouting.sh >/dev/null ;;
        nftables-netdev) $SF down -i "$IFACE" >/dev/null 2>&1; bash lab/nft/netdev.sh "$IFACE" >/dev/null ;;
        fixed-xdp)       bash lab/nft/down.sh >/dev/null; $SF up -i "$IFACE" --algo fixed --mode guard --config configs/segfault.toml --no-control >/dev/null ;;
        segfault)        bash lab/nft/down.sh >/dev/null
                         $SF up -i "$IFACE" --algo segfault --mode guard --config configs/segfault.toml --seconds "$total" \
                             > "$OUT/${baseline}-${scenario}-ctl.log" 2>&1 & ;;
    esac
    sleep 1
    # Repeat each combination so the report can take a stable median.
    for k in $(seq 1 "$REPEATS"); do
        ssh "$GEN_HOST" "$GEN_BIN run --server $SERVER_IP --scenario $scenario --pps $PPS --probe-qps $PROBE_QPS --secs $SECS --seed $k" \
            > "$OUT/${baseline}-${scenario}-r${k}.txt" 2>/dev/null
        grep RESULT "$OUT/${baseline}-${scenario}-r${k}.txt" || echo "  (no RESULT on run $k; check gen host)"
    done
    if [[ "$baseline" == fixed-xdp || "$baseline" == segfault ]]; then
        $SF stats --json > "$OUT/${baseline}-${scenario}.json" 2>/dev/null
    fi
    $SF down -i "$IFACE" >/dev/null 2>&1
    wait 2>/dev/null
    bash lab/nft/down.sh >/dev/null
}

for scenario in "${SCENARIOS[@]}"; do
    for baseline in none nftables nftables-netdev fixed-xdp segfault; do
        run_one "$baseline" "$scenario"
    done
done
echo "raw results in $OUT; now: ./target/release/segfault-bench $OUT -o results"
