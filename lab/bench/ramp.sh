#!/usr/bin/env bash
# Ramps the flood rate against one baseline to find its ceiling. Run on the TARGET VM.
# For each step it records goodput, p99, achieved pps, and the busiest CPU's softirq/idle,
# so you can tell whether the wall is the generator, a CPU (XDP/softirq), or the NIC.
set -uo pipefail
IFACE="${IFACE:-eth1}"
GEN_HOST="${GEN_HOST:-kali@kali.mshome.net}"
SERVER_IP="${SERVER_IP:-10.53.0.10}"
GEN_BIN="${GEN_BIN:-/home/kali/segfault-test/target/release/segfault-gen}"
SCENARIO="${SCENARIO:-single}"
THREADS="${THREADS:-4}"
SECS="${SECS:-15}"
BASELINE="${BASELINE:-segfault}"
RATES="${RATES:-250000 500000 1000000 2000000 4000000 8000000}"
SF="sudo ./target/release/segfault"

cpu_snapshot() { grep '^cpu[0-9]' /proc/stat; }
# Busiest-core softirq% and lowest idle% over the interval between two /proc/stat snapshots.
cpu_report() {
    awk 'BEGIN{smax=0; imin=100}
    NR==FNR { for(i=2;i<=11;i++) b[$1,i]=$i; next }
    { dt=0; for(i=2;i<=11;i++) dt+=($i-b[$1,i]);
      ds=($8-b[$1,8]); di=($5-b[$1,5])+($6-b[$1,6]);
      if(dt>0){ s=100*ds/dt; idl=100*di/dt; if(s>smax)smax=s; if(idl<imin)imin=idl } }
    END{ printf "%-10.0f %-10.0f", smax, imin }' "$1" "$2"
}

bash lab/nft/down.sh >/dev/null
case "$BASELINE" in
  segfault)  $SF up -i "$IFACE" --algo segfault --mode guard --config configs/segfault.toml --seconds 99999 >/tmp/sf-ramp.log 2>&1 & ;;
  fixed-xdp) $SF up -i "$IFACE" --algo fixed --mode guard --config configs/segfault.toml --no-control >/dev/null ;;
  none)      $SF down -i "$IFACE" >/dev/null 2>&1 || true ;;
esac
sleep 1
echo "ramp: baseline=$BASELINE scenario=$SCENARIO threads=$THREADS secs=$SECS"
printf "%-10s %-13s %-8s %-9s %-10s %-10s\n" "rate_pps" "achieved_pps" "goodput" "p99_us" "soft_max%" "idle_min%"
for R in $RATES; do
    cpu_snapshot > /tmp/cpu_a
    # shellcheck disable=SC2029  # vars intentionally expand locally before the remote runs
    out=$(ssh "$GEN_HOST" "$GEN_BIN run --server $SERVER_IP --scenario $SCENARIO --pps $R --threads $THREADS --probe-qps 200 --secs $SECS" 2>/dev/null)
    cpu_snapshot > /tmp/cpu_b
    fs=$(grep -o 'flood_sent=[0-9]*' <<<"$out" | head -1 | cut -d= -f2)
    gp=$(grep -o 'goodput=[0-9.]*' <<<"$out" | head -1 | cut -d= -f2)
    p99=$(grep -o 'p99_us=[0-9]*' <<<"$out" | head -1 | cut -d= -f2)
    ach=$(( ${fs:-0} / SECS ))
    printf "%-10s %-13s %-8s %-9s %s\n" "$R" "$ach" "${gp:-?}" "${p99:-?}" "$(cpu_report /tmp/cpu_a /tmp/cpu_b)"
done
$SF down -i "$IFACE" >/dev/null 2>&1 || true
bash lab/nft/down.sh >/dev/null
echo "Ceiling = where achieved_pps stops rising (generator-bound), OR soft_max% nears 100 (CPU/XDP-bound),"
echo "         OR goodput drops below 1.0 / p99 climbs (Segfault bending). Note which happens first."
