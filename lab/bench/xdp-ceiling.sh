#!/usr/bin/env bash
# In-kernel XDP throughput ceiling microbench. Run on the TARGET VM as root, from the repo root.
# Generates packets in-kernel (pktgen) into a veth pair and measures how fast the XDP program on
# the other end sheds them -- no virtual switch in the path, so it is CPU-bound, not switch-bound.
# BASELINE=drop measures a minimal XDP_DROP (the floor); BASELINE=segfault measures Segfault.
set -uo pipefail

IFACE_GEN="vgen"
IFACE_XDP="vxdp"
BASELINE="${BASELINE:-segfault}"
THREADS="${THREADS:-4}"     # pktgen TX threads (one CPU each); raise toward your vCPU count
SECS="${SECS:-10}"
PKT="${PKT:-64}"
SF="sudo ./target/release/segfault"

cleanup() {
  echo "stop" > /proc/net/pktgen/pgctrl 2>/dev/null
  $SF down -i "$IFACE_XDP" >/dev/null 2>&1
  ip link set dev "$IFACE_XDP" xdp off 2>/dev/null
  ip link del "$IFACE_GEN" 2>/dev/null
}
trap cleanup EXIT

# 1. pktgen
modprobe pktgen 2>/dev/null
[ -e /proc/net/pktgen/pgctrl ] || { echo "ERROR: pktgen module not available (modprobe pktgen failed)"; exit 1; }

# 2. veth pair; offloads off so XDP sees raw frames
ip link del "$IFACE_GEN" 2>/dev/null
ip link add "$IFACE_GEN" type veth peer name "$IFACE_XDP"
for d in "$IFACE_GEN" "$IFACE_XDP"; do
  ethtool -K "$d" tx off rx off tso off gso off gro off lro off 2>/dev/null
  ip link set dev "$d" up
done
MAC=$(cat /sys/class/net/$IFACE_XDP/address)

# 3. attach the program under test to the XDP side
if [ "$BASELINE" = drop ]; then
  clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c lab/bench/xdp_drop.c -o /tmp/xdp_drop.o
  ip link set dev "$IFACE_XDP" xdpdrv obj /tmp/xdp_drop.o sec xdp 2>/dev/null \
    || ip link set dev "$IFACE_XDP" xdpgeneric obj /tmp/xdp_drop.o sec xdp
else
  $SF up -i "$IFACE_XDP" --algo segfault --mode siege --config configs/segfault.toml --no-control
fi
sleep 1

# 4. configure pktgen: clone the gen device across THREADS CPUs, UDP/53 small packets
for t in $(seq 0 $((THREADS-1))); do
  echo "rem_device_all" > /proc/net/pktgen/kpktgend_$t 2>/dev/null
  echo "add_device ${IFACE_GEN}@$t" > /proc/net/pktgen/kpktgend_$t
  D=/proc/net/pktgen/${IFACE_GEN}@$t
  echo "count 0"            > $D
  echo "clone_skb 0"        > $D
  echo "pkt_size $PKT"      > $D
  echo "delay 0"            > $D
  echo "dst 10.53.0.10"     > $D
  echo "dst_mac $MAC"       > $D
  echo "udp_src_min 1024"   > $D
  echo "udp_src_max 65000"  > $D
  echo "udp_dst_min 53"     > $D
  echo "udp_dst_max 53"     > $D
  echo "flag UDPSRC_RND"    > $D
done

# 5. run for SECS, sampling the busiest CPU's softirq and the XDP-processed count
echo "ceiling microbench: baseline=$BASELINE threads=$THREADS secs=$SECS pkt=${PKT}B"
xdp_count() { ethtool -S "$IFACE_XDP" 2>/dev/null | awk '/xdp_packets/{s+=$2} END{print s+0}'; }
XP_A=$(xdp_count)
grep '^cpu[0-9]' /proc/stat > /tmp/c_a
echo "start" > /proc/net/pktgen/pgctrl &
sleep "$SECS"
echo "stop" > /proc/net/pktgen/pgctrl
wait 2>/dev/null
grep '^cpu[0-9]' /proc/stat > /tmp/c_b
XP_B=$(xdp_count)
PROC=$(( (XP_B - XP_A) / SECS ))

# 6. sum pktgen pps across threads
TOT=0
for t in $(seq 0 $((THREADS-1))); do
  PPS=$(grep -oE '[0-9]+pps' /proc/net/pktgen/${IFACE_GEN}@$t 2>/dev/null | head -1 | tr -dc '0-9')
  TOT=$(( TOT + ${PPS:-0} ))
done
CPU=$(awk 'BEGIN{smax=0;imin=100}
  NR==FNR{for(i=2;i<=11;i++)b[$1,i]=$i;next}
  {dt=0;for(i=2;i<=11;i++)dt+=($i-b[$1,i]); ds=($8-b[$1,8]); di=($5-b[$1,5])+($6-b[$1,6]);
   if(dt>0){s=100*ds/dt;idl=100*di/dt; if(s>smax)smax=s; if(idl<imin)imin=idl}}
  END{printf "soft_max=%.0f%%  idle_min=%.0f%%", smax, imin}' /tmp/c_a /tmp/c_b)

echo "-----------------------------------------------"
echo "XDP processed : $PROC pps  (~$(( PROC/1000000 )).$(( (PROC/100000)%10 )) Mpps)   <- the ceiling figure"
echo "pktgen offered: $TOT pps  (~$(( TOT/1000000 )).$(( (TOT/100000)%10 )) Mpps)"
echo "CPU           : $CPU"
if [ "$BASELINE" = segfault ]; then
  echo "segfault stats:"; $SF stats 2>/dev/null | grep -E 'queries|drop|pass' | head -8
fi
echo "-----------------------------------------------"
echo "Read: if soft_max% is ~100, that core is the ceiling (CPU-bound = Segfault's real limit)."
echo "      if soft_max% stays low, raise THREADS toward your vCPU count to push harder."
