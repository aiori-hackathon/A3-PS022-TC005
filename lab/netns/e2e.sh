#!/usr/bin/env bash
# Single-host end-to-end smoke test. The server (DNS + Segfault) runs in the host netns so
# its pinned maps persist across commands; only the client lives in its own netns. Needs root.
set -uo pipefail

SF="${SF:-target/release/segfault}"
GEN="${GEN:-target/release/segfault-gen}"
CLI_NS=sf-cli
SRV_IP=10.80.0.1
CLI_IP=10.80.0.2
IFACE=sfveths

cleanup() {
	"$SF" down -i "$IFACE" >/dev/null 2>&1
	ip netns del "$CLI_NS" 2>/dev/null
	ip link del "$IFACE" 2>/dev/null
	kill "${DNS_PID:-0}" 2>/dev/null
}
trap cleanup EXIT
ip netns del "$CLI_NS" 2>/dev/null
ip link del "$IFACE" 2>/dev/null

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
ip netns add "$CLI_NS"
ip link add "$IFACE" type veth peer name sfvethc netns "$CLI_NS"
ip addr add "$SRV_IP/24" dev "$IFACE"
ip link set "$IFACE" up
ip -n "$CLI_NS" addr add "$CLI_IP/24" dev sfvethc
ip -n "$CLI_NS" link set sfvethc up
ip -n "$CLI_NS" link set lo up

# Tiny DNS responder: answers every UDP and TCP query (the client treats a TCP answer as a proof).
cat >/tmp/sf_dns.py <<'PY'
import socket, sys, struct, select
ip = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((ip, 53))
t = socket.socket(socket.AF_INET, socket.SOCK_STREAM); t.bind((ip, 53)); t.listen(32); t.setblocking(False)
def answer(q): return q[:2] + b'\x81\x80' + q[4:6] + q[4:6] + b'\x00\x00\x00\x00' + q[12:]
while True:
    r,_,_ = select.select([s,t],[],[],1.0)
    for sock in r:
        if sock is s:
            d,a = s.recvfrom(2048)
            if len(d) >= 12: s.sendto(answer(d), a)
        else:
            try:
                c,_ = t.accept(); h = c.recv(2)
                if len(h)==2:
                    q = c.recv(struct.unpack('!H',h)[0]); r2 = answer(q)
                    c.sendall(struct.pack('!H',len(r2)) + r2)
                c.close()
            except Exception: pass
PY
python3 /tmp/sf_dns.py "$SRV_IP" & DNS_PID=$!
sleep 1

cat >/tmp/sf.toml <<TOML
capacity_qps = 3000.0
proven_share = 0.5
unknown_share = 0.3
src_qps = 40.0
src_burst = 60.0
prefix_qps = 20000.0
prefix_burst = 40000.0
promote_qps = 100.0
promote_burst = 150.0
heavy_threshold = 400
promote_min = 2
promote_max = 300
strikes_ban = 100000
ban_secs = 10.0
proven_ttl_secs = 120.0
cost_any = 8
cost_do = 2
cost_big = 3
slip_k = 4
learn_in_calm = true
TOML

echo "== attach Segfault (GUARD) on $IFACE"
"$SF" up -i "$IFACE" --mode guard --config /tmp/sf.toml --no-control
echo

echo "== 1) legit prober alone, no attack (expect ~100%)"
ip netns exec "$CLI_NS" "$GEN" probe --server "$SRV_IP" --qps 100 --secs 4
echo

echo "== 2) single-source flood (20k pps) + legit prober, different source (expect legit still high)"
ip netns exec "$CLI_NS" "$GEN" run --server "$SRV_IP" --scenario single --pps 20000 --probe-qps 100 --secs 6 --seed 1
echo

echo "== server counters"
"$SF" stats
echo
echo "== why the flooder vs a fresh IP"
"$SF" why "$CLI_IP"
echo "== done"
