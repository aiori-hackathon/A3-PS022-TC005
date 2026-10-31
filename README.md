# Segfault — Drop the Flood, Keep the Queries

**Team A3-PS022-TC005 · IEM Kolkata.** eBPF/XDP rate limiting for DNS query floods (PS-022).

Most rate limiters ask *how fast is this source sending?* Segfault asks a better pair of
questions: *is this source real, and how much does its query actually cost the server?*

## Demo

📺 **Demo video:** [▶ Watch the demo](https://youtu.be/PQQvaYzG-lU)

## Results

Legitimate-client goodput under attack, across five baselines (median of 3; *queries completed / p99 ms*):

| Scenario | none | nftables | nft-netdev | fixed-xdp | **segfault** |
|----------|------|----------|------------|-----------|--------------|
| distributed | 116 / 414 | 53 / 529 | 28 / 594 | 119 / 544 | **3719 / 1.1** |
| adaptive | 180 / 422 | 38 / 620 | 60 / 451 | 65 / 432 | **3670 / 1.1** |
| prefix-spoof | 0 | 0 | 0 | 0 | **3729 / 0.4** |
| water-torture | 113 / 392 | 49 / 469 | 52 / 592 | 68 / 680 | **3684 / 1.1** |

Segfault held **100% goodput** in every scenario while absorbing 7–12 M packets/run; under
**prefix-spoof** it served **3,729** legitimate queries where every baseline served **0**. At
~290 cycles/packet it sits in the line-rate regime of production XDP. The full matrix (IPv4 + IPv6 +
recursive-realism) is in [`results/`](results/); see [`docs/benchmarks.md`](docs/benchmarks.md) for
the method and [`docs/pseudocode.md`](docs/pseudocode.md) for the datapath algorithm.

## Three ideas

1. **Trust before rate.** Unknown sources (T0) get **no per-source state** — only a fixed-memory
   Count-Min sketch, so a spoofed flood can never exhaust memory. A source earns a real limiter (T1)
   by behaving, and becomes *proven* (T2) only by completing TCP after a truncation hint.
2. **Cost, not count.** A query is charged tokens by predicted work: ANY/large types, the DNSSEC
   DO bit, and zones that are producing lots of NXDOMAIN (random-subdomain floods pay more
   automatically — no special-case rule).
3. **Measured capacity.** Limits are shares of the server's real measured capacity, not magic
   numbers. The controller moves between CALM / GUARD / SIEGE from live observer feedback.

Excess unknown queries get a **TC-slip**: a truncated (`TC=1`) reply via `XDP_TX`, never larger
than the query, so reflection gain is at most `1/k`. A real client retries over TCP; the egress
**observer** sees the TCP answer and promotes that client to proven. Spoofers can't.

## Build and run

```bash
make setup ROLE=target        # toolchain (clang, libbpf, bpftool, Rust, Unbound)
make build                    # BPF object + Rust release binaries
make test test-c              # Rust + C parser unit tests
make verify                   # load the datapath through the kernel verifier
sudo make net ROLE=target IFACE=eth1

# protect an interface:
sudo ./target/release/segfault up -i eth1 --config configs/segfault.toml
./target/release/segfault stats
./target/release/segfault why 10.53.0.20
sudo ./target/release/segfault down -i eth1

# extras:
./target/release/segfault-gen calibrate --server 10.53.0.10   # find capacity_qps
sudo ./target/release/segfault cookie-secret 000102030405060708090a0b0c0d0e0f  # RFC 9018 proof path
sudo ./target/release/segfault top            # live full-screen counters
sudo ./target/release/segfault serve          # Prometheus /metrics + dashboard on :9108
```

### Two proof paths to "proven" (T2)

A source becomes **proven** either by (a) answering a TC-slip over **TCP** — the egress observer sees
the TCP reply and promotes it — or (b) presenting a valid **RFC 9018 DNS Cookie**, which Segfault
verifies in XDP with SipHash-2-4 against a secret shared with the resolver. A spoofer can do neither.
Set the same secret on Segfault (`cookie-secret`) and Unbound (`cookie-secret:` in `lab/dns/unbound.conf`).

Single-host smoke test (no second VM needed): `sudo make e2e`.

## Benchmark

Five baselines (no filter, nftables prerouting, nftables netdev-ingress, a plain fixed-threshold
XDP limiter, and Segfault) across five scenarios (single, distributed-spoofed, pulsed
random-subdomain, adaptive-under-threshold, prefix-spoof):

```bash
IFACE=eth1 GEN_HOST=kali@kali.mshome.net bash lab/bench/run.sh
./target/release/segfault-bench results/raw -o results   # -> results.csv, goodput.svg, report.md
```

## Layout

```
bpf/        shared.h parse.h maps.h limit.h slip.h segfault.bpf.c   (XDP + tc datapath)
crates/     core (config/maps/stats) · cli (segfault) · gen (generator+prober) · bench (report)
lab/        vm/ netns/ dns/ nft/ bench/                              (lab, baselines, orchestrator)
tests/      bpf/parse_test.c  bpf/fuzz_parse.c                       (parser unit + fuzz)
configs/    segfault.toml
docs/       pseudocode.md · architecture.md · benchmarks.md
results/    raw/ (IPv4) · raw6*/ (IPv6) · raw-rec*/ (recursive) · results.csv · charts
```

See `docs/lab-setup.md` for the full two-VM setup.

## Team

Debangan Mali · Saraswata Chatterjee · Partha Chakraborty (Faculty) — IEM Kolkata · Team A3-PS022-TC005
