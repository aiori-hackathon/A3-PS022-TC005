# Segfault — Benchmarks

## How to reproduce

Run on the **target VM** (the one running the DNS server and Segfault). The harness drives
the flood from the **Kali** generator VM over SSH and probes the legitimate client:

```bash
sudo SERVER_IP=10.53.0.10 PPS=200000 bash lab/bench/run.sh
```

Environment overrides: `SCENARIOS`, `REPEATS` (default 3), `SECS` (default 20),
`PROBE_QPS`, `GEN_HOST`, `OUT` (default `results/raw`). Set `SERVER_IP=fd53::10` to run
over IPv6. A family-aware **preflight** confirms the (spoofed) flood can actually be sent
before any run is trusted, so zero-sent "ghost" runs cannot pollute the numbers. Each
reported cell is the **median of `REPEATS` runs**.

## Metrics

- **Goodput** — legitimate queries completed under attack.
- **Tail latency** — p99 of the legitimate client.
- **Packets absorbed** — attack packets shed per run.
- **CPU cost** — core utilisation while defending.

## IPv4 results (median of 3; *queries completed / p99 ms*)

| Scenario | none | nftables | nft-netdev | fixed-xdp | **segfault** |
|----------|------|----------|------------|-----------|--------------|
| distributed | 116 / 414 | 53 / 529 | 28 / 594 | 119 / 544 | **3719 / 1.1** |
| adaptive | 180 / 422 | 38 / 620 | 60 / 451 | 65 / 432 | **3670 / 1.1** |
| prefix-spoof | 0 | 0 | 0 | 0 | **3729 / 0.4** |
| water-torture | 113 / 392 | 49 / 469 | 52 / 592 | 68 / 680 | **3684 / 1.1** |

Segfault held 100% goodput in every scenario while absorbing 7–12 million packets per run.
Under **prefix-spoof** it served 3,729 legitimate queries where every baseline served **0**,
because it admits on proof, not on prefix.

## Result integrity

The clean result was checked four ways: a **failing control** (the no-defence baseline
degrades under the identical attack), **no allow-list** (`pass_allow = 0`; the client earns
protection through the proof path), **exact counter reconciliation** (total T0 queries =
pool-drop + heavy-drop + prefix + admitted, with only ~0.17% admitted and slips ≈ ½ of
drops at `k = 2`), and **full offered load** (the prober sent its full ~3,700 queries/run).

## Throughput ceiling

Measured in-kernel (veth + pktgen, no virtual switch): a bare `XDP_DROP` sheds **2.52 Mpps
at 16%** of one core; Segfault's full pipeline sheds **2.32 Mpps at 21%** — only ~40% more
CPU per packet than a do-nothing drop. At ~290 cycles/packet the per-core ceiling is
~6.9–10 Mpps, so on a server NIC Segfault is line-rate-bound:

$$C = \min\!\left(R_{\text{line}},\; N_{\text{core}} \cdot \frac{f}{c}\right)$$

The lab's ~900 kpps plateau was the Hyper-V virtual switch, not Segfault.
