# Segfault — Architecture

Segfault is an in-kernel DNS flood defence built on eBPF/XDP. It answers *"who is this
source, and what does the query cost?"* rather than *"how fast is this source?"*, and
enforces that answer at the earliest point in the kernel.

## Datapath — two eBPF programs

- **XDP ingress** (NIC driver, before the kernel allocates a socket buffer): bounded-parses
  each packet and decides **admit / drop / slip**. Dropping here costs almost nothing, which
  is why it is the right layer for volumetric defence.
- **TC egress**: observes the server's own replies. It never blocks traffic — it records
  **TCP proofs** (a completed response promotes the source to the proven tier) and per-zone
  **NXDOMAIN ratios** (to flag water-torture targets).

## Trust tiers

| Tier | Meaning | State | Treatment |
|------|---------|-------|-----------|
| **T0** | Unknown | none (Count-Min sketch) | heavy hitters shed first, cheapest path |
| **T1** | Returning | per-source GCRA bucket (LRU) | per-source + per-prefix + pool limits; strikes → ban |
| **T2** | Proven | cookie or TCP proof (TTL) | bypasses the per-prefix and heavy-hitter checks |

Promotion to T2 requires evidence an off-path spoofer cannot forge: an RFC 9018 DNS cookie
(a SipHash-2-4 keyed MAC) or a completed TCP exchange observed on egress.

## Pinned maps — `/sys/fs/bpf/segfault`

T1 sources (LRU) · T2 proven (TTL) · Count-Min sketch · GCRA pools · per-prefix buckets ·
config · counters · per-zone stats.

## Userspace controller (libbpf-rs)

Loads and pins the programs and maps, polls the counters, measures the live drop fraction,
and moves the datapath between modes — **CALM → GUARD → SIEGE** — with hysteresis so a noisy
flood does not make it oscillate. The kernel stays on the fast path; policy lives in
userspace. Escalation is reversible: as the flood eases, the controller de-escalates back
toward CALM.

## Repository layout

| Path | Contents |
|------|----------|
| `bpf/` | the eBPF datapath (XDP admission + TC observer) and shared headers |
| `crates/core` | shared types and config |
| `crates/cli` | the `segfault` controller (`up` / `down` / `stats` / `top` / `why` / `serve`) |
| `crates/gen` | the attack generator / prober (`segfault-gen`) |
| `crates/bench` | benchmark helpers |
| `configs/` | policy files per algorithm and mode |
| `lab/` | the Hyper-V lab: nftables baselines, DNS configs, and the benchmark harness |
| `tests/` | BPF and end-to-end tests |
| `docs/` | pseudocode, architecture, and benchmark docs |

See `docs/pseudocode.md` for the admission algorithm and `docs/benchmarks.md` to reproduce
the results.
