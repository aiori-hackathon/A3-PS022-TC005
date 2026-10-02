# Segfault

DNS-aware XDP rate limiter for DNS query floods, with a Rust CLI and a one-command benchmark suite. Built by team **Segfault** for AIORI hackathon problem statement **PS-022** (eBPF/XDP Rate Limiting for DNS Query Floods in a Lab).

> Status: **Part 0 — Foundations** (`v0.0.1`). The XDP program is a pass-through stub; the datapath lands in Part 1.

## What it will do

- Parse Ethernet, VLAN, IPv4/IPv6, UDP 53 and the DNS header with bounded checks at the XDP hook.
- Enforce per-source, per-prefix (/24, /64) and global token buckets before the kernel allocates an `sk_buff`.
- Extras: TC-slip (truncated replies via `XDP_TX`), adaptive thresholds, shadow mode, strike bans.
- `segfault bench` runs 3 scenarios × baselines (none, nftables, XDP) × repeats and writes CSV, charts and a report.

## Quick start (Ubuntu 24.04 VM)

```bash
git clone https://github.com/DebanganMALI/Segfault.git && cd Segfault
make setup ROLE=target      # or ROLE=gen on the generator VM
source ~/.cargo/env
make build                  # BPF object + release binaries
make verify                 # load the BPF object through the kernel verifier
./target/release/segfault --version
```

Full two-VM lab guide: [docs/lab-setup.md](docs/lab-setup.md). Run `make help` for every target.

## Layout

| Path | Contents |
| --- | --- |
| `bpf/` | XDP datapath in C (libbpf) |
| `crates/core` | Loader, maps, config (`segfault-core`) |
| `crates/cli` | `segfault` binary (`segfault-cli`) |
| `crates/gen` | Synthetic flood generator (`segfault-gen`) |
| `crates/bench` | Benchmark runner and report writer (`segfault-bench`) |
| `lab/` | VM, netns, DNS server and nftables lab assets |
| `configs/` | Example `segfault.toml` files |
| `tests/` | BPF packet tests and end-to-end tests |
| `docs/` | Setup, usage and architecture docs |
| `results/` | Benchmark outputs used in the report |

## Ethics

Floods are generated only inside an isolated lab network. Never point `segfault gen` at systems you do not own.

## License

Userspace code (Rust, scripts): [MIT](LICENSE). BPF program in `bpf/`: [GPL-2.0](LICENSES/GPL-2.0.txt), required by GPL-only kernel helpers.
