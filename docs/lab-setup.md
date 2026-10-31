# Lab setup

Two Linux VMs on an isolated Hyper-V private switch `segfault-lab`: `segfault-target` runs the
DNS server (Unbound) and Segfault; the gen VM (Kali) runs the flood generator and the legitimate
prober. Spoofed traffic never leaves the private switch.

| VM | Lab IPv4 | Lab IPv6 | Role |
| --- | --- | --- | --- |
| segfault-target | 10.53.0.10/24 | fd53::10/64 | DNS server + Segfault |
| segfault-gen (Kali) | 10.53.0.20/24 | fd53::20/64 | flood + prober |

Each VM has two NICs: **eth0 = Default Switch** (internet for apt/cargo) and **eth1 =
segfault-lab** (all test traffic). On Hyper-V, `hv_netvsc` supports native XDP.

## Toolchain

```bash
sudo apt-get update && sudo apt-get install -y git make
# clone from your local sync (no GitHub needed): see the offline workflow
cd ~/segfault
make setup ROLE=target     # on the gen VM: make setup ROLE=gen
source ~/.cargo/env
```

## Network

```bash
sudo make net ROLE=target IFACE=eth1    # on gen: ROLE=gen
make check ROLE=target IFACE=eth1
```

## Build and verify

```bash
make build            # BPF object + Rust release binaries
make test             # Rust unit tests
make test-c           # userspace parser tests
make verify           # load the datapath through the kernel verifier
```

## Run

```bash
# server (target):
sudo ./target/release/segfault up -i eth1 --config configs/segfault.toml
# client (gen; spoofing needs raw sockets, so sudo or the setcap below):
sudo ./target/release/segfault-gen run --server 10.53.0.10 --scenario single --pps 200000 --secs 20
```

## Benchmark

Passwordless SSH from target to the gen VM is needed so the orchestrator can trigger the load:

```bash
ssh-keygen -t ed25519           # on target, if you have no key
ssh-copy-id kali@kali.mshome.net
# on gen, after every build: let the flood spoof sources without sudo
sudo setcap cap_net_raw+ep target/release/segfault-gen
IFACE=eth1 GEN_HOST=kali@kali.mshome.net bash lab/bench/run.sh
./target/release/segfault-bench results/raw -o results
```

Outputs `results/results.csv`, `results/goodput.svg` and `results/report.md`.
