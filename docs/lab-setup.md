# Lab setup (Part 0)

Two Ubuntu 24.04 VMs on an isolated internal network: `segfault-target` runs the DNS server and Segfault, `segfault-gen` runs the flood generator and legitimate clients.

| VM | Lab IPv4 | Lab IPv6 | vCPU | RAM | Disk |
| --- | --- | --- | --- | --- | --- |
| segfault-target | 10.53.0.10/24 | fd53::10/64 | 2–4 | 2 GB | 25 GB |
| segfault-gen | 10.53.0.20/24 | fd53::20/64 | 2–4 | 2 GB | 25 GB |

Each VM has two NICs: **NIC 1 = NAT** (internet for apt and cargo) and **NIC 2 = internal network `segfault-lab`**, virtio-net, for all test traffic. Spoofed traffic never leaves NIC 2.

## 1. Create the VMs (VirtualBox on Windows)

Download the Ubuntu 24.04 **server** ISO, then in PowerShell from the repo root:

```powershell
powershell -ExecutionPolicy Bypass -File lab\vm\create-vms.ps1 -Iso "D:\ISO\ubuntu-24.04-live-server-amd64.iso"
```

Add `-Unattended` to let VirtualBox install Ubuntu automatically (user `segfault`, password `segfault`; change it after first login). Without it, install Ubuntu by hand in each VM window and tick **Install OpenSSH server**.

Using VMware or Hyper-V instead: create the same two VMs by hand, give NIC 2 a host-only or private switch with no uplink, and pick a VMXNET3/virtio-class adapter if offered.

## 2. Toolchain (both VMs)

```bash
sudo apt-get update && sudo apt-get install -y git make
git clone https://github.com/DebanganMALI/Segfault.git && cd Segfault
make setup ROLE=target      # on segfault-gen: make setup ROLE=gen
source ~/.cargo/env
```

## 3. Lab network (both VMs)

Find the lab NIC (usually `enp0s8`) with `ip -br link`, then:

```bash
make net ROLE=target IFACE=enp0s8   # on segfault-gen: make net ROLE=gen IFACE=enp0s8
```

## 4. Check and build

```bash
make check ROLE=target IFACE=enp0s8   # on segfault-gen: ROLE=gen
make build
make verify                           # target VM: kernel verifier accepts the object
```

`check` reports whether the NIC driver supports native XDP (`virtio_net` does). If it does not, Segfault falls back to generic mode, which PS-022 allows; record the mode with every result.

## Part 0 done when

- `make setup && make build` succeeds on the target VM.
- Both VMs ping each other over IPv4 and IPv6 on the lab network.
- CI is green on `main`; tag `v0.0.1`.

## Before benchmarking

Cut NIC 1 during runs so nothing reaches the internet:

```powershell
& "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe" controlvm segfault-target setlinkstate1 off
& "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe" controlvm segfault-gen setlinkstate1 off
```
