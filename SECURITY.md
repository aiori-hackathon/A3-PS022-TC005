# Security policy

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on this repository. Please do not open a public issue.

Include the affected version or commit, steps to reproduce, and the impact you observed. We aim to acknowledge within 72 hours and to ship a fix or mitigation within 14 days.

## Supported versions

| Version | Supported |
| --- | --- |
| latest `main` and newest tag | yes |
| older tags | no |

## Scope

- XDP datapath (`bpf/`): out-of-bounds reads, verifier bypass ideas, crafted packets that crash or mis-classify.
- Control plane and CLI (`crates/`): privilege issues, unsafe config handling, pinned-map tampering.
- Lab scripts (`lab/`): anything that could leak spoofed traffic outside the isolated lab network.

Traffic generation against systems you do not own is out of scope and not permitted.
