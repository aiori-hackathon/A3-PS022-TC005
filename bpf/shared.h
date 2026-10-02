/* SPDX-License-Identifier: (GPL-2.0 OR MIT) */
/* Constants and enums shared by the BPF program and the Rust control plane. */
#ifndef SEGFAULT_SHARED_H
#define SEGFAULT_SHARED_H

#define SF_DNS_PORT 53
#define SF_MAX_VLAN 2
#define SF_MAX_QNAME 255
#define SF_MAX_LABELS 127

/* Verdict reasons, one counter each in the per-CPU stats map. */
enum sf_reason {
	SF_PASS_NON_DNS = 0,
	SF_PASS_OK,
	SF_PASS_ALLOW,
	SF_DROP_DENY,
	SF_DROP_BANNED,
	SF_DROP_SOURCE,
	SF_DROP_PREFIX,
	SF_DROP_GLOBAL,
	SF_DROP_MALFORMED,
	SF_TX_SLIP,
	SF_SHADOW,
	SF_REASON_MAX,
};

#endif /* SEGFAULT_SHARED_H */
