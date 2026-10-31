/* SPDX-License-Identifier: (GPL-2.0 OR MIT) */
/* Constants, enums and map value layouts shared by the BPF programs and the Rust control plane. */
#ifndef SEGFAULT_SHARED_H
#define SEGFAULT_SHARED_H

#define SF_DNS_PORT 53
#define SF_MAX_VLAN 2
#define SF_MAX_QNAME 255
#define SF_MAX_EXT 4
#define SF_MAX_COST 64
#define SF_SKETCH_ROWS 4
#define SF_SKETCH_COLS 4096
#define SF_T1_MAX 65536
#define SF_T2_MAX 16384
#define SF_PFX_MAX 65536
#define SF_ZONE_MAX 8192
#define SF_LIST_MAX 4096

/* Trust tiers: unknown, returning, proven. */
enum sf_tier {
	SF_T0 = 0,
	SF_T1 = 1,
	SF_T2 = 2,
	SF_TIERS = 3,
};

/* Defense modes chosen by the controller. */
enum sf_mode {
	SF_MODE_CALM = 0,
	SF_MODE_GUARD = 1,
	SF_MODE_SIEGE = 2,
};

/* Admission algorithm: Segfault or the fixed-threshold baseline. */
enum sf_algo {
	SF_ALGO_SEGFAULT = 0,
	SF_ALGO_FIXED = 1,
};

/* Ingress verdict reasons, one per-CPU counter each. */
enum sf_reason {
	SF_PASS_NON_DNS = 0,
	SF_PASS_TCP,
	SF_PASS_FRAG,
	SF_PASS_CALM,
	SF_PASS_T0,
	SF_PASS_T1,
	SF_PASS_T2,
	SF_PASS_ALLOW,
	SF_PASS_FIXED,
	SF_DROP_DENY,
	SF_DROP_BANNED,
	SF_DROP_MALFORMED,
	SF_DROP_SOURCE,
	SF_DROP_PREFIX,
	SF_DROP_POOL,
	SF_DROP_HEAVY,
	SF_TX_SLIP,
	SF_SHADOW_DROP,
	SF_PROMOTE_T1,
	SF_PROMOTE_DENIED,
	SF_BAN_ISSUED,
	SF_COST_UNITS,
	SF_QUERIES,
	SF_QUERIES_T0,
	SF_QUERIES_T1,
	SF_QUERIES_T2,
	SF_COOKIE_OK,
	SF_REASON_MAX,
};

/* Egress observer counters, one per-CPU counter each. */
enum sf_obs {
	SF_OBS_RESP = 0,
	SF_OBS_NXDOMAIN,
	SF_OBS_SERVFAIL,
	SF_OBS_TCP_RESP,
	SF_OBS_PROOFS,
	SF_OBS_MAX,
};

/* DNS Cookie secret (RFC 9018) shared with the resolver; validated in XDP. */
struct sf_secret {
	__u8 key[16];
	__u32 enabled;
	__u32 pad;
};

/* 16-byte address; IPv4 is stored IPv4-mapped (::ffff:a.b.c.d). */
struct sf_addr {
	__u8 a[16];
};

/* LPM key for allow/deny lists. */
struct sf_lpm_key {
	__u32 prefixlen;
	__u8 a[16];
};

/* Per-source state for returning (T1) sources and the fixed baseline. */
struct sf_src {
	__u64 tat;
	__u64 first_ns;
	__u64 last_ns;
	__u64 ban_until;
	__u32 strikes;
	__u32 queries;
};

/* Per-zone response counters written by the observer. */
struct sf_zone_stat {
	__u64 resp;
	__u64 nx;
};

/* Count-Min Sketch window over T0 sources. */
struct sf_sketch {
	__u32 c[SF_SKETCH_ROWS * SF_SKETCH_COLS];
};

/* Runtime policy written by the controller; field order is mirrored in crates/core. */
struct sf_config {
	__u32 algo;
	__u32 mode;
	__u32 shadow;
	__u32 slip_k;
	__u32 epoch;
	__u32 t0_heavy;
	__u32 promote_min;
	__u32 promote_max;
	__u32 strikes_ban;
	__u32 cost_any;
	__u32 cost_do;
	__u32 cost_big;
	__u32 learn_in_calm;
	__u32 pad;
	__u64 pool_ns[SF_TIERS];
	__u64 pool_burst_ns[SF_TIERS];
	__u64 src_ns[SF_TIERS];
	__u64 src_burst_ns;
	__u64 pfx_ns;
	__u64 pfx_burst_ns;
	__u64 promo_ns;
	__u64 promo_burst_ns;
	__u64 ban_ns;
	__u64 t2_ttl_ns;
};

#define SF_CONFIG_SIZE 184

#endif /* SEGFAULT_SHARED_H */
