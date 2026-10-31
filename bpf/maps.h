/* SPDX-License-Identifier: GPL-2.0 */
/* BPF maps shared by the XDP admission program and the tc observer; all pinned by name. */
#ifndef SEGFAULT_MAPS_H
#define SEGFAULT_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "shared.h"
#include "parse.h"

/* Pool bucket slots: three tier pools, the promotion budget and the fixed-baseline global bucket.
 */
#define SF_POOL_PROMO 3
#define SF_POOL_FIXED 4
#define SF_POOL_SLOTS 8

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sf_config);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sf_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sf_secret);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sf_secret SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SF_POOL_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sf_pools SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, SF_REASON_MAX);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sf_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, SF_OBS_MAX);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sf_obs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, SF_T1_MAX);
	__type(key, struct sf_addr);
	__type(value, struct sf_src);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sf_t1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, SF_T1_MAX);
	__type(key, struct sf_addr);
	__type(value, struct sf_src);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sf_fixed SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, SF_T2_MAX);
	__type(key, struct sf_addr);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sf_t2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, SF_PFX_MAX);
	__type(key, struct sf_addr);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sf_pfx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct sf_sketch);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sf_sketch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SF_ZONE_MAX);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sf_zone_cost SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, SF_ZONE_MAX);
	__type(key, __u32);
	__type(value, struct sf_zone_stat);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sf_zone_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, SF_LIST_MAX);
	__type(key, struct sf_lpm_key);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sf_allow SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, SF_LIST_MAX);
	__type(key, struct sf_lpm_key);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sf_deny SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} sf_slip_ctr SEC(".maps");

/* Per-CPU scratch buffer holding the DNS section for bounded parsing (struct sf_scratch in
 * parse.h). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sf_scratch);
} sf_buf SEC(".maps");

/* Adds n to one per-CPU stats counter. */
static __always_inline void sf_count(__u32 reason, __u64 n)
{
	__u64 *v = bpf_map_lookup_elem(&sf_stats, &reason);
	if (v)
		*v += n;
}

/* Adds one to one per-CPU observer counter. */
static __always_inline void sf_obs_count(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&sf_obs, &idx);
	if (v)
		*v += 1;
}

#endif /* SEGFAULT_MAPS_H */
