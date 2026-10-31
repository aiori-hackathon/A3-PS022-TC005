/* SPDX-License-Identifier: GPL-2.0 */
/* Lock-free GCRA buckets, Count-Min Sketch, prefix keys and query cost for the XDP admission path.
 */
#ifndef SEGFAULT_LIMIT_H
#define SEGFAULT_LIMIT_H

#include "maps.h"
#include "parse.h"

#define SF_CAS_TRIES 3

/* GCRA admit: true if the bucket has room for inc ns of work; commits with bounded CAS retries. */
static __always_inline int sf_gcra(__u64 *tat, __u64 now, __u64 inc, __u64 burst)
{
	if (inc == 0)
		return 1;
	for (int i = 0; i < SF_CAS_TRIES; i++) {
		__u64 old = *(volatile __u64 *)tat;
		__u64 base = old > now ? old : now;
		if (base - now > burst)
			return 0;
		if (__sync_val_compare_and_swap(tat, old, base + inc) == old)
			return 1;
	}
	return 0;
}

/* Gives back inc ns of work to a bucket after a later stage rejected the packet. */
static __always_inline void sf_refund(__u64 *tat, __u64 inc)
{
	if (tat && inc)
		__sync_fetch_and_add(tat, -inc);
}

/* 32-bit finalizer used to derive sketch rows. */
static __always_inline __u32 sf_mix(__u32 h)
{
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}

/* FNV-1a over a 16-byte address. */
static __always_inline __u32 sf_hash_addr(const struct sf_addr *a)
{
	__u32 h = SF_FNV_OFF;
	for (int i = 0; i < 16; i++)
		h = (h ^ a->a[i]) * SF_FNV_PRIME;
	return h;
}

/* Bumps a source in the current sketch window; returns current and previous window estimates. */
static __always_inline void sf_sketch_hit(__u32 epoch, const struct sf_addr *a, __u32 *cur_est,
					  __u32 *prev_est)
{
	__u32 ci = epoch & 1, pi = ci ^ 1;
	struct sf_sketch *cur = bpf_map_lookup_elem(&sf_sketch, &ci);
	struct sf_sketch *prev = bpf_map_lookup_elem(&sf_sketch, &pi);
	__u32 h1 = sf_hash_addr(a), h2 = sf_mix(h1) | 1;
	__u32 cmin = 0xffffffff, pmin = 0xffffffff;

	*cur_est = 0;
	*prev_est = 0;
	if (!cur || !prev)
		return;
	for (__u32 r = 0; r < SF_SKETCH_ROWS; r++) {
		__u32 idx = r * SF_SKETCH_COLS + ((h1 + r * h2) & (SF_SKETCH_COLS - 1));
		if (idx >= SF_SKETCH_ROWS * SF_SKETCH_COLS)
			return;
		__u32 v = __sync_fetch_and_add(&cur->c[idx], 1) + 1;
		__u32 pv = prev->c[idx];
		cmin = v < cmin ? v : cmin;
		pmin = pv < pmin ? pv : pmin;
	}
	*cur_est = cmin;
	*prev_est = pmin;
}

/* Masks a source to its fairness prefix: /24 for IPv4, /48 for IPv6. */
static __always_inline void sf_prefix(struct sf_addr *k, const struct sf_addr *a, int v6)
{
	__builtin_memcpy(k->a, a->a, 16);
	if (!v6) {
		k->a[15] = 0;
		return;
	}
	for (int i = 6; i < 16; i++)
		k->a[i] = 0;
}

/* Predicted work of a query in cost units: qtype, DO bit and the zone's NXDOMAIN multiplier. */
static __always_inline __u32 sf_cost(const struct sf_config *cfg, const struct sf_pkt *p)
{
	__u32 c = 1;
	__u16 t = p->qtype;

	if (t == 255)
		c *= cfg->cost_any ? cfg->cost_any : 1;
	else if (t == 16 || t == 46 || t == 48 || t == 43 || t == 99)
		c *= cfg->cost_big ? cfg->cost_big : 1;
	if (p->do_bit)
		c *= cfg->cost_do ? cfg->cost_do : 1;

	__u32 zone = p->zone;
	__u32 *zm = bpf_map_lookup_elem(&sf_zone_cost, &zone);
	if (zm && *zm > 1)
		c *= *zm;
	return c > SF_MAX_COST ? SF_MAX_COST : c;
}

#endif /* SEGFAULT_LIMIT_H */
