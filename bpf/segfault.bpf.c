// SPDX-License-Identifier: GPL-2.0
/* Segfault datapath: trust-tiered, cost-weighted DNS admission at XDP plus a tc-egress observer. */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#include "shared.h"
#include "parse.h"
#include "maps.h"
#include "limit.h"
#include "slip.h"
#include "cookie.h"

_Static_assert(sizeof(struct sf_config) == SF_CONFIG_SIZE, "sf_config layout changed");

/* Decides slip, drop or shadow-pass for a rejected query. */
static __always_inline int sf_reject(struct xdp_md *ctx, const struct sf_config *cfg,
				     struct sf_pkt *p, __u32 reason, int slippable)
{
	if (cfg->shadow) {
		sf_count(SF_SHADOW_DROP, 1);
		sf_count(reason, 1);
		return XDP_PASS;
	}
	sf_count(reason, 1);
	if (slippable && cfg->slip_k) {
		__u32 z = 0;
		__u32 *c = bpf_map_lookup_elem(&sf_slip_ctr, &z);
		if (c) {
			*c += 1;
			if (*c >= cfg->slip_k) {
				*c = 0;
				if (sf_slip(ctx, p) == 0) {
					sf_count(SF_TX_SLIP, 1);
					return XDP_TX;
				}
			}
		}
	}
	return XDP_DROP;
}

/* Fixed-threshold baseline: per-source plus global bucket for every source, no tiers. */
static __always_inline int sf_fixed_path(struct xdp_md *ctx, const struct sf_config *cfg,
					 struct sf_pkt *p, __u64 now)
{
	struct sf_src *s = bpf_map_lookup_elem(&sf_fixed, &p->src);
	if (!s) {
		struct sf_src init = {.first_ns = now};
		bpf_map_update_elem(&sf_fixed, &p->src, &init, BPF_NOEXIST);
		s = bpf_map_lookup_elem(&sf_fixed, &p->src);
		if (!s)
			return XDP_PASS;
	}
	if (!sf_gcra(&s->tat, now, cfg->src_ns[SF_T1], cfg->src_burst_ns))
		return sf_reject(ctx, cfg, p, SF_DROP_SOURCE, 0);
	__u32 gk = SF_POOL_FIXED;
	__u64 *g = bpf_map_lookup_elem(&sf_pools, &gk);
	if (g && !sf_gcra(g, now, cfg->pool_ns[SF_T1], cfg->pool_burst_ns[SF_T1])) {
		sf_refund(&s->tat, cfg->src_ns[SF_T1]);
		return sf_reject(ctx, cfg, p, SF_DROP_POOL, 0);
	}
	sf_count(SF_PASS_FIXED, 1);
	return XDP_PASS;
}

/* Promotes a well-behaved unknown source to T1 if the promotion budget allows. */
static __always_inline void sf_promote(const struct sf_config *cfg, const struct sf_pkt *p,
				       __u64 now)
{
	__u32 pk = SF_POOL_PROMO;
	__u64 *pb = bpf_map_lookup_elem(&sf_pools, &pk);
	if (!pb || !sf_gcra(pb, now, cfg->promo_ns, cfg->promo_burst_ns)) {
		sf_count(SF_PROMOTE_DENIED, 1);
		return;
	}
	struct sf_src init = {.first_ns = now, .last_ns = now};
	if (bpf_map_update_elem(&sf_t1, &p->src, &init, BPF_NOEXIST) == 0)
		sf_count(SF_PROMOTE_T1, 1);
}

SEC("xdp")
int segfault_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	struct sf_pkt p = {};
	__u32 zero = 0;
	struct sf_scratch *sb = bpf_map_lookup_elem(&sf_buf, &zero);
	if (!sb)
		return XDP_PASS;

	int r = sf_parse(ctx, data, end, &p, sb->b, 1, 1);
	if (r == SF_P_OTHER) {
		sf_count(SF_PASS_NON_DNS, 1);
		return XDP_PASS;
	}
	if (r == SF_P_TCP53) {
		sf_count(SF_PASS_TCP, 1);
		return XDP_PASS;
	}
	if (r == SF_P_FRAG) {
		sf_count(SF_PASS_FRAG, 1);
		return XDP_PASS;
	}

	struct sf_config *cfg = bpf_map_lookup_elem(&sf_cfg, &zero);
	if (!cfg)
		return XDP_PASS;
	if (r == SF_P_MALFORMED)
		return sf_reject(ctx, cfg, &p, SF_DROP_MALFORMED, 0);

	__u64 now = bpf_ktime_get_ns();
	sf_count(SF_QUERIES, 1);

	struct sf_lpm_key lk = {.prefixlen = 128};
	__builtin_memcpy(lk.a, p.src.a, 16);
	if (bpf_map_lookup_elem(&sf_allow, &lk)) {
		sf_count(SF_PASS_ALLOW, 1);
		return XDP_PASS;
	}
	if (bpf_map_lookup_elem(&sf_deny, &lk))
		return sf_reject(ctx, cfg, &p, SF_DROP_DENY, 0);

	if (cfg->algo == SF_ALGO_FIXED)
		return sf_fixed_path(ctx, cfg, &p, now);

	__u32 cost = sf_cost(cfg, &p);
	__u32 tier = SF_T0;
	struct sf_src *src = 0;

	/* A valid RFC 9018 server cookie proves a real return path: admit as proven and record it.
	 */
	if (sf_cookie_valid(&p)) {
		__u64 exp_c = now + (cfg->t2_ttl_ns ? cfg->t2_ttl_ns : 300000000000ULL);
		bpf_map_update_elem(&sf_t2, &p.src, &exp_c, BPF_ANY);
		sf_count(SF_COOKIE_OK, 1);
		sf_count(SF_QUERIES_T2, 1);
		sf_count(SF_PASS_T2, 1);
		sf_count(SF_COST_UNITS, cost);
		return XDP_PASS;
	}

	__u64 *exp = bpf_map_lookup_elem(&sf_t2, &p.src);
	if (exp && *exp > now) {
		tier = SF_T2;
	} else {
		src = bpf_map_lookup_elem(&sf_t1, &p.src);
		if (src) {
			tier = SF_T1;
			if (src->ban_until > now)
				return sf_reject(ctx, cfg, &p, SF_DROP_BANNED, 0);
			src->last_ns = now;
			src->queries += 1;
		}
	}
	sf_count(SF_QUERIES_T0 + tier, 1);

	__u32 cur_est = 0, prev_est = 0;
	if (tier == SF_T0)
		sf_sketch_hit(cfg->epoch, &p.src, &cur_est, &prev_est);

	/* CALM: admit everything, learn who returns politely. */
	if (cfg->mode == SF_MODE_CALM) {
		if (tier == SF_T0 && cfg->learn_in_calm && prev_est >= cfg->promote_min &&
		    prev_est <= cfg->promote_max && cur_est <= cfg->promote_max)
			sf_promote(cfg, &p, now);
		sf_count(SF_PASS_CALM, 1);
		sf_count(SF_COST_UNITS, cost);
		return XDP_PASS;
	}

	/* GUARD / SIEGE: heavy unknowns, per-source, per-prefix, then the tier pool. */
	if (tier == SF_T0 && cfg->t0_heavy && cur_est > cfg->t0_heavy)
		return sf_reject(ctx, cfg, &p, SF_DROP_HEAVY, 1);

	__u64 src_inc = 0;
	if (src) {
		src_inc = (__u64)cost * cfg->src_ns[SF_T1];
		if (!sf_gcra(&src->tat, now, src_inc, cfg->src_burst_ns)) {
			__u32 st = __sync_fetch_and_add(&src->strikes, 1) + 1;
			if (cfg->strikes_ban && st >= cfg->strikes_ban) {
				src->ban_until = now + cfg->ban_ns;
				src->strikes = 0;
				sf_count(SF_BAN_ISSUED, 1);
			}
			return sf_reject(ctx, cfg, &p, SF_DROP_SOURCE, 1);
		}
	}

	__u64 *ptat = 0;
	__u64 pfx_inc = 0;
	if (tier != SF_T2 && cfg->pfx_ns) {
		struct sf_addr pk;
		sf_prefix(&pk, &p.src, p.v6);
		ptat = bpf_map_lookup_elem(&sf_pfx, &pk);
		if (!ptat) {
			__u64 init = 0;
			bpf_map_update_elem(&sf_pfx, &pk, &init, BPF_NOEXIST);
			ptat = bpf_map_lookup_elem(&sf_pfx, &pk);
		}
		pfx_inc = (__u64)cost * cfg->pfx_ns;
		if (ptat && !sf_gcra(ptat, now, pfx_inc, cfg->pfx_burst_ns)) {
			if (src)
				sf_refund(&src->tat, src_inc);
			return sf_reject(ctx, cfg, &p, SF_DROP_PREFIX, 1);
		}
	}

	__u32 pool = tier;
	__u64 *pt = bpf_map_lookup_elem(&sf_pools, &pool);
	if (pool < SF_TIERS && pt) {
		__u64 inc = (__u64)cost * cfg->pool_ns[pool];
		if (!sf_gcra(pt, now, inc, cfg->pool_burst_ns[pool])) {
			if (src)
				sf_refund(&src->tat, src_inc);
			if (ptat)
				sf_refund(ptat, pfx_inc);
			return sf_reject(ctx, cfg, &p, SF_DROP_POOL, 1);
		}
	}

	sf_count(SF_PASS_T0 + tier, 1);
	sf_count(SF_COST_UNITS, cost);
	return XDP_PASS;
}

/* Egress observer: counts server responses, per-zone NXDOMAIN, and records TCP proofs as T2. */
SEC("tc")
int segfault_tc(struct __sk_buff *skb)
{
	__u32 len = skb->len < 600 ? skb->len : 600;
	bpf_skb_pull_data(skb, len);

	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;
	struct sf_pkt p = {};
	__u32 zero = 0;
	struct sf_scratch *sb = bpf_map_lookup_elem(&sf_buf, &zero);
	if (!sb)
		return TC_ACT_OK;

	int r = sf_parse(skb, data, end, &p, sb->b, 0, 0);
	if (r == SF_P_TCP53) {
		if (p.tcp_payload > 0) {
			struct sf_config *cfg = bpf_map_lookup_elem(&sf_cfg, &zero);
			__u64 ttl = cfg && cfg->t2_ttl_ns ? cfg->t2_ttl_ns : 300000000000ULL;
			__u64 exp = bpf_ktime_get_ns() + ttl;
			bpf_map_update_elem(&sf_t2, &p.dst, &exp, BPF_ANY);
			sf_obs_count(SF_OBS_TCP_RESP);
			sf_obs_count(SF_OBS_PROOFS);
		}
		return TC_ACT_OK;
	}
	if (r != SF_P_DNS)
		return TC_ACT_OK;

	sf_obs_count(SF_OBS_RESP);
	int nx = p.rcode == 3;
	if (nx)
		sf_obs_count(SF_OBS_NXDOMAIN);
	else if (p.rcode == 2)
		sf_obs_count(SF_OBS_SERVFAIL);

	__u32 zone = p.zone;
	struct sf_zone_stat *zs = bpf_map_lookup_elem(&sf_zone_stats, &zone);
	if (!zs) {
		struct sf_zone_stat init = {};
		bpf_map_update_elem(&sf_zone_stats, &zone, &init, BPF_NOEXIST);
		zs = bpf_map_lookup_elem(&sf_zone_stats, &zone);
	}
	if (zs) {
		__sync_fetch_and_add(&zs->resp, 1);
		if (nx)
			__sync_fetch_and_add(&zs->nx, 1);
	}
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
