/* SPDX-License-Identifier: GPL-2.0 */
/* TC-slip: turns an over-budget query into a truncated (TC=1) reply sent back with XDP_TX. */
#ifndef SEGFAULT_SLIP_H
#define SEGFAULT_SLIP_H

#include "parse.h"

#define SF_SLIP_MAX_L4 320

/* Folds a 32-bit one's-complement sum to 16 bits. */
static __always_inline __u16 sf_fold(__u32 s)
{
	s = (s & 0xffff) + (s >> 16);
	s = (s & 0xffff) + (s >> 16);
	return (__u16)s;
}

/* Sums n bytes as big-endian 16-bit words, bounded for the verifier. */
static __always_inline __u32 sf_sum(__u8 *b, __u32 n, void *end)
{
	__u32 s = 0;
	for (__u32 i = 0; i < SF_SLIP_MAX_L4 / 2; i++) {
		__u32 off = i * 2;
		if (off + 2 > n)
			break;
		if ((void *)(b + off + 2) > end)
			break;
		s += ((__u32)b[off] << 8) | b[off + 1];
	}
	if (n & 1) {
		__u32 last = n - 1;
		if (last < SF_SLIP_MAX_L4 && (void *)(b + last + 1) <= end)
			s += (__u32)b[last] << 8;
	}
	return s;
}

/* Swaps n bytes between two buffers. */
static __always_inline void sf_swap(__u8 *a, __u8 *b, int n)
{
	for (int i = 0; i < n; i++) {
		__u8 t = a[i];
		a[i] = b[i];
		b[i] = t;
	}
}

/* Rewrites the packet into a TC=1 reply in place; returns 0 when ready for XDP_TX (verified once as
 * a global function). */
__noinline int sf_slip(struct xdp_md *ctx, struct sf_pkt *p)
{
	if (!ctx || !p)
		return -1;
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	__u32 l3 = p->l3off, l4 = p->l4off, dns = p->dnsoff, qend = p->qend;

	if (!p->simple_l3 || l3 > 64 || l4 > 128 || dns != l4 + 8 || qend > l4 + SF_SLIP_MAX_L4 ||
	    qend < dns + SF_DNS_HDR + 5)
		return -1;
	/* Mask to hard bounds so the ranges survive stack spills on stricter verifiers
	 * (kernel 6.8). */
	l3 &= 0x3f;
	l4 &= 0x7f;
	dns &= 0xff;
	qend &= 0x1ff;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return -1;
	sf_swap(eth->h_dest, eth->h_source, ETH_ALEN);

	__u8 *ip = (__u8 *)data + l3;
	__u8 *udp = (__u8 *)data + l4;
	if ((void *)(udp + 8 + SF_DNS_HDR) > end)
		return -1;
	__u8 *d = udp + 8;
	d[2] = 0x80 | 0x02 | (d[2] & 0x01);
	d[3] = 0;
	__builtin_memset(d + 6, 0, 6);
	sf_swap(udp, udp + 2, 2);

	if (!p->v6) {
		if ((void *)(ip + 20) > end)
			return -1;
		sf_swap(ip + 12, ip + 16, 4);
		ip[8] = 64;
	} else {
		if ((void *)(ip + 40) > end)
			return -1;
		sf_swap(ip + 8, ip + 24, 16);
		ip[7] = 64;
	}

	long delta = (long)qend - (long)(end - data);
	if (delta > 0)
		return -1;
	if (delta < 0 && bpf_xdp_adjust_tail(ctx, (int)delta))
		return -1;

	data = (void *)(long)ctx->data;
	end = (void *)(long)ctx->data_end;
	ip = (__u8 *)data + l3;
	udp = (__u8 *)data + l4;
	__u32 l4len = qend - l4;
	__u32 sum;

	if ((void *)(udp + 8) > end)
		return -1;
	udp[4] = l4len >> 8;
	udp[5] = l4len & 0xff;
	udp[6] = 0;
	udp[7] = 0;

	if (!p->v6) {
		if ((void *)(ip + 20) > end)
			return -1;
		__u32 tot = qend - l3;
		ip[2] = tot >> 8;
		ip[3] = tot & 0xff;
		ip[10] = 0;
		ip[11] = 0;
		__u16 ic = ~sf_fold(sf_sum(ip, 20, end));
		ip[10] = ic >> 8;
		ip[11] = ic & 0xff;
		sum = sf_sum(ip + 12, 8, end);
	} else {
		if ((void *)(ip + 40) > end)
			return -1;
		ip[4] = l4len >> 8;
		ip[5] = l4len & 0xff;
		sum = sf_sum(ip + 8, 32, end);
	}
	sum += IPPROTO_UDP + l4len;
	sum += sf_sum(udp, l4len, end);
	__u16 uc = ~sf_fold(sum);
	if (uc == 0)
		uc = 0xffff;
	udp[6] = uc >> 8;
	udp[7] = uc & 0xff;
	return 0;
}

#endif /* SEGFAULT_SLIP_H */
