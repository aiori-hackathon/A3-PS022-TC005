/* SPDX-License-Identifier: (GPL-2.0 OR MIT) */
/* Bounded Ethernet/VLAN/IPv4/IPv6/UDP/DNS parser shared by XDP, tc and the userspace fuzz harness.
 */
#ifndef SEGFAULT_PARSE_H
#define SEGFAULT_PARSE_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "shared.h"

#ifdef SF_USERSPACE
/* Network-to-host for a 16-bit value without pulling in arpa/inet.h (avoids struct clashes). */
static inline __u16 sf_ntohs_u(__u16 x)
{
	return (__u16)((x >> 8) | (x << 8));
}
#define SF_NTOHS(x) sf_ntohs_u(x)
#define SF_INLINE static inline
#else
#include <bpf/bpf_endian.h>
#define SF_NTOHS(x) bpf_ntohs(x)
#define SF_INLINE static __always_inline
#endif

#define SF_ETH_P_8021Q 0x8100
#define SF_ETH_P_8021AD 0x88A8
#define SF_DNS_HDR 12
#define SF_FNV_OFF 2166136261u
#define SF_FNV_PRIME 16777619u
#define SF_OPT_TYPE 41
#define SF_OPT_COOKIE 10
#define SF_COOKIE_MAX 40

/* Parse outcome. */
enum sf_parse {
	SF_P_OTHER = 0,
	SF_P_DNS,
	SF_P_TCP53,
	SF_P_FRAG,
	SF_P_MALFORMED,
};

/* Everything later stages need to know about a packet. */
struct sf_pkt {
	__u32 l3off;
	__u32 l4off;
	__u32 dnsoff;
	__u32 qend;
	__u32 zone;
	__u32 tcp_payload;
	__u32 l4len;
	__u16 qtype;
	__u16 flags;
	__u16 arcount;
	__u16 sport;
	__u16 dport;
	__u8 v6;
	__u8 simple_l3;
	__u8 do_bit;
	__u8 rcode;
	__u8 l4proto;
	__u8 cookie_len;
	struct sf_addr src;
	struct sf_addr dst;
	__u8 cookie[SF_COOKIE_MAX];
};

/* Writes an IPv4 address as IPv4-mapped IPv6. */
SF_INLINE void sf_addr_v4(struct sf_addr *out, __u32 be_addr)
{
	__builtin_memset(out->a, 0, 10);
	out->a[10] = 0xff;
	out->a[11] = 0xff;
	__builtin_memcpy(&out->a[12], &be_addr, 4);
}

/* Lowercases one ASCII byte. */
SF_INLINE __u8 sf_lower(__u8 c)
{
	return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

#define SF_QBUF 288

/* Parses a DNS message copied into a fixed buffer b[0..n): header, bounded QNAME, QTYPE, OPT DO
 * bit. */
SF_INLINE int sf_parse_dns(const __u8 *b, __u32 n, struct sf_pkt *p, int response)
{
	if (n < SF_DNS_HDR || n > SF_QBUF)
		return SF_P_MALFORMED;
	__u16 flags = ((__u16)b[2] << 8) | b[3];
	__u16 qd = ((__u16)b[4] << 8) | b[5];
	__u16 an = ((__u16)b[6] << 8) | b[7];
	__u16 ns = ((__u16)b[8] << 8) | b[9];
	__u16 ar = ((__u16)b[10] << 8) | b[11];
	int qr = (flags >> 15) & 1;
	int opcode = (flags >> 11) & 0xf;

	if (qr != response || opcode != 0 || qd != 1)
		return SF_P_MALFORMED;
	if (!response && (an != 0 || ns != 0 || ar > 2))
		return SF_P_MALFORMED;
	p->flags = flags;
	p->arcount = ar;
	p->rcode = flags & 0xf;

	__u32 h_all = SF_FNV_OFF, h_zone = SF_FNV_OFF;
	__u32 rem = 0, i, pos = SF_DNS_HDR;
	__u8 started = 0, zone_on = 0;
	int done = 0;

	/* Walk the QNAME byte by byte; rem counts bytes left in the current label. */
	for (i = 0; i < SF_MAX_QNAME; i++) {
		pos = SF_DNS_HDR + i;
		if (pos >= n || pos >= SF_QBUF)
			return SF_P_MALFORMED;
		__u8 c = b[pos];
		if (rem == 0) {
			if (c == 0) {
				done = 1;
				break;
			}
			if (c > 63)
				return SF_P_MALFORMED;
			rem = c;
			zone_on = started;
			started = 1;
		} else {
			c = sf_lower(c);
			rem--;
		}
		h_all = (h_all ^ c) * SF_FNV_PRIME;
		if (zone_on)
			h_zone = (h_zone ^ c) * SF_FNV_PRIME;
	}
	if (!done)
		return SF_P_MALFORMED;
	p->zone = zone_on ? h_zone : h_all;

	__u32 t = pos + 1;
	if (t + 4 > n || t + 4 > SF_QBUF)
		return SF_P_MALFORMED;
	p->qtype = ((__u16)b[t] << 8) | b[t + 1];
	t += 4;
	p->qend = p->dnsoff + t;
	p->do_bit = 0;
	p->cookie_len = 0;

	/* EDNS OPT: root name, type 41, class, ext-rcode, version, flags (DO = top bit), rdlen,
	 * options. */
	if (!response && ar >= 1 && t + 11 <= n && t + 11 <= SF_QBUF && b[t] == 0 &&
	    b[t + 1] == 0 && b[t + 2] == SF_OPT_TYPE) {
		p->do_bit = (b[t + 7] & 0x80) ? 1 : 0;
		__u32 rdlen = ((__u32)b[t + 9] << 8) | b[t + 10];
		__u32 o = t + 11;
		__u32 rdend = o + rdlen;
		if (rdend > n)
			rdend = n;
		if (rdend > 256)
			rdend = 256;
		/* Walk EDNS options (bounded to the first 256 bytes) looking for COOKIE (code 10).
		 */
		for (int opt = 0; opt < 8; opt++) {
			o &= 255;
			if (o + 4 > rdend)
				break;
			__u32 code = ((__u32)b[o] << 8) | b[o + 1];
			__u32 olen = ((__u32)b[o + 2] << 8) | b[o + 3];
			__u32 od = (o + 4) & 255;
			if (code == SF_OPT_COOKIE && olen >= 8 && olen <= SF_COOKIE_MAX &&
			    od + olen <= rdend && od + SF_COOKIE_MAX <= 256) {
				for (__u32 i = 0; i < SF_COOKIE_MAX; i++) {
					__u32 ci = (od + i) & 255;
					if (i < olen)
						p->cookie[i] = b[ci];
				}
				p->cookie_len = (__u8)olen;
				break;
			}
			o = od + olen;
		}
	}
	return SF_P_DNS;
}

#ifndef SF_USERSPACE
struct sf_scratch {
	__u8 b[SF_QBUF];
};

/* Global wrapper so the QNAME loop is verified once, not once per L2/L3 path. */
__noinline int sf_parse_dns_g(struct sf_scratch *sb, __u32 n, struct sf_pkt *p, int response)
{
	if (!sb || !p)
		return SF_P_MALFORMED;
	return sf_parse_dns(sb->b, n, p, response);
}
#endif

/* Copies up to SF_QBUF bytes of the DNS section into buf; returns bytes copied or 0. */
#ifdef SF_USERSPACE
SF_INLINE __u32 sf_load(void *ctx, void *data, void *end, __u32 off, __u8 *buf, int xdp)
{
	(void)ctx;
	(void)xdp;
	__u32 len = (__u32)((__u8 *)end - (__u8 *)data);
	if (off >= len)
		return 0;
	__u32 n = len - off;
	n = n > SF_QBUF ? SF_QBUF : n;
	__builtin_memcpy(buf, (__u8 *)data + off, n);
	return n;
}
#else
SF_INLINE __u32 sf_load(void *ctx, void *data, void *end, __u32 off, __u8 *buf, int xdp)
{
	__u32 len = (__u32)((__u8 *)end - (__u8 *)data);
	if (off >= len || off > 512)
		return 0;
	__u32 n = len - off;
	if (n > SF_QBUF)
		n = SF_QBUF;
	/* Barrier keeps both bounds visible to the verifier after clang folding. */
	asm volatile("" : "+r"(n));
	if (n < 1 || n > SF_QBUF)
		return 0;
	long rc = xdp ? bpf_xdp_load_bytes(ctx, off, buf, n) : bpf_skb_load_bytes(ctx, off, buf, n);
	return rc ? 0 : n;
}
#endif

/* Parses L2-L4 then the DNS section via a scratch buffer; ingress=1 queries to :53, 0 responses
 * from :53. */
SF_INLINE int sf_parse(void *ctx, void *data, void *end, struct sf_pkt *p, __u8 *buf, int ingress,
		       int xdp)
{
	__u8 *cur = data;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > end)
		return SF_P_OTHER;
	__u16 proto = SF_NTOHS(eth->h_proto);
	cur += sizeof(*eth);

	/* Up to two VLAN tags (802.1Q / 802.1ad). */
	for (int v = 0; v < SF_MAX_VLAN; v++) {
		if (proto != SF_ETH_P_8021Q && proto != SF_ETH_P_8021AD)
			break;
		if ((void *)(cur + 4) > end)
			return SF_P_OTHER;
		proto = ((__u16)cur[2] << 8) | cur[3];
		cur += 4;
	}

	p->l3off = (__u32)(cur - (__u8 *)data);
	__u8 l4proto;
	p->simple_l3 = 1;

	if (proto == ETH_P_IP) {
		struct iphdr *ip = (void *)cur;
		if ((void *)(ip + 1) > end)
			return SF_P_OTHER;
		if (ip->ihl < 5)
			return SF_P_MALFORMED;
		__u32 ihl = ip->ihl * 4;
		if ((void *)(cur + ihl) > end)
			return SF_P_OTHER;
		p->v6 = 0;
		p->simple_l3 = ip->ihl == 5;
		sf_addr_v4(&p->src, ip->saddr);
		sf_addr_v4(&p->dst, ip->daddr);
		l4proto = ip->protocol;
		p->l4len = SF_NTOHS(ip->tot_len) > ihl ? SF_NTOHS(ip->tot_len) - ihl : 0;
		__u16 frag = SF_NTOHS(ip->frag_off);
		cur += ihl;
		if (frag & 0x3fff) {
			if ((frag & 0x1fff) == 0 && l4proto == IPPROTO_UDP &&
			    (void *)(cur + sizeof(struct udphdr)) <= end) {
				struct udphdr *u = (void *)cur;
				if (SF_NTOHS(ingress ? u->dest : u->source) == SF_DNS_PORT)
					return SF_P_MALFORMED;
			}
			return SF_P_FRAG;
		}
	} else if (proto == ETH_P_IPV6) {
		struct ipv6hdr *ip6 = (void *)cur;
		if ((void *)(ip6 + 1) > end)
			return SF_P_OTHER;
		p->v6 = 1;
		__builtin_memcpy(p->src.a, &ip6->saddr, 16);
		__builtin_memcpy(p->dst.a, &ip6->daddr, 16);
		l4proto = ip6->nexthdr;
		p->l4len = SF_NTOHS(ip6->payload_len);
		cur += sizeof(*ip6);
		/* Bounded walk over hop-by-hop, routing and destination-option headers. */
		for (int e = 0; e < SF_MAX_EXT; e++) {
			if (l4proto == 44)
				return SF_P_FRAG;
			if (l4proto != 0 && l4proto != 43 && l4proto != 60)
				break;
			if ((void *)(cur + 2) > end)
				return SF_P_OTHER;
			__u32 hlen = ((__u32)cur[1] + 1) * 8;
			l4proto = cur[0];
			p->simple_l3 = 0;
			p->l4len = p->l4len > hlen ? p->l4len - hlen : 0;
			if ((void *)(cur + hlen) > end)
				return SF_P_OTHER;
			cur += hlen;
		}
	} else {
		return SF_P_OTHER;
	}

	p->l4off = (__u32)(cur - (__u8 *)data);
	p->l4proto = l4proto;

	if (l4proto == IPPROTO_TCP) {
		struct tcphdr *t = (void *)cur;
		if ((void *)(t + 1) > end)
			return SF_P_OTHER;
		p->sport = SF_NTOHS(t->source);
		p->dport = SF_NTOHS(t->dest);
		if ((ingress ? p->dport : p->sport) != SF_DNS_PORT)
			return SF_P_OTHER;
		__u32 thl = (__u32)t->doff * 4;
		p->tcp_payload = p->l4len > thl ? p->l4len - thl : 0;
		return SF_P_TCP53;
	}
	if (l4proto != IPPROTO_UDP)
		return SF_P_OTHER;

	struct udphdr *udp = (void *)cur;
	if ((void *)(udp + 1) > end)
		return SF_P_OTHER;
	p->sport = SF_NTOHS(udp->source);
	p->dport = SF_NTOHS(udp->dest);
	if ((ingress ? p->dport : p->sport) != SF_DNS_PORT)
		return SF_P_OTHER;
	if (SF_NTOHS(udp->len) < sizeof(*udp) + SF_DNS_HDR)
		return SF_P_MALFORMED;

	cur += sizeof(*udp);
	p->dnsoff = (__u32)(cur - (__u8 *)data);
	__u32 n = sf_load(ctx, data, end, p->dnsoff, buf, xdp);
	if (n == 0)
		return SF_P_MALFORMED;
#ifdef SF_USERSPACE
	return sf_parse_dns(buf, n, p, !ingress);
#else
	return sf_parse_dns_g((struct sf_scratch *)buf, n, p, !ingress);
#endif
}

#endif /* SEGFAULT_PARSE_H */
