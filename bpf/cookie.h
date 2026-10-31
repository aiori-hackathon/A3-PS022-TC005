/* SPDX-License-Identifier: GPL-2.0 */
/* RFC 9018 DNS Cookie validation in XDP: a valid server cookie proves a real return path -> T2. */
#ifndef SEGFAULT_COOKIE_H
#define SEGFAULT_COOKIE_H

#include "maps.h"
#include "parse.h"
#include "siphash.h"

/* True if the query carries a server cookie whose SipHash matches our shared secret. */
static __always_inline int sf_cookie_valid(const struct sf_pkt *p)
{
	/* Need the 8-byte client cookie plus a full 16-byte server cookie. */
	if (p->cookie_len < 24)
		return 0;
	__u32 zero = 0;
	struct sf_secret *sec = bpf_map_lookup_elem(&sf_secret, &zero);
	if (!sec || !sec->enabled)
		return 0;

	/* Message = Client-Cookie(8) | Version(1) | Reserved(3) | Timestamp(4) | Client-IP. */
	__u8 msg[32];
	__builtin_memset(msg, 0, sizeof(msg));
#pragma unroll
	for (int i = 0; i < 16; i++)
		msg[i] = p->cookie[i]; /* client cookie + version+reserved+timestamp */
	__u32 iplen;
	if (p->v6) {
		iplen = 16;
#pragma unroll
		for (int i = 0; i < 16; i++)
			msg[16 + i] = p->src.a[i];
	} else {
		iplen = 4;
#pragma unroll
		for (int i = 0; i < 4; i++)
			msg[16 + i] = p->src.a[12 + i];
	}

	__u64 h = sf_siphash24(sec->key, msg, 16 + iplen);
	/* Compare the 8 hash octets of the server cookie (cookie[16..24]) little-endian. */
#pragma unroll
	for (int i = 0; i < 8; i++) {
		if (p->cookie[16 + i] != (__u8)(h >> (8 * i)))
			return 0;
	}
	return 1;
}

#endif /* SEGFAULT_COOKIE_H */
