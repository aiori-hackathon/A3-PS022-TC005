/* SPDX-License-Identifier: (GPL-2.0 OR MIT) */
/* SipHash-2-4 for DNS Cookie (RFC 9018) validation; bounded for the verifier and the fuzzer. */
#ifndef SEGFAULT_SIPHASH_H
#define SEGFAULT_SIPHASH_H

#include <linux/types.h>

#ifdef SF_USERSPACE
#define SH_INLINE static inline
#else
#define SH_INLINE static __always_inline
#endif

#define SF_SIP_MAXLEN 48

/* Rotate-left for 64-bit. */
SH_INLINE __u64 sf_rotl(__u64 x, int b)
{
	return (x << b) | (x >> (64 - b));
}

#define SF_SIPROUND                                                                                \
	do {                                                                                       \
		v0 += v1;                                                                          \
		v1 = sf_rotl(v1, 13);                                                              \
		v1 ^= v0;                                                                          \
		v0 = sf_rotl(v0, 32);                                                              \
		v2 += v3;                                                                          \
		v3 = sf_rotl(v3, 16);                                                              \
		v3 ^= v2;                                                                          \
		v0 += v3;                                                                          \
		v3 = sf_rotl(v3, 21);                                                              \
		v3 ^= v0;                                                                          \
		v2 += v1;                                                                          \
		v1 = sf_rotl(v1, 17);                                                              \
		v1 ^= v2;                                                                          \
		v2 = sf_rotl(v2, 32);                                                              \
	} while (0)

/* Reads 8 little-endian bytes from a fixed buffer at offset off. */
SH_INLINE __u64 sf_le64(const __u8 *p, __u32 off)
{
	__u64 x = 0;
	for (int i = 0; i < 8; i++)
		x |= (__u64)p[off + i] << (8 * i);
	return x;
}

/* SipHash-2-4 over in[0..len) (len <= SF_SIP_MAXLEN) with a 16-byte key k[0..16). */
SH_INLINE __u64 sf_siphash24(const __u8 *k, const __u8 *in, __u32 len)
{
	__u64 k0 = sf_le64(k, 0), k1 = sf_le64(k, 8);
	__u64 v0 = 0x736f6d6570736575ULL ^ k0;
	__u64 v1 = 0x646f72616e646f6dULL ^ k1;
	__u64 v2 = 0x6c7967656e657261ULL ^ k0;
	__u64 v3 = 0x7465646279746573ULL ^ k1;
	__u32 end = len & ~7u;

	/* Full 8-byte blocks. */
	for (__u32 off = 0; off < SF_SIP_MAXLEN; off += 8) {
		if (off >= end)
			break;
		__u64 m = sf_le64(in, off);
		v3 ^= m;
		SF_SIPROUND;
		SF_SIPROUND;
		v0 ^= m;
	}

	/* Trailing bytes plus length in the top byte. */
	__u64 b = (__u64)(len & 0xff) << 56;
	__u32 left = len & 7;
	for (__u32 i = 0; i < 7; i++) {
		if (i >= left)
			break;
		b |= (__u64)in[end + i] << (8 * i);
	}
	v3 ^= b;
	SF_SIPROUND;
	SF_SIPROUND;
	v0 ^= b;

	v2 ^= 0xff;
	SF_SIPROUND;
	SF_SIPROUND;
	SF_SIPROUND;
	SF_SIPROUND;
	return v0 ^ v1 ^ v2 ^ v3;
}

#endif /* SEGFAULT_SIPHASH_H */
