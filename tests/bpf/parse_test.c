/* SPDX-License-Identifier: (GPL-2.0 OR MIT) */
/* Userspace unit tests for the shared bounded parser (compiled with SF_USERSPACE). */
#define SF_USERSPACE
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../../bpf/parse.h"

static int tests, fails;
#define CHECK(cond, msg)                                                       \
	do {                                                                   \
		tests++;                                                       \
		if (!(cond)) {                                                 \
			fails++;                                                \
			printf("  FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
		}                                                              \
	} while (0)

/* Builds Eth+IPv4+UDP/53 around a DNS payload; returns total length. */
static int build_v4(unsigned char *p, const unsigned char *dns, int dlen, int vlan)
{
	int o = 0;
	memset(p, 0, 14);
	if (vlan) {
		p[12] = 0x81;
		p[13] = 0x00;
		p[16] = 0x08;
		p[17] = 0x00;
		o = 18;
	} else {
		p[12] = 0x08;
		p[13] = 0x00;
		o = 14;
	}
	unsigned char *ip = p + o;
	memset(ip, 0, 20);
	ip[0] = 0x45;
	int tot = 20 + 8 + dlen;
	ip[2] = tot >> 8;
	ip[3] = tot & 0xff;
	ip[9] = 17;
	o += 20;
	unsigned char *udp = p + o;
	udp[0] = 0xc0;
	udp[1] = 0x00;
	udp[2] = 0x00;
	udp[3] = 53;
	int ul = 8 + dlen;
	udp[4] = ul >> 8;
	udp[5] = ul & 0xff;
	udp[6] = 0;
	udp[7] = 0;
	o += 8;
	memcpy(p + o, dns, dlen);
	return o + dlen;
}

/* A minimal query for "flood.test" A. */
static int dns_query(unsigned char *d, int qdcount, int qtype)
{
	memset(d, 0, 12);
	d[5] = qdcount;
	int o = 12;
	const char *labels[] = {"flood", "test"};
	for (int i = 0; i < 2; i++) {
		int l = strlen(labels[i]);
		d[o++] = l;
		memcpy(d + o, labels[i], l);
		o += l;
	}
	d[o++] = 0;
	d[o++] = qtype >> 8;
	d[o++] = qtype & 0xff;
	d[o++] = 0;
	d[o++] = 1;
	return o;
}

int main(void)
{
	unsigned char pkt[1500] __attribute__((aligned(4))), dns[512], pkt2b[1500] __attribute__((aligned(4)));
	struct sf_pkt p;

	/* Valid IPv4 query parses as DNS. */
	int dlen = dns_query(dns, 1, 1);
	int n = build_v4(pkt, dns, dlen, 0);
	memset(&p, 0, sizeof(p));
	CHECK(sf_parse(0, pkt, pkt + n, &p, dns, 1, 0) == SF_P_DNS, "valid v4 query");
	CHECK(p.qtype == 1, "qtype A");
	CHECK(p.v6 == 0, "is v4");

	/* One VLAN tag still parses. */
	n = build_v4(pkt, dns, dlen, 1);
	memset(&p, 0, sizeof(p));
	CHECK(sf_parse(0, pkt, pkt + n, &p, dns, 1, 0) == SF_P_DNS, "vlan-tagged query");

	/* QDCOUNT != 1 is malformed. */
	dlen = dns_query(dns, 2, 1);
	n = build_v4(pkt, dns, dlen, 0);
	memset(&p, 0, sizeof(p));
	CHECK(sf_parse(0, pkt, pkt + n, &p, dns, 1, 0) == SF_P_MALFORMED, "qdcount 2 rejected");

	/* A response (QR=1) on the ingress path is malformed. */
	dlen = dns_query(dns, 1, 1);
	dns[2] = 0x80;
	n = build_v4(pkt, dns, dlen, 0);
	memset(&p, 0, sizeof(p));
	CHECK(sf_parse(0, pkt, pkt + n, &p, dns, 1, 0) == SF_P_MALFORMED, "response on ingress rejected");

	/* Truncated DNS header is malformed. */
	dns_query(dns, 1, 1);
	dns[2] = 0;
	n = build_v4(pkt, dns, 6, 0);
	memset(&p, 0, sizeof(p));
	CHECK(sf_parse(0, pkt, pkt + n, &p, dns, 1, 0) == SF_P_MALFORMED, "short header rejected");

	/* ANY query keeps its qtype so the cost weighting can see it. */
	dlen = dns_query(dns, 1, 255);
	n = build_v4(pkt, dns, dlen, 0);
	memset(&p, 0, sizeof(p));
	CHECK(sf_parse(0, pkt, pkt + n, &p, dns, 1, 0) == SF_P_DNS, "ANY parses");
	CHECK(p.qtype == 255, "qtype ANY preserved");

	/* Same zone hash for two names sharing their last two labels. */
	struct sf_pkt a = {}, b = {};
	unsigned char da[512], db[512];
	int la = 12, lb = 12;
	memset(da, 0, 12); da[5] = 1;
	memset(db, 0, 12); db[5] = 1;
	/* a = x.flood.test, b = y.flood.test */
	const char *A[] = {"x", "flood", "test"}, *B[] = {"yy", "flood", "test"};
	for (int i = 0; i < 3; i++) { da[la++] = strlen(A[i]); memcpy(da+la, A[i], strlen(A[i])); la += strlen(A[i]); }
	da[la++] = 0; da[la++]=0; da[la++]=1; da[la++]=0; da[la++]=1;
	for (int i = 0; i < 3; i++) { db[lb++] = strlen(B[i]); memcpy(db+lb, B[i], strlen(B[i])); lb += strlen(B[i]); }
	db[lb++] = 0; db[lb++]=0; db[lb++]=1; db[lb++]=0; db[lb++]=1;
	int na = build_v4(pkt, da, la, 0);
	sf_parse(0, pkt, pkt + na, &a, da, 1, 0);
	unsigned char pkt2[1500];
	int nb = build_v4(pkt2, db, lb, 0);
	sf_parse(0, pkt2, pkt2 + nb, &b, db, 1, 0);
	CHECK(a.zone == b.zone, "same 2-label zone hashes equal");

	printf("%s: %d checks, %d failures\n", fails ? "FAIL" : "PASS", tests, fails);
	return fails ? 1 : 0;
}
