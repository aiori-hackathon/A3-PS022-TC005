// SPDX-License-Identifier: GPL-2.0
/* Segfault XDP entry point; the Part 0 stub passes every packet. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "shared.h"

SEC("xdp")
int segfault_xdp(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
