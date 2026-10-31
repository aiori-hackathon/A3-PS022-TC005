// Minimal XDP_DROP program: the "do-nothing drop" baseline for the ceiling microbench.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp") int xdp_drop(struct xdp_md *ctx)
{
	(void)ctx;
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
