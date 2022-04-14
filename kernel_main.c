// kern_main.c file - rewriting starts...
// gl hf to us

// Enable debug logs
#define DEBUG 0

// Should we only allow google and cloudflare dns?
#define DO_check_google_CF_DNS 0

// Are we running a DNS Server?
#define RUNNING_DNS_SERVER 0

// Linux includes
#include <linux/bpf.h>
#include <linux/types.h>

#include <linux/if_ether.h>
#include <linux/ip.h>

// BPF includes
#include "libbpf/src/bpf_helpers.h"
#include "libbpf/src/bpf_endian.h"

SEC("xdp_stats1")
int xdp_stats1_func(struct xdp_md *ctx)
{

	int ifindex = 0; // TODO allow setting from userspace using redirect_map?
	int action = bpf_redirect(ifindex, 0);

	return action;
}

char _license[] SEC("license") = "GPL";

/* Copied from: $KERNEL/include/uapi/linux/bpf.h
 *
 * User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will
 * result in packet drops and a warning via bpf_warn_invalid_xdp_action().
 */
// enum xdp_action {
// 	XDP_ABORTED = 0,
// 	XDP_DROP,
// 	XDP_PASS,
// 	XDP_TX,
// 	XDP_REDIRECT,
// };
/*
 * user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
 */
// struct xdp_md {
// 	// (Note: type __u32 is NOT the real-type)
// 	__u32 data;
// 	__u32 data_end;
// 	__u32 data_meta;
// 	// Below access go through struct xdp_rxq_info
// 	__u32 ingress_ifindex; // rxq->dev->ifindex
// 	__u32 rx_queue_index;  // rxq->queue_index
// };