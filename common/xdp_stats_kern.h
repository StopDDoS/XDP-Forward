/* SPDX-License-Identifier: GPL-2.0 */

/* Used *ONLY* by BPF-prog running kernel side. */
#ifndef __XDP_STATS_KERN_H
#define __XDP_STATS_KERN_H

/* Data record type 'struct datarec' is defined in common/xdp_stats_kern_user.h,
 * programs using this header must first include that file.
 */
#ifndef __XDP_STATS_KERN_USER_H
#warning "You forgot to #include <../common/xdp_stats_kern_user.h>"
#include <../common/xdp_stats_kern_user.h>
#endif

#include "../libbpf/src/bpf_helpers.h"

#ifndef PacketTypes
enum packetTypes
{
	PT_SYN = XDP_REDIRECT + 1,
	PT_ACK,
	PT_SYNACK,
	PT_OTHERUDP,
	PT_UDPAMP,
	PT_RST,
	PT_PSH,
};

#ifndef PT_MAX
#define PT_MAX (PT_PSH + 1)
#endif
#define PacketTypes 1
#endif

#endif /* __XDP_STATS_KERN_H */
