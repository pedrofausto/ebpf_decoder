/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __HELPERS_H
#define __HELPERS_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

#define MAX_SESSIONS 1024

/* Inline helper for token bucket rate limiting */
static __always_inline bool is_rate_limited(__u32 src_ip, __u16 dst_port, __u32 threshold_pps) {
    __u64 key = ((__u64)dst_port << 32) | src_ip;
    __u64 now = bpf_ktime_get_ns();
    __u64 *val = bpf_map_lookup_elem(&rate_limit_map, &key);
    
    if (!val) {
        __u64 init_val[2] = {now, 1};
        bpf_map_update_elem(&rate_limit_map, &key, &init_val, BPF_ANY);
        return false;
    }

    /* Simple 1-second window check */
    if (now - val[0] > 1000000000ULL) {
        val[0] = now;
        val[1] = 1;
        return false;
    }

    __sync_fetch_and_add(&val[1], 1);
    if (val[1] > threshold_pps) {
        return true;
    }

    return false;
}

#endif /* __HELPERS_H */
