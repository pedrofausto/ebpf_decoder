/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"
#include "structs.h"

SEC("socket")
int socket_filter_plaintext(struct __sk_buff *skb) {
    /* PASSED from TC? */
    if (skb->cb[0] != LOG_STREAM_CANDIDATE)
        return 0;

    __u32 len = skb->len;
    if (len == 0)
        return 0;

    /* Perform fast heuristic check for JSON frame boundary '{' */
    __u8 first_byte;
    if (bpf_skb_load_bytes(skb, 0, &first_byte, 1) < 0)
        return 0;

    if (first_byte != '{' && first_byte != '[') {
        /* Not a JSON start candidate */
        return 0;
    }

    /* Forward to Layer 3 dynptr handler via shared MAP_TYPE_QUEUE (simplified here) */
    /* In this scaffold, we directly emit to ringbuf or arena */

    return 0;
}

/*
 * NOTE: Socket Filters and Syscall Tracepoints are NOT interchangeable.
 *
 * BPF_PROG_TYPE_SOCKET_FILTER:
 *   - Passive inspection of sk_buff payloads on a specific socket
 *   - Zero impact on send/recv syscall path
 *   - Ideal for read-only L7 payload inspection on plaintext streams
 */

char _license[] SEC("license") = "GPL";
