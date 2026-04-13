/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "maps.h"
#include "structs.h"
#include "helpers.h"

SEC("tc")
int ringbuf_producer(struct __sk_buff *skb) {
    struct bpf_dynptr ptr;
    __u32 event_size = sizeof(log_event_t);

    /* Use bpf_ringbuf_reserve_dynptr + bpf_ringbuf_submit_dynptr for zero-copy variable-length submission */
    long ret = bpf_ringbuf_reserve_dynptr(&log_ringbuf, event_size, 0, &ptr);
    if (ret != 0) {
        /* BACKPRESSURE: ring buffer full */
        __u32 key = 0;
        __u64 *count = bpf_map_lookup_elem(&drop_counters, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }
        return TC_ACT_OK;
    }

    /* write data via dynptr... (demonstration) */
    // bpf_dynptr_write(&ptr, 0, event_data, event_size, 0);

    /* Always submit or discard to release the reference */
    bpf_ringbuf_submit_dynptr(&ptr, 0);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
