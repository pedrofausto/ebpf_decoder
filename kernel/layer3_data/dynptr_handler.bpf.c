/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "maps.h"
#include "structs.h"
#include "helpers.h"

/* kfuncs for dynptr support */
extern int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags, struct bpf_dynptr *ptr) __ksym;
extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, __u32 offset, void *buffer, __u32 buffer__szk) __ksym;

SEC("tc")
int handle_dynptr_log(struct __sk_buff *skb) {
    struct bpf_dynptr ptr;
    __u32 len = skb->len;

    if (len > MAX_LOG_CHUNK_SIZE)
        len = MAX_LOG_CHUNK_SIZE;

    /* 1. Create a dynptr over the packet data without copying */
    if (bpf_dynptr_from_skb(skb, 0, &ptr) < 0)
        return TC_ACT_OK;

    /* 2. Extract raw bytes into a staging buffer (respecting stack limit) */
    /* The stack is 512 bytes. MAX_LOG_CHUNK_SIZE (1024) is too large for the stack.
     * We must use PER-CPU maps or Arena.
     */
    
    /* Demonstrate using bpf_dynptr_slice for fast inspection */
    __u8 buffer[8]; /* Small enough for stack */
    void *data = bpf_dynptr_slice(&ptr, 0, buffer, sizeof(buffer));
    if (!data)
        return TC_ACT_OK;

    /* 
     * STACK LIMIT: The BPF verifier enforces a hard 512-byte stack per program.
     * This is the PRIMARY constraint preventing full JSON tree parsing in-kernel.
     *
     * The correct approach: extract raw bytes in-kernel, defer all JSON
     * semantic parsing to userspace.
     */

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
