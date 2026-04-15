#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "structs.h"
#include "maps.h"

#ifndef __arena
#define __arena __attribute__((address_space(1)))
#endif

/* Fixed-Slot Payload Array for SK_MSG (Ensures Verifier Safety) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, 4);
    __uint(value_size, 65536);   /* 64KB per slot (max packet size) */
    __uint(max_entries, 8192);   /* 512MB total capacity */
    __uint(map_flags, BPF_F_MMAPABLE);
} large_payload_array SEC(".maps");

/* Map to track the state of the circular buffer */
struct arena_state {
    __u64 base_addr;
    __u64 head;
    __u64 size;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, 4);
    __uint(value_size, sizeof(struct arena_state));
    __uint(max_entries, 1);
} arena_state_map SEC(".maps");

#define SLOT_SIZE 65536
#define SLOT_COUNT 8192
#define SLOT_MASK (SLOT_COUNT - 1)

SEC("sk_msg")
int sk_msg_interceptor(struct sk_msg_md *msg)
{
    __u32 data_len = msg->size;
    
    /* Max packet size is 64KB. If it's larger, we clamp it to the slot size. */
    if (data_len == 0) return SK_PASS;
    if (data_len > SLOT_SIZE) data_len = SLOT_SIZE;

    /* Ensure data is linear for copying. */
    if (bpf_msg_pull_data(msg, 0, data_len, 0) < 0) {
        return SK_PASS;
    }

    /* Re-fetch data and data_end after pull */
    void *data = (void *)(long)msg->data;
    void *data_end = (void *)(long)msg->data_end;
    if (data + data_len > data_end) {
        return SK_PASS;
    }

    __u32 zero = 0;
    struct arena_state *state = bpf_map_lookup_elem(&arena_state_map, &zero);
    if (!state) return SK_PASS;

    /* 
     * 1. Fixed-Slot Indexing:
     * We increment head by 1 (slot sequence number) instead of variable data_len.
     */
    __u64 slot_seq = __sync_fetch_and_add(&state->head, 1);
    __u32 slot_idx = (__u32)(slot_seq & SLOT_MASK);
    __u32 offset = slot_idx * SLOT_SIZE;

    void *dst = bpf_map_lookup_elem(&large_payload_array, &slot_idx);
    if (!dst) return SK_PASS;

    /* 
     * 2. Zero-Offset Write:
     * Since every write starts at dst (offset 0) and data_len is bounded by SLOT_SIZE,
     * the verifier can trivially prove this is safe.
     */
    bpf_probe_read_kernel(dst, data_len, data);

    /* 3. Emit an event to log_ringbuf */
    log_event_t *event = bpf_ringbuf_reserve(&log_ringbuf, sizeof(log_event_t), 0);
    if (event) {
        event->is_arena_ptr = 1;
        event->arena_offset = offset; // Start of the 64KB slot in the 512MB window
        event->data_len = data_len;
        event->ts_ns = bpf_ktime_get_ns();
        bpf_ringbuf_submit(event, 0);
    }

    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
