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

    /*
     * 1. Policy lookup: SK_MSG runs on TCP sockets, so proto is always 6.
     * msg->local_port is the server listening port in host byte order.
     */
    __u16 dst_port = (__u16)msg->local_port;
    struct port_proto_key pkey = {.port = dst_port, .proto = 6 /* IPPROTO_TCP */, .padding = 0};
    port_proto_config_t *cfg = bpf_map_lookup_elem(&port_proto_filter, &pkey);

    if (!cfg) {
        /* Not in YAML config — pass without capture */
        return SK_PASS;
    }

    /* 2. Action enforcement — enforce before any data processing */
    if (cfg->action == ACTION_DROP) {
        return SK_DROP;
    }
    if (cfg->action == ACTION_PASS) {
        return SK_PASS;
    }

    /* 3. For CHECK and DECODE: linearize data, then validate format */
    if (bpf_msg_pull_data(msg, 0, data_len, 0) < 0) {
        return SK_PASS;
    }

    void *data = (void *)(long)msg->data;
    void *data_end = (void *)(long)msg->data_end;
    if (data + data_len > data_end) {
        return SK_PASS;
    }

    __u32 conn_id = msg->remote_ip4 ^ msg->local_ip4 ^
        msg->remote_port ^ (((__u32)msg->local_port) << 16) ^ (6 << 24);
    __u8 fmt = cfg->format;
    __u8 *stream_fmt = bpf_map_lookup_elem(&stream_format_state, &conn_id);

    if (!stream_fmt || *stream_fmt != fmt) {
        /* 3a. Format check on direct data pointer using verifier-friendly bounds checks. */
        __u8 *payload = (__u8 *)data;
        __u8 b0 = 0, b1 = 0, b2 = 0, b3 = 0, b4 = 0;

        if (data_len > 0) {
            if ((void *)(payload + 1) > data_end)
                return SK_PASS;
            b0 = payload[0];
        }
        if (data_len > 1) {
            if ((void *)(payload + 2) > data_end)
                return SK_PASS;
            b1 = payload[1];
        }
        if (data_len > 2) {
            if ((void *)(payload + 3) > data_end)
                return SK_PASS;
            b2 = payload[2];
        }
        if (data_len > 3) {
            if ((void *)(payload + 4) > data_end)
                return SK_PASS;
            b3 = payload[3];
        }
        if (data_len > 4) {
            if ((void *)(payload + 5) > data_end)
                return SK_PASS;
            b4 = payload[4];
        }

        if (!bpf_format_check(b0, b1, b2, b3, b4, fmt)) {
            return SK_DROP; /* Type mismatch — drop */
        }
        bpf_map_update_elem(&stream_format_state, &conn_id, &fmt, BPF_ANY);
    }

    /*
     * 3b. CHECK: format valid, pass without capturing to arena or ringbuf.
     * Pure kernel enforcement with zero pipeline cost.
     */
    if (cfg->action == ACTION_CHECK) {
        return SK_PASS;
    }

    /* 4. DECODE: write payload to arena slot and emit ringbuf ticket */
    __u32 zero = 0;
    struct arena_state *state = bpf_map_lookup_elem(&arena_state_map, &zero);
    if (!state) return SK_PASS;

    /*
     * Fixed-Slot Indexing: increment head by 1 (slot sequence number).
     */
    __u64 slot_seq = __sync_fetch_and_add(&state->head, 1);
    __u32 slot_idx = (__u32)(slot_seq & SLOT_MASK);
    __u32 offset   = slot_idx * SLOT_SIZE;

    void *dst = bpf_map_lookup_elem(&large_payload_array, &slot_idx);
    if (!dst) return SK_PASS;

    /*
     * Zero-Offset Write: verifier can trivially prove safety since
     * data_len is bounded by SLOT_SIZE and dst starts at offset 0.
     */
    bpf_probe_read_kernel(dst, data_len, data);

    /* 5. Emit ringbuf ticket with format/action from config (not hardcoded) */
    log_event_t *event = bpf_ringbuf_reserve(&log_ringbuf, sizeof(log_event_t), 0);
    if (event) {
        event->conn_id      = conn_id;
        event->pid          = 0;
        event->tid          = 0;
        event->is_arena_ptr = 1;
        event->arena_offset = offset;
        event->data_len     = data_len;
        event->ts_ns        = bpf_ktime_get_ns();
        event->format       = cfg->format;
        event->action       = cfg->action;
        event->protocol     = 6;
        event->dst_port     = dst_port;
        event->pad          = 0;
        bpf_ringbuf_submit(event, 0);
    }

    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
