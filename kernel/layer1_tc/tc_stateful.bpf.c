/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"
#include "structs.h"
#include "helpers.h"

SEC("classifier")
int tc_unified_filter(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u16 h_proto = eth->h_proto;
    __u32 offset = sizeof(struct ethhdr);

    /* Implement VLAN (802.1Q/802.1AD) parsing logic */
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr *vhdr = (void *)data + offset;
            if ((void *)(vhdr + 1) > data_end)
                return TC_ACT_OK;
            h_proto = vhdr->h_vlan_encapsulated_proto;
            offset += sizeof(struct vlan_hdr);
        } else {
            break;
        }
    }

    if (h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)data + offset;
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    __u16 dst_port = 0;
    __u32 payload_offset = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *th = (void *)(iph + 1);
        if ((void *)(th + 1) > data_end) {
            if (bpf_skb_pull_data(skb, (void *)(th + 1) - (void *)eth) < 0)
                return TC_ACT_OK;
            data_end = (void *)(long)skb->data_end;
            data = (void *)(long)skb->data;
            eth = data; 
            iph = (void *)data + offset; 
            th = (void *)(iph + 1);
            if ((void *)(th + 1) > data_end) return TC_ACT_OK;
        }
        dst_port = bpf_ntohs(th->dest);
        payload_offset = offset + sizeof(struct iphdr) + (th->doff * 4);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *uh = (void *)(iph + 1);
        if ((void *)(uh + 1) > data_end)
            return TC_ACT_OK;
        dst_port = bpf_ntohs(uh->dest);
        payload_offset = offset + sizeof(struct iphdr) + sizeof(struct udphdr);
    } else {
        return TC_ACT_OK;
    }

    /* 1. Check if this port/proto is in our YAML config */
    struct port_proto_key pkey = {.port = dst_port, .proto = iph->protocol};
    void *is_intercepted = bpf_map_lookup_elem(&port_proto_filter, &pkey);
    if (!is_intercepted) {
        return TC_ACT_OK;
    }

    /* 2. Capture and Send to RingBuffer */
    __u16 ip_tot_len = bpf_ntohs(iph->tot_len);
    __u16 extra_len = payload_offset - offset;
    if (ip_tot_len <= extra_len) {
        return TC_ACT_OK;
    }

    __u32 payload_len = ip_tot_len - extra_len;
    
    /* Phase 2: Delegate large payloads (> 1024) to L7 path by ignoring them */
    if (payload_len > MAX_LOG_CHUNK_SIZE) {
        return TC_ACT_OK;
    }

    /* 
     * Verifier safety: The compiler knows payload_len > 0 because of the 
     * (ip_tot_len <= extra_len) check above, so it optimizes away any == 0 
     * check. However, the BPF verifier is not as smart and still thinks 0 
     * is possible, failing the bpf_skb_load_bytes call.
     * We use a volatile read to break the compiler's knowledge.
     */
    volatile __u32 v_len = payload_len;
    __u32 safe_len = v_len;

    if (safe_len == 0) {
        return TC_ACT_OK;
    }

    log_event_t *event = bpf_ringbuf_reserve(&log_ringbuf, sizeof(log_event_t), 0);
    if (!event) return TC_ACT_OK;

    event->ts_ns = bpf_ktime_get_ns();
    event->data_len = safe_len;
    
    /* Copy payload into ringbuffer event */
    bpf_skb_load_bytes(skb, payload_offset, event->data, safe_len);

    bpf_ringbuf_submit(event, 0);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
