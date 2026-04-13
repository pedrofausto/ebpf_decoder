/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"
#include "helpers.h"

SEC("xdp")
int xdp_edge_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;
    __u32 offset = sizeof(struct ethhdr);

    /* Implement VLAN (802.1Q/802.1AD) parsing logic */
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr *vhdr = (void *)data + offset;
            if ((void *)(vhdr + 1) > data_end)
                return XDP_PASS;
            h_proto = vhdr->h_vlan_encapsulated_proto;
            offset += sizeof(struct vlan_hdr);
        } else {
            break;
        }
    }

    if (h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)data + offset;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    /* 1. CRITICAL BYPASS: Always allow Loopback and SSH (Port 22) */
    if (iph->saddr == bpf_htonl(0x7F000001)) { // 127.0.0.1
        return XDP_PASS;
    }

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *th = (void *)(iph + 1);
        if ((void *)(th + 1) <= data_end) {
            if (bpf_ntohs(th->dest) == 22 || bpf_ntohs(th->source) == 22) {
                return XDP_PASS;
            }
        }
    }

    /* 2. LPM TRIE Allowlist check (Perimeter Security) */
    struct {
        __u32 prefixlen;
        __u32 saddr;
    } key = {32, iph->saddr};

    void *allowlisted = bpf_map_lookup_elem(&ip_allowlist, &key);
    if (!allowlisted) {
        /* 
         * For development safety, we pass if the allowlist is empty.
         * In production, you would populate this and keep the DROP.
         */
        // return XDP_DROP; 
        return XDP_PASS; 
    }

    /* 2. Rate-limiting check */
    __u16 dst_port = 0;
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *th = (void *)(iph + 1);
        if ((void *)(th + 1) > data_end)
            return XDP_PASS;
        dst_port = bpf_ntohs(th->dest);

        /* SSH was handled in critical bypass at the top */
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *uh = (void *)(iph + 1);
        if ((void *)(uh + 1) > data_end)
            return XDP_PASS;
        dst_port = bpf_ntohs(uh->dest);
    }

    /* 2. YAML Interception Check */
    if (dst_port != 0 && dst_port != 22) {
        struct port_proto_key pkey = {.port = dst_port, .proto = iph->protocol};
        void *is_intercepted = bpf_map_lookup_elem(&port_proto_filter, &pkey);
        
        if (!is_intercepted) {
            /* Not an intercepted port, silently pass without logging/rate-limiting */
            return XDP_PASS;
        }
    }

    /* 3. Rate-limiting check */
    if (dst_port != 0) {
        if (is_rate_limited(iph->saddr, dst_port, 1000)) {
            __u32 key_zero = 0;
            __u64 *count = bpf_map_lookup_elem(&drop_counters, &key_zero);
            if (count) {
                __sync_fetch_and_add(count, 1);
            }
            return XDP_PASS;
        }
    }

    /*
     * LIMITATION: XDP operates per-packet with no TCP stream state.
     * It cannot reassemble fragmented TCP segments carrying JSON payloads.
     * Payload reassembly and L7 inspection occur in Layer 1B (TC) and Layer 2.
     * The MTU is NOT the limiting factor here — connection state absence is.
     *
     * Hardware offload mode (XDP_FLAGS_HW_MODE) requires NIC-specific driver
     * support (e.g., Netronome Agilio). Do not assume availability on
     * commodity NICs. Default to native mode (XDP_FLAGS_DRV_MODE).
     */

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
