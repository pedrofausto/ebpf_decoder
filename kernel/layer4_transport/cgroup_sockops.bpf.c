/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"
#include "structs.h"

SEC("sockops")
int bpf_sockmap_ops(struct bpf_sock_ops *skops) {
    __u32 op = skops->op;

    /* Phase 2: Intercept connection establishment to populate the sockmap */
    if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ||
        op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        
        struct port_proto_key key = {};
        
        /* 
         * Using the local port as the key.
         * local_port in bpf_sock_ops is in network byte order for some kernels, 
         * but our map uses host byte order for the port. 
         */
        key.port = (__u16)bpf_ntohl(skops->local_port);
        key.proto = IPPROTO_TCP;

        /* Add the socket to the sockhash map */
        bpf_sock_hash_update(skops, &sockmap, &key, BPF_NOEXIST);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
