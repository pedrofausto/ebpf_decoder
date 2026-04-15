/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MAPS_H
#define __MAPS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "structs.h"

/* Main data transport: Kernel -> Userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024); /* 64MB */
} log_ringbuf SEC(".maps");

/* Control plane: Userspace -> Kernel */
struct {
    __uint(type, BPF_MAP_TYPE_USER_RINGBUF);
    __uint(max_entries, 1024 * 1024); /* 1MB */
} filter_config_urb SEC(".maps");

/* LPM TRIE for IP allowlisting */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(key_size, 8); /* 4 bytes prefix len + 4 bytes IPv4 */
    __uint(value_size, 4);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_allowlist SEC(".maps");

/* Port and Protocol filtering for interception */
struct port_proto_key {
    __u16 port;
    __u8 proto;
    __u8 padding;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct port_proto_key);
    __type(value, __u8);
} port_proto_filter SEC(".maps");

/* Rate limiting keyed by (src_ip, dst_port) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, 8); /* src_ip (4) + dst_port (2) + padding (2) */
    __uint(value_size, 16); /* last_ts (8) + tokens (8) */
    __uint(max_entries, 10240);
} rate_limit_map SEC(".maps");

/* Drop counters for metrics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, 4);
    __uint(value_size, 8);
    __uint(max_entries, 1);
} drop_counters SEC(".maps");

/* Sockmap for sk_msg interception */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 10240);
    __type(key, struct port_proto_key);
    __type(value, __u32);
} sockmap SEC(".maps");

#endif /* __MAPS_H */
