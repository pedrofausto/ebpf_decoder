/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __STRUCTS_H
#define __STRUCTS_H

#include "vmlinux.h"

#define MAX_LOG_CHUNK_SIZE 1024
#define MAX_STACK_SIZE 512

typedef struct {
    __u32 conn_id;
    __u32 pid;
    __u32 tid;
    __u64 ts_ns;
    __u8  is_arena_ptr;
    __u8  pad[3];
    __u32 arena_offset;
    __u32 data_len;
    __u8  data[MAX_LOG_CHUNK_SIZE];
} log_event_t;

typedef struct {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  flags;
} metadata_t;

typedef struct {
    __u32 version;
    __u32 max_rate_pps;
    __u32 ip_allowlist_update;
    __u32 sampling_numerator;
    __u32 sampling_denominator;
} filter_config_t;

enum log_flags {
    LOG_STREAM_CANDIDATE = 1 << 0,
    LOG_PLAIN_TEXT       = 1 << 1,
    LOG_TLS              = 1 << 2,
};

#endif /* __STRUCTS_H */
