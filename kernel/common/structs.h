/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __STRUCTS_H
#define __STRUCTS_H

#include "vmlinux.h"

#define MAX_LOG_CHUNK_SIZE 1024
#define MAX_STACK_SIZE 512

/* Format encoding (must match userspace PayloadFormat::as_u8) */
#define FORMAT_JSON      0
#define FORMAT_SYSLOG    1
#define FORMAT_HTML      2
#define FORMAT_PLAIN     3

/* Action encoding (must match userspace InterceptAction::as_u8) */
#define ACTION_DECODE    0
#define ACTION_DROP      1
#define ACTION_PASS      2
#define ACTION_CHECK     3

/* Map value written by loader for each (port, proto) entry */
typedef struct {
    __u8  format;   /* FORMAT_* constant */
    __u8  action;   /* ACTION_* constant */
    __u8  _pad[2];
} port_proto_config_t;

typedef struct {
    __u32 conn_id;
    __u32 pid;
    __u32 tid;
    __u64 ts_ns;
    __u8  is_arena_ptr;
    __u8  format;   /* FORMAT_* from port_proto_config */
    __u8  action;   /* ACTION_* from port_proto_config */
    __u8  protocol;
    __u16 dst_port;
    __u16 pad;
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

/*
 * bpf_format_check — bounded format heuristic for check/decode actions.
 *
 * Returns 1 if the first bytes of payload are consistent with `fmt`.
 * Returns 0 if the payload obviously does NOT match, meaning the kernel
 * should drop it (decode) or reject it (check) rather than submitting to userspace.
 *
 * Intentionally coarse: kernel can only do a O(1) sanity check. Deep parsing
 * is exclusively a userspace responsibility.
 *
 * @b0-b4: first five payload bytes, missing bytes must be passed as 0
 * @fmt:   FORMAT_* constant
 */
static __always_inline int bpf_format_check(__u8 b0, __u8 b1, __u8 b2, __u8 b3, __u8 b4, __u8 fmt)
{
    if (b0 == 'M' && b1 == 'Z')
        return 0;
    if (b0 == 0x7f && b1 == 'E' && b2 == 'L' && b3 == 'F')
        return 0;
    if (b0 == '%' && b1 == 'P' && b2 == 'D' && b3 == 'F')
        return 0;
    if (b0 == 'P' && b1 == 'K' && b2 == 0x03 && b3 == 0x04)
        return 0;

    switch (fmt) {
    case FORMAT_JSON:
        return (b0 == '{' || b0 == '[') ? 1 : 0;

    case FORMAT_SYSLOG:
        if (b0 != '<')
            return 0;
        if (b1 == '>' || b1 < '0' || b1 > '9')
            return 0;
        __u32 pri = b1 - '0';
        if (b2 == '>')
            return pri <= 191;
        if (b2 < '0' || b2 > '9')
            return 0;
        pri = (pri * 10) + (b2 - '0');
        if (b3 == '>')
            return pri <= 191;
        if (b3 < '0' || b3 > '9')
            return 0;
        pri = (pri * 10) + (b3 - '0');
        if (b4 == '>')
            return pri <= 191;
        return 0;

    case FORMAT_HTML:
        if (b0 != '<')
            return 0;
        if ((b1 == 'h' || b1 == 'H') &&
            (b2 == 't' || b2 == 'T') &&
            (b3 == 'm' || b3 == 'M') &&
            (b4 == 'l' || b4 == 'L'))
            return 1;
        if (b1 == '!' &&
            (b2 == 'd' || b2 == 'D') &&
            (b3 == 'o' || b3 == 'O') &&
            (b4 == 'c' || b4 == 'C'))
            return 1;
        return 0;

    case FORMAT_PLAIN:
        if (b0 == 0x00)
            return 0;
        return 1;

    default:
        return 1; /* Unknown: allow through */
    }
}

#endif /* __STRUCTS_H */
