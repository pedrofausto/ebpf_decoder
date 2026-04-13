/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "maps.h"
#include "structs.h"

/* Per-CPU staging buffer for large logs */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, 4);
    __uint(value_size, sizeof(log_event_t));
    __uint(max_entries, 1);
} log_staging SEC(".maps");

/* Map to store SSL_read context (buffer pointer) keyed by TID */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1024);
} ssl_read_context SEC(".maps");

struct ssl_st {
    int dummy;
};

SEC("uprobe/SSL_read")
int BPF_UPROBE(uprobe_ssl_read_enter, struct ssl_st *ssl, void *buf, int num) {
    __u32 tid = bpf_get_current_pid_tgid();
    __u64 buf_ptr = (__u64)buf;

    bpf_map_update_elem(&ssl_read_context, &tid, &buf_ptr, BPF_ANY);
    return 0;
}

/* 
 * NOTE: OpenSSL SSL_read(SSL *s, void *buf, int num)
 * BoringSSL SSL_read(SSL *s, void *buf, int num)
 * GnuTLS gnutls_record_recv(gnutls_session_t session, void *data, size_t data_size)
 */

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(uprobe_ssl_read_exit, int ret) {
    if (ret <= 0)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();

    __u64 *buf_ptr = bpf_map_lookup_elem(&ssl_read_context, &tid);
    if (!buf_ptr)
        return 0;

    __u32 key = 0;
    log_event_t *event = bpf_map_lookup_elem(&log_staging, &key);
    if (!event)
        goto cleanup;

    event->pid = pid;
    event->tid = tid;
    event->ts_ns = ts;
    event->data_len = (__u32)ret > MAX_LOG_CHUNK_SIZE ? MAX_LOG_CHUNK_SIZE : (__u32)ret;

    /* Capture decrypted data from userspace buffer */
    bpf_probe_read_user(event->data, event->data_len, (void *)*buf_ptr);

    /* Submit to RingBuffer */
    bpf_ringbuf_output(&log_ringbuf, event, sizeof(log_event_t), 0);

cleanup:
    bpf_map_delete_elem(&ssl_read_context, &tid);
    return 0;
}

/*
 * OVERHEAD WARNING: uprobes insert software breakpoints into the target
 * process's address space. Each SSL_read/SSL_write invocation incurs
 * a context switch to the BPF program. On high-throughput TLS connections
 * (>100k ops/sec), this overhead becomes measurable.
 *
 * Alternative for kernel-space TLS (kTLS, kernel >= 4.13): use
 * BPF_PROG_TYPE_SCHED_CLS on TC with BPF_CGROUP_SOCK_OPS to access
 * decrypted data without uprobes if kTLS is negotiated.
 */

char _license[] SEC("license") = "GPL";
