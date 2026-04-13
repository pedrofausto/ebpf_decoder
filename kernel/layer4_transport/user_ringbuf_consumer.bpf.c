/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "maps.h"
#include "structs.h"
#include "helpers.h"

/* kfuncs for dynptr support */
extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, __u32 offset, void *buffer, __u32 buffer__szk) __ksym;

/* Global config state (writable via USER_RINGBUF) */
static filter_config_t global_config = {
    .version = 1,
    .max_rate_pps = 1000,
    .sampling_numerator = 1,
    .sampling_denominator = 1,
};

/* Callback for bpf_user_ringbuf_drain */
static long config_drain_callback(struct bpf_dynptr *dynptr, void *context) {
    filter_config_t *new_config;
    
    /* Get a pointer to the config record in the ringbuf */
    new_config = bpf_dynptr_slice(dynptr, 0, NULL, sizeof(filter_config_t));
    if (!new_config) {
        /* Fallback if slice is not direct */
        filter_config_t buffer;
        if (bpf_dynptr_read(&buffer, sizeof(buffer), dynptr, 0, 0) < 0)
            return 1;
        new_config = &buffer;
    }

    /* Update global configuration */
    global_config.version = new_config->version;
    global_config.max_rate_pps = new_config->max_rate_pps;
    global_config.sampling_numerator = new_config->sampling_numerator;
    global_config.sampling_denominator = new_config->sampling_denominator;

    return 0;
}

SEC("tc")
int user_ringbuf_consumer(struct __sk_buff *skb) {
    /* Poll the user ringbuffer for configuration updates at a safe frequency */
    /* In a production scenario, this might be triggered by a specific event or timer */
    bpf_user_ringbuf_drain(&filter_config_urb, config_drain_callback, NULL, 0);

    /*
     * CORRECT USE CASE for BPF_MAP_TYPE_USER_RINGBUF:
     * Direction: userspace → kernel (control plane only)
     * Designed for: injecting configuration records into BPF programs
     * at runtime WITHOUT reloading the program.
     */

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
