# Performance Engineering Guide: eBPF Event Ingester

This document outlines the methodology, metrics, and tooling required to measure and optimize the performance of the eBPF event ingester.

## 1. Key Performance Metrics

To establish a comprehensive baseline, we track the following metrics:

*   **Throughput (Events/sec):** The number of eBPF events successfully processed and ingested per second.
*   **Latency (µs/ms):** 
    *   **Processing Latency:** Time taken from event capture in eBPF to insertion into the downstream storage/queue.
    *   **Tail Latency (p99/p99.9):** Critical for identifying performance bottlenecks or scheduling delays.
*   **CPU Overhead:**
    *   **Kernel-space:** CPU cycles spent in BPF programs (eBPF helper calls, map lookups).
    *   **User-space:** CPU cycles spent in the `decoder` service (JSON parsing, data transformation).
*   **Memory Usage:**
    *   **Resident Set Size (RSS):** Tracking memory growth over time for memory leaks.
    *   **Ring Buffer Pressure:** High usage here indicates the userspace reader is slower than the kernel producer.

## 2. Latency Tracking Methodology

We employ a precise latency tracking methodology to measure the end-to-end traversal time of events.

### Implementation
We utilize `nix::time::clock_gettime(CLOCK_BOOTTIME)` in our tracking logic. This provides a monotonic clock that includes time spent during system suspend, ensuring accurate interval calculation regardless of system power states.

### Output Format
The resulting latency measurements are reported with high precision, formatted as:
`[minutes]m [seconds]s [milliseconds]ms [microseconds]µs`

### Accuracy and Kernel-Userspace Gap
By capturing timestamps at the point of origin in the kernel and correlating them against the arrival time in userspace, this approach effectively bridges the kernel-userspace time gap. Using `CLOCK_BOOTTIME` ensures that the timestamps are consistent across the boundary, minimizing drift caused by clock skew or system state changes. This allows us to isolate precise processing delays caused by context switching, ring buffer contention, or scheduling jitter.

## 3. Recommended Toolset

### eBPF/Kernel Profiling
*   **`bpftool`:** Inspect map usage and program run-time statistics.
*   **`perf`:** General CPU sampling and event counting.
*   **`bcc` / `bpftrace`:** For custom event tracing and latency distributions.

### Rust Userspace Profiling
*   **`tokio-console`:** Essential for diagnosing async task bottlenecks, blocking, and contention in the `decoder` service.
*   **`flamegraph` (cargo-flamegraph):** Identifying hotspots in CPU-intensive code paths (e.g., JSON parsing).
*   **`dhat` / `heaptrack`:** Memory profiling to detect heap allocations and memory usage patterns.

## 4. Establishing a Performance Baseline

Follow these steps to generate a baseline measurement:

### Step 1: Baseline Environment
*   Ensure a dedicated test environment with consistent hardware.
*   Run the pipeline using `scripts/load_pipeline.sh`.

### Step 2: Collection
1.  **Run `tokio-console`** to capture async runtime performance.
2.  **Generate a CPU Flamegraph** while the ingest rate is sustained:
    `cargo flamegraph --bin decoder -- <args>`
3.  **Use `bpftool prog show`** to get stats on the eBPF programs:
    `bpftool prog show --stats`

### Step 3: Analysis
*   Store metrics in a CSV format for tracking regressions in CI/CD.
*   Compare current runs against the `docs/PERFORMANCE_GUIDE.md` baseline (to be appended as results are gathered).

## 5. Troubleshooting Strategy
1.  If high **CPU** in userspace: Check `format_router.rs`, `json_parser.rs`, and parser modules for allocation or parse hotspots.
2.  If **Ring Buffer** drops: reduce configured `decode` traffic, increase ring buffer capacity, or shift non-output policies to `pass`/`check`.
3.  If high **Kernel** CPU: audit BPF helper calls, action gates, and bounded format checks in `layer1_tc/tc_stateful.bpf.c` and `layer4_transport/sk_msg_intercept.bpf.c`.
