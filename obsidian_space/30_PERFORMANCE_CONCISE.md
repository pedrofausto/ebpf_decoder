---
tags:
  - ebpf_decoder
  - performance
source: docs/PERFORMANCE_GUIDE.md
---
# Performance Guide (Concise)

## Metrics
- Throughput: events/sec processed.
- Latency: capture->userspace processing; focus p99/p99.9.
- CPU: kernel (BPF helpers/map ops) vs userspace (parse/transform).
- Memory: RSS growth + ringbuf pressure (producer faster than consumer).

## Latency measurement (concept)
- Timestamp at origin in kernel; compare to userspace receive time.
- IMPORTANT: use the same clock domain end-to-end.

## Tooling
- Kernel: `bpftool`, `perf`, `bcc`/`bpftrace`.
- Userspace: `tokio-console`, `cargo flamegraph`, heap profilers.

## Baseline workflow
- Run pipeline with stable hardware and config.
- Collect:
  - tokio runtime behavior (`tokio-console`)
  - CPU hotspots (flamegraph)
  - BPF stats (`bpftool prog show --stats`)
- Track regressions (CSV/CI).

## Fast triage
- Userspace CPU high: `userspace/decoder/src/json_parser.rs` allocations/parsing.
- Ringbuf drops: increase ringbuf size or reduce work per event.
- Kernel CPU high: audit helper calls + map lookups in TC/XDP/SK_MSG programs.
