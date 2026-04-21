---
tags:
  - ebpf_decoder
  - architecture
source: docs/ARCHITECTURE.md
---
# Architecture (Concise)

Goal: observe configured payloads with minimal app impact. Ringbuf pressure drops logs, while configured `drop` and `check`/`decode` mismatches drop packets.

## Data path (packet -> log)
- XDP: early IP/port filter, ignore non-matching traffic.
- TC:
  - Small (<~1KB): copy payload into ringbuf event.
  - Large: let it proceed upward; do not copy here.
- SK_MSG:
  - Intercepts large payload from socket buffer.
  - Copies into fixed-slot shared array ("arena").
  - Emits small ringbuf event containing offset/metadata ("ticket").
- Rust decoder:
  - Reads ringbuf event.
  - For large payloads, looks into mmap’d arena by offset.
  - Parses JSON and emits log.

## Why two paths
- Ringbuf: fast, fixed-size events, good for small payloads.
- Arena: handles large payloads by sharing memory; ringbuf carries only metadata.

## Key maps
- `port_proto_filter`: what to intercept.
- `large_payload_array`: shared payload storage.
- `log_ringbuf`: kernel->userspace event transport.
- `sockmap`: connection tracking/lookup.

## Safety intent
- If ringbuf full: drop log event.
- If arena full: wrap/overwrite old slots (circular behavior).
