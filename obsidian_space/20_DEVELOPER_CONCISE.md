---
tags:
  - ebpf_decoder
  - developer
source: docs/DEVELOPER_MANUAL.md
---
# Developer Manual (Concise)

## Common failures
- Verifier "permission denied": inspect verifier log via `bpftool`; usually missing NULL checks or complex pointer math.
- Pinned map not found under `/sys/fs/bpf/ebpf-json-pipeline`: loader didn’t pin maps; clear directory and restart loader.
- Scrambled/partial JSON: TCP segmentation or slot overflow; payloads > `SLOT_SIZE` truncate.

## Kernel debugging toolkit
- `bpf_printk` + view output:
  - `sudo bpftool prog tracelog`
  - `sudo cat /sys/kernel/debug/tracing/trace_pipe`
- Inspect map state:
  - `sudo bpftool map dump name port_proto_filter`
- Ground truth:
  - `sudo tcpdump -i any port 8080 -X`

## Tuning shared memory (arena)
- Change `SLOT_COUNT` and/or `SLOT_SIZE` in `kernel/common/maps.h` (power-of-two count).
- Keep userspace mmap size consistent: `userspace/decoder/src/main.rs` `arena_size` must match.

## Build/run (typical)
- `make clean` then `make all`
- Load pipeline (interface varies): `sudo ./target/release/ebpf-json-loader <ifname>`
- Run decoder: `sudo ./target/release/ebpf-json-decoder`
