---
tags:
  - ebpf_decoder
  - index
source_repo: ebpf_decoder
---
# ebpf_decoder Obsidian Space (Concise)

Purpose: small, stable notes to reference when indexing code and answering questions with low token cost.

## Entry points
- Userspace decoder: `userspace/decoder/src/main.rs`
- JSON parsing + event handling: `userspace/decoder/src/json_parser.rs`
- Event struct layout: `userspace/decoder/src/structs.rs` (mirrors `kernel/common/structs.h`)
- Loader/config: `userspace/loader` + `config/intercept.yaml`
- Pipeline loader script: `scripts/load_pipeline.sh` (if present/used)

## Kernel programs (high-level)
- XDP edge filter: `kernel/*/xdp_edge.bpf.c` (filter early)
- TC stateful: `kernel/layer1_tc/tc_stateful.bpf.c` (state/size routing)
- SK_MSG large intercept: `kernel/layer4_transport/sk_msg_intercept.bpf.c` (copies payload, emits ringbuf alert)

## Maps / pinned paths
- Pinned dir: `/sys/fs/bpf/ebpf-json-pipeline`
- `large_payload_array` (shared mmap "arena")
- `log_ringbuf` (kernel -> userspace events)
- `port_proto_filter` (ports/protos of interest)

## Notes
- Architecture: [[10_ARCHITECTURE_CONCISE]]
- Developer ops: [[20_DEVELOPER_CONCISE]]
- Performance: [[30_PERFORMANCE_CONCISE]]
- QA/Security: [[40_QA_SECURITY_CONCISE]]
- Code index: [[50_CODE_INDEX_CONCISE]]
- Format expansion plan: [[60_FORMAT_EXPANSION_PLAN]]
- Security fix plan: [[61_SECURITY_FIX_PLAN]]
- Actions implementation guide: [[62_ACTIONS_IMPLEMENTATION_GUIDE]]
- Inject implementation session: [[63_SESSION_INJECT_IMPLEMENTATION]]
- Current packet policy: `drop` always drops; `check`/`decode` drop obvious format mismatches via bounded kernel guards.

## Phase 1 new files (multi-format decoder)
- Format router: `userspace/decoder/src/format_router.rs`
- Framing layer: `userspace/decoder/src/framing.rs`
- Stream state: `userspace/decoder/src/stream_state.rs`
- Content classifier: `userspace/decoder/src/content_classifier.rs`
- Output envelope: `userspace/decoder/src/output.rs`
- Parser modules: `userspace/decoder/src/parsers/{json,syslog,html,plain}.rs`
- Refactored dispatcher: `userspace/decoder/src/json_parser.rs` (now thin; calls router)
- Config hints: `config/intercept.yaml` + `userspace/loader/src/config.rs`
