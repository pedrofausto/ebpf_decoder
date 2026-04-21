---
tags:
  - ebpf_decoder
  - implementation
  - actions
source_repo: ebpf_decoder
---
# Actions Implementation Guide (`decode` / `drop` / `pass` / `check`)

## Current State
Implemented. `config/intercept.yaml` uses one required `action` and one required `format` per `(port, protocol)`. Kernel programs enforce `drop`/`pass` and run bounded format guards for `check`/`decode`; obvious payload mismatches are dropped before userspace decode.

## Objective
Implemented per `(port, protocol)` behavior with a required single `action` and required `format`:
- `decode`: validate payload type; if valid, decode and print small payload output; if invalid type, drop.
- `drop`: always drop.
- `pass`: always pass without capture/decode.
- `check`: verify type only; pass when valid, drop when invalid; do not decode output.

## Design Decisions (Strict)
- Enforcement for `drop/pass/check` must happen in kernel (`XDP`/`TC`/`SK_MSG`), not only userspace.
- Userspace is authoritative for deep decode only after kernel gates permit.
- YAML uses one `action` per entry to avoid precedence ambiguity.
- Kernel format checks are bounded scalar-prefix heuristics, never deep parsers.
- Keep SSH/loopback bypass and arena/ringbuf safety paths unchanged.

## Config Contract
Each entry in `config/intercept.yaml` must include:
- `port`
- `protocol` (`tcp|udp`)
- `format` (`json|syslog|html|plain_text`)
- `action` (`decode|drop|pass|check`)

Example:
```yaml
intercept:
  - port: 8080
    protocol: tcp
    format: json
    action: decode
  - port: 514
    protocol: udp
    format: syslog
    action: check
```

## Implementation Steps

### 1) Shared Types and Map Value
- Add kernel enum values for format and action in `kernel/common/structs.h`.
- Replace `port_proto_filter` map value type (`__u8`) with a packed config struct (format + action) in `kernel/common/maps.h`.
- Mirror userspace loader-side config struct in `userspace/loader/src/config.rs`.

Expected outcome:
- One lookup in data path returns both expected format and action.

### 2) Loader Validation and Programming
- Parse YAML into strict enums.
- Reject duplicates `(port, protocol)`.
- Reject missing/invalid `action` or `format`.
- Write map value as config struct instead of `1`.

Expected outcome:
- Control plane guarantees no ambiguous config reaches kernel.

### 3) Kernel Fast-Path Enforcement
- In XDP and TC:
  - lookup `(port, protocol)` config struct.
  - `drop`: return `XDP_DROP` / `TC_ACT_SHOT`.
  - `pass`: return `XDP_PASS` / `TC_ACT_OK` without capture.
  - `check|decode`: run bounded scalar-prefix format guard:
    - reject obvious binary signatures (`MZ`, ELF, PDF, ZIP).
    - JSON: leading token sanity (`{`/`[`).
    - Syslog: `<PRI>` shape with `PRI <= 191`.
    - HTML: `<html` / `<!doc` prefix hints.
    - Plain text: allow unless obvious binary signature policy rejects.
  - invalid guard => drop.
  - valid + `check` => pass without ringbuf emit.
  - valid + `decode` => existing emit flow.
- In SK_MSG path:
  - mirror same action behavior for large TCP payload interception using direct bounded scalar reads.

Expected outcome:
- Packet decision (`drop/pass/check/decode`) is enforced before userspace.

### 4) Event Metadata for Decode Routing
- Extend `log_event_t` with minimal metadata required for userspace policy-aware routing:
  - selected `format`
  - selected `action`
  - optionally `dst_port`/`proto` for diagnostics
- Mirror struct exactly in `userspace/decoder/src/structs.rs`.

Expected outcome:
- Userspace decoder receives action/format from kernel decision context.

### 5) Decoder Behavior
- In dispatcher/router:
  - if action is not `decode`, do not emit decoded payload.
  - if action is `decode`, dispatch parser by expected format first (no sniff-first as primary).
  - on decode mismatch/failure under `decode`, mark as violation and ensure outcome aligns with kernel decision model (already dropped upstream for mismatches).
- Keep small-payload output behavior as current stdout JSON envelope.

Expected outcome:
- Decode output only appears for configured `decode` entries.

### 6) Documentation and Index
- Update:
  - `README.md`
  - `docs/DEVELOPER_MANUAL.md`
  - `docs/PLAN_CONFIG_EXTENSIONS.md`
- Update `obsidian_space/50_CODE_INDEX_CONCISE.md` with any new symbols/anchors added by this implementation.

## Must-Not-Break List
- SSH/loopback bypass in XDP.
- Existing map pin paths in loader/decoder startup.
- Arena slot math and mmap alignment assumptions.
- `log_event_t` ABI parity between kernel and userspace.
- Existing payload size caps and checked bounds in userspace parser path.

## Verification Checklist
- Build checks:
  - `cargo check --manifest-path userspace/loader/Cargo.toml`
  - `cargo check --manifest-path userspace/decoder/Cargo.toml`
- Unit tests:
  - loader enum parsing and duplicate rejection
  - router behavior for action gating
- Functional tests with traffic replay:
  - `drop` entry drops valid and invalid payloads.
  - `pass` entry passes with no decode output.
  - `check` entry passes valid payloads and drops invalid type payloads.
  - `decode` entry decodes expected payload and drops mismatched payload type.

## Dumb AI Section (Do Exactly This)
This section is intentionally procedural and references `IDX-*` anchors from `50_CODE_INDEX_CONCISE.md`.

### Step 0: Navigate by Code Index
Open and use these IDs first:
- `IDX-SH-STRUCT` (`kernel/common/structs.h`)
- `IDX-SH-FILTERMAP` (`kernel/common/maps.h`)
- `IDX-K-XDP-FILTER` (`kernel/layer1_xdp/xdp_edge.bpf.c`)
- `IDX-K-TC-FILTER` and `IDX-K-TC-EMIT` (`kernel/layer1_tc/tc_stateful.bpf.c`)
- `IDX-K-SKMSG-EMIT` (`kernel/layer4_transport/sk_msg_intercept.bpf.c`)
- `IDX-LOAD-CONFIG` (`userspace/loader/src/config.rs`)
- `IDX-UDEC-SAMPLE` and `IDX-UDEC-EVENT` (`userspace/decoder/src/json_parser.rs`, `userspace/decoder/src/structs.rs`)
- `IDX-UDEC-ROUTER` (`userspace/decoder/src/format_router.rs`)

### Step 1: Change Config Schema
In `config/intercept.yaml`:
- legacy `actions` lists are gone.
- each entry has one `action` string.
- each entry keeps required `format`.

### Step 2: Change Loader Types
In `userspace/loader/src/config.rs`:
- add enum `InterceptAction { Decode, Drop, Pass, Check }`.
- make `action: InterceptAction` required.
- keep `format` required.
- keep duplicate `(port, proto)` rejection.
- encode map value as struct `{format, action}`.

### Step 3: Change Kernel Map Value
In `kernel/common/maps.h` and `kernel/common/structs.h`:
- define struct value for `port_proto_filter`.
- include `format` and `action` fields.

### Step 4: Enforce Action in Kernel Programs
In:
- `kernel/layer1_xdp/xdp_edge.bpf.c`
- `kernel/layer1_tc/tc_stateful.bpf.c`
- `kernel/layer4_transport/sk_msg_intercept.bpf.c`

Add logic:
- if action=`drop`: drop.
- if action=`pass`: pass.
- if action=`check` or `decode`: run bounded format check.
- if check fails: drop.
- if action=`check` and check passes: pass without emit.
- if action=`decode` and check passes: continue existing emit flow.

### Step 5: Propagate Metadata to Userspace
In:
- `kernel/common/structs.h`
- `userspace/decoder/src/structs.rs`

Add action/format metadata in `log_event_t` (same field order and layout both sides).

### Step 6: Decoder Action Gate
In:
- `userspace/decoder/src/json_parser.rs`
- `userspace/decoder/src/format_router.rs`

Rules:
- only decode+emit when action=`decode`.
- skip decode output for `check/pass/drop`.
- parser selection should prefer expected format from metadata.

### Step 7: Docs + Index
Update docs and add/refresh IDs in `obsidian_space/50_CODE_INDEX_CONCISE.md` for all new enums/fields/anchors.

### Step 8: Validate
Run:
```bash
cargo check --manifest-path userspace/loader/Cargo.toml
cargo check --manifest-path userspace/decoder/Cargo.toml
```
Then run targeted tests for each action behavior.
