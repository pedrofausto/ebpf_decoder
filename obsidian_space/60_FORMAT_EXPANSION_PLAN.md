---
tags:
  - ebpf_decoder
  - roadmap
  - formats
source_repo: ebpf_decoder
---
# Format Expansion Plan

Purpose: expand the project from JSON-only decoding into a multi-format payload decoder with minimal risk to the current capture path.

## Scope
- Add support for structured and semi-structured payloads such as JSON, syslog, HTML, and generic plaintext.
- Keep kernel capture mostly payload-agnostic.
- Move format detection, framing, parsing, and normalized output into userspace.
- Preserve the current mmap/ringbuf/arena behavior unless a later phase explicitly changes it.

## Delivery Phases

### Phase 1: Safe userspace-only expansion
- Build a format router.
- Split parser logic by format.
- Add normalized output.
- Add config hints for format/framing.
- Keep kernel event ABI unchanged.

### Phase 2: Stream-aware decoding
- Populate `conn_id` consistently in kernel emitters.
- Add userspace stream state and framing for TCP-delivered logs.
- Support partial/chunked payload reconstruction where justified.

### Phase 3: Optional metadata ABI extension
- Add event flags or format hints to `log_event_t` only if the userspace router still lacks enough context.
- Change kernel/user structs together and revalidate every emitter/consumer path.

## File-by-File Changes

### `userspace/decoder/src/json_parser.rs`
Current role:
- Validates event size and arena bounds.
- Extracts payload bytes.
- Parses everything as JSON.
- Computes latency and prints output.

Required changes:
- Keep `MAX_JSON_SIZE`, `ARENA_BASE`, arena bounds checks, and latency math.
- Stop assuming all payloads are JSON.
- Refactor payload extraction into a helper that returns:
  - payload bytes
  - source metadata derived from `log_event_t`
- Replace direct JSON parser usage with a router call such as `decode_payload(payload, context)`.
- Keep the current rejection behavior for invalid event sizes and out-of-bounds arena access.

Must not break:
- `MAX_JSON_SIZE` enforcement.
- `event.data_len` validation.
- arena offset bounds check before `from_raw_parts`.
- `CLOCK_MONOTONIC` latency calculation.

### `userspace/decoder/src/main.rs`
Current role:
- Opens pinned maps.
- `mmap`s the arena.
- pre-faults arena pages.
- polls the ringbuf.

Required changes:
- Keep startup, mmap, and polling behavior unchanged.
- Rename user-facing startup messages so the binary is no longer described as JSON-only.
- Optionally load decode config or parser hints and pass shared state into the event-processing callback.
- Keep the callback lightweight; format-specific work should remain in downstream modules.

Must not break:
- pinned map paths.
- arena mmap sizing and `MAP_FIXED` usage.
- page pre-fault loop.
- ringbuf callback registration and poll loop.

### `userspace/decoder/src/structs.rs`
Current role:
- Userspace mirror of kernel `log_event_t`.

Required changes:
- Phase 1: no struct layout changes.
- Phase 2: continue using the existing `conn_id` field once kernel writers populate it.
- Phase 3: only add fields if absolutely required, and only in lockstep with `kernel/common/structs.h`.

Must not break:
- field order.
- alignment and padding.
- 1:1 ABI match with `kernel/common/structs.h`.

### `userspace/decoder/Cargo.toml`
Required changes:
- Keep existing JSON dependencies.
- Add only minimal extra dependencies needed for planned formats.
- Candidate additions:
  - `syslog_loose` for RFC3164/RFC5424 parsing
  - `memchr` for cheap delimiter/framing scans
  - a lightweight HTML tokenizer/parser, not a browser-style DOM stack

Must not break:
- existing `simd-json` fast path.
- buildability of the current decoder crate.

### `userspace/decoder/src/format_router.rs` (new)
Purpose:
- Centralize payload type selection.

Required changes:
- Implement a detection order:
  - explicit config hint by port/protocol
  - framing hint
  - content sniffing
  - fallback to plaintext
- Return a normalized enum such as:
  - `Json`
  - `Syslog`
  - `Html`
  - `PlainText`
  - `Unknown`
- Keep the router pure and deterministic.

Must not break:
- JSON remaining the preferred fast path when hints/content clearly indicate JSON.
- low-overhead processing for already-known formats.

### `userspace/decoder/src/output.rs` (new)
Purpose:
- Normalize decoded events into one output schema.

Required changes:
- Define a common envelope containing at least:
  - capture timestamp or latency
  - detected format
  - source path (`ringbuf inline` vs `arena`)
  - parser status
  - parsed fields or summarized payload
- Keep output format stable across parsers.
- Avoid parser-specific ad hoc `println!` logic.

Must not break:
- existing latency emission unless intentionally redesigned.
- machine-parseable output discipline once finalized.

### `userspace/decoder/src/parsers/json.rs` (new)
Purpose:
- Move current JSON-specific logic out of `json_parser.rs`.

Required changes:
- Move `ParserBackend`, `get_parser_backend()`, SIMD buffer reuse, and JSON parsing logic here.
- Preserve size-cap checks relevant to JSON.
- Preserve graceful failure on malformed input.

Must not break:
- current AVX2/serde fallback behavior.
- recursion/resource exhaustion protections described in QA docs.

### `userspace/decoder/src/parsers/syslog.rs` (new)
Purpose:
- Support RFC3164 and RFC5424 style syslog payloads.

Required changes:
- Add parsers for:
  - UDP syslog datagrams
  - complete TCP syslog frames
- Defer partial TCP stream reconstruction to the framing/stream-state phase.
- Normalize priority, timestamp, host/app/process fields when present.

Must not break:
- current handling of UDP 514 as intercepted traffic.
- fallback to plaintext when syslog parse confidence is low.

### `userspace/decoder/src/parsers/html.rs` (new)
Purpose:
- Extract safe metadata from HTML/text payloads.

Required changes:
- Treat HTML as data, not executable instructions.
- Extract bounded metadata only:
  - title
  - short text excerpt
  - tag presence/summary
  - maybe selected safe attributes
- Enforce truncation limits on extracted text.

Must not break:
- size caps.
- memory discipline on large or malformed documents.
- security posture by accidentally interpreting HTML as trusted instructions.

### `userspace/decoder/src/parsers/plain.rs` (new)
Purpose:
- Preserve observability for unsupported or ambiguous plaintext logs.

Required changes:
- Return a bounded raw-text representation.
- Handle non-UTF8 payloads safely, e.g. lossy decoding or explicit binary marker.
- Provide parser status that explains why richer decoding did not happen.

Must not break:
- current malformed/binary safety expectations.

### `userspace/decoder/src/framing.rs` (new)
Purpose:
- Separate framing from content parsing.

Required changes:
- Support framing strategies such as:
  - datagram
  - newline-delimited
  - octet-counted syslog
  - raw blob
- Expose “complete frame” vs “partial chunk” result types.
- Allow parsers to operate on complete units instead of arbitrary transport chunks.

Must not break:
- fast path for already-complete small payloads.

### `userspace/decoder/src/stream_state.rs` (new, Phase 2)
Purpose:
- Hold per-connection buffers for stream-aware parsing.

Required changes:
- Key state by `conn_id`.
- Add byte limits and time-based eviction to avoid memory DOS.
- Support chunk accumulation for TCP syslog and chunked/plain streaming payloads.

Must not break:
- bounded memory usage.
- decoder stability under many concurrent flows.

### `userspace/decoder/src/config.rs` (new)
Purpose:
- Read decode hints from the same config source used by the loader.

Required changes:
- Parse optional fields such as:
  - `format`
  - `framing`
  - `streaming`
  - `content_type`
- Provide lookup by port/protocol for the router.

Must not break:
- ability to run with no new hint fields set.

### `config/intercept.yaml`
Current role:
- Declares intercepted ports/protocols.

Required changes:
- Extend schema with optional decode hints, for example:
  - `format: syslog`
  - `framing: datagram`
  - `streaming: true`
  - `content_type: text/html`
- Keep current entries valid without requiring new fields.

Must not break:
- current minimal config syntax.
- loader compatibility with legacy entries.

### `userspace/loader/src/config.rs`
Current role:
- Loads YAML and updates `port_proto_filter`.

Required changes:
- Extend the config structs to accept optional decode/framing hints.
- Continue updating the BPF map using only port/protocol fields in Phase 1.
- Ignore decode hints at kernel-programming time unless a later phase adds a userspace-to-kernel control channel for them.

Must not break:
- current YAML parsing for existing configs.
- `port_proto_filter` update behavior.

### `userspace/loader/src/main.rs`
Required changes:
- Keep current loader flow.
- If config schema expands, ensure startup validation errors remain clear.
- No format-specific kernel wiring should be added here in Phase 1.

Must not break:
- loader startup sequence.
- pin-path expectations.

### `userspace/loader/src/loader.rs`
Current role:
- Loads and pins BPF maps/programs.
- Attaches XDP, TC, SockOps, and SK_MSG.
- Maintains operator safety timer.

Required changes:
- Phase 1: no functional changes required.
- Phase 2+: only touch if a new control-plane map is added for format hints or stream metadata.

Must not break:
- safety timer / dead-man switch.
- pin directory cleanup and recreation.
- map pin/reuse flow.
- attach ordering.

### `kernel/common/structs.h`
Current role:
- Defines kernel event ABI.
- Already contains `conn_id` and `log_flags`, though not fully used by emitters.

Required changes:
- Phase 1: leave `log_event_t` layout unchanged.
- Phase 2: if needed, start populating existing `conn_id`.
- Phase 3: add fields such as `flags` or `format_hint` only if the router cannot infer enough context from payload + config.

Must not break:
- ABI stability with `userspace/decoder/src/structs.rs`.
- verifier-safe size assumptions in emitters.

### `kernel/common/maps.h`
Current role:
- Defines shared maps including `log_ringbuf`, `port_proto_filter`, and control-plane maps.

Required changes:
- Phase 1: no changes required.
- Later: consider a dedicated control map only if userspace hints must reach the kernel.

Must not break:
- names and types of pinned maps.
- ringbuf sizing unless benchmarking justifies a change.

### `kernel/layer1_xdp/xdp_edge.bpf.c`
Current role:
- Early filter, bypass rules, allowlist, and rate limiting.

Required changes:
- No format-specific parsing should be added here.
- Keep this layer focused on safe L3/L4 decisions only.

Must not break:
- loopback bypass.
- SSH bypass.
- allowlist behavior.
- rate limiting behavior.

### `kernel/layer1_tc/tc_stateful.bpf.c`
Current role:
- Small-payload capture path into `log_ringbuf`.

Required changes:
- Phase 1: leave payload capture logic intact.
- Phase 2: populate `conn_id` for small-payload events if reliable flow correlation is required in userspace.
- Optionally populate existing flags only if verifier-safe and materially useful.

Must not break:
- `MAX_LOG_CHUNK_SIZE` assumptions.
- small-payload fast path.
- verifier-safe payload copy logic.
- current decision to delegate large payloads to SK_MSG.

### `kernel/layer4_transport/sk_msg_intercept.bpf.c`
Current role:
- Large-payload capture path into mmap-able arena plus ringbuf metadata.

Required changes:
- Phase 1: no functional format changes.
- Phase 2: populate `conn_id` consistently for reassembly/correlation.
- Keep arena writes fixed-slot and zero-offset.

Must not break:
- `SLOT_SIZE`, `SLOT_COUNT`, and `SLOT_MASK`.
- fixed-slot indexing.
- `large_payload_array` semantics.
- ringbuf event emission contract.

### `kernel/layer2_capture/uprobe_tls.bpf.c`
Current role:
- Captures decrypted TLS read buffers into ringbuf events.

Required changes:
- Phase 1: no format-specific parsing here.
- Phase 2: populate `conn_id` or equivalent metadata if TLS plaintext must participate in stream-aware decoding.

Must not break:
- current capture safety around `SSL_read`.
- ringbuf submission path.
- cleanup of `ssl_read_context`.

### `docs/ARCHITECTURE.md`
Required changes:
- Update architecture text to describe “multi-format payload decoder” instead of JSON-only decoding.
- Preserve the dual-path description: small payload ringbuf, large payload arena.

### `docs/QA_JSON_DECODER.md`
Required changes:
- Rename or supersede with a broader decoder QA/security document.
- Add test cases for syslog/html/plaintext and stream-state DOS limits.

### `obsidian_space/50_CODE_INDEX_CONCISE.md`
Required changes:
- Add index entries for:
  - `format_router.rs`
  - `framing.rs`
  - parser modules
  - `stream_state.rs`
- Keep IDs stable once introduced.

## Explicit No-Break Zones

### Userspace safety-critical areas
- Do not remove `MAX_JSON_SIZE`-style upper bounds; generalize them if needed, but keep hard caps.
- Do not weaken arena bounds validation before dereferencing shared memory.
- Do not change latency math back to a mixed clock domain.
- Do not let unsupported formats fall through to panics or uncontrolled allocations.

### Kernel capture-critical areas
- Do not add deep content parsing to XDP, TC, or SK_MSG.
- Do not change pinned map names casually.
- Do not alter event struct layout in only one side of the ABI.
- Do not change arena slot math without revalidating userspace mmap assumptions and verifier behavior.

### Operational safety areas
- Do not break SSH/loopback bypass in XDP.
- Do not break the loader safety timer and detach behavior.
- Do not require new config fields for existing deployments.

## Recommended Implementation Order
1. Extract JSON parser into its own module.
2. Add normalized output envelope.
3. Add format router with config-driven hints.
4. Add plaintext fallback parser.
5. Add syslog parser for datagram and complete-frame inputs.
6. Add HTML parser with bounded metadata extraction.
7. Extend config schema in loader and decoder.
8. Add framing layer.
9. Populate `conn_id` in kernel emitters.
10. Add stream state only after `conn_id` is reliable.

## Validation Checklist
- Existing JSON payloads still decode successfully.
- Oversized payload rejection still works.
- Malformed/binary payloads still fail safely.
- UDP syslog on port 514 decodes without requiring stream state.
- HTML payloads produce bounded summaries, not unbounded extraction.
- Decoder memory remains bounded under many partial TCP chunks.
- Loader and pinned-map startup still work unchanged.
- Arena-backed large payload path still decodes without regressions.

## Design Constraints to Keep in Mind
- Format detection belongs in userspace, not in BPF.
- Framing and parsing are separate concerns and should stay separate.
- Stream reconstruction is a second-phase capability, not a prerequisite for Phase 1 multi-format support.
- If config hints can disambiguate a format, prefer them over expensive sniffing.
- Preserve the current fast path for small complete payloads.
