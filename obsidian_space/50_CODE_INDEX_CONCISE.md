---
tags:
  - ebpf_decoder
  - code_index
source_repo: ebpf_decoder
---
# Code Index (Stable IDs)

Goal: jump to relevant code without re-grepping files. Use IDs in discussions.

Notes:
- Line numbers may drift; the `Anchor` is the stable identifier.
- Keep this small; add entries only for frequently referenced paths.

## Userspace decoder (Rust)
| ID | Location | Anchor | What it is |
|---|---|---|---|
| IDX-UDEC-MAIN | `userspace/decoder/src/main.rs:12` | `main()` | Pins/maps, mmaps arena, starts ringbuf poll |
| IDX-UDEC-ARENA-PIN | `userspace/decoder/src/main.rs:23` | `arena_pin_path` | Pinned `large_payload_array` path |
| IDX-UDEC-RB-PIN | `userspace/decoder/src/main.rs:74` | `rb_pin_path` | Pinned `log_ringbuf` path |
| IDX-UDEC-POLL | `userspace/decoder/src/main.rs:86` | `RingBufferBuilder` | Callback + polling loop |
| IDX-UDEC-LIMIT | `userspace/decoder/src/json_parser.rs:14` | `MAX_EVENT_PAYLOAD_SIZE` | Global payload hard cap |
| IDX-UDEC-BACKEND | `userspace/decoder/src/parsers/json.rs:21` | `get_parser_backend()` | AVX2 simd-json vs serde fallback |
| IDX-UDEC-PARSE | `userspace/decoder/src/parsers/json.rs:39` | `parse()` | Parses JSON payload; enforces JSON size cap |
| IDX-UDEC-ARENA-BASE | `userspace/decoder/src/json_parser.rs:18` | `set_arena_layout()` | Stores arena layout (base + size) for reads |
| IDX-UDEC-SAMPLE | `userspace/decoder/src/json_parser.rs:23` | `process_sample()` | Decodes `log_event_t`, arena bounds checks |
| IDX-UDEC-OUT | `userspace/decoder/src/json_parser.rs:125` | `println!("Latency:")` | Current stdout log format |
| IDX-UDEC-EVENT | `userspace/decoder/src/structs.rs:15` | `log_event_t` | Userspace view of event struct |

## Userspace loader (Rust)
| ID | Location | Anchor | What it is |
|---|---|---|---|
| IDX-LOAD-MAIN | `userspace/loader/src/main.rs:22` | `main()` | Loads BPF objs, updates pinned maps |
| IDX-LOAD-PF-PIN | `userspace/loader/src/main.rs:31` | `pin_path` | Pinned `port_proto_filter` path |
| IDX-LOAD-PINDIR | `userspace/loader/src/loader.rs:112` | `pin_dir` | Pin directory `/sys/fs/bpf/ebpf-json-pipeline` |
| IDX-LOAD-PINMAPS | `userspace/loader/src/loader.rs:127` | `maps = [...]` | Set of maps pinned by loader |
| IDX-LOAD-CONFIG | `userspace/loader/src/config.rs:64` | `port_proto_filter` update | Applies YAML config to map |

## Kernel programs (eBPF C)
| ID | Location | Anchor | What it is |
|---|---|---|---|
| IDX-K-XDP-FILTER | `kernel/layer1_xdp/xdp_edge.bpf.c:90` | `port_proto_filter` lookup | Early traffic filter |
| IDX-K-TC-FILTER | `kernel/layer1_tc/tc_stateful.bpf.c:71` | `port_proto_filter` lookup | Stateful/size routing |
| IDX-K-TC-EMIT | `kernel/layer1_tc/tc_stateful.bpf.c:104` | `bpf_ringbuf_reserve` | Emits `log_event_t` to ringbuf |
| IDX-K-TC-MISMATCH | `kernel/layer1_tc/tc_stateful.bpf.c:120` | `bpf_format_check(...)` | Drops `check`/`decode` packets with mismatched payload prefix |
| IDX-K-TC-CONNID | `kernel/layer1_tc/tc_stateful.bpf.c:137` | `event->conn_id` | Populates TCP stream key for userspace framing |
| IDX-K-TC-TS | `kernel/layer1_tc/tc_stateful.bpf.c:107` | `event->ts_ns` | Kernel event timestamp |
| IDX-K-SKMSG-SLOTS | `kernel/layer4_transport/sk_msg_intercept.bpf.c:34` | `SLOT_*` | Arena slot sizing/mask |
| IDX-K-SKMSG-COPY | `kernel/layer4_transport/sk_msg_intercept.bpf.c:71` | `large_payload_array` lookup | Copies payload into arena slot |
| IDX-K-SKMSG-EMIT | `kernel/layer4_transport/sk_msg_intercept.bpf.c:82` | `log_ringbuf` reserve | Emits arena offset ticket |
| IDX-K-SKMSG-MISMATCH | `kernel/layer4_transport/sk_msg_intercept.bpf.c:86` | `bpf_format_check(...)` | Drops large TCP payloads with mismatched configured format |
| IDX-K-SKMSG-CONNID | `kernel/layer4_transport/sk_msg_intercept.bpf.c:144` | `event->conn_id` | Populates large-payload TCP stream key |
| IDX-K-SKMSG-TS | `kernel/layer4_transport/sk_msg_intercept.bpf.c:87` | `event->ts_ns` | Kernel timestamp for large path |
| IDX-K-UPROBE-TS | `kernel/layer2_capture/uprobe_tls.bpf.c:63` | `event->ts_ns` | Timestamp for TLS uprobe events |

## Format expansion modules (Phase 1)
| ID | Location | Anchor | What it is |
|---|---|---|---|
| IDX-UDEC-ROUTER | `userspace/decoder/src/format_router.rs:1` | `decode_payload()` | Central format dispatcher (hint → sniff → fallback) |
| IDX-UDEC-FRAMING | `userspace/decoder/src/framing.rs:1` | `frame()` | Framing strategy selector (Datagram/Newline/OctetCounted/RawBlob) |
| IDX-UDEC-STREAM | `userspace/decoder/src/stream_state.rs:1` | `StreamState::frames_for_event()` | Bounded TCP stream buffering; drains newline and octet-counted frames |
| IDX-UDEC-CLASSIFY | `userspace/decoder/src/content_classifier.rs:1` | `classify()` | Userspace signature/text-shape classifier before strict decode |
| IDX-UDEC-OUTPUT | `userspace/decoder/src/output.rs:1` | `DecodedEvent` | Normalized output envelope + `emit()` + `format_latency()` |
| IDX-UDEC-P-JSON | `userspace/decoder/src/parsers/json.rs:1` | `parse()` | JSON parser (AVX2 simd-json + serde fallback) extracted from json_parser.rs |
| IDX-UDEC-P-PLAIN | `userspace/decoder/src/parsers/plain.rs:1` | `parse()` | Plaintext fallback (lossy UTF-8, bounded 4 KB display) |
| IDX-UDEC-P-SYSLOG | `userspace/decoder/src/parsers/syslog.rs:1` | `parse()` | RFC 3164 + RFC 5424 datagram syslog parser |
| IDX-UDEC-P-HTML | `userspace/decoder/src/parsers/html.rs:1` | `parse()` | Bounded HTML metadata extractor (title, excerpt, tag count) |
| IDX-UDEC-DISPATCH | `userspace/decoder/src/json_parser.rs:1` | `process_sample()` | Ringbuf callback — validates event, extracts payload, calls router |
| IDX-UDEC-UTILS | `userspace/decoder/src/text_utils.rs:1` | `safe_truncate()` | Shared UTF-8 safe string truncation helper |

## Shared types / maps
| ID | Location | Anchor | What it is |
|---|---|---|---|
| IDX-SH-STRUCT | `kernel/common/structs.h:10` | `FORMAT_*/ACTION_* / port_proto_config_t / log_event_t` | Kernel event layout + format/action encoding |
| IDX-SH-FMT-GUARD | `kernel/common/structs.h:79` | `bpf_format_check()` | Scalar-prefix kernel guard for JSON/syslog/HTML/plain mismatch drops |
| IDX-SH-MAPS | `kernel/common/maps.h:13` | `log_ringbuf` | Ringbuf map definition |
| IDX-SH-FILTERMAP | `kernel/common/maps.h:37` | `port_proto_filter` | Port/proto filter map — value is now `port_proto_config_t` |

## Actions pipeline (Plan 62)
| ID | Location | Anchor | What it is |
|---|---|---|---|
| IDX-LOAD-ACTION | `userspace/loader/src/config.rs:65` | `InterceptAction::{Decode,Drop,Pass,Check}` | Single-action enum; encoded as u8 in map value |
| IDX-LOAD-FORMAT | `userspace/loader/src/config.rs:45` | `PayloadFormat::{Json,Syslog,Html,PlainText}` | Required format per YAML entry |
| IDX-LOAD-MAPVAL | `userspace/loader/src/config.rs:113` | `PortProtoConfig { format, action }` | Map value written to port_proto_filter |
| IDX-UDEC-STRUCTS | `userspace/decoder/src/structs.rs:1` | `EventFormat / EventAction` | Userspace mirrors of kernel format/action enums |
| IDX-UDEC-ACTION-GATE | `userspace/decoder/src/json_parser.rs:47` | `match event_action` | Action gate: skips drop/pass, gates emit on decode vs check |
| IDX-K-XDP-ACTION | `kernel/layer1_xdp/xdp_edge.bpf.c:87` | `cfg->action == ACTION_DROP/PASS` | XDP enforces drop/pass before rate-limiter |
| IDX-K-TC-ACTION | `kernel/layer1_tc/tc_stateful.bpf.c:69` | `cfg->action == ACTION_DROP/PASS` | TC enforces drop/pass; propagates format+action in event |
