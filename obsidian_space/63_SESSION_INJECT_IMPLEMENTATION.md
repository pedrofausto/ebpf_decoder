---
tags:
  - ebpf_decoder
  - session
  - inject
source_repo: ebpf_decoder
---
# Session: Inject Configured Classification Fields

Date: 2026-04-22

Implemented optional YAML `inject` for `action: decode` entries.

Key anchors:
- `IDX-UDEC-INJECT` applies decoder output injection.
- `IDX-UDEC-INJECT-CONFIG` parses decoder-side injection rules from YAML.
- `IDX-UDEC-INJECT-APPLY` calls injection after decode.

Validation run:
- `cargo check --manifest-path userspace/loader/Cargo.toml`
- `cargo check --manifest-path userspace/decoder/Cargo.toml`
- `cargo test --manifest-path userspace/decoder/Cargo.toml`
- `cargo test --manifest-path userspace/loader/Cargo.toml` (rerun outside sandbox for UDP bind)
- `make kernel`
