---
tags:
  - ebpf_decoder
  - security
  - remediation
source_repo: ebpf_decoder
---
# Security Fix Plan (P1 Remediation)

## Summary
- Fix panicable string slicing and parser fallback visibility gaps.
- Preserve current output envelope and decoder architecture.
- Keep changes limited to userspace parser/router modules.

## Implementation
- `userspace/decoder/src/parsers/plain.rs`
  - Replace `&text[..MAX_PLAIN_DISPLAY]` with UTF-8 boundary-safe truncation.
  - Keep `MAX_PLAIN_DISPLAY` and truncation marker behavior.
- `userspace/decoder/src/parsers/html.rs`
  - Remove slicing offsets derived from `to_lowercase()`.
  - Use ASCII case-insensitive search on original bytes to locate `<title>` and `</title>`, then slice original string using those offsets.
  - Keep bounded title and excerpt behavior.
- `userspace/decoder/src/format_router.rs`
  - On JSON parse failure, fall back to plaintext parse instead of terminal `ParseError`.
  - Preserve detection order and output envelope shape.

## Test Plan
- Unit tests:
  - Multibyte UTF-8 boundary around 4096 bytes in plaintext parser does not panic.
  - HTML payload with non-ASCII before `<title>` does not panic and extracts title.
  - Malformed `{...` payload falls back to plaintext routing.
- Build checks:
  - `cargo check --manifest-path userspace/decoder/Cargo.toml`
  - `cargo check --manifest-path userspace/loader/Cargo.toml`

## Assumptions
- Preferred default is observability over strict parse failure.
- No changes to kernel programs or `log_event_t` layout.
- No config schema changes are required for this patch set.

## Acceptance Criteria
- No panic from crafted multibyte plaintext payloads.
- No panic from Unicode-heavy HTML payloads with title tags.
- JSON-sniffed-but-invalid payloads are emitted as plaintext events instead of being dropped.
- Decoder and loader both pass `cargo check`.
