---
tags:
  - ebpf_decoder
  - qa
  - security
source: docs/QA_JSON_DECODER.md
---
# QA / Security Hardening (Concise)

## Controls claimed
- Payload caps: `MAX_EVENT_PAYLOAD_SIZE` = 1MB in dispatcher; `MAX_JSON_SIZE` = 1MB in `parsers/json.rs`.
- Recursion protection: serde-json recursion limit (defaults to 128); simd-json builtin.
- Malformed JSON under sniff/fallback can become plaintext in userspace router tests.
- Configured `check`/`decode` traffic is fail-closed on obvious kernel format mismatch (`MZ`, ELF, PDF, ZIP, or wrong leading token).
- HTML: bounded extraction only (title ≤512B, excerpt ≤1KB); no DOM execution.
- Syslog: hand-rolled RFC parser; graceful fallback to plaintext on low-confidence.
- Resource control: reuse preallocated SIMD buffer; clear after parse.
- Logging strategy: failures logged at `tracing::debug!` to reduce IO-based DoS.

## Adversarial test cases mentioned
- Deep recursion attack (e.g. 200 nesting) rejected.
- Invalid UTF-8 rejected.
- Arbitrary binary (e.g. ELF header) rejected.
- Massive keys/strings within limit handled.
- >1MB payload rejected.

## Practical security notes
- Ensure bounds checks before arena reads (offset + len) and data_len slicing.
- Prefer stable, machine-parseable output if logs feed security pipelines.
- Do not describe the whole pipeline as fail-passive: ringbuf pressure drops logs, but configured `drop` and mismatch under `check`/`decode` drop packets.
