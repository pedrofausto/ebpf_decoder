# Per-Port Format and Action Contract

## Purpose
`intercept.yaml` is now explicit per `(port, protocol)` pair. Each pair must declare:
- `format`: intended payload type
- `action`: one processing policy for that pair

## Required Schema
```yaml
intercept:
  - port: 443
    protocol: tcp
    format: html
    action: decode
  - port: 8080
    protocol: tcp
    format: json
    action: decode
  - port: 53
    protocol: udp
    format: plain_text
    action: pass
  - port: 514
    protocol: udp
    format: syslog
    action: check
```

## Valid Values
- `protocol`: `tcp` | `udp`
- `format`: `json` | `syslog` | `html` | `plain_text`
- `action`: `decode` | `drop` | `pass` | `check`

## Current Enforcement
- Loader validation fails on:
  - duplicate `(port, protocol)` entries
  - missing `format` or `action`
  - invalid enum values
- The kernel `port_proto_filter` map is keyed by `(port, protocol)` and stores `{ format, action }`.
- XDP enforces unconditional `drop`/`pass`; TC and SK_MSG enforce `drop`/`pass` plus bounded format checks for `check`/`decode`.
- If the bounded guard sees a payload mismatch under `check` or `decode`, the packet is dropped.

## Current Limitation
Kernel checks are intentionally coarse and bounded. Deep parsing and rich content classification remain userspace responsibilities after the kernel has admitted a `decode` payload.
