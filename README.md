# eBPF Multi-Format Log Processing Pipeline

Production-grade eBPF pipeline for high-performance log ingestion across multiple payload formats.

## Architecture

- **XDP Edge Filter**: L3/L4 filtering and rate limiting on `ens33`.
- **TC Stateful Filter**: Connection tracking and candidate marking.
- **TLS Uprobe Capture**: Plaintext interception from OpenSSL/GnuTLS.
- **Socket Filter**: Plaintext payload extraction.
- **Dynptr Data Handler**: Variable-length buffer management.
- **Ringbuffer / Arena**: Zero-copy data transport.

## Implementation Details

- **Kernel Requirement**: 6.9+ (Current: 6.10, Arena enabled).
- **Format Pipeline**: JSON (`simd-json`/`serde-json`), syslog, HTML, and plaintext routing in userspace.
- **Policy Enforcement**: Kernel action gates enforce `drop`, `pass`, `check`, and `decode` before userspace decode.

## Configuration Contract

Each `(port, protocol)` entry in `config/intercept.yaml` must now include:
- `format`: `json` | `syslog` | `html` | `plain_text`
- `action`: `decode` | `drop` | `pass` | `check`

`decode` and `check` run a bounded kernel format guard. If the payload does not match the configured `format` (for example, an ELF/PDF/ZIP payload sent to a JSON entry), the packet is dropped before decode output is emitted. `drop` always drops, while `pass` bypasses capture/decode.

## Kernel Version Compatibility Matrix

| Feature                      | Minimum Kernel | Status          |
|------------------------------|---------------|-----------------|
| eBPF + BTF (CO-RE)           | 5.8           | ✅ Supported    |
| Bounded loops                | 5.3           | ✅ Supported    |
| `BPF_MAP_TYPE_RINGBUF`       | 5.8           | ✅ Supported    |
| `bpf_dynptr` kfuncs          | 5.19          | ✅ Supported    |
| `BPF_MAP_TYPE_USER_RINGBUF`  | 6.1           | ✅ Supported    |
| BPF Arena                    | 6.9           | ✅ Supported    |

## Setup & Build

Refer to [DEVELOPER_MANUAL.md](DEVELOPER_MANUAL.md) for prerequisite checks.

```bash
make all                 # Compile BPF and Rust workspace
sudo ./scripts/load_pipeline.sh  # Attach to ens33
```
