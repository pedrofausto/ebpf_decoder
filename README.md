# eBPF JSON Log Processing Pipeline

Production-grade eBPF pipeline for high-performance JSON log ingestion.

## Architecture

- **XDP Edge Filter**: L3/L4 filtering and rate limiting on `ens33`.
- **TC Stateful Filter**: Connection tracking and candidate marking.
- **TLS Uprobe Capture**: Plaintext interception from OpenSSL/GnuTLS.
- **Socket Filter**: Plaintext payload extraction.
- **Dynptr Data Handler**: Variable-length buffer management.
- **Ringbuffer / Arena**: Zero-copy data transport.

## Implementation Details

- **Kernel Requirement**: 6.9+ (Current: 6.10, Arena enabled).
- **JSON Parser**: `simd-json` with AVX2 acceleration and `serde-json` fallback.
- **Backpressure**: Three-tier system (Kernel -> Channel -> Parser).

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
