# Developer Manual: eBPF JSON Log Processing Pipeline

This manual provides instructions for setting up the environment, verifying prerequisites, and building the eBPF JSON log processing pipeline.

## System Requirements

### Kernel
- **Minimum Version**: Linux 6.9+ (Required for `BPF_MAP_TYPE_ARENA`).
- **Configuration**: Must be compiled with `CONFIG_DEBUG_INFO_BTF=y`.
- **BTF Presence**: Ensure `/sys/kernel/btf/vmlinux` exists.

### Toolchain
- **Clang**: version 16 or newer (Required for BTF and CO-RE generation).
- **libbpf**: version 1.3 or newer.
- **bpftool**: Required for CO-RE skeleton generation and BTF inspection.
- **Rust**: Nightly toolchain (Required for `libbpf-rs` with arena support).
- **Cargo**: With `simd-json` dependencies (requires AVX2 or fallback).

## Prerequisite Verification

Before building the project, run the following checks:

```bash
# 1. Kernel version
uname -r

# 2. BTF presence
ls /sys/kernel/btf/vmlinux

# 3. BPF Arena support
grep "BPF_MAP_TYPE_ARENA" /usr/include/linux/bpf.h

# 4. clang version
clang --version

# 5. libbpf version
pkg-config --modversion libbpf

# 6. bpftool presence
bpftool version

# 7. Rust toolchain (ensure nightly is available)
rustup toolchain list
```

## Setup Instructions

1.  **Generate vmlinux.h**:
    ```bash
    mkdir -p vmlinux
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux/vmlinux.h
    ```

2.  **Build the Project**:
    ```bash
    make all
    ```

## Architecture Overview

The pipeline consists of multiple layers:
- **Layer 1 (XDP/TC)**: Fast filtering and connection tracking.
- **Layer 2 (Capture)**: TLS (uprobes) and plaintext (socket filter) capture.
- **Layer 3 (Data)**: Dynamic handling with `bpf_dynptr`.
- **Layer 4 (Transport)**: `RINGBUF` and `ARENA` for high-performance data transfer to userspace.
- **Userspace**: Rust-based decoder and config injector.

## Deployment

1.  **BPF Pinning**: Maps are pinned to `/sys/fs/bpf/ebpf-json-pipeline`. Ensure the directory exists and has appropriate permissions.
2.  **Network Interface**: Attach XDP/TC to the desired interface (e.g., `eth0` or `lo`).
