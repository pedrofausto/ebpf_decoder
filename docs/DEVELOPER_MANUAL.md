# Developer Manual: Maintaining the eBPF Pipeline

This manual is for the developer who needs to build, debug, and optimize the pipeline. If the code is working but you need to change how it behaves, start here.

---

## 1. Troubleshooting (FAQ)

### "Permission Denied" when loading the BPF object
- **Cause**: The BPF Verifier failed.
- **Fix**: Check the verifier logs. Run `sudo bpftool prog load ...` and read the massive output. It usually means you tried to access memory without a NULL check Or your pointer math is too complex.

### "Map not found" at `/sys/fs/bpf/...`
- **Cause**: The loader failed or crashed before it could pin the maps.
- **Fix**: Ensure the directory `/sys/fs/bpf/ebpf-json-pipeline` is empty or delete it and restart `ebpf-json-loader`.

### "JSON logs are showing up as scrambled or partial"
- **Cause**: TCP Segmentation or 64KB slot overflows.
- **Fix**: If the JSON is larger than 64KB, it will be truncated. You may need to increase `SLOT_SIZE` in `maps.h`.

---

## 2. The Debugging Toolkit

When things go wrong in the kernel, you can't use a standard debugger. Use these tools instead:

### `bpf_printk` (The "Kernel Printf")
You can add `bpf_printk("Value: %d\n", my_val);` to your C code. 
To see the output, run:
```bash
sudo bpftool prog tracelog
# OR
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### `bpftool map dump` (Inspecting State)
To see what's actually inside your port filter or your shared memory:
```bash
sudo bpftool map dump name port_proto_filter
```

### `tcpdump` (The Ground Truth)
If you aren't sure if a packet is even hitting the NIC, run:
```bash
sudo tcpdump -i any port 8080 -X
```

---

## 3. Performance Tuning

### Adjusting Shared Memory Size
If your server has a lot of RAM and you want to keep more history of large JSONs:
1.  **Change Slot Count**: Increase `SLOT_COUNT` in `maps.h` from 8192 to 16384 (must be a power of two!).
2.  **Change Slot Size**: Increase `SLOT_SIZE` from 64KB to 128KB if you have truly massive JSON blobs.
3.  **Update Rust**: Ensure `arena_size` in `main.rs` matches the new total (Count * Size).

---

## 4. Building from Source

```bash
# 1. Clean the environment
make clean

# 2. Build everything (Kernel and Userspace)
make all

# 3. Load the pipeline onto 'eth0'
sudo ./target/release/ebpf-json-loader eth0

# 4. Start the decoder
sudo ./target/release/ebpf-json-decoder
```
