# Rust Beginner Guide: Userspace eBPF Control & Data Planes

Welcome to the Rust userspace portion of the eBPF JSON Intercept Pipeline! While the eBPF C code handles the high-speed packet inspection inside the kernel, the Rust code acts as both the **Control Plane** (loading, configuring, and attaching the programs) and the **Data Plane** (receiving and decoding the intercepted data).

This guide explains the core concepts, crates, and paradigms used to bridge the gap between the Linux kernel and our high-performance Rust applications.

---

## 1. The Core Library: `libbpf-rs`

Just as the kernel code uses `libbpf` headers, the Rust code uses `libbpf-rs`. This crate provides safe, idiomatic Rust bindings to the C `libbpf` library. 

It handles the heavy lifting of managing the full eBPF lifecycle: reading compiled `.bpf.o` (ELF) files, loading them into the kernel, pinning maps, and attaching programs to hooks.

### Lifecycle: Opening, Loading, and Attaching

We use the `ObjectBuilder` pattern to manage this lifecycle in discrete steps.

1. **Opening (`open_file`)**: This reads the compiled ELF object from disk and parses its sections (maps, programs). At this stage, nothing is in the kernel yet. You can inspect the map names and program types.
2. **Loading (`load`)**: This is the critical step where the kernel takes over. The bytecode is sent to the Linux kernel's BPF verifier. The verifier checks for safety. If it passes, the kernel allocates memory for the maps and JIT-compiles the bytecode. The program now lives in the kernel, but it isn't processing traffic.
3. **Pinning (`pin`)**: To keep maps alive independently of the userspace process, we "pin" them to the BPF virtual filesystem (`/sys/fs/bpf/`).
4. **Attaching (`attach`)**: Finally, we hook the loaded program to an event source (like a network interface for XDP/TC, or a function for Uprobes).

In `userspace/loader/src/loader.rs`, you will see:
```rust
let mut xdp_obj_builder = ObjectBuilder::default();
let xdp_open = xdp_obj_builder.open_file("kernel/layer1_xdp/xdp_edge.bpf.o")?;
let xdp_loaded = xdp_open.load()?;
```

---

## 2. BPF Maps in Rust: Pinning and Reusing

eBPF Maps are the primary way the kernel communicates with userspace. However, map file descriptors (FDs) are typically tied to the process that created them. If the loader exits, the maps disappear.

### The Virtual BPF Filesystem (`/sys/fs/bpf/`)
Once pinned, the map acts like a file. Other programs (like our TC program, or our separate Decoder application) can access the exact same kernel memory by pointing to that path.

### Reusing Pinned Maps
In the Loader, we attach both XDP and TC programs. They need to share the same `log_ringbuf` and `port_proto_filter` maps. We load XDP, pin its maps, and then tell the TC object to *reuse* them before loading it:
```rust
tc_open.maps_mut().find(|m| m.name() == "log_ringbuf")
    .unwrap().reuse_pinned_map("/sys/fs/bpf/ebpf-json-pipeline/log_ringbuf")?;
```

---

## 3. Safe Unsafe: The C-to-Rust Memory Contract

The eBPF kernel code writes raw bytes into the Ring Buffer. Rust reads those raw bytes (`&[u8]`). How do we safely turn a byte array into a structured event without causing panics or memory corruption?

### `#[repr(C)]`
In `userspace/decoder/src/structs.rs`:
```rust
#[repr(C)]
#[derive(Clone, Copy)]
pub struct log_event_t {
    pub conn_id: u32,
    pub pid: u32,
    pub tid: u32,
    pub ts_ns: u64,
    pub data_len: u32,
    pub data: [u8; 1024],
}
```
- **What it is:** The `#[repr(C)]` attribute enforces the memory layout contract. It forces the Rust compiler to lay out the struct in memory exactly as a standard C compiler would. This includes inserting necessary padding between fields for alignment. 
- **The Risk:** If you omit this, Rust might reorder fields to optimize space. If the padding doesn't match, you will read offset, corrupted data. A `u32` might be read as part of a `u64`, leading to complete garbage values and potentially disastrous logic bugs.

### The Unsafe Cast
In `json_parser.rs`, we cast the raw byte slice into our struct:
```rust
let event = unsafe { &*(data.as_ptr() as *const log_event_t) };
```
- **Why `unsafe`?:** We are telling Rust, "Trust me, the kernel wrote exactly `sizeof(log_event_t)` bytes here, formatted correctly." Because this bypasses Rust's guarantees, we must manually ensure that `data.len()` is at least the size of the struct before running this line.

---

## 4. The Decoder: Ring Buffers and Async Starvation

The Decoder (`ebpf-json-decoder`) continuously listens for incoming events from the kernel.

### Polling the Ring Buffer
We use `libbpf_rs::RingBufferBuilder` to attach a callback function to the `log_ringbuf` map. To actually receive data, we must repeatedly call `manager.poll()`.

### The Async Blocking Trap
Our Decoder uses `tokio` to handle async operations. Tokio uses a small pool of native OS threads (a reactor) to run thousands of async tasks concurrently.

However, `manager.poll()` is a **blocking** C-library call. It tells the OS thread to wait until data is available in the kernel buffer. 
If we run a blocking loop inside `tokio::main`, we block the very thread Tokio relies on. This causes **async starvation**: Tokio cannot process other async tasks, timers fail, and the entire runtime grinds to a halt.

**The Fix:**
We isolate the blocking kernel interaction by wrapping the polling loop in a dedicated native OS thread using `std::thread::spawn`:
```rust
std::thread::spawn(move || {
    loop {
        manager.poll(std::time::Duration::from_millis(100));
    }
});
```
This dedicates one OS thread exclusively to blocking on the kernel, freeing Tokio's executor threads to handle async control flow seamlessly.

### Loader Safety: Preventing SSH Lockout
When working with XDP edge filtering, a simple bug can drop all packets, completely locking you out of a remote server. Our loader in `userspace/loader/src/loader.rs` implements safety checks and a "dead man's switch":

```rust
    /// Schedule an automatic detach if not confirmed within N minutes.
    fn schedule_safety_timer(interface: String, minutes: u64) {
        thread::spawn(move || {
            info!("SAFETY: Dead man's switch armed. XDP will detach in {} minutes unless confirmed.", minutes);
            // Wait for N minutes
            for _ in 0..(minutes * 60) {
                thread::sleep(Duration::from_secs(1));
                if CONFIRMED.load(Ordering::SeqCst) {
                    info!("SAFETY: Deployment confirmed. Safety timer disarmed.");
                    return;
                }
            }

            warn!("SAFETY: Safety timer expired! Detaching XDP from {}...", interface);
            let _ = std::process::Command::new("ip")
                .args(["link", "set", "dev", &interface, "xdp", "off"])
                .status();
            
            warn!("SAFETY: XDP detached to prevent operator lockout. Exiting.");
            std::process::exit(1);
        });
    }
```
This spawns a thread that waits 5 minutes. If the deployment isn't explicitly confirmed (e.g., via an API call indicating the control plane is reachable), it shells out to remove the XDP program, restoring connectivity.

---

## 5. Performance Optimization: SIMD & Zero-Allocation

JSON parsing is typically CPU-intensive. Since this pipeline intercepts network traffic at edge speeds, the decoder must parse gigabytes of JSON per second.

### `simd-json` and AVX2
We use the `simd-json` crate, which leverages SIMD (Single Instruction, Multiple Data) technologies like AVX2 vector instructions on modern CPUs. Instead of looking at one character at a time in a loop, SIMD allows the CPU to load 32 bytes of JSON simultaneously and process structural characters (like brackets and quotes) in a single clock cycle, bypassing slow branch prediction.

### The Allocation Bottleneck
`simd-json` achieves its speed by modifying the input string in-place (e.g., resolving escape characters like `\n`) rather than allocating new memory. 
However, the eBPF ring buffer gives us an immutable `&[u8]`. If we call `.to_vec()` to make it mutable, we allocate a new vector on the heap for *every single network packet*, destroying our performance gains entirely.

### Thread-Local Buffers
To solve this, we use a `thread_local!` pre-allocated buffer in `userspace/decoder/src/json_parser.rs`:

```rust
thread_local! {
    // Pre-allocate enough capacity for the maximum chunk size (1024 bytes)
    // This eliminates the allocation overhead on every single packet.
    static SIMD_BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(1024));
}

// Inside the parser:
SIMD_BUF.with(|buf_cell| {
    let mut buf = buf_cell.borrow_mut();
    buf.clear();
    buf.extend_from_slice(data);
    Ok(simd_json::from_slice(&mut buf)?)
})
```
By re-using the exact same memory block repeatedly on the thread, we achieve zero-allocation parsing, unlocking the true speed of AVX2.

---

## Summary of the Userspace Lifecycle

1. **Safety First:** The Loader checks `/proc/net/tcp` to ensure it won't kill active SSH sessions when attaching XDP, and arms a thread-based dead man's switch.
2. **Load & Pin:** The Loader parses the BPF objects via `ObjectBuilder`, loads them into the kernel, and pins the shared maps (like the ring buffer and port filters) to `/sys/fs/bpf`.
3. **Attach:** The Loader attaches TC (for stateful payload extraction) and XDP (for fast edge filtering) to the interface.
4. **Decode:** The Decoder finds the pinned ring buffer, spawns a dedicated polling thread to prevent Tokio starvation, safely casts the C-struct bytes via `#[repr(C)]`, copies the payload into a thread-local buffer to avoid allocations, and parses the JSON at gigabytes-per-second using SIMD instructions.
