# eBPF Beginner Guide: Understanding the JSON Intercept Pipeline

Welcome to the eBPF layer of the JSON Intercept Pipeline! If you are new to eBPF (Extended Berkeley Packet Filter), reading C code that runs inside the Linux kernel can be daunting. This guide explains the core concepts, the data structures (structs), the memory maps, and the unique logic patterns used in this project.

## 1. The eBPF Environment & Imports

eBPF programs are written in restricted C and compiled into eBPF bytecode (usually via Clang/LLVM). They run inside a virtual machine within the Linux kernel.

### `vmlinux.h`
At the top of most of our `.bpf.c` files, you will see `#include "vmlinux.h"`. 
- **What it is:** This is a massive, auto-generated header file that contains **every single struct definition** from the running Linux kernel. 
- **Why we use it:** Instead of including dozens of standard Linux headers (like `<linux/ip.h>`, `<linux/tcp.h>`) which often conflict or differ between kernel versions, we use BPF CO-RE (Compile Once, Run Everywhere). `vmlinux.h` provides types like `struct ethhdr` (Ethernet header) and `struct iphdr` (IP header) exactly as the kernel sees them.

### `<bpf/bpf_helpers.h>` and `<bpf/bpf_endian.h>`
- These are provided by `libbpf`. They contain the definitions for BPF helper functions (e.g., `bpf_map_lookup_elem`, `bpf_ringbuf_reserve`) and macros for network byte-order conversions (e.g., `bpf_htons` to convert Host TO Network Short).

### Section Macros: `SEC("...")`
You will see functions prefixed with `SEC("xdp")` or `SEC("classifier")`.
- **Convention:** This is a libbpf convention. It places the compiled bytecode into a specific ELF section. When the Rust userspace loader reads the `.o` (object) file, it looks at the section name to determine what *type* of eBPF program this is (e.g., XDP, TC, uprobe) and how to attach it to the kernel.

---

## 2. Kernel Structs: Reading Network Packets

eBPF network programs receive context from the kernel representing the packet. The context differs significantly depending on where the eBPF program is hooked.

### `struct xdp_md` (Used in Layer 1 XDP - Driver Level)
This is the context provided to XDP programs. It is incredibly lightweight.
- `ctx->data`: A pointer to the very first byte of the packet.
- `ctx->data_end`: A pointer to the end of the packet.
- **The Driver Level (XDP):** XDP operates directly on the network driver's RX ring buffer memory, *before* the kernel has allocated a socket buffer (`sk_buff`) or done any networking stack processing. It is the absolute earliest point you can intercept a packet, making it incredibly fast.
- **Limitation:** Because it lacks higher-level stream context and TCP state, XDP cannot easily handle fragmented packets or inspect deep L7 payloads.

### `struct __sk_buff` (Used in Layer 1 TC - Qdisc Level)
This is the context provided to TC (Traffic Control) programs. 
- **What it is:** It is the eBPF representation of the kernel's `struct sk_buff` (Socket Buffer), which is the fundamental data structure for networking in Linux.
- **The Qdisc Level (TC):** TC operates at the queueing discipline (qdisc) layer. By the time a packet reaches TC, the kernel has done some preliminary parsing and metadata allocation. 
- **Difference from XDP:** TC has a broader context. We can use helpers like `bpf_skb_pull_data()` to safely access payloads that might be fragmented across different memory pages (which XDP cannot easily do). This is essential for our pipeline because JSON payloads are often large and span multiple packets or memory pages. TC is where we can reliably extract the L7 payload.

### Network Headers (`struct ethhdr`, `struct iphdr`, `struct tcphdr`)
These come from `vmlinux.h`. Because network packets are just contiguous arrays of bytes, we parse them by casting pointers.
```c
struct ethhdr *eth = data;
struct iphdr *iph = (void *)(eth + 1); // Jump past the Ethernet header
```

---

## 3. The BPF Verifier: Why the Code Looks "Weird"

The Linux kernel contains a **BPF Verifier**. Before any eBPF program is allowed to run, the verifier analyzes the bytecode to ensure it cannot crash the kernel, loop infinitely, or access out-of-bounds memory. This dictates how we write logic.

### Register State Tracking
The verifier statically tracks the state of every CPU register as it simulates the execution of your program. It tracks the **minimum and maximum possible values** for every variable (scalars) and ensures pointers always fall within valid bounds (e.g., between `data` and `data_end`). If it cannot guarantee safety, it rejects the program.

### Stack Size Limits & BPF Arena
Historically, eBPF programs have a strict stack size limit, typically **512 bytes**. You cannot declare large arrays or deeply nested structs on the stack. If you needed more memory, you had to use BPF Maps (like `BPF_MAP_TYPE_PERCPU_ARRAY`) or tail calls to chain programs together.

**Modern Workaround: BPF Arena (Linux 6.9+)**
While the stack itself remains limited to 512 bytes, the introduction of **BPF Arena** (`BPF_MAP_TYPE_ARENA`) in Linux 6.9 provides a modern solution. BPF Arena acts as a massive (up to 4GB) virtual memory region shared between the BPF program and userspace. 

Instead of allocating large buffers on the stack, modern eBPF programs can allocate memory pages on-demand and use **standard C pointers** to manipulate data directly within the Arena. This allows developers to build large buffers, linked lists, and complex data structures in kernel space without hitting the historical 512-byte stack limit, while also enabling zero-copy sharing with userspace.

### 4. BPF Arena: Circular Buffer Implementation
In this pipeline, we leverage BPF Arena to handle large JSON payloads that exceed the fixed 1024-byte `log_event_t` limit.

- **The Strategy:** To avoid the overhead of complex memory allocation and deallocation logic in the kernel, we implement a **1GB circular buffer** within the 4GB Arena. 
- **Head Offset Tracking:** We use a specialized BPF Map (`arena_state_map`) to track the current write position (the "head"). 
- **Concurrency & Atomics:** Because multiple CPU cores may be processing packets and trying to write to the Arena at the same time, we must use atomic operations. We use the C intrinsic `__sync_fetch_and_add(&state->head, data_len)` to reserve a block of memory for each packet. This ensures that every packet gets its own unique memory space without any risk of race conditions or data corruption.
- **Relative Offsets:** When passing the captured data to userspace, the kernel sends a **relative offset** rather than an absolute pointer. Userspace adds this offset to its own local memory-map base pointer. This approach prevents issues with pointer truncation and ensures that memory addresses remain valid even if userspace and the kernel have different virtual memory views.

### 5. Bounded Loops
Historically, eBPF didn't allow loops at all. Now, bounded loops are allowed, but the verifier must be able to prove they will terminate within a strict number of iterations. We often use `#pragma unroll` to unroll small loops at compile time, completely avoiding loop verification issues.

Here is an example from `kernel/layer1_xdp/xdp_edge.bpf.c` showing our bounded loop for VLAN parsing logic:
```c
    /* Implement VLAN (802.1Q/802.1AD) parsing logic */
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr *vhdr = (void *)data + offset;
            if ((void *)(vhdr + 1) > data_end)
                return XDP_PASS;
            h_proto = vhdr->h_vlan_encapsulated_proto;
            offset += sizeof(struct vlan_hdr);
        } else {
            break;
        }
    }
```

### Pointer Bounds Checking
You will see this pattern everywhere:
```c
if ((void *)(eth + 1) > data_end)
    return XDP_PASS;
```
- **Why:** You must prove to the verifier that the `eth` struct fits entirely between `data` and `data_end` before reading from it.

### Forcing Bounds (`asm volatile`)
Sometimes the C compiler optimizes code in a way that hides bounds checks from the verifier. The compiler knows a value must be bounded, but the verifier loses that context during its abstract interpretation.

In `kernel/layer1_tc/tc_stateful.bpf.c`, we use a volatile read to force the verifier to re-evaluate bounds:
```c
    __u32 payload_len = ip_tot_len - extra_len;
    
    /* 
     * Verifier safety: The compiler knows payload_len > 0 because of the 
     * (ip_tot_len <= extra_len) check above, so it optimizes away any == 0 
     * check. However, the BPF verifier is not as smart and still thinks 0 
     * is possible, failing the bpf_skb_load_bytes call.
     * We use a volatile read to break the compiler's knowledge.
     */
    volatile __u32 v_len = payload_len;
    __u32 safe_len = v_len;

    if (safe_len == 0 || safe_len > MAX_LOG_CHUNK_SIZE) {
        return TC_ACT_OK;
    }
```

---

## 4. eBPF Maps: Bridging Kernel and Userspace

eBPF programs cannot allocate memory dynamically (no `malloc`) and cannot keep global state easily. Instead, they use **Maps**—key/value stores that reside in kernel memory but can be read and written by both eBPF programs and userspace applications (our Rust code).

### 1. Hash Maps (`BPF_MAP_TYPE_HASH`)
- **Example:** `port_proto_filter`
- **Use:** Standard key/value lookup. Userspace writes a port (e.g., 443) and protocol (TCP) into this map. The eBPF program looks up the packet's port in this map.

### 2. LRU Hash Maps (`BPF_MAP_TYPE_LRU_HASH`)
- **Example:** `ssl_read_context`
- **Use:** Used in our Uprobe TLS capture. It stores memory pointers temporarily between the start and end of an `SSL_read` function. 
- **Under the hood:** "Least Recently Used" (LRU) is crucial for state management in tracing. If a userspace process crashes in the middle of a traced function (between the entry probe and exit probe), the state stored in a regular hash map would leak forever. An LRU map automatically evicts the oldest entries when it gets full, ensuring we never run out of memory due to orphaned state.

### 3. Ring Buffers (`BPF_MAP_TYPE_RINGBUF`)
- **Example:** `log_ringbuf`
- **Use:** The ultimate high-throughput conduit from Kernel to Userspace.
- **Ringbuffer vs. Perf Buffer:** Older eBPF programs used `BPF_MAP_TYPE_PERF_EVENT_ARRAY` (Perf buffers). Perf buffers are allocated per-CPU, meaning userspace has to poll multiple buffers, and memory can be wasted if traffic hits one CPU disproportionately. The BPF Ringbuffer is a multi-producer, single-consumer (MPSC) queue shared across all CPUs. It uses a reservation model (`bpf_ringbuf_reserve` -> write data -> `bpf_ringbuf_submit`), which prevents unnecessary memory copying and reduces CPU overhead significantly compared to the older perf buffers.

### 4. LPM Trie (`BPF_MAP_TYPE_LPM_TRIE`)
- **Example:** `ip_allowlist`
- **Use:** "Longest Prefix Match". It is a specialized map for IP routing and CIDR block matching (e.g., checking if `192.168.1.5` falls within `192.168.1.0/24`).

---

## 5. Custom Structs: The C-to-Rust Contract

When sending data through the Ring Buffer, the layout of the bytes must be perfectly understood by both the C kernel code and the Rust userspace code.

### `log_event_t`
```c
typedef struct {
    __u32 conn_id;
    __u32 pid;
    __u32 tid;
    __u64 ts_ns;
    __u32 data_len;
    __u8  data[MAX_LOG_CHUNK_SIZE];
} log_event_t;
```
- **Convention:** Notice the `__u32` and `__u64` types. These are strict-width integer types used in the kernel to ensure the struct is exactly the same size on every architecture.
- **The Rust Side:** In Rust, we define the exact same struct and annotate it with `#[repr(C)]`. This tells the Rust compiler: "Lay this out in memory exactly as a C compiler would." This allows Rust to safely cast the raw bytes from the Ring Buffer directly into a usable struct.

---

## Summary of the Pipeline Logic

1. **Packet Arrives:** `xdp_edge.bpf.c` gets the `xdp_md` context.
2. **Parse & Bound:** It casts pointers, proving to the verifier that it isn't reading out of bounds, stripping Ethernet and VLAN headers to find the IP header.
3. **Filter (Maps):** It checks the `port_proto_filter` Hash Map. If it's a target port, it passes the packet to the next layer.
4. **Payload Extraction:** `tc_stateful.bpf.c` gets the `__sk_buff` context. It calculates exactly where the application payload starts.
5. **Export (RingBuffer):** It reserves a `log_event_t` in `log_ringbuf`, copies the payload, and submits it for the Rust decoder to read.
