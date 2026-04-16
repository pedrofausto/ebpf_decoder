# eBPF Beginner's Guide: The Kernel Deep-Dive

Welcome to the eBPF Decoder project! This guide is designed for developers who have a basic understanding of programming but are new to eBPF and Kernel-level C. We will break down every complex concept into plain language, walk you through the implementation of this project, and give you tips for success.

---

## 1. What is eBPF? (The 30,000 Foot View)

eBPF (Extended Berkeley Packet Filter) allows you to run custom code **inside the Linux kernel** without changing the kernel source code or loading a kernel module.

Think of it as a **safe, programmable plugin system** for the heart of your operating system. Because it runs in the kernel, it has access to everything happening on the system (network traffic, file access, program execution, etc.) at lightning speed.

### The Lifecycle of an eBPF Program
1.  **Write**: You write a program in restricted C.
2.  **Verify**: You compile it to eBPF bytecode. When you try to load it, the **Kernel Verifier** performs a strict audit. It checks:
    - Does this code crash?
    - Does it run for an infinite amount of time?
    - Does it access forbidden memory?
    *If it fails any of these, the kernel rejects it. This is why eBPF is safe.*
3.  **Attach**: Once verified, it is attached to a "Hook" (a specific event in the kernel).
4.  **Execute**: Every time that event happens, your code triggers.

---

## 2. The "Magic" Headers: The Kernel's DNA

In standard C, you include `<stdio.h>`. In eBPF, the rules are different.

- **`vmlinux.h`**: This is a single, massive file that contains **every struct and definition** in your current Linux kernel. It is generated dynamically based on your running kernel's configuration. Think of it as the "DNA" of your OS.
- **`bpf_helpers.h`**: Because eBPF programs cannot call normal C libraries (like `printf`), the kernel provides "Helper Functions" (like `bpf_printk`) through this header to interact with the kernel safely.

---

## 3. Map Mastery: How We Store Data

eBPF programs are ephemeral—they start, run, and finish in microseconds. They cannot "remember" data across executions in standard variables. They use **Maps** to persist data and to communicate with user-space.

### The Two Most Common Types:
1.  **`BPF_MAP_TYPE_HASH`**: Like a Rust `HashMap` or a Python `dict`. You give it a Key (like an IP address) and it returns a Value (like a Counter).
2.  **`BPF_MAP_TYPE_ARRAY`**: A high-performance array indexed by a number (0, 1, 2...). We use this for our massive, pre-allocated shared memory blocks.

### How to use them (The Code):
```c
// 1. Finding something (Lookup)
struct my_data *val = bpf_map_lookup_elem(&my_map, &my_key);
if (!val) return 0; // ALWAYS check for NULL! The verifier REQUIRES this.

// 2. Saving something (Update)
bpf_map_update_elem(&my_map, &my_key, &new_value, BPF_ANY);
```

---

## 4. Practical Implementation: The eBPF Decoder Pipeline

In this project, we intercept data at different layers of the kernel and pass it to user-space. Here is the flow:

1.  **Kernel Probes (The Producers)**: Programs like `sk_msg_intercept.bpf.c` sit inside the kernel. They "hook" into events (e.g., a packet arrives, a socket message is sent).
2.  **Shared Memory (The Maps)**: The kernel program copies data into an eBPF Map (often a `BPF_MAP_TYPE_RINGBUF` or a large array).
3.  **User-space (The Consumer)**: A Rust program in `userspace/decoder/` reads from these maps using the `libbpf-rs` library.
4.  **Processing**: The Rust decoder parses the data (e.g., into JSON), handles backpressure, and performs the required analysis.

---

## 5. Line-by-Line Breakdown: The Slot Interceptor

Let's look at a critical part of our pipeline in `sk_msg_intercept.bpf.c`:

```c
// [LINE 67] Take a ticket from the Deli machine
__u64 slot_seq = __sync_fetch_and_add(&state->head, 1);
```
> **Explanation**: Multiple CPU cores might process packets at the exact same microsecond. `__sync_fetch_and_add` ensures that only ONE core gets "Ticket #1", the next gets "Ticket #2", etc. It's safe and synchronized.

```c
// [LINE 68] Find which bucket to use
__u32 slot_idx = (__u32)(slot_seq & SLOT_MASK);
```
> **Explanation**: We only have 8,192 buckets. The bitwise `&` operator uses math to "wrap around." If your ticket is 8,193, you go back to Bucket #0. This is the foundation of a **Circular Buffer**.

```c
// [LINE 71] Look up the physical bucket in the 512MB RAM
void *dst = bpf_map_lookup_elem(&large_payload_array, &slot_idx);
if (!dst) return SK_PASS;
```
> **Explanation**: We ask the kernel: "Where is Bucket #5?" If the kernel says "I don't know" (NULL), we immediately let the packet pass—we don't want to break system networking just to capture data!

---

## 6. Detailed Code Walkthrough: `sk_msg_intercept.bpf.c`

This file is a high-performance interceptor for `SK_MSG` (Socket Message) hooks. Its job is to capture socket data and place it into a massive, pre-allocated shared memory area without slowing down the networking stack.

### 1. Data Structures (The Maps)
```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(value_size, 65536);
    __uint(max_entries, 8192);
    __uint(map_flags, BPF_F_MMAPABLE);
} large_payload_array SEC(".maps");
```
*   **Purpose**: This is our 512MB shared memory pool (8,192 slots * 64KB per slot).
*   **`BPF_F_MMAPABLE`**: This is key—it tells the kernel to allow user-space (our Rust code) to "map" this memory directly into its own address space. This makes data access lightning fast by avoiding costly `read()` system calls.

### 2. The Interceptor Function
When a message is sent via a socket, `sk_msg_interceptor` is triggered:

```c
if (bpf_msg_pull_data(msg, 0, data_len, 0) < 0) {
    return SK_PASS;
}
```
*   **`bpf_msg_pull_data`**: Socket data isn't always "linear" (contiguous in memory). It might be scattered across different buffers. This function forces the kernel to copy the data into a single, contiguous block so we can read it easily. If it fails (e.g., memory constraints), we `SK_PASS` (let the packet continue) to keep the system stable.

### 3. Slot Management
```c
__u64 slot_seq = __sync_fetch_and_add(&state->head, 1);
__u32 slot_idx = (__u32)(slot_seq & SLOT_MASK);
```
*   **`__sync_fetch_and_add`**: An atomic operation. It guarantees that multiple CPUs won't grab the same slot. It safely increments the index and returns the old value.
*   **`& SLOT_MASK`**: A bitwise AND. It ensures the index stays within the range of 0 to 8,191. This is a very fast way to implement a "circular" behavior where we wrap around to the start once we hit the end of the array.

### 4. Copying and Logging
```c
bpf_probe_read_kernel(dst, data_len, data);
```
*   **`bpf_probe_read_kernel`**: Safely copies the packet data from the kernel's memory (`data`) into our `large_payload_array` (`dst`).

```c
log_event_t *event = bpf_ringbuf_reserve(&log_ringbuf, sizeof(log_event_t), 0);
...
bpf_ringbuf_submit(event, 0);
```
*   **Ring Buffer**: We don't send the *entire packet* to user-space here; that would be slow. Instead, we send a tiny "event" notification. This event contains the `arena_offset` (where the data is in our 512MB pool) and the `data_len`. The Rust consumer reads this event and knows exactly where to look in the shared memory.

---

## 7. Debugging and Development Tips

1.  **The Verifier is your friend**: If your program doesn't load, the kernel will spit out a long error message. It usually tells you exactly which line or instruction caused the issue. Read it carefully!
2.  **Use `bpf_printk`**: It's the `printf` of the kernel. It writes to `/sys/kernel/debug/tracing/trace_pipe`.
    - Run `sudo cat /sys/kernel/debug/tracing/trace_pipe` in a separate terminal while your program is running to see your debug logs.
3.  **Check your environment**: Ensure your `vmlinux` header is up-to-date and matches your running kernel.
4.  **No-No List for Beginners**:
    - **NO Loops (mostly)**: Keep them unrolled or very simple.
    - **NO Global Variables**: Use Maps.
    - **NO Standard C**: No `malloc`, `free`, or complex string libraries.

---

## 7. Next Steps

- **Read the source**: Look at `kernel/layer4_transport/sk_msg_intercept.bpf.c`.
- **Explore User-space**: Check out `userspace/decoder/src/main.rs` to see how we consume the data.
- **Run the tests**: Use `cargo test` in the `userspace/decoder` directory.
