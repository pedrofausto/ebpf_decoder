# Rust Beginner's Guide: The Bridge to the Kernel

This guide explains how we use Rust to "talk" to the eBPF programs in the kernel. Rust is famous for being "Safe," but once we start sharing memory with the kernel, we have to enter the world of **Unsafe Rust**.

---

## 1. The "Unsafe" Manifesto: Shared Chalkboards

Imagine two people are assigned to work on the same chalkboard (the Shared Memory).
- Person A (The Kernel) is writing very fast.
- Person B (The Rust Decoder) is reading very fast.

If they aren't careful, Person B might start reading a sentence *before* Person A has finished writing it. This is a **Data Race**, and it can lead to crashes or "garbage" data.

### Why do we use `unsafe`?
Rust has a "Safety Inspector" (the Borrow Checker) that prevents these accidents. But the inspector can only see inside your Rust code. It **cannot see inside the Linux Kernel**. 

When we say `unsafe { ... }`, we are telling Rust: *"The Safety Inspector is blind here. Trust me, I have checked the code myself."*

---

## 2. Memory Layout: Building the Telescope

How does Rust "see" the 512MB memory block inside the kernel? We use a technique called **Memory Mapping (mmap)**.

Imagine the Kernel's memory is a house with a locked front door.
1.  **The Key**: The loader gets a "File Descriptor" (a key) to the BPF map.
2.  **The Telescope**: We use `libc::mmap` to map that key into our own program's space. 
3.  **The Result**: The 512MB block now looks like a simple array to Rust.

```rust
// userspace/decoder/src/main.rs

let arena_ptr = unsafe {
    libc::mmap(
        core::ptr::null_mut(), // "Put it anywhere in RAM"
        512 * 1024 * 1024,      // "Give me a 512MB window"
        libc::PROT_READ,        // "I only want to read"
        libc::MAP_SHARED,       // "Let the Kernel and I see the same thing"
        fd,                     // "The Key to the map"
        0,
    )
};
```

---

## 3. Lifecycle of an Event: From Bytes to Structs

When a packet is captured, it arrives in Rust as a "bunch of raw bytes" (a `&[u8]` slice). We need to turn those bytes back into something we can understand (a `struct`).

### Step 1: Receiving the Bytes
The Ring Buffer gives us a raw pointer to memory: `data: *const u8`.

### Step 2: The "Cast" (The Magic Mirror)
We "cast" the bytes onto our `LogEvent` structure. It's like putting a transparency over a map to see the roads.

```rust
// userspace/decoder/src/json_parser.rs

// This line is essentially saying: "Treat these bytes like a LogEvent"
let event = unsafe { &*(data.as_ptr() as *const log_event_t) };
```

### Step 3: Bounds Checking (The Final Guard)
Even though the Kernel told us the JSON is at `offset 5000`, we MUST check that this doesn't go off the edge of our 512MB plate.

```rust
if offset + len > 512 * 1024 * 1024 {
    return Err(anyhow!("KERNEL CORRUPTION OR MALICIOUS OFFSET!"));
}
```

---

## 4. Why use Rust for eBPF Decoders?
1.  **SIMD-JSON**: Rust can use special CPU instructions (AVX2) to parse JSON at gigabit speeds.
2.  **Zero-Copy**: Because we map the memory directly (`mmap`), we don't have to copy the huge 64KB JSONs from the kernel to userspace. We just read them where they sit.
3.  **Modern Concurrency**: Rust's `async` and `tokio` features allow us to poll thousands of events per second without slowing down the rest of the server.
