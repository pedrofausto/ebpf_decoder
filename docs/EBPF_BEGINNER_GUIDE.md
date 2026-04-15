# eBPF Beginner's Guide: The Kernel Deep-Dive

This guide is designed for developers who have a basic understanding of programming but are completely new to eBPF and Kernel-level C. We will break down every complex concept into plain language.

---

## 1. The "Magic" Headers: The Kernel's DNA

In standard C, you include `<stdio.h>`. In eBPF, the rules are different.

- **`vmlinux.h`**: This is a single, massive file that contains **every struct and definition** in your current Linux kernel. It is generated dynamically. Think of it as the "DNA" of your operating system.
- **`bpf_helpers.h`**: This file provides the "Tools." Because eBPF programs cannot call normal C libraries (like `printf`), the kernel provides "Helper Functions" (like `bpf_printk`) through this header.

---

## 2. Map Mastery: How We Store Data

eBPF programs are like "functions that forget everything" as soon as they finish. To remember things, they use **Maps**.

### The Two Most Common Types:
1.  **`BPF_MAP_TYPE_HASH`**: Like a Rust `HashMap` or a Python `dict`. You give it a Key (like an IP address) and it returns a Value (like a Counter). 
    - *Common use*: Rate limiting, where the IP is the key.
2.  **`BPF_MAP_TYPE_ARRAY`**: Like a standard array. It is indexed by a number (0, 1, 2...). 
    - *Common use*: Global configuration or huge shared memory blocks (like our 512MB array).

### How to use them (The Code):
```c
// 1. Finding something (Lookup)
struct my_data *val = bpf_map_lookup_elem(&my_map, &my_key);
if (!val) return 0; // ALWAYS check for NULL! The verifier REQUIRES this.

// 2. Saving something (Update)
bpf_map_update_elem(&my_map, &my_key, &new_value, BPF_ANY);
```

---

## 3. Core Struct Reference: The Context

Every eBPF program receives a **Context**—a pointer to the data it is supposed to process.

| Type | Name | Used In | What's inside? |
| :--- | :--- | :--- | :--- |
| `struct xdp_md` | **XDP** | NIC Driver | Raw packet bytes. Very fast but "bare bones." |
| `struct __sk_buff` | **TC** | Network Stack | The "Socket Buffer" (skb). Contains extra info like the interface index. |
| `struct sk_msg_md` | **SK_MSG** | Socket Layer | Data being sent by an app. It knows the IP and Port of the sender. |

---

## 4. Line-by-Line Breakdown: The Slot Interceptor

Let's look at the most important part of our pipeline in `sk_msg_intercept.bpf.c`:

```c
// [LINE 67] Take a ticket from the Deli machine
__u64 slot_seq = __sync_fetch_and_add(&state->head, 1);
```
> **Explanation**: Multiple CPU cores might be processing packets at the exact same microsecond. `__sync_fetch_and_add` ensures that only ONE core gets "Ticket #1", the next gets "Ticket #2", etc. It's perfectly safe and synchronized.

```c
// [LINE 68] Find which bucket to use
__u32 slot_idx = (__u32)(slot_seq & SLOT_MASK);
```
> **Explanation**: We only have 8,192 buckets (slots). The `& SLOT_MASK` (which is `8192-1`) uses bitwise math to "wrap around." If your ticket is 8,193, you go back to Bucket #0. This is how a **Circular Buffer** works.

```c
// [LINE 71] Look up the physical bucket in the 512MB RAM
void *dst = bpf_map_lookup_elem(&large_payload_array, &slot_idx);
if (!dst) return SK_PASS;
```
> **Explanation**: We ask the kernel: "Where is the start of Bucket #5 in memory?" It gives us a pointer `dst`. If the kernel says "I can't find it" (NULL), we let the packet pass through without capturing it (safety first!).

```c
// [LINE 79] The actual Copying
bpf_probe_read_kernel(dst, data_len, data);
```
> **Explanation**: This is the moment of capture. We copy `data_len` bytes from the application (`data`) into our shared memory bucket (`dst`). Because we always write at the start of the bucket, the eBPF Verifier knows we won't crash the system.

---

## 5. The "No-No" List for Beginners
1.  **NO Loops (mostly)**: The kernel doesn't want you to stall the system. You must unroll loops or keep them very simple.
2.  **NO Global Variables**: You must use Maps to store data that needs to persist.
3.  **NO Standard C Libraries**: No `malloc`, `free`, `printf`, or `memcpy`. You must use the BPF helpers like `bpf_probe_read_kernel`.
