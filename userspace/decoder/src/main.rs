mod json_parser;
mod structs;
mod test_map_fd;

use anyhow::{Context, Result};
use libbpf_rs::{RingBufferBuilder, MapHandle, MapCore};
use std::path::Path;
use std::os::fd::{AsFd, AsRawFd};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting eBPF JSON Decoder...");

    /* 1. Identify SIMD backend */
    #[cfg(target_feature = "avx2")]
    info!("Using JSON backend: \"simd-json (AVX2)\"");
    #[cfg(not(target_feature = "avx2"))]
    info!("Using JSON backend: \"serde-json (Fallback)\"");

    /* 2. Map the Large Payload Array */
    let arena_pin_path = "/sys/fs/bpf/ebpf-json-pipeline/large_payload_array";
    if !Path::new(arena_pin_path).exists() {
        return Err(anyhow::anyhow!(
            "Array map not found at {}. Is the pipeline loaded?", 
            arena_pin_path
        ));
    }

    let arena_map = MapHandle::from_pinned_path(arena_pin_path)
        .context("Failed to open pinned Arena map")?;

    let info = arena_map.info().context("Failed to get Arena map info")?;
    let required_vma_start = info.info.map_extra as *mut libc::c_void;

    // The arena is 128 * 1024 pages (512MiB) as defined in kernel/common/maps.h
    let arena_size = 512 * 1024 * 1024; 
    let arena_ptr = unsafe {
        libc::mmap(
            required_vma_start,
            arena_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_FIXED,
            arena_map.as_fd().as_raw_fd(),
            0,
        )
    };

    if arena_ptr == libc::MAP_FAILED {
        return Err(anyhow::anyhow!(
            "Failed to mmap large_payload_array: {}", 
            std::io::Error::last_os_error()
        ));
    }
    
    info!("Mapped large_payload_array at {:p}", arena_ptr);

    /* PAGE FAULT: Eagerly instantiate the physical memory pages so the Kernel (sk_msg)
     * does not cause a fault (which is forbidden in non-sleepable contexts!)
     */
    info!("Pre-allocating physical arena pages (page-faulting 512MB)...");
    unsafe {
        let mut ptr = arena_ptr as *mut u8;
        for _ in 0..(arena_size / 4096) {
            std::ptr::write_volatile(ptr, 0); // Force fault
            ptr = ptr.add(4096);
        }
    }
    info!("Array physical pages successfully instantiated.");
    json_parser::set_arena_base(arena_ptr as usize);

    /* 3. Attach to the pinned RingBuffer map */
    let rb_pin_path = "/sys/fs/bpf/ebpf-json-pipeline/log_ringbuf";
    if !Path::new(rb_pin_path).exists() {
        return Err(anyhow::anyhow!(
            "RingBuffer map not found at {}. Is the pipeline loaded?", 
            rb_pin_path
        ));
    }

    let rb_map = MapHandle::from_pinned_path(rb_pin_path)
        .context("Failed to open pinned RingBuffer map")?;

    /* 4. Setup RingBuffer polling */
    let mut builder = RingBufferBuilder::new();
    builder.add(&rb_map, move |data| {
        if let Err(e) = json_parser::process_sample(data) {
            eprintln!("Error processing JSON sample: {}", e);
        }
        0 /* Continue polling */
    })?;

    let manager = builder.build()?;

    /* 4. Run polling in a dedicated thread to avoid blocking the Tokio executor */
    std::thread::spawn(move || {
        loop {
            if let Err(e) = manager.poll(std::time::Duration::from_millis(100)) {
                eprintln!("RingBuffer polling error: {:?}", e);
                break;
            }
        }
    });

    info!("Polling for intercepted logs. Press CTRL+C to stop.");

    /* 5. Keep the main task alive until interrupted */
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}
