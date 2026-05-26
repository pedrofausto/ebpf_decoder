mod content_classifier;
mod format_router;
mod framing;
mod injection;
mod json_parser;
mod output;
mod parsers;
mod stream_state;
mod structs;
mod text_utils;

use anyhow::{Context, Result};
use clap::Parser;
use libbpf_rs::{MapCore, MapHandle, RingBufferBuilder};
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use tracing::info;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "config/intercept.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    info!("Starting eBPF Multi-Format Payload Decoder...");
    info!("Configuration file: {}", args.config);

    let config_path = Path::new(&args.config);
    let injection_rules = injection::load_rules_from_path(config_path)?;
    info!("Loaded {} decoder injection rules.", injection_rules.len());
    injection::set_rules(injection_rules);

    /* 1. Identify SIMD backend */
    #[cfg(target_feature = "avx2")]
    info!("JSON fast-path: simd-json (AVX2)");
    #[cfg(not(target_feature = "avx2"))]
    info!("JSON fast-path: serde-json (fallback)");

    /* 2. Map the Large Payload Array (arena) */
    let arena_pin_path = "/sys/fs/bpf/ebpf-json-pipeline/large_payload_array";
    if !Path::new(arena_pin_path).exists() {
        return Err(anyhow::anyhow!(
            "Array map not found at {}. Is the pipeline loaded?",
            arena_pin_path
        ));
    }

    let arena_map =
        MapHandle::from_pinned_path(arena_pin_path).context("Failed to open pinned Arena map")?;

    let info = arena_map.info().context("Failed to get Arena map info")?;
    let required_vma_start = info.info.map_extra as *mut libc::c_void;

    // Get actual arena size from MapInfo (max_entries * value_size)
    let arena_size = (info.info.max_entries as usize) * (info.info.value_size as usize);
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

    /* PAGE FAULT: pre-fault arena pages so sk_msg never triggers a fault */
    info!("Pre-faulting arena pages (512 MiB)...");
    unsafe {
        let mut ptr = arena_ptr as *mut u8;
        for _ in 0..(arena_size / 4096) {
            std::ptr::write_volatile(ptr, 0);
            ptr = ptr.add(4096);
        }
    }
    info!("Arena pages ready.");
    let (base, size) = (arena_ptr as usize, arena_size);
    json_parser::set_arena_layout(base, size).context("Failed to set arena layout")?;

    /* 3. Attach to the pinned RingBuffer map */
    let rb_pin_path = "/sys/fs/bpf/ebpf-json-pipeline/log_ringbuf";
    if !Path::new(rb_pin_path).exists() {
        return Err(anyhow::anyhow!(
            "RingBuffer map not found at {}. Is the pipeline loaded?",
            rb_pin_path
        ));
    }

    let rb_map =
        MapHandle::from_pinned_path(rb_pin_path).context("Failed to open pinned RingBuffer map")?;

    /* 4. Setup RingBuffer polling */
    let mut builder = RingBufferBuilder::new();
    builder.add(&rb_map, move |data| {
        if let Err(e) = json_parser::process_sample(data) {
            tracing::debug!("Error processing sample: {}", e);
        }
        0
    })?;

    let manager = builder.build()?;

    /* 5. Poll in a dedicated thread — avoids blocking Tokio executor */
    std::thread::spawn(move || loop {
        if let Err(e) = manager.poll(std::time::Duration::from_millis(100)) {
            eprintln!("RingBuffer polling error: {:?}", e);
            break;
        }
    });

    info!("Decoder active — intercepting traffic on configured ports. CTRL+C to stop.");

    tokio::signal::ctrl_c().await?;
    info!("Shutting down.");

    Ok(())
}
