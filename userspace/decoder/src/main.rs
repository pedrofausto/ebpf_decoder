mod json_parser;
mod structs;

use anyhow::{Context, Result};
use libbpf_rs::{RingBufferBuilder, MapHandle};
use std::path::Path;
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

    /* 2. Attach to the pinned RingBuffer map */
    let rb_pin_path = "/sys/fs/bpf/ebpf-json-pipeline/log_ringbuf";
    if !Path::new(rb_pin_path).exists() {
        return Err(anyhow::anyhow!(
            "RingBuffer map not found at {}. Is the pipeline loaded?", 
            rb_pin_path
        ));
    }

    let rb_map = MapHandle::from_pinned_path(rb_pin_path)
        .context("Failed to open pinned RingBuffer map")?;

    /* 3. Setup RingBuffer polling */
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
