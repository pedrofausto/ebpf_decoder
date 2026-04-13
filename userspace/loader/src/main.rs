mod loader;
mod config;

use anyhow::{Result, Context};
use clap::Parser;
use libbpf_rs::MapCore;
use notify::{Watcher, RecursiveMode, EventKind};
use std::path::Path;
use tracing::{info, error};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "ens33")]
    interface: String,

    #[arg(short, long, default_value = "config/intercept.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    info!("Starting eBPF JSON Pipeline Loader...");
    info!("Target interface: {}", args.interface);
    info!("Configuration file: {}", args.config);

    /* 1. Initialize BPF Pipeline Access */
    let pin_path = "/sys/fs/bpf/ebpf-json-pipeline/port_proto_filter";
    
    // Attempt to open the pinned map first (Passive Mode)
    let (port_filter_map, pipeline): (Box<dyn libbpf_rs::MapCore>, Option<loader::BpfPipeline>) = if Path::new(pin_path).exists() {
        info!("Existing pinned pipeline detected. Using shared map at {}", pin_path);
        let map = libbpf_rs::MapHandle::from_pinned_path(pin_path)?;
        (Box::new(map), None)
    } else {
        info!("No pinned pipeline found. Initializing BPF Pipeline...");
        let p = loader::BpfPipeline::load_and_attach(&args.interface)?;
        info!("BPF programs attached to {}", args.interface);
        
        // Find it in the newly loaded object
        let map = p.xdp_obj.maps()
            .find(|m| m.name() == "port_proto_filter")
            .ok_or_else(|| anyhow::anyhow!("port_proto_filter map not found in XDP object"))?;
        
        // We need to move the pipeline handle out to keep programs alive.
        // MapImpl is not Clone, so we create a MapHandle from its ID.
        let info = map.info().context("Failed to get map info")?;
        let map_handle = libbpf_rs::MapHandle::from_map_id(info.info.id)?;
        (Box::new(map_handle), Some(p))
    };

    /* 2. Initial Config Load */
    let config_path = Path::new(&args.config);
    if !config_path.exists() {
        error!("Config file not found: {:?}", config_path);
        return Err(anyhow::anyhow!("Config file missing"));
    }

    info!("Applying initial configuration...");
    config::update_port_filter_map(&*port_filter_map, config_path)?;
    info!("Initial configuration applied.");

    // If we just loaded the pipeline, confirm deployment to disarm the safety timer
    if pipeline.is_some() {
        loader::BpfPipeline::confirm();
    }

    /* 3. Setup File Watcher */
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                let _ = tx.blocking_send(());
            }
        }
    })?;

    watcher.watch(config_path, RecursiveMode::NonRecursive)?;

    /* 4. Setup CTRL+C for graceful shutdown */
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel(1);
    ctrlc::set_handler(move || {
        let _ = shutdown_tx.blocking_send(());
    })?;

    info!("Pipeline configuration watcher active. Press CTRL+C to stop.");

    loop {
        tokio::select! {
            _ = rx.recv() => {
                info!("Configuration change detected! Reloading...");
                if let Err(e) = config::update_port_filter_map(&*port_filter_map, config_path) {
                    error!("Failed to reload configuration: {}", e);
                } else {
                    info!("Configuration successfully reloaded.");
                }
            }
            _ = shutdown_rx.recv() => {
                info!("Shutting down...");
                break;
            }
        }
    }

    Ok(())
}
