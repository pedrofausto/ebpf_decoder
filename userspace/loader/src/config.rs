use anyhow::{Context, Result};
use libbpf_rs::MapCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct PortProtoKey {
    port: u16,
    proto: u8,
    _padding: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InterceptConfig {
    pub intercept: Vec<InterceptEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InterceptEntry {
    pub port: u16,
    pub protocol: String,
}

pub fn update_port_filter_map(map: &dyn MapCore, config_path: &Path) -> Result<()> {
    let content = fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config file at {:?}", config_path))?;
    let config: InterceptConfig = serde_yaml::from_str(&content)
        .context("Failed to parse YAML configuration")?;

    /* 1. Clear existing map (brute force for small maps, or we could handle diffs) */
    /* Note: libbpf-rs doesn't have a clear() for hash maps easily, 
     * but we can iterate and delete or just overwrite. 
     * For now, we'll overwrite and rely on the fact that we can't easily 'delete' 
     * without knowing all keys. In a production system, we'd use a better sync logic.
     */

    for entry in config.intercept {
        let proto = match entry.protocol.to_lowercase().as_str() {
            "tcp" => 6,
            "udp" => 17,
            _ => {
                eprintln!("Unsupported protocol: {}", entry.protocol);
                continue;
            }
        };

        let key = PortProtoKey {
            port: entry.port,
            proto,
            _padding: 0,
        };

        let key_bytes = unsafe {
            std::slice::from_raw_parts(
                &key as *const _ as *const u8,
                std::mem::size_of::<PortProtoKey>(),
            )
        };
        
        let value: u8 = 1;
        map.update(key_bytes, &[value], libbpf_rs::MapFlags::ANY)
            .context("Failed to update port_proto_filter map")?;
    }

    Ok(())
}
