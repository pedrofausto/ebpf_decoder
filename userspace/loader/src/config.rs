use anyhow::{bail, Context, Result};
use libbpf_rs::MapCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

// ---- Kernel-side map value struct (must match kernel/common/structs.h port_proto_config_t) ----
// Format encoding: Json=0, Syslog=1, Html=2, PlainText=3
// Action encoding: Decode=0, Drop=1, Pass=2, Check=3
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct PortProtoKey {
    port: u16,
    proto: u8,
    _padding: u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct PortProtoConfig {
    format: u8,
    action: u8,
    _pad: [u8; 2],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InterceptConfig {
    pub intercept: Vec<InterceptEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InterceptEntry {
    pub port: u16,
    pub protocol: String,
    /// Required: payload format expected on this (port, protocol) pair.
    pub format: PayloadFormat,
    /// Required: action for this entry (decode|drop|pass|check).
    pub action: InterceptAction,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PayloadFormat {
    Json,
    Syslog,
    Html,
    PlainText,
}

impl PayloadFormat {
    pub fn as_u8(self) -> u8 {
        match self {
            PayloadFormat::Json => 0,
            PayloadFormat::Syslog => 1,
            PayloadFormat::Html => 2,
            PayloadFormat::PlainText => 3,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InterceptAction {
    Decode,
    Drop,
    Pass,
    Check,
}

impl InterceptAction {
    pub fn as_u8(self) -> u8 {
        match self {
            InterceptAction::Decode => 0,
            InterceptAction::Drop => 1,
            InterceptAction::Pass => 2,
            InterceptAction::Check => 3,
        }
    }
}

pub fn update_port_filter_map(map: &dyn MapCore, config_path: &Path) -> Result<()> {
    let content = fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config file at {:?}", config_path))?;
    let config: InterceptConfig =
        serde_yaml::from_str(&content).context("Failed to parse YAML configuration")?;

    let mut seen: HashSet<(u16, u8)> = HashSet::new();
    for entry in config.intercept {
        let proto = match entry.protocol.to_lowercase().as_str() {
            "tcp" => 6u8,
            "udp" => 17u8,
            _ => {
                eprintln!("Unsupported protocol: {}", entry.protocol);
                continue;
            }
        };

        let key_tuple = (entry.port, proto);
        if !seen.insert(key_tuple) {
            bail!(
                "Duplicate intercept entry for port={} protocol={}",
                entry.port,
                entry.protocol
            );
        }

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

        // Write the full config struct (format + action) as the map value
        let value = PortProtoConfig {
            format: entry.format.as_u8(),
            action: entry.action.as_u8(),
            _pad: [0; 2],
        };
        let value_bytes = unsafe {
            std::slice::from_raw_parts(
                &value as *const _ as *const u8,
                std::mem::size_of::<PortProtoConfig>(),
            )
        };

        map.update(key_bytes, value_bytes, libbpf_rs::MapFlags::ANY)
            .context("Failed to update port_proto_filter map")?;

        tracing::debug!(
            "  port={} proto={} format={:?} action={:?}",
            entry.port,
            entry.protocol,
            entry.format,
            entry.action
        );
    }

    Ok(())
}
