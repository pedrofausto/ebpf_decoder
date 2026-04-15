use serde::{Deserialize, Serialize};
use anyhow::{Result, bail, Context};
use crate::structs::log_event_t;
use std::cell::RefCell;
use std::sync::OnceLock;

#[derive(Debug, Serialize, Deserialize)]
pub struct GenericLog {
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

pub enum ParserBackend {
    SimdJson,
    SerdeJson,
}

/// Cache the parser capability detection so it only runs once
pub fn get_parser_backend() -> &'static ParserBackend {
    static BACKEND: OnceLock<ParserBackend> = OnceLock::new();
    BACKEND.get_or_init(|| {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx2") {
                return ParserBackend::SimdJson;
            }
        }
        ParserBackend::SerdeJson
    })
}

thread_local! {
    // Pre-allocate enough capacity for the maximum chunk size (1024 bytes)
    // This eliminates the allocation overhead on every single packet.
    static SIMD_BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(1024));
}

pub fn parse_log(data: &[u8], backend: &ParserBackend) -> Result<GenericLog> {
    match backend {
        ParserBackend::SimdJson => {
            /* simd_json::from_slice requires a mutable slice. 
               We use a thread-local buffer to avoid allocating a new Vec on every packet. */
            SIMD_BUF.with(|buf_cell| {
                let mut buf = buf_cell.borrow_mut();
                buf.clear();
                buf.extend_from_slice(data);
                Ok(simd_json::from_slice(&mut buf)?)
            })
        }
        ParserBackend::SerdeJson => {
            Ok(serde_json::from_slice(data)?)
        }
    }
}

static ARENA_BASE: OnceLock<usize> = OnceLock::new();

/// Set the base pointer for the BPF_MAP_TYPE_ARENA.
/// This pointer is used to resolve absolute addresses from offsets.
pub fn set_arena_base(ptr: usize) {
    let _ = ARENA_BASE.set(ptr);
}

pub fn process_sample(data: &[u8]) -> Result<()> {
    if data.len() < std::mem::size_of::<log_event_t>() {
        bail!("Sample too small to contain log_event_t");
    }

    let event = unsafe { &*(data.as_ptr() as *const log_event_t) };
    let data_len = event.data_len as usize;

    if data_len == 0 {
        bail!("Invalid data_len (0) in log_event_t");
    }

    let backend = get_parser_backend();
    
    let result = if event.is_arena_ptr == 1 {
        let base_ptr = *ARENA_BASE.get().context("Arena base pointer not set")?;
        
        // Safety: Bounds check against the 4GB mmap region to prevent out-of-bounds reads
        // if the kernel provides a corrupted offset or length.
        let arena_size = 4 * 1024 * 1024 * 1024;
        let offset = event.arena_offset as usize;
        
        if offset + data_len > arena_size {
            bail!("Arena access out of bounds: offset {} + len {} > {}", offset, data_len, arena_size);
        }

        let ptr = (base_ptr + offset) as *const u8;
        
        // Safety: The BPF program uses a circular buffer strategy within the Arena.
        // Data is valid for the duration of this call.
        let payload = unsafe { std::slice::from_raw_parts(ptr, data_len) };
        
        parse_log(payload, backend)
    } else {
        if data_len > event.data.len() {
            bail!("Invalid data_len ({}) in log_event_t (max {})", data_len, event.data.len());
        }
        let payload = &event.data[..data_len];
        parse_log(payload, backend)
    };

    match result {
        Ok(log) => {
            /* 
             * In a production system, this would push to a secondary pipeline 
             * or storage backend. For now, we print to stdout.
             */
            if let Ok(out) = serde_json::to_string(&log) {
                println!("{}", out);
            }
        }
        Err(e) => {
            // TCP fragmentation or 1024-byte truncation means we frequently see partial JSON.
            // Log this at the debug level instead of failing the event processor.
            tracing::debug!("Failed to parse JSON (fragmented or non-JSON payload): {}", e);
        }
    }
    
    Ok(())
}
