use serde::{Deserialize, Serialize};
use anyhow::{Result, bail, Context};
use crate::structs::log_event_t;
use std::cell::RefCell;
use std::sync::OnceLock;

const MAX_JSON_SIZE: usize = 1024 * 1024; // 1MB limit

#[derive(Debug, Serialize, Deserialize)]
pub struct GenericLog {
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

pub enum ParserBackend {
    SimdJson,
    SerdeJson,
}

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
    static SIMD_BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(MAX_JSON_SIZE));
}

pub fn parse_log(data: &[u8], backend: &ParserBackend) -> Result<GenericLog> {
    if data.len() > MAX_JSON_SIZE {
        bail!("JSON payload too large: {} bytes", data.len());
    }

    match backend {
        ParserBackend::SimdJson => {
            SIMD_BUF.with(|buf_cell| {
                let mut buf = buf_cell.borrow_mut();
                buf.clear();
                buf.extend_from_slice(data);
                let res: GenericLog = simd_json::from_slice(&mut buf)?;
                buf.clear(); // Robust cleanup
                Ok(res)
            })
        }
        ParserBackend::SerdeJson => {
            let res: GenericLog = serde_json::from_slice(data)?;
            Ok(res)
        }
    }
}

static ARENA_BASE: OnceLock<usize> = OnceLock::new();

pub fn set_arena_base(ptr: usize) {
    let _ = ARENA_BASE.set(ptr);
}

pub fn process_sample(data: &[u8]) -> Result<()> {
    if data.len() < std::mem::size_of::<log_event_t>() {
        bail!("Sample too small to contain log_event_t");
    }

    // Replace unsafe pointer cast with standard field access from struct
    let event: &log_event_t = unsafe { &*(data.as_ptr() as *const log_event_t) };
    let data_len = event.data_len as usize;

    if data_len == 0 {
        bail!("Invalid data_len (0) in log_event_t");
    }
    
    if data_len > MAX_JSON_SIZE {
        bail!("Event data_len too large: {}", data_len);
    }

    let backend = get_parser_backend();
    
    let result = if event.is_arena_ptr == 1 {
        let base_ptr = *ARENA_BASE.get().context("Arena base pointer not set")?;
        
        let arena_size = 4 * 1024 * 1024 * 1024;
        let offset = event.arena_offset as usize;
        
        if offset + data_len > arena_size {
            bail!("Arena access out of bounds");
        }

        let ptr = (base_ptr + offset) as *const u8;
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
            if let Ok(out) = serde_json::to_string(&log) {
                println!("{}", out);
            }
        }
        Err(e) => {
            tracing::debug!("Failed to parse JSON: {}", e);
        }
    }
    
    Ok(())
}
