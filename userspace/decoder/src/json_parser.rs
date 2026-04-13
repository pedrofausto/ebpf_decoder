use serde::{Deserialize, Serialize};
use anyhow::{Result, bail};
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

pub fn process_sample(data: &[u8]) -> Result<()> {
    if data.len() < std::mem::size_of::<log_event_t>() {
        bail!("Sample too small to contain log_event_t");
    }

    let event = unsafe { &*(data.as_ptr() as *const log_event_t) };
    let data_len = event.data_len as usize;

    if data_len == 0 || data_len > event.data.len() {
        bail!("Invalid data_len in log_event_t: {}", data_len);
    }

    let payload = &event.data[..data_len];

    let backend = get_parser_backend();
    let log = parse_log(payload, backend)?;
    
    /* 
     * In a production system, this would push to a secondary pipeline 
     * or storage backend. For now, we print to stdout.
     */
    println!("{}", serde_json::to_string(&log)?);
    
    Ok(())
}
