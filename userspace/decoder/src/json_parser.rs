use serde::{Deserialize, Serialize};
use anyhow::{Result, bail};
use crate::structs::log_event_t;

#[derive(Debug, Serialize, Deserialize)]
pub struct GenericLog {
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

pub enum ParserBackend {
    SimdJson,
    SerdeJson,
}

/// Select parser at startup based on CPU feature detection.
pub fn detect_parser_capability() -> ParserBackend {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            return ParserBackend::SimdJson;
        }
    }
    ParserBackend::SerdeJson
}

pub fn parse_log(data: &[u8], backend: &ParserBackend) -> Result<GenericLog> {
    match backend {
        ParserBackend::SimdJson => {
            /* simd_json::from_slice require mutable borrow */
            let mut buf = data.to_vec();
            Ok(simd_json::from_slice(&mut buf)?)
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

    let backend = detect_parser_capability();
    let log = parse_log(payload, &backend)?;
    
    /* 
     * In a production system, this would push to a secondary pipeline 
     * or storage backend. For now, we print to stdout.
     */
    println!("{}", serde_json::to_string(&log)?);
    
    Ok(())
}
