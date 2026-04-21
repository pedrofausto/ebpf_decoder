//! JSON payload parser (AVX2 simd-json fast path + serde-json fallback).

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::sync::OnceLock;

pub const MAX_JSON_SIZE: usize = 1024 * 1024; // 1 MB hard cap

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

/// Parse raw bytes as JSON. Enforces `MAX_JSON_SIZE`.
pub fn parse(data: &[u8], backend: &ParserBackend) -> Result<GenericLog> {
    if data.len() > MAX_JSON_SIZE {
        anyhow::bail!(
            "JSON payload too large: {} bytes (limit: {})",
            data.len(),
            MAX_JSON_SIZE
        );
    }

    match backend {
        ParserBackend::SimdJson => SIMD_BUF.with(|buf_cell| {
            let mut buf = buf_cell.borrow_mut();
            buf.clear();
            buf.extend_from_slice(data);
            let res: GenericLog = simd_json::from_slice(&mut buf)
                .map_err(|e| anyhow::anyhow!("SIMD-JSON parse failed: {}", e))?;
            buf.clear();
            Ok(res)
        }),
        ParserBackend::SerdeJson => {
            let res: GenericLog = serde_json::from_slice(data)
                .map_err(|e| anyhow::anyhow!("serde-json parse failed: {}", e))?;
            Ok(res)
        }
    }
}
