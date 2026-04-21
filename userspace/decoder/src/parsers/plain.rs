//! Plaintext fallback parser.
//! Returns a bounded raw-text representation of any payload.

use crate::output::ParseStatus;
use anyhow::Result;

const MAX_PLAIN_DISPLAY: usize = 4096;

pub struct PlainResult {
    pub text: String,
    pub status: ParseStatus,
}

/// Decode bytes as UTF-8 (lossy). Truncates at `MAX_PLAIN_DISPLAY`.
pub fn parse(data: &[u8]) -> Result<PlainResult> {
    let text = String::from_utf8_lossy(data);
    let truncated = if text.len() > MAX_PLAIN_DISPLAY {
        format!(
            "{}…[truncated]",
            crate::text_utils::safe_truncate(&text, MAX_PLAIN_DISPLAY)
        )
    } else {
        text.into_owned()
    };
    Ok(PlainResult {
        text: truncated,
        status: ParseStatus::Ok,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse, MAX_PLAIN_DISPLAY};

    #[test]
    fn truncates_without_panicking_on_multibyte_boundary() {
        let mut data = vec![b'a'; MAX_PLAIN_DISPLAY - 1];
        data.extend_from_slice("é".as_bytes());
        data.extend_from_slice("tail".as_bytes());

        let parsed = parse(&data).expect("plain parse should succeed");
        assert!(parsed.text.contains("[truncated]"));
    }
}
