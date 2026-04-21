//! Format router: determines payload type and dispatches to the correct parser.
//!
//! Detection priority:
//!   1. Config hint (port/protocol derived, passed by caller)
//!   2. Content sniffing (cheap byte-level heuristics)
//!   3. Fallback → PlainText

use serde_json::Value;
use crate::output::{DetectedFormat, ParseStatus};
use crate::parsers::{json, syslog, html, plain};

/// Decoded payload ready for output emission.
pub struct RouterResult {
    pub format: DetectedFormat,
    pub status: ParseStatus,
    pub fields: Option<Value>,
}

/// Decode `payload` using `hint` if provided, otherwise sniff content.
/// When `hint` is present, parsing is strict for that format (no plaintext fallback).
pub fn decode_payload(payload: &[u8], hint: Option<DetectedFormat>) -> RouterResult {
    if let Some(format) = hint {
        return match format {
            DetectedFormat::Json => route_json_strict(payload),
            DetectedFormat::Syslog => route_syslog_strict(payload),
            DetectedFormat::Html => route_html_strict(payload),
            DetectedFormat::PlainText => route_plain(payload),
            DetectedFormat::Unknown => RouterResult {
                format: DetectedFormat::Unknown,
                status: ParseStatus::Unsupported,
                fields: None,
            },
        };
    }

    let format = sniff(payload);
    match format {
        DetectedFormat::Json => route_json_lenient(payload),
        DetectedFormat::Syslog => route_syslog_lenient(payload),
        DetectedFormat::Html => route_html_lenient(payload),
        DetectedFormat::PlainText | DetectedFormat::Unknown => route_plain(payload),
    }
}

fn sniff(data: &[u8]) -> DetectedFormat {
    // Trim leading whitespace
    let trimmed = data.iter().position(|b| !b.is_ascii_whitespace())
        .map(|i| &data[i..])
        .unwrap_or(data);

    if trimmed.is_empty() {
        return DetectedFormat::Unknown;
    }

    // JSON: starts with { or [
    if matches!(trimmed[0], b'{' | b'[') {
        return DetectedFormat::Json;
    }

    // Syslog: starts with <NNN>
    if trimmed[0] == b'<' {
        if let Some(end) = trimmed.iter().position(|&b| b == b'>') {
            if end >= 2 && end <= 5 && trimmed[1..end].iter().all(|b| b.is_ascii_digit()) {
                return DetectedFormat::Syslog;
            }
        }
    }

    // HTML: look for <!DOCTYPE, <html, or <HTTP response
    let prefix = std::str::from_utf8(&trimmed[..trimmed.len().min(64)])
        .unwrap_or("")
        .to_lowercase();
    if prefix.starts_with("<!doctype") || prefix.starts_with("<html") || prefix.contains("<head") {
        return DetectedFormat::Html;
    }

    DetectedFormat::PlainText
}

fn route_json_strict(payload: &[u8]) -> RouterResult {
    let backend = json::get_parser_backend();
    match json::parse(payload, backend) {
        Ok(log) => RouterResult {
            format: DetectedFormat::Json,
            status: ParseStatus::Ok,
            fields: serde_json::to_value(&log).ok(),
        },
        Err(_) => RouterResult {
            format: DetectedFormat::Json,
            status: ParseStatus::ParseError,
            fields: None,
        },
    }
}

fn route_json_lenient(payload: &[u8]) -> RouterResult {
    let backend = json::get_parser_backend();
    match json::parse(payload, backend) {
        Ok(log) => RouterResult {
            format: DetectedFormat::Json,
            status: ParseStatus::Ok,
            fields: serde_json::to_value(&log).ok(),
        },
        Err(_) => route_plain(payload),
    }
}

fn route_syslog_strict(payload: &[u8]) -> RouterResult {
    match syslog::parse(payload) {
        Ok(r) => RouterResult {
            format: DetectedFormat::Syslog,
            status: ParseStatus::Ok,
            fields: Some(r.fields),
        },
        Err(_) => RouterResult {
            format: DetectedFormat::Syslog,
            status: ParseStatus::ParseError,
            fields: None,
        },
    }
}

fn route_syslog_lenient(payload: &[u8]) -> RouterResult {
    match syslog::parse(payload) {
        Ok(r) => RouterResult {
            format: DetectedFormat::Syslog,
            status: ParseStatus::Ok,
            fields: Some(r.fields),
        },
        Err(_) => route_plain(payload), // graceful fallback
    }
}

fn route_html_strict(payload: &[u8]) -> RouterResult {
    match html::parse(payload) {
        Ok(r) => RouterResult {
            format: DetectedFormat::Html,
            status: ParseStatus::Ok,
            fields: Some(r.fields),
        },
        Err(_) => RouterResult {
            format: DetectedFormat::Html,
            status: ParseStatus::ParseError,
            fields: None,
        },
    }
}

fn route_html_lenient(payload: &[u8]) -> RouterResult {
    match html::parse(payload) {
        Ok(r) => RouterResult {
            format: DetectedFormat::Html,
            status: ParseStatus::Ok,
            fields: Some(r.fields),
        },
        Err(_) => route_plain(payload),
    }
}

fn route_plain(payload: &[u8]) -> RouterResult {
    match plain::parse(payload) {
        Ok(r) => RouterResult {
            format: DetectedFormat::PlainText,
            status: r.status,
            fields: Some(Value::String(r.text)),
        },
        Err(_) => RouterResult {
            format: DetectedFormat::Unknown,
            status: ParseStatus::ParseError,
            fields: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::decode_payload;
    use crate::output::{DetectedFormat, ParseStatus};

    #[test]
    fn falls_back_to_plain_when_json_parse_fails() {
        let payload = br#"{"unterminated": "value""#;
        let result = decode_payload(payload, None);
        assert_eq!(result.format, DetectedFormat::PlainText);
    }

    #[test]
    fn hinted_json_is_strict_and_does_not_fallback_to_plain() {
        let payload = br#"{"unterminated": "value""#;
        let result = decode_payload(payload, Some(DetectedFormat::Json));
        assert_eq!(result.format, DetectedFormat::Json);
        assert!(matches!(result.status, ParseStatus::ParseError));
    }
}
