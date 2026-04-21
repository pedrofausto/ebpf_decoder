//! Normalized output envelope for all decoder formats.

use crate::structs::EventFormat;
use serde::{Deserialize, Serialize};

/// End result emitted (stdout JSON line) for every decoded event.
#[derive(Debug, Serialize, Deserialize)]
pub struct DecodedEvent {
    /// End-to-end latency from kernel timestamp to userspace decode.
    pub latency: String,
    /// Detected / confirmed payload format.
    pub format: DetectedFormat,
    /// How the payload reached userspace.
    pub source: PayloadSource,
    /// Whether parsing succeeded.
    pub status: ParseStatus,
    /// Action for this event (from kernel decision).
    pub action: EventAction,
    /// Userspace content classification result for the emitted frame.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<ClassificationMetadata>,
    /// Parsed fields or bounded raw text, depending on format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetectedFormat {
    Json,
    Syslog,
    Html,
    PlainText,
    Unknown,
}

/// Action mirrored from kernel decision — used for emit gating.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EventAction {
    Decode,
    Drop,
    Pass,
    Check,
}

/// Convert kernel EventFormat into DetectedFormat for router dispatch.
pub fn format_from_event(ef: EventFormat) -> DetectedFormat {
    match ef {
        EventFormat::Json => DetectedFormat::Json,
        EventFormat::Syslog => DetectedFormat::Syslog,
        EventFormat::Html => DetectedFormat::Html,
        EventFormat::PlainText => DetectedFormat::PlainText,
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PayloadSource {
    RingbufInline,
    Arena,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParseStatus {
    Ok,
    ParseError,
    TooLarge,
    Unsupported,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ClassificationMetadata {
    pub verdict: ClassificationVerdict,
    pub observed: ContentKind,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationVerdict {
    Match,
    Mismatch,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    Json,
    Syslog,
    Html,
    PlainText,
    Elf,
    Pe,
    Pdf,
    Zip,
    Gzip,
    Png,
    Jpeg,
    Binary,
    Unknown,
}

/// Format a latency duration (nanoseconds) into a human-readable string.
pub fn format_latency(ns: u64) -> String {
    let mut remaining = ns;
    let mut s = String::with_capacity(32);

    let minutes = remaining / 60_000_000_000;
    if minutes > 0 {
        s.push_str(&format!("{}m", minutes));
        remaining %= 60_000_000_000;
    }
    let seconds = remaining / 1_000_000_000;
    if seconds > 0 || !s.is_empty() {
        s.push_str(&format!("{}s", seconds));
        remaining %= 1_000_000_000;
    }
    let ms = remaining / 1_000_000;
    if ms > 0 || !s.is_empty() {
        s.push_str(&format!("{}ms", ms));
        remaining %= 1_000_000;
    }
    let us = remaining / 1_000;
    if us > 0 || s.is_empty() {
        s.push_str(&format!("{}us", us));
    }
    s
}

/// Emit a decoded event as a single JSON line to stdout.
pub fn emit(event: &DecodedEvent) {
    if let Ok(line) = serde_json::to_string(event) {
        println!("{}", line);
    }
}
