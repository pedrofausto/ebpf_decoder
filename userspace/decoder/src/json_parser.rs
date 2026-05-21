//! `json_parser.rs` — event dispatcher (retains original public API for compatibility).
//!
//! All format-specific logic has moved to `parsers/` and `format_router`.
//! This module is the ringbuf callback entry point. It reads action/format from
//! the kernel-populated log_event_t and applies the action gate before decoding.

use anyhow::{bail, Context, Result};
use std::sync::{Mutex, OnceLock};

use crate::content_classifier::classify;
use crate::format_router::decode_payload;
use crate::injection;
use crate::output::{
    self, format_from_event, ClassificationVerdict, DecodedEvent, DetectedFormat,
    EventAction as OutputAction, ParseStatus, PayloadSource,
};
use crate::stream_state::{StreamContext, StreamState};
use crate::structs::{log_event_t, EventAction, EventFormat};

pub const MAX_EVENT_PAYLOAD_SIZE: usize = 1024 * 1024; // 1MB global cap

static ARENA_BASE: OnceLock<usize> = OnceLock::new();
static ARENA_SIZE: OnceLock<usize> = OnceLock::new();
static STREAM_STATE: OnceLock<Mutex<StreamState>> = OnceLock::new();

pub fn set_arena_layout(ptr: usize, size: usize) {
    if size > isize::MAX as usize {
        panic!("Arena size exceeds isize::MAX, which is required for safe slice construction.");
    }
    if ptr.checked_add(size).is_none() {
        panic!("Arena ptr + size overflows usize.");
    }
    let _ = ARENA_BASE.set(ptr);
    let _ = ARENA_SIZE.set(size);
}

/// Called for every ringbuf event. Validates struct, extracts payload, routes to decoder.
pub fn process_sample(data: &[u8]) -> Result<()> {
    // --- Struct size guard ---
    if data.len() < std::mem::size_of::<log_event_t>() {
        bail!("Sample too small to contain log_event_t");
    }

    let event: &log_event_t = unsafe { &*(data.as_ptr() as *const log_event_t) };
    let data_len = event.data_len as usize;

    if data_len == 0 {
        bail!("Invalid data_len (0) in log_event_t");
    }
    if data_len > MAX_EVENT_PAYLOAD_SIZE {
        bail!("Event data_len too large: {} bytes", data_len);
    }

    // --- Decode action/format from kernel metadata ---
    let event_action = EventAction::from_u8(event.action);
    let event_format = EventFormat::from_u8(event.format);

    // Action gate: kernel enforces drop/pass/check at TC/XDP level.
    // These guards are defense-in-depth for misconfiguration only.
    match event_action {
        EventAction::Drop | EventAction::Pass | EventAction::Check => {
            tracing::debug!(
                "Unexpected action={:?} reached userspace (kernel should have gated)",
                event_action
            );
            return Ok(());
        }
        EventAction::Decode => {}
    }

    // --- Payload extraction ---
    let (payload, source) = if event.is_arena_ptr == 1 {
        let base_ptr = *ARENA_BASE.get().context("Arena base pointer not set")?;
        let arena_size = *ARENA_SIZE.get().context("Arena size not set")?;
        let offset = event.arena_offset as usize;

        let end = offset
            .checked_add(data_len)
            .context("Arena offset + len overflow")?;

        // Safe slice construction: arena layout was validated in set_arena_layout
        let arena_slice = unsafe { std::slice::from_raw_parts(base_ptr as *const u8, arena_size) };

        let slice = arena_slice.get(offset..end).context(format!(
            "Arena access out of bounds: end={} > size={}",
            end, arena_size
        ))?;

        (slice, PayloadSource::Arena)
    } else {
        if data_len > event.data.len() {
            bail!(
                "Invalid data_len ({}) > inline buffer ({})",
                data_len,
                event.data.len()
            );
        }
        (&event.data[..data_len], PayloadSource::RingbufInline)
    };

    // --- Latency ---
    use nix::time::{clock_gettime, ClockId};
    let ts = clock_gettime(ClockId::CLOCK_MONOTONIC)
        .map_err(|e| anyhow::anyhow!("clock_gettime failed: {}", e))?;
    let now_ns = ts.tv_sec() as u64 * 1_000_000_000 + ts.tv_nsec() as u64;
    let latency_ns = now_ns.saturating_sub(event.ts_ns);

    // --- Emit: only for ACTION_DECODE; ACTION_CHECK skips output ---
    let output_action = match event_action {
        EventAction::Decode => OutputAction::Decode,
        EventAction::Check => OutputAction::Check,
        EventAction::Pass => OutputAction::Pass,
        EventAction::Drop => OutputAction::Drop,
    };

    // --- Stream framing ---
    let expected_format = format_from_event(event_format);
    let frames = {
        let mut stream_state = STREAM_STATE
            .get_or_init(|| Mutex::new(StreamState::new()))
            .lock()
            .map_err(|_| anyhow::anyhow!("stream state lock poisoned"))?;
        stream_state.frames_for_event(
            payload,
            StreamContext {
                conn_id: event.conn_id,
                format: expected_format,
                source,
                now_ns,
            },
        )?
    };

    let injection_rule = injection::rule_for(event.dst_port, event.protocol);
    for frame in frames {
        let decoded = decode_frame(
            &frame,
            expected_format,
            source,
            output_action,
            latency_ns,
            injection_rule,
        );

        match (decoded.status, decoded.action) {
            (ParseStatus::Ok, OutputAction::Decode) => output::emit(&decoded),
            (ParseStatus::Ok, OutputAction::Check) => {
                tracing::debug!("CHECK pass: format={:?}", decoded.format);
            }
            _ => tracing::debug!("Decode failed or non-emit action: {:?}", decoded.status),
        }
    }

    Ok(())
}

fn decode_frame(
    frame: &[u8],
    expected_format: DetectedFormat,
    source: PayloadSource,
    output_action: OutputAction,
    latency_ns: u64,
    injection_rule: Option<&injection::InjectionRule>,
) -> DecodedEvent {
    let classification = classify(frame, expected_format);

    if classification.verdict == ClassificationVerdict::Mismatch {
        let mut decoded = DecodedEvent {
            latency: output::format_latency(latency_ns),
            format: expected_format,
            source,
            status: ParseStatus::ParseError,
            action: output_action,
            classification: Some(classification.metadata()),
            inject: None,
            fields: None,
        };
        injection::apply(&mut decoded, injection_rule);
        return decoded;
    }

    // Route strictly by expected format from kernel metadata, not sniff-first.
    let result = decode_payload(frame, Some(expected_format));

    let mut decoded = DecodedEvent {
        latency: output::format_latency(latency_ns),
        format: result.format,
        source,
        status: result.status,
        action: output_action,
        classification: Some(classification.metadata()),
        inject: None,
        fields: result.fields,
    };
    injection::apply(&mut decoded, injection_rule);
    decoded
}

#[cfg(test)]
mod tests {
    use super::decode_frame;
    use crate::output::{
        ClassificationVerdict, DetectedFormat, EventAction as OutputAction, ParseStatus,
        PayloadSource,
    };

    #[test]
    fn classifier_mismatch_blocks_hinted_json_output() {
        let decoded = decode_frame(
            b"\x7fELFbad",
            DetectedFormat::Json,
            PayloadSource::RingbufInline,
            OutputAction::Decode,
            0,
            None,
        );

        assert_eq!(decoded.status, ParseStatus::ParseError);
        assert!(decoded.fields.is_none());
        assert_eq!(
            decoded.classification.as_ref().map(|c| c.verdict),
            Some(ClassificationVerdict::Mismatch)
        );
    }
}
