//! `json_parser.rs` — event dispatcher (retains original public API for compatibility).
//!
//! All format-specific logic has moved to `parsers/` and `format_router`.
//! This module is the ringbuf callback entry point. It reads action/format from
//! the kernel-populated log_event_t and applies the action gate before decoding.

use anyhow::{Context, Result, bail};
use std::sync::OnceLock;

use crate::structs::{log_event_t, EventFormat, EventAction};
use crate::format_router::decode_payload;
use crate::framing::{frame, FrameStrategy};
use crate::output::{self, DecodedEvent, EventAction as OutputAction, PayloadSource, ParseStatus, format_from_event};

pub const MAX_EVENT_PAYLOAD_SIZE: usize = 1024 * 1024; // 1MB global cap

static ARENA_BASE: OnceLock<usize> = OnceLock::new();
static ARENA_SIZE: OnceLock<usize> = OnceLock::new();

pub fn set_arena_layout(ptr: usize, size: usize) {
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

        let end = offset.checked_add(data_len)
            .context("Arena offset + len overflow")?;

        if end > arena_size {
            bail!("Arena access out of bounds: end={} > size={}", end, arena_size);
        }
        let ptr = (base_ptr + offset) as *const u8;
        let slice = unsafe { std::slice::from_raw_parts(ptr, data_len) };
        (slice, PayloadSource::Arena)
    } else {
        if data_len > event.data.len() {
            bail!("Invalid data_len ({}) > inline buffer ({})", data_len, event.data.len());
        }
        (&event.data[..data_len], PayloadSource::RingbufInline)
    };

    // --- Framing (Phase 1: datagram) ---
    let framed = match frame(payload, FrameStrategy::Datagram) {
        crate::framing::FrameResult::Complete(f) => f,
        _ => bail!("Unexpected partial frame in datagram mode"),
    };

    // --- Latency ---
    use nix::time::{clock_gettime, ClockId};
    let ts = clock_gettime(ClockId::CLOCK_MONOTONIC)
        .map_err(|e| anyhow::anyhow!("clock_gettime failed: {}", e))?;
    let now_ns = ts.tv_sec() as u64 * 1_000_000_000 + ts.tv_nsec() as u64;
    let latency_ns = now_ns.saturating_sub(event.ts_ns);

    // --- Route: prefer expected format from kernel metadata, not sniff-first ---
    let hint = Some(format_from_event(event_format));
    let result = decode_payload(framed, hint);

    // --- Emit: only for ACTION_DECODE; ACTION_CHECK skips output ---
    let output_action = match event_action {
        EventAction::Decode => OutputAction::Decode,
        EventAction::Check  => OutputAction::Check,
        EventAction::Pass   => OutputAction::Pass,
        EventAction::Drop   => OutputAction::Drop,
    };

    let decoded = DecodedEvent {
        latency: output::format_latency(latency_ns),
        format: result.format,
        source,
        status: result.status,
        action: output_action,
        fields: result.fields,
    };

    match (decoded.status, decoded.action) {
        (ParseStatus::Ok, OutputAction::Decode) => output::emit(&decoded),
        (ParseStatus::Ok, OutputAction::Check)  => {
            tracing::debug!("CHECK pass: format={:?}", decoded.format);
        }
        _ => tracing::debug!("Decode failed or non-emit action: {:?}", decoded.status),
    }

    Ok(())
}
