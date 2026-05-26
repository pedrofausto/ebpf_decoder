//! Bounded TCP stream reconstruction for complete log frames.

use std::collections::HashMap;

use anyhow::{bail, Result};

use crate::framing::FrameStrategy;
use crate::output::{DetectedFormat, PayloadSource};

pub const MAX_STREAM_BUFFER_BYTES: usize = 1024 * 1024;
const STREAM_IDLE_NS: u64 = 60_000_000_000;

#[derive(Debug, Clone, Copy)]
pub struct StreamContext {
    pub conn_id: u32,
    pub format: DetectedFormat,
    pub source: PayloadSource,
    pub now_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StreamKey {
    conn_id: u32,
    format: u8,
    source: u8,
}

#[derive(Debug, Default)]
struct StreamBuffer {
    bytes: Vec<u8>,
    last_seen_ns: u64,
}

#[derive(Debug, Default)]
pub struct StreamState {
    streams: HashMap<StreamKey, StreamBuffer>,
}

impl StreamState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn frames_for_event(&mut self, payload: &[u8], ctx: StreamContext) -> Result<Vec<Vec<u8>>> {
        if payload.is_empty() {
            return Ok(Vec::new());
        }

        self.evict_idle(ctx.now_ns);

        match strategy_for(ctx) {
            FrameStrategy::Datagram | FrameStrategy::RawBlob => Ok(vec![payload.to_vec()]),
            FrameStrategy::NewlineDelimited => {
                self.process_stream(payload, ctx, drain_newline_frames)
            }
            FrameStrategy::OctetCounted => {
                self.process_stream(payload, ctx, drain_syslog_frames)
            }
        }
    }

    fn process_stream(
        &mut self,
        payload: &[u8],
        ctx: StreamContext,
        drain_fn: fn(&mut Vec<u8>, &mut Vec<Vec<u8>>),
    ) -> Result<Vec<Vec<u8>>> {
        let key = StreamKey::from_context(ctx);
        let stream = self.streams.entry(key).or_insert_with(|| StreamBuffer {
            bytes: Vec::new(),
            last_seen_ns: ctx.now_ns,
        });

        let next_len = stream
            .bytes
            .len()
            .checked_add(payload.len())
            .unwrap_or(MAX_STREAM_BUFFER_BYTES + 1);
        if next_len > MAX_STREAM_BUFFER_BYTES {
            stream.bytes.clear();
            bail!("stream buffer exceeded {} bytes", MAX_STREAM_BUFFER_BYTES);
        }

        stream.bytes.extend_from_slice(payload);
        stream.last_seen_ns = ctx.now_ns;

        let mut frames = Vec::new();
        drain_fn(&mut stream.bytes, &mut frames);
        Ok(frames)
    }

    fn evict_idle(&mut self, now_ns: u64) {
        self.streams
            .retain(|_, stream| now_ns.saturating_sub(stream.last_seen_ns) <= STREAM_IDLE_NS);
    }
}

impl StreamKey {
    fn from_context(ctx: StreamContext) -> Self {
        Self {
            // TODO: remove zero-conn fallback once all TCP emitters reliably populate conn_id.
            conn_id: ctx.conn_id,
            format: format_id(ctx.format),
            source: source_id(ctx.source),
        }
    }
}

fn strategy_for(ctx: StreamContext) -> FrameStrategy {
    match ctx.format {
        DetectedFormat::Json => FrameStrategy::NewlineDelimited,
        DetectedFormat::Syslog if ctx.conn_id != 0 => FrameStrategy::OctetCounted,
        DetectedFormat::Syslog => FrameStrategy::Datagram,
        DetectedFormat::Html | DetectedFormat::PlainText | DetectedFormat::Unknown => {
            FrameStrategy::RawBlob
        }
    }
}

fn drain_newline_frames(buffer: &mut Vec<u8>, frames: &mut Vec<Vec<u8>>) {
    while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
        let mut frame: Vec<u8> = buffer.drain(..=pos).collect();
        if frame.last() == Some(&b'\n') {
            frame.pop();
        }
        if frame.last() == Some(&b'\r') {
            frame.pop();
        }
        if !frame.is_empty() {
            frames.push(frame);
        }
    }
}

fn drain_syslog_frames(buffer: &mut Vec<u8>, frames: &mut Vec<Vec<u8>>) {
    loop {
        if buffer.is_empty() {
            return;
        }

        if buffer[0].is_ascii_digit() {
            match try_drain_octet_counted(buffer, frames) {
                DrainProgress::Drained => continue,
                DrainProgress::NeedMore => return,
                DrainProgress::NotOctetCounted => {}
            }
        }

        let before = frames.len();
        drain_newline_frames(buffer, frames);
        if frames.len() == before {
            return;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainProgress {
    Drained,
    NeedMore,
    NotOctetCounted,
}

fn try_drain_octet_counted(buffer: &mut Vec<u8>, frames: &mut Vec<Vec<u8>>) -> DrainProgress {
    let Some(sep) = buffer.iter().position(|&b| b == b' ') else {
        return DrainProgress::NeedMore;
    };
    if sep == 0 || sep > 10 || !buffer[..sep].iter().all(|b| b.is_ascii_digit()) {
        return DrainProgress::NotOctetCounted;
    }

    let len = buffer[..sep].iter().fold(0usize, |acc, b| {
        acc.saturating_mul(10).saturating_add(usize::from(b - b'0'))
    });
    if len > MAX_STREAM_BUFFER_BYTES {
        buffer.clear();
        return DrainProgress::NeedMore;
    }

    let payload_start = sep + 1;
    let Some(total_len) = payload_start.checked_add(len) else {
        buffer.clear();
        return DrainProgress::NeedMore;
    };
    if buffer.len() < total_len {
        return DrainProgress::NeedMore;
    }

    let drained: Vec<u8> = buffer.drain(..total_len).collect();
    let frame = drained[payload_start..].to_vec();
    if !frame.is_empty() {
        frames.push(frame);
    }
    DrainProgress::Drained
}

fn format_id(format: DetectedFormat) -> u8 {
    match format {
        DetectedFormat::Json => 0,
        DetectedFormat::Syslog => 1,
        DetectedFormat::Html => 2,
        DetectedFormat::PlainText => 3,
        DetectedFormat::Unknown => 255,
    }
}

fn source_id(source: PayloadSource) -> u8 {
    match source {
        PayloadSource::RingbufInline => 0,
        PayloadSource::Arena => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::{StreamContext, StreamState, MAX_STREAM_BUFFER_BYTES};
    use crate::output::{DetectedFormat, PayloadSource};

    fn ctx(format: DetectedFormat) -> StreamContext {
        StreamContext {
            conn_id: 42,
            format,
            source: PayloadSource::RingbufInline,
            now_ns: 1,
        }
    }

    #[test]
    fn newline_framing_buffers_partial_json() {
        let mut state = StreamState::new();
        let frames = state
            .frames_for_event(br#"{"event":"part"#, ctx(DetectedFormat::Json))
            .unwrap();
        assert!(frames.is_empty());

        let frames = state
            .frames_for_event(br#"ial"}"#, ctx(DetectedFormat::Json))
            .unwrap();
        assert!(frames.is_empty());

        let frames = state
            .frames_for_event(b"\n", ctx(DetectedFormat::Json))
            .unwrap();
        assert_eq!(frames, vec![br#"{"event":"partial"}"#.to_vec()]);
    }

    #[test]
    fn newline_framing_emits_multiple_frames() {
        let mut state = StreamState::new();
        let frames = state
            .frames_for_event(b"{\"a\":1}\n{\"b\":2}\n", ctx(DetectedFormat::Json))
            .unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], br#"{"a":1}"#);
        assert_eq!(frames[1], br#"{"b":2}"#);
    }

    #[test]
    fn octet_counted_syslog_buffers_until_complete() {
        let mut state = StreamState::new();
        let frames = state
            .frames_for_event(b"10 <34>hello", ctx(DetectedFormat::Syslog))
            .unwrap();
        assert!(frames.is_empty());

        let frames = state
            .frames_for_event(b"!", ctx(DetectedFormat::Syslog))
            .unwrap();
        assert_eq!(frames, vec![b"<34>hello!".to_vec()]);
    }

    #[test]
    fn stream_overflow_clears_stream() {
        let mut state = StreamState::new();
        let large = vec![b'a'; MAX_STREAM_BUFFER_BYTES + 1];
        let err = state
            .frames_for_event(&large, ctx(DetectedFormat::Json))
            .unwrap_err();
        assert!(err.to_string().contains("stream buffer exceeded"));

        let frames = state
            .frames_for_event(b"{\"ok\":true}\n", ctx(DetectedFormat::Json))
            .unwrap();
        assert_eq!(frames, vec![br#"{"ok":true}"#.to_vec()]);
    }
}
