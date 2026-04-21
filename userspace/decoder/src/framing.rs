//! Framing layer: separates transport framing from content parsing.
//! Phase 1: all payloads arrive as complete frames (datagram or ringbuf slice).

/// Result of a framing attempt.
#[allow(dead_code)]
pub enum FrameResult<'a> {
    /// A complete, parse-ready frame.
    Complete(&'a [u8]),
    /// Only a partial chunk was received — stream reassembly needed (Phase 2).
    Partial,
    /// Empty or zero-length data.
    Empty,
}

/// Strategy used to delimit payload frames.
#[derive(Debug, Clone, Copy)]
pub enum FrameStrategy {
    /// Each kernel event is a self-contained datagram.
    Datagram,
    /// Frames end at newline boundaries (NDJSON, syslog TCP).
    NewlineDelimited,
    /// Octet-counted syslog (RFC 5425): `<len> <frame>`.
    OctetCounted,
    /// Raw blob — treat the entire slice as one frame.
    RawBlob,
}

/// Attempt to extract a complete frame from `data` using `strategy`.
/// Phase 1: only `Datagram` and `RawBlob` return `Complete`; others return `Partial`
/// to signal that stream state (Phase 2) is required.
#[allow(dead_code)]
pub fn frame<'a>(data: &'a [u8], strategy: FrameStrategy) -> FrameResult<'a> {
    if data.is_empty() {
        return FrameResult::Empty;
    }

    match strategy {
        FrameStrategy::Datagram | FrameStrategy::RawBlob => FrameResult::Complete(data),
        FrameStrategy::NewlineDelimited => {
            // Return the first complete line if available; otherwise Partial.
            if let Some(pos) = data.iter().position(|&b| b == b'\n') {
                FrameResult::Complete(&data[..pos])
            } else {
                FrameResult::Partial
            }
        }
        FrameStrategy::OctetCounted => {
            // Format: "<len> <payload>"
            let header_end = data.iter().position(|&b| b == b' ');
            if let Some(sep) = header_end {
                let len_str = std::str::from_utf8(&data[..sep]).unwrap_or("");
                if let Ok(n) = len_str.parse::<usize>() {
                    let payload_start = sep + 1;
                    if data.len() >= payload_start + n {
                        return FrameResult::Complete(&data[payload_start..payload_start + n]);
                    }
                }
            }
            FrameResult::Partial
        }
    }
}
