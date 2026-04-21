//! Lightweight userspace content classifier.
//!
//! This is deliberately signature- and shape-based. Kernel eBPF keeps the
//! bounded fast guard; this module performs deeper userspace validation without
//! introducing external runtime dependencies.

use crate::output::{ClassificationMetadata, ClassificationVerdict, ContentKind, DetectedFormat};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub verdict: ClassificationVerdict,
    pub observed: ContentKind,
    pub reason: &'static str,
}

impl Classification {
    pub fn metadata(&self) -> ClassificationMetadata {
        ClassificationMetadata {
            verdict: self.verdict,
            observed: self.observed,
            reason: self.reason.to_string(),
        }
    }
}

pub fn classify(payload: &[u8], expected: DetectedFormat) -> Classification {
    let observed = observe(payload);
    let verdict = verdict_for(expected, observed);
    let reason = reason_for(expected, observed, verdict);

    Classification {
        verdict,
        observed,
        reason,
    }
}

fn observe(payload: &[u8]) -> ContentKind {
    if payload.is_empty() {
        return ContentKind::Unknown;
    }

    if payload.starts_with(b"\x7fELF") {
        return ContentKind::Elf;
    }
    if payload.starts_with(b"MZ") {
        return ContentKind::Pe;
    }
    if payload.starts_with(b"%PDF") {
        return ContentKind::Pdf;
    }
    if payload.starts_with(b"PK\x03\x04")
        || payload.starts_with(b"PK\x05\x06")
        || payload.starts_with(b"PK\x07\x08")
    {
        return ContentKind::Zip;
    }
    if payload.starts_with(&[0x1f, 0x8b]) {
        return ContentKind::Gzip;
    }
    if payload.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        return ContentKind::Png;
    }
    if payload.starts_with(&[0xff, 0xd8, 0xff]) {
        return ContentKind::Jpeg;
    }
    if payload.iter().take(32).any(|&b| b == 0) {
        return ContentKind::Binary;
    }

    let trimmed = trim_ascii_whitespace(payload);
    if trimmed.is_empty() {
        return ContentKind::PlainText;
    }
    if matches!(trimmed[0], b'{' | b'[') {
        return ContentKind::Json;
    }
    if is_syslog_prefix(trimmed) {
        return ContentKind::Syslog;
    }
    if looks_like_html(trimmed) {
        return ContentKind::Html;
    }
    if looks_textual(payload) {
        return ContentKind::PlainText;
    }

    ContentKind::Unknown
}

fn verdict_for(expected: DetectedFormat, observed: ContentKind) -> ClassificationVerdict {
    use ClassificationVerdict::{Match, Mismatch, Unknown};
    use ContentKind::{
        Binary, Elf, Gzip, Html, Jpeg, Json, Pdf, Pe, PlainText, Png, Syslog,
        Unknown as UnknownKind, Zip,
    };
    use DetectedFormat::{
        Html as ExpectedHtml, Json as ExpectedJson, PlainText as ExpectedPlain,
        Syslog as ExpectedSyslog, Unknown as ExpectedUnknown,
    };

    let binary = matches!(observed, Binary | Elf | Pe | Pdf | Zip | Gzip | Png | Jpeg);

    match expected {
        ExpectedJson => match observed {
            Json => Match,
            UnknownKind => Unknown,
            _ if binary => Mismatch,
            PlainText | Syslog | Html => Mismatch,
            _ => Unknown,
        },
        ExpectedSyslog => match observed {
            Syslog => Match,
            UnknownKind => Unknown,
            _ if binary => Mismatch,
            PlainText | Json | Html => Mismatch,
            _ => Unknown,
        },
        ExpectedHtml => match observed {
            Html => Match,
            UnknownKind => Unknown,
            _ if binary => Mismatch,
            PlainText | Json | Syslog => Mismatch,
            _ => Unknown,
        },
        ExpectedPlain => {
            if binary {
                Mismatch
            } else if observed == UnknownKind {
                Unknown
            } else {
                Match
            }
        }
        ExpectedUnknown => Unknown,
    }
}

fn reason_for(
    expected: DetectedFormat,
    observed: ContentKind,
    verdict: ClassificationVerdict,
) -> &'static str {
    match verdict {
        ClassificationVerdict::Match => "observed content matches expected format",
        ClassificationVerdict::Unknown => "content shape is inconclusive",
        ClassificationVerdict::Mismatch => {
            if matches!(
                observed,
                ContentKind::Elf
                    | ContentKind::Pe
                    | ContentKind::Pdf
                    | ContentKind::Zip
                    | ContentKind::Gzip
                    | ContentKind::Png
                    | ContentKind::Jpeg
                    | ContentKind::Binary
            ) {
                "binary signature does not match expected format"
            } else {
                match expected {
                    DetectedFormat::Json => "payload is not shaped like JSON",
                    DetectedFormat::Syslog => "payload is not shaped like syslog",
                    DetectedFormat::Html => "payload is not shaped like HTML",
                    DetectedFormat::PlainText => "payload is not acceptable plaintext",
                    DetectedFormat::Unknown => "expected format is unknown",
                }
            }
        }
    }
}

fn trim_ascii_whitespace(data: &[u8]) -> &[u8] {
    let start = data
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(data.len());
    &data[start..]
}

fn is_syslog_prefix(data: &[u8]) -> bool {
    if data.first() != Some(&b'<') {
        return false;
    }

    let Some(end) = data.iter().position(|&b| b == b'>') else {
        return false;
    };
    if !(2..=4).contains(&end) {
        return false;
    }

    let pri = data[1..end].iter().try_fold(0u32, |acc, b| {
        if b.is_ascii_digit() {
            Some((acc * 10) + u32::from(b - b'0'))
        } else {
            None
        }
    });
    matches!(pri, Some(v) if v <= 191)
}

fn looks_like_html(data: &[u8]) -> bool {
    starts_ascii_case_insensitive(data, b"<!doctype")
        || starts_ascii_case_insensitive(data, b"<html")
        || contains_ascii_case_insensitive(&data[..data.len().min(128)], b"<head")
}

fn looks_textual(data: &[u8]) -> bool {
    data.iter()
        .all(|&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7e).contains(&b) || b >= 0x80)
}

fn starts_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len()
        && haystack[..needle.len()]
            .iter()
            .zip(needle)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| starts_ascii_case_insensitive(window, needle))
}

#[cfg(test)]
mod tests {
    use super::classify;
    use crate::output::{ClassificationVerdict, ContentKind, DetectedFormat};

    #[test]
    fn detects_common_binary_signatures() {
        let cases: &[(&[u8], ContentKind)] = &[
            (b"\x7fELFbad", ContentKind::Elf),
            (b"MZbad", ContentKind::Pe),
            (b"%PDF-1.7", ContentKind::Pdf),
            (b"PK\x03\x04zip", ContentKind::Zip),
            (&[0x1f, 0x8b, 0x08], ContentKind::Gzip),
            (
                &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a],
                ContentKind::Png,
            ),
            (&[0xff, 0xd8, 0xff, 0xe0], ContentKind::Jpeg),
        ];

        for (payload, observed) in cases {
            let result = classify(payload, DetectedFormat::Json);
            assert_eq!(result.observed, *observed);
            assert_eq!(result.verdict, ClassificationVerdict::Mismatch);
        }
    }

    #[test]
    fn accepts_expected_text_shapes() {
        assert_eq!(
            classify(br#"{"event":"ok"}"#, DetectedFormat::Json).verdict,
            ClassificationVerdict::Match
        );
        assert_eq!(
            classify(b"<34>Oct 11 host app: ok", DetectedFormat::Syslog).verdict,
            ClassificationVerdict::Match
        );
        assert_eq!(
            classify(b"<!doctype html><html></html>", DetectedFormat::Html).verdict,
            ClassificationVerdict::Match
        );
    }

    #[test]
    fn rejects_text_shape_mismatch_for_json() {
        let result = classify(b"not-json", DetectedFormat::Json);
        assert_eq!(result.observed, ContentKind::PlainText);
        assert_eq!(result.verdict, ClassificationVerdict::Mismatch);
    }
}
