//! HTML parser: bounded metadata extraction only.
//! Extracts title + short text excerpt. No DOM execution, no unsafe attribute eval.

use anyhow::Result;
use serde_json::{json, Value};

const MAX_TITLE_BYTES: usize = 512;
const MAX_EXCERPT_BYTES: usize = 1024;

pub struct HtmlResult {
    pub fields: Value,
}

/// Extract bounded metadata from an HTML payload.
pub fn parse(data: &[u8]) -> Result<HtmlResult> {
    let text = std::str::from_utf8(data).map_err(|_| anyhow::anyhow!("html: non-UTF8 payload"))?;

    // --- Title ---
    let title =
        extract_between_ascii_case_insensitive(text, "<title>", "</title>").unwrap_or_default();
    let title = crate::text_utils::safe_truncate(&title, MAX_TITLE_BYTES).to_string();

    // --- Body excerpt: strip tags, take first N bytes of text ---
    let excerpt = strip_tags(text, MAX_EXCERPT_BYTES);

    // --- Count top-level tags for a lightweight summary ---
    let tag_count = count_tags(text);

    Ok(HtmlResult {
        fields: json!({
            "title":     title,
            "excerpt":   excerpt,
            "tag_count": tag_count,
        }),
    })
}

fn extract_between_ascii_case_insensitive(
    original: &str,
    open: &str,
    close: &str,
) -> Option<String> {
    let bytes = original.as_bytes();
    let open_bytes = open.as_bytes();
    let close_bytes = close.as_bytes();

    let start_tag = find_ascii_case_insensitive(bytes, open_bytes)?;
    let content_start = start_tag + open_bytes.len();
    let end_rel = find_ascii_case_insensitive(&bytes[content_start..], close_bytes)?;
    let content_end = content_start + end_rel;

    Some(original[content_start..content_end].trim().to_string())
}

fn find_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| {
        window
            .iter()
            .zip(needle.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

fn strip_tags(html: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(max_bytes);
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => {
                if out.len() + c.len_utf8() > max_bytes {
                    out.push_str("…");
                    break;
                }
                out.push(c);
            }
            _ => {}
        }
    }
    // Collapse whitespace
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn count_tags(text: &str) -> usize {
    text.matches('<').count()
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn extracts_title_with_unicode_prefix_without_panic() {
        let html = "Préfixo ✅ <TITLE>Hello</TITLE><p>body</p>";
        let parsed = parse(html.as_bytes()).expect("html parse should succeed");
        assert_eq!(parsed.fields["title"], "Hello");
    }
}
