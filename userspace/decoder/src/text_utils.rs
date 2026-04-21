//! Shared text processing utilities for the eBPF decoder.

/// Safely truncate a string to a maximum number of bytes, ensuring the split 
/// occurs on a valid UTF-8 character boundary to prevent panics.
pub fn safe_truncate(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::safe_truncate;

    #[test]
    fn test_safe_truncate_unicode() {
        let s = "🦀🦀🦀"; // Each 🦀 is 4 bytes
        assert_eq!(safe_truncate(s, 4), "🦀");
        assert_eq!(safe_truncate(s, 6), "🦀"); // Drops the partial 🦀
        assert_eq!(safe_truncate(s, 8), "🦀🦀");
        assert_eq!(safe_truncate(s, 12), "🦀🦀🦀");
    }
}
