pub fn parse_protocol(protocol: &str) -> Option<u8> {
    match protocol.to_lowercase().as_str() {
        "tcp" => Some(6),
        "udp" => Some(17),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_protocol() {
        assert_eq!(parse_protocol("tcp"), Some(6));
        assert_eq!(parse_protocol("TCP"), Some(6));
        assert_eq!(parse_protocol("udp"), Some(17));
        assert_eq!(parse_protocol("UDP"), Some(17));
        assert_eq!(parse_protocol("icmp"), None);
        assert_eq!(parse_protocol(""), None);
    }
}
