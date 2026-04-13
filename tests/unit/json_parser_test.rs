#[cfg(test)]
mod tests {
    use ebpf_json_decoder::json_parser::*;
    
    #[test]
    fn test_generic_parsing() {
        let data = b"{\"event\": \"login\", \"user_id\": 123, \"status\": \"success\"}";
        let backend = detect_parser_capability();
        let log = parse_log(data, &backend).unwrap();
        
        assert_eq!(log.extra.get("event").unwrap(), "login");
        assert_eq!(log.extra.get("user_id").unwrap(), 123);
    }

    #[test]
    fn test_malformed_json() {
        let data = b"{\"event\": \"login\", ";
        let backend = detect_parser_capability();
        let result = parse_log(data, &backend);
        assert!(result.is_err());
    }
}
