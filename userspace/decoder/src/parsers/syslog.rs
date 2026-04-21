//! Syslog parser supporting RFC 3164 and RFC 5424 datagram formats.
//! Phase 1: datagram (complete frame) only. Stream reassembly is Phase 2.

use anyhow::Result;
use serde_json::{json, Value};

/// Bounded result from syslog parsing.
pub struct SyslogResult {
    pub fields: Value,
}

/// Try to parse a complete syslog datagram (RFC 3164 or RFC 5424).
/// Falls back gracefully if confidence is low.
pub fn parse(data: &[u8]) -> Result<SyslogResult> {
    let text =
        std::str::from_utf8(data).map_err(|_| anyhow::anyhow!("syslog: non-UTF8 payload"))?;

    // RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
    if let Some(fields) = try_rfc5424(text) {
        return Ok(SyslogResult { fields });
    }

    // RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG: MSG
    if let Some(fields) = try_rfc3164(text) {
        return Ok(SyslogResult { fields });
    }

    anyhow::bail!("syslog: unrecognised format");
}

fn try_rfc5424(s: &str) -> Option<Value> {
    // Must start with <PRI>1
    if !s.starts_with('<') {
        return None;
    }
    let end_pri = s.find('>')?;
    let pri_str = &s[1..end_pri];
    let pri: u16 = pri_str.parse().ok()?;
    let rest = &s[end_pri + 1..];

    // Version must be "1 "
    if !rest.starts_with("1 ") {
        return None;
    }
    let parts: Vec<&str> = rest[2..].splitn(7, ' ').collect();
    if parts.len() < 6 {
        return None;
    }

    let facility = pri >> 3;
    let severity = pri & 0x07;

    Some(json!({
        "version": "rfc5424",
        "facility": facility,
        "severity": severity,
        "timestamp": parts[0],
        "hostname":  parts[1],
        "app_name":  parts[2],
        "proc_id":   parts[3],
        "msg_id":    parts[4],
        "message":   parts.get(6).unwrap_or(&""),
    }))
}

fn try_rfc3164(s: &str) -> Option<Value> {
    if !s.starts_with('<') {
        return None;
    }
    let end_pri = s.find('>')?;
    let pri_str = &s[1..end_pri];
    let pri: u16 = pri_str.parse().ok()?;
    let rest = &s[end_pri + 1..];

    let facility = pri >> 3;
    let severity = pri & 0x07;

    // Timestamp is "Mmm dd hh:mm:ss " (16 chars)
    if rest.len() < 16 {
        return None;
    }
    let timestamp = &rest[..15];
    let after_ts = &rest[16..];

    // Next token is hostname
    let mut parts = after_ts.splitn(3, ' ');
    let hostname = parts.next().unwrap_or("-");
    let message = parts.next().unwrap_or("").to_string() + parts.next().unwrap_or("");

    Some(json!({
        "version":   "rfc3164",
        "facility":  facility,
        "severity":  severity,
        "timestamp": timestamp,
        "hostname":  hostname,
        "message":   message,
    }))
}
