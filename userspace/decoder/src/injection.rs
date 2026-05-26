//! Configured output injection for decoded payload classification.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use crate::output::{DecodedEvent, DetectedFormat, EventAction, ParseStatus};

static INJECTION_RULES: OnceLock<HashMap<InjectionKey, InjectionRule>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InjectionKey {
    pub port: u16,
    pub protocol: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectionRule {
    pub format: DetectedFormat,
    pub inject: String,
}

#[derive(Debug, Deserialize)]
struct InterceptConfig {
    intercept: Vec<InterceptEntry>,
}

#[derive(Debug, Deserialize)]
struct InterceptEntry {
    port: u16,
    protocol: String,
    format: ConfigFormat,
    action: ConfigAction,
    #[serde(default)]
    inject: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ConfigFormat {
    Json,
    Syslog,
    Html,
    PlainText,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ConfigAction {
    Decode,
    Drop,
    Pass,
    Check,
}

impl ConfigFormat {
    fn detected(self) -> DetectedFormat {
        match self {
            Self::Json => DetectedFormat::Json,
            Self::Syslog => DetectedFormat::Syslog,
            Self::Html => DetectedFormat::Html,
            Self::PlainText => DetectedFormat::PlainText,
        }
    }
}

pub fn load_rules_from_path(path: &Path) -> Result<HashMap<InjectionKey, InjectionRule>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read decoder config file at {:?}", path))?;
    parse_rules(&content)
}

pub fn set_rules(rules: HashMap<InjectionKey, InjectionRule>) {
    if INJECTION_RULES.set(rules).is_err() {
        tracing::debug!("Decoder injection rules were already initialized");
    }
}

pub fn rule_for(port: u16, protocol: u8) -> Option<&'static InjectionRule> {
    INJECTION_RULES
        .get()
        .and_then(|rules| rules.get(&InjectionKey { port, protocol }))
}

pub fn apply(event: &mut DecodedEvent, rule: Option<&InjectionRule>) {
    if event.status != ParseStatus::Ok || event.action != EventAction::Decode {
        return;
    }

    let Some(rule) = rule else {
        return;
    };
    if event.format != rule.format {
        tracing::debug!(
            "Skipping inject because decoded format {:?} does not match configured format {:?}",
            event.format,
            rule.format
        );
        return;
    }

    match event.format {
        DetectedFormat::Json => apply_json(event, &rule.inject),
        DetectedFormat::Syslog | DetectedFormat::Html | DetectedFormat::PlainText => {
            event.inject = Some(rule.inject.clone());
        }
        DetectedFormat::Unknown => {}
    }
}

fn parse_rules(content: &str) -> Result<HashMap<InjectionKey, InjectionRule>> {
    let config: InterceptConfig =
        serde_yaml::from_str(content).context("Failed to parse decoder YAML configuration")?;
    let mut rules = HashMap::new();

    for entry in config.intercept {
        let Some(inject) = entry.inject else {
            continue;
        };

        if entry.action != ConfigAction::Decode {
            bail!(
                "inject is only valid with action=decode for port={} protocol={}",
                entry.port,
                entry.protocol
            );
        }

        if entry.format == ConfigFormat::Json {
            validate_json_inject(&inject, entry.port, &entry.protocol)?;
        }

        let protocol = ebpf_common::parse_protocol(&entry.protocol)
            .with_context(|| format!("Unsupported protocol: {}", entry.protocol))?;
        rules.insert(
            InjectionKey {
                port: entry.port,
                protocol,
            },
            InjectionRule {
                format: entry.format.detected(),
                inject,
            },
        );
    }

    Ok(rules)
}

fn apply_json(event: &mut DecodedEvent, inject: &str) {
    let Some((field, value)) = inject.split_once(':') else {
        tracing::debug!("Skipping malformed JSON inject string");
        return;
    };
    let field = field.trim();
    if field.is_empty() {
        tracing::debug!("Skipping JSON inject with empty field name");
        return;
    }

    let Some(Value::Object(fields)) = event.fields.as_mut() else {
        tracing::debug!("Skipping JSON inject because decoded fields are not an object");
        return;
    };

    fields.insert(field.to_string(), Value::String(value.trim().to_string()));
}

fn validate_json_inject(inject: &str, port: u16, protocol: &str) -> Result<()> {
    let Some((field, _value)) = inject.split_once(':') else {
        bail!(
            "JSON inject must use field:value for port={} protocol={}",
            port,
            protocol
        );
    };

    if field.trim().is_empty() {
        bail!(
            "JSON inject field name cannot be empty for port={} protocol={}",
            port,
            protocol
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{apply, parse_rules, InjectionRule};
    use crate::output::{
        ClassificationVerdict, ContentKind, DecodedEvent, DetectedFormat, EventAction, ParseStatus,
        PayloadSource,
    };
    use serde_json::json;

    fn event(format: DetectedFormat, fields: serde_json::Value) -> DecodedEvent {
        DecodedEvent {
            latency: "0us".to_string(),
            format,
            source: PayloadSource::RingbufInline,
            status: ParseStatus::Ok,
            action: EventAction::Decode,
            classification: Some(crate::output::ClassificationMetadata {
                verdict: ClassificationVerdict::Match,
                observed: ContentKind::Json,
                reason: "test".to_string(),
            }),
            inject: None,
            fields: Some(fields),
        }
    }

    #[test]
    fn json_object_receives_injected_string_field() {
        let mut decoded = event(DetectedFormat::Json, json!({"event":"login"}));
        let rule = InjectionRule {
            format: DetectedFormat::Json,
            inject: "classification:auth".to_string(),
        };

        apply(&mut decoded, Some(&rule));

        assert_eq!(
            decoded.fields,
            Some(json!({"event":"login","classification":"auth"}))
        );
        assert!(decoded.inject.is_none());
    }

    #[test]
    fn json_inject_overwrites_existing_field() {
        let mut decoded = event(
            DetectedFormat::Json,
            json!({"classification":"old","event":"login"}),
        );
        let rule = InjectionRule {
            format: DetectedFormat::Json,
            inject: "classification:new".to_string(),
        };

        apply(&mut decoded, Some(&rule));

        assert_eq!(
            decoded.fields,
            Some(json!({"classification":"new","event":"login"}))
        );
    }

    #[test]
    fn non_json_sets_top_level_inject_without_mutating_fields() {
        let mut decoded = event(DetectedFormat::Syslog, json!({"message":"hello"}));
        let rule = InjectionRule {
            format: DetectedFormat::Syslog,
            inject: "classification:syslog".to_string(),
        };

        apply(&mut decoded, Some(&rule));

        assert_eq!(decoded.fields, Some(json!({"message":"hello"})));
        assert_eq!(decoded.inject.as_deref(), Some("classification:syslog"));
    }

    #[test]
    fn missing_rule_leaves_output_unchanged() {
        let mut decoded = event(DetectedFormat::Json, json!({"event":"login"}));

        apply(&mut decoded, None);

        assert_eq!(decoded.fields, Some(json!({"event":"login"})));
        assert!(decoded.inject.is_none());
    }

    #[test]
    fn parses_only_decode_injection_rules() {
        let rules = parse_rules(
            r#"
intercept:
  - port: 8080
    protocol: tcp
    format: json
    action: decode
    inject: "classification:login"
  - port: 514
    protocol: udp
    format: syslog
    action: decode
"#,
        )
        .expect("valid config");

        assert_eq!(rules.len(), 1);
    }
}
