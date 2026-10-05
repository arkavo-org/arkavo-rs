//! Moderation intake (arkavo-rs#77): signed-in viewers report creators and
//! recordings; moderators are notified, respond, and act. See
//! `docs/moderation.md`.

pub mod api;
pub mod auth;
pub mod report;
pub mod store;

use std::collections::HashSet;

/// Settings read from the environment when `MODERATION_INTAKE=on`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub table: String,
    pub status_index: String,
    pub issuer: String,
    pub cose_keys_url: String,
    pub audience: String,
    pub moderators: HashSet<String>,
    pub retention_days: i64,
    pub hourly_limit: u64,
    pub daily_limit: u64,
    pub subject_prefix: String,
    /// DynamoDB endpoint override, e.g. a DynamoDB Local container. When
    /// set, the moderation client uses it with static placeholder
    /// credentials, leaving the process's AWS credentials (S3) untouched.
    pub dynamodb_endpoint: Option<String>,
}

pub const DEFAULT_STATUS_INDEX: &str = "status-received_at-index";

/// `Ok(None)` when the intake is off (the default).
pub fn settings_from(get: impl Fn(&str) -> Option<String>) -> Result<Option<Settings>, String> {
    let get = |k: &str| get(k).filter(|v| !v.trim().is_empty());
    match get("MODERATION_INTAKE").map(|v| v.to_ascii_lowercase()) {
        None => return Ok(None),
        Some(v) if v == "off" => return Ok(None),
        Some(v) if v == "on" => {}
        Some(other) => return Err(format!("MODERATION_INTAKE must be off or on, got {other}")),
    }
    let table = get("MODERATION_REPORTS_TABLE")
        .ok_or("MODERATION_INTAKE=on requires MODERATION_REPORTS_TABLE")?;
    let issuer = get("OIDC_ISSUER").unwrap_or_else(|| "https://identity.arkavo.net".into());
    let cose_keys_url = get("MODERATION_COSE_KEYS_URL")
        .unwrap_or_else(|| format!("{}/.well-known/cose-keys", issuer.trim_end_matches('/')));
    let number = |k: &str, default: i64| -> Result<i64, String> {
        match get(k) {
            None => Ok(default),
            Some(v) => v
                .trim()
                .parse::<i64>()
                .ok()
                .filter(|n| *n >= 0)
                .ok_or(format!("{k} must be a non-negative integer, got {v}")),
        }
    };
    let retention_days = number("MODERATION_RETENTION_DAYS", 365)?;
    if retention_days == 0 {
        return Err("MODERATION_RETENTION_DAYS must be at least 1".into());
    }
    Ok(Some(Settings {
        table,
        status_index: get("MODERATION_STATUS_INDEX").unwrap_or_else(|| DEFAULT_STATUS_INDEX.into()),
        issuer,
        cose_keys_url,
        audience: get("MODERATION_EXPECTED_AUD").unwrap_or_else(|| "arkavo".into()),
        moderators: get("MODERATION_MODERATORS")
            .map(|v| auth::parse_moderators(&v))
            .unwrap_or_default(),
        retention_days,
        hourly_limit: number("MODERATION_RATE_LIMIT_HOURLY", 10)? as u64,
        daily_limit: number("MODERATION_RATE_LIMIT_DAILY", 50)? as u64,
        subject_prefix: get("MODERATION_NATS_PREFIX").unwrap_or_else(|| "moderation".into()),
        dynamodb_endpoint: get("MODERATION_DYNAMODB_ENDPOINT"),
    }))
}

pub fn settings_from_env() -> Result<Option<Settings>, String> {
    settings_from(|k| std::env::var(k).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn settings(pairs: &[(&str, &str)]) -> Result<Option<Settings>, String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        settings_from(|k| m.get(k).cloned())
    }

    #[test]
    fn off_unless_enabled() {
        assert_eq!(settings(&[]), Ok(None));
        assert_eq!(settings(&[("MODERATION_INTAKE", "off")]), Ok(None));
        assert!(settings(&[("MODERATION_INTAKE", "yes")]).is_err());
    }

    #[test]
    fn on_requires_a_table_and_has_defaults() {
        assert!(settings(&[("MODERATION_INTAKE", "on")]).is_err());
        let s = settings(&[
            ("MODERATION_INTAKE", "ON"),
            ("MODERATION_REPORTS_TABLE", "prod-moderation-reports"),
            ("MODERATION_MODERATORS", "arkavo:m1,m2"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(s.table, "prod-moderation-reports");
        assert_eq!(s.status_index, DEFAULT_STATUS_INDEX);
        assert_eq!(s.issuer, "https://identity.arkavo.net");
        assert_eq!(
            s.cose_keys_url,
            "https://identity.arkavo.net/.well-known/cose-keys"
        );
        assert_eq!(s.audience, "arkavo");
        assert_eq!(s.moderators.len(), 2);
        assert_eq!(s.retention_days, 365);
        assert_eq!((s.hourly_limit, s.daily_limit), (10, 50));
        assert_eq!(s.subject_prefix, "moderation");
        assert_eq!(s.dynamodb_endpoint, None);
    }

    #[test]
    fn a_local_dynamodb_endpoint_can_be_set() {
        let s = settings(&[
            ("MODERATION_INTAKE", "on"),
            ("MODERATION_REPORTS_TABLE", "prod-moderation-reports"),
            ("MODERATION_DYNAMODB_ENDPOINT", "http://127.0.0.1:8000"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            s.dynamodb_endpoint.as_deref(),
            Some("http://127.0.0.1:8000")
        );
    }

    #[test]
    fn numbers_are_checked() {
        let base = [
            ("MODERATION_INTAKE", "on"),
            ("MODERATION_REPORTS_TABLE", "t"),
        ];
        for (k, v) in [
            ("MODERATION_RETENTION_DAYS", "0"),
            ("MODERATION_RETENTION_DAYS", "-1"),
            ("MODERATION_RATE_LIMIT_HOURLY", "many"),
        ] {
            let mut p = base.to_vec();
            p.push((k, v));
            assert!(settings(&p).is_err(), "{k}={v}");
        }
    }
}
