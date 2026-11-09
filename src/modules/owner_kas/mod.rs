//! The owner KAS address on platform.arkavo.net (arkavo-rs#163, arkavo-ios
//! ADR-0070 and design §4.2): a relay that queues a receiver's OpenTDF Rewrap
//! until the owner's phone fetches it, holds the phone's answer until the
//! receiver collects it, and sends the owner an APNs hint. It never decides
//! access and never holds a key it could use. Route records and APNs tokens
//! live at identity. See `docs/owner-kas.md`.

pub mod api;
pub mod apns;
pub mod identity;
pub mod store;
pub mod token;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApnsSettings {
    pub key_path: String,
    pub key_id: String,
    pub team_id: String,
    pub topic: String,
}

/// Settings read from the environment when `OWNER_KAS=on`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub issuer: String,
    pub cose_keys_url: String,
    /// The owner's session token must name this audience (and `arkavo`).
    pub platform_audience: String,
    /// Identity's per-route read; `{route_id}` is replaced.
    pub relay_url: String,
    /// Identity's service `DELETE` of a route's push token.
    pub push_url: String,
    pub token_url: String,
    /// The relay's own identity client (not `arks-media`).
    pub client_id: String,
    pub client_secret: String,
    pub client_audience: Option<String>,
    /// `None`: no `.p8` configured; requests queue without an alert.
    pub apns: Option<ApnsSettings>,
}

pub const DEFAULT_APNS_TOPIC: &str = "com.arkavo.Arkavo";

/// `Ok(None)` when the relay is off (the default).
pub fn settings_from(get: impl Fn(&str) -> Option<String>) -> Result<Option<Settings>, String> {
    let get = |k: &str| {
        get(k)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    match get("OWNER_KAS").map(|v| v.to_ascii_lowercase()) {
        None => return Ok(None),
        Some(v) if v == "off" => return Ok(None),
        Some(v) if v == "on" => {}
        Some(other) => return Err(format!("OWNER_KAS must be off or on, got {other}")),
    }
    let issuer = get("OIDC_ISSUER").unwrap_or_else(|| "https://identity.arkavo.net".into());
    let base = issuer.trim_end_matches('/').to_string();
    let client_secret = get("OWNER_KAS_RELAY_CLIENT_SECRET")
        .ok_or("OWNER_KAS=on requires OWNER_KAS_RELAY_CLIENT_SECRET")?;
    let apns = match (
        get("APNS_KEY_PATH"),
        get("APNS_KEY_ID"),
        get("APNS_TEAM_ID"),
    ) {
        (None, None, None) => None,
        (Some(key_path), Some(key_id), Some(team_id)) => Some(ApnsSettings {
            key_path,
            key_id,
            team_id,
            topic: get("APNS_TOPIC").unwrap_or_else(|| DEFAULT_APNS_TOPIC.into()),
        }),
        _ => return Err("APNS_KEY_PATH, APNS_KEY_ID and APNS_TEAM_ID are set together".into()),
    };
    Ok(Some(Settings {
        cose_keys_url: format!("{base}/.well-known/cose-keys"),
        platform_audience: get("MEDIA_PLATFORM_AUDIENCE")
            .unwrap_or_else(|| crate::modules::license::config::DEFAULT_PLATFORM_AUDIENCE.into()),
        relay_url: get("OWNER_KAS_RELAY_URL")
            .unwrap_or_else(|| format!("{base}/owner-kas/routes/{{route_id}}/relay")),
        push_url: get("OWNER_KAS_PUSH_URL")
            .unwrap_or_else(|| format!("{base}/owner-kas/routes/{{route_id}}/relay/push")),
        token_url: format!("{base}/oauth/token"),
        client_id: get("OWNER_KAS_RELAY_CLIENT_ID").unwrap_or_else(|| "owner-kas-relay".into()),
        client_secret,
        client_audience: get("OWNER_KAS_RELAY_CLIENT_AUDIENCE"),
        issuer,
        apns,
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
        assert_eq!(settings(&[("OWNER_KAS", "off")]), Ok(None));
        assert!(settings(&[("OWNER_KAS", "yes")]).is_err());
        assert!(settings(&[("OWNER_KAS", "on")]).is_err(), "needs a secret");
    }

    #[test]
    fn defaults() {
        let s = settings(&[("OWNER_KAS", "on"), ("OWNER_KAS_RELAY_CLIENT_SECRET", "s")])
            .unwrap()
            .unwrap();
        assert_eq!(s.issuer, "https://identity.arkavo.net");
        assert_eq!(
            s.cose_keys_url,
            "https://identity.arkavo.net/.well-known/cose-keys"
        );
        assert_eq!(s.platform_audience, "https://platform.arkavo.net");
        assert_eq!(
            s.relay_url,
            "https://identity.arkavo.net/owner-kas/routes/{route_id}/relay"
        );
        assert_eq!(s.token_url, "https://identity.arkavo.net/oauth/token");
        assert_eq!(s.client_id, "owner-kas-relay");
        assert_eq!(s.apns, None);
    }

    #[test]
    fn apns_settings_come_together() {
        let base = [("OWNER_KAS", "on"), ("OWNER_KAS_RELAY_CLIENT_SECRET", "s")];
        let mut p = base.to_vec();
        p.push(("APNS_KEY_PATH", "/k.p8"));
        assert!(settings(&p).is_err());
        p.extend([
            ("APNS_KEY_ID", "ABC123DEFG"),
            ("APNS_TEAM_ID", "M8GS7ZT95Y"),
        ]);
        let s = settings(&p).unwrap().unwrap();
        assert_eq!(s.apns.unwrap().topic, DEFAULT_APNS_TOPIC);
    }
}
