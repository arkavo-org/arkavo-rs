//! Verification-agnostic CWT → `$token` / SARC projection (draft-arkavo-authzen-cwt-00 PR 2).
//! Wired by the AuthZEN facade; clippy `--bin arks` without `--tests` would
//! otherwise treat these as dead.

#![allow(dead_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Map, Value};
use std::fmt;

pub const DEVICECHECK_AUD: &str = "arkavo:devicecheck";

/// The claim a device's entity carries its signed DeviceCheck token under, the
/// only claim the platform reads from it.
pub const DEVICE_TOKEN_CLAIM: &str = "arkavo_device_token";

/// Strip a single leading `arkavo:` prefix. Does not strip `apple:` or `client:`.
pub fn subject_id_bind(s: &str) -> &str {
    s.strip_prefix("arkavo:").unwrap_or(s)
}

#[derive(Debug, Clone)]
pub enum Aud {
    One(String),
    Many(Vec<String>),
}

impl Aud {
    pub fn contains(&self, want: &str) -> bool {
        match self {
            Aud::One(s) => s == want,
            Aud::Many(v) => v.iter().any(|s| s == want),
        }
    }
}

/// Service client IDs from a comma-separated list: trimmed, empty entries dropped.
pub fn parse_client_ids(raw: &str) -> std::collections::HashSet<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// The client ID of a service account's `client_credentials` token: `sub`
/// `client:<id>`, role `service-account`, and `<id>` in `aud`. `None` for any
/// other kind of token. Shared by every service-credential check.
pub fn service_client_id(claims: &DecodedClaims) -> Option<&str> {
    let id = claims
        .sub
        .strip_prefix("client:")
        .filter(|s| !s.is_empty())?;
    let service = claims
        .arkavo_roles
        .as_ref()
        .is_some_and(|r| r.iter().any(|x| x == "service-account"));
    (service && claims.aud.contains(id)).then_some(id)
}

/// Already-verified CWT claims. Mapping only — no COSE verify here.
#[derive(Debug, Clone)]
pub struct DecodedClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Aud,
    pub exp: u64,
    pub iat: u64,
    pub nbf: Option<u64>,
    pub cti: Vec<u8>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub idp: Option<String>,
    pub arkavo_account_id: Option<String>,
    pub arkavo_roles: Option<Vec<String>>,
    pub arkavo_entitlements: Option<Vec<String>>,
    pub client_id: Option<String>,
    pub arkavo_patreon: Option<Value>,
    /// OIDC access tokens carry `scope`; a passkey auth CWT never does.
    pub scope: Option<String>,
    /// OIDC access tokens carry `auth_time`; a passkey auth CWT never does.
    pub auth_time: Option<u64>,
    /// Any agent marker (arkavo_npe, arkavo_swarm, arkavo_state_version, or
    /// the `agent` role). Presence alone counts, whatever the value.
    pub agent_marker: bool,
    /// An agent marker as the platform's `KindOf` reads one: an `arkavo_npe`
    /// whose `type` is anything but `device`, `arkavo_swarm`,
    /// `arkavo_state_version`, or the `agent` role (a list or a string). A
    /// DeviceCheck token's device `arkavo_npe` alone is not one.
    pub non_device_agent_marker: bool,
    /// The `arkavo_npe` map as JSON (a DeviceCheck token's `{type: "device", ...}`).
    pub arkavo_npe: Option<Value>,
    /// A proof-of-possession key (`cnf`, claim 8) is present.
    pub cnf: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct DeviceObject {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub kid: String,
    /// The raw DeviceCheck CWT as the PEP received it (unpadded base64url).
    /// A bearer credential: `Debug` redacts it and nothing logs it.
    pub token: Option<String>,
}

impl fmt::Debug for DeviceObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceObject")
            .field("sub", &self.sub)
            .field("iss", &self.iss)
            .field("aud", &self.aud)
            .field("kid", &self.kid)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceError {
    MissingField(&'static str),
    BothDeviceAndDevices,
    EmptyDevices,
    /// `token` present but not a non-empty string, or with surrounding
    /// whitespace: verification trims it, but it is forwarded as sent and the
    /// platform's base64url decoding refuses whitespace.
    BadToken,
}

/// `$token` map: text claim names, no integer keys, no `cnf`.
pub fn token_map(claims: &DecodedClaims) -> Value {
    let mut m = Map::new();
    m.insert("iss".into(), json!(claims.iss));
    m.insert("sub".into(), json!(claims.sub));
    m.insert(
        "aud".into(),
        match &claims.aud {
            Aud::One(s) => json!(s),
            Aud::Many(v) => json!(v),
        },
    );
    m.insert("exp".into(), json!(claims.exp));
    m.insert("iat".into(), json!(claims.iat));
    if let Some(nbf) = claims.nbf {
        m.insert("nbf".into(), json!(nbf));
    }
    m.insert("cti".into(), json!(URL_SAFE_NO_PAD.encode(&claims.cti)));
    insert_opt_str(&mut m, "email", claims.email.as_deref());
    if let Some(v) = claims.email_verified {
        m.insert("email_verified".into(), json!(v));
    }
    insert_opt_str(&mut m, "idp", claims.idp.as_deref());
    insert_opt_str(
        &mut m,
        "arkavo_account_id",
        claims.arkavo_account_id.as_deref(),
    );
    if let Some(roles) = &claims.arkavo_roles {
        m.insert("arkavo_roles".into(), json!(roles));
    }
    if let Some(ents) = &claims.arkavo_entitlements {
        m.insert("arkavo_entitlements".into(), json!(ents));
    }
    insert_opt_str(&mut m, "client_id", claims.client_id.as_deref());
    if let Some(patreon) = &claims.arkavo_patreon {
        m.insert("arkavo_patreon".into(), sanitize_patreon(patreon));
    }
    Value::Object(m)
}

fn insert_opt_str(m: &mut Map<String, Value>, k: &str, v: Option<&str>) {
    if let Some(s) = v {
        m.insert(k.into(), json!(s));
    }
}

/// Fields of `arkavo_patreon` that may reach the PDP. Everything else — OAuth
/// access/refresh tokens, e-mail, anything a future issuer adds — is dropped:
/// this projection is copied into `$token` and `subject.properties` and lands
/// in decision logs, so it must be an allowlist, not a denylist of one key.
const PATREON_ALLOWED: [&str; 5] = [
    "role",
    "patreon_user_id",
    "memberships",
    "verified_at",
    "cache_expires_at",
];

pub fn sanitize_patreon(p: &Value) -> Value {
    let Some(obj) = p.as_object() else {
        return Value::Object(Map::new());
    };
    let mut out = Map::new();
    for k in PATREON_ALLOWED {
        if let Some(v) = obj.get(k) {
            out.insert(k.into(), v.clone());
        }
    }
    // Only a creator may carry campaign_id. An absent, mis-cased or non-string
    // role redacts rather than passing the field through.
    if obj.get("role").and_then(Value::as_str) == Some("creator") {
        if let Some(v) = obj.get("campaign_id") {
            out.insert("campaign_id".into(), v.clone());
        }
    }
    Value::Object(out)
}

/// Upper bound on forwarded Patreon entitlements. Over it nothing is forwarded.
pub const MAX_FORWARDED_ENTITLEMENTS: usize = 256;

const PATREON_ATTR_PREFIX: &str = "https://patreon.arkavo.com/attr/";

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The creator-publishing entitlement, granted by the platform's `identity-core`
/// source (arkavo-rs#95). Patreon and App Store Creator Membership both mint it.
const PUBLISH_ENTITLEMENT: &str = "https://patreon.arkavo.com/attr/arkavo-creator/value/publish";

/// True for exactly `campaign/value/<digits>`,
/// `campaign-tier/value/<digits>_<[a-z0-9-]+>` and `arkavo-creator/value/publish`
/// under the Patreon attr namespace. Expects an already ASCII-lowercased FQN.
fn is_patreon_entitlement(fqn: &str) -> bool {
    if fqn == PUBLISH_ENTITLEMENT {
        return true;
    }
    let Some(rest) = fqn.strip_prefix(PATREON_ATTR_PREFIX) else {
        return false;
    };
    if let Some(id) = rest.strip_prefix("campaign/value/") {
        return is_digits(id);
    }
    if let Some(v) = rest.strip_prefix("campaign-tier/value/") {
        return v
            .split_once('_')
            .is_some_and(|(id, slug)| is_digits(id) && is_slug(slug));
    }
    false
}

/// Filter PEP-supplied `arkavo_entitlements` down to the Patreon definitions the
/// platform's composite `patreon` source owns, plus the publish entitlement its
/// `identity-core` source owns. Lowercases, de-duplicates (input
/// order), and returns `Ok(None)` when the input is not an array or nothing
/// survives. More than `MAX_FORWARDED_ENTITLEMENTS` survivors is `Err(count)`
/// (never truncates); the caller owns logging so one subject yields one line.
pub fn sanitize_patreon_entitlements(v: &Value) -> Result<Option<Value>, usize> {
    let Some(arr) = v.as_array() else {
        return Ok(None);
    };
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for fqn in arr.iter().filter_map(Value::as_str) {
        let fqn = fqn.to_ascii_lowercase();
        if is_patreon_entitlement(&fqn) && seen.insert(fqn.clone()) {
            out.push(fqn);
        }
    }
    if out.is_empty() {
        return Ok(None);
    }
    if out.len() > MAX_FORWARDED_ENTITLEMENTS {
        return Err(out.len());
    }
    Ok(Some(Value::Array(
        out.into_iter().map(Value::String).collect(),
    )))
}

/// AuthZEN subject (`type=identity`, `id` as minted).
pub fn subject(claims: &DecodedClaims) -> Value {
    let mut properties = Map::new();
    properties.insert("iss".into(), json!(claims.iss));
    insert_opt_str(&mut properties, "email", claims.email.as_deref());
    if let Some(v) = claims.email_verified {
        properties.insert("email_verified".into(), json!(v));
    }
    insert_opt_str(&mut properties, "idp", claims.idp.as_deref());
    insert_opt_str(
        &mut properties,
        "arkavo_account_id",
        claims.arkavo_account_id.as_deref(),
    );
    if let Some(roles) = &claims.arkavo_roles {
        properties.insert("arkavo_roles".into(), json!(roles));
    }
    if let Some(ents) = &claims.arkavo_entitlements {
        properties.insert("arkavo_entitlements".into(), json!(ents));
    }
    if let Some(patreon) = &claims.arkavo_patreon {
        properties.insert("arkavo_patreon".into(), sanitize_patreon(patreon));
    }
    json!({
        "type": "identity",
        "id": claims.sub,
        "properties": properties,
    })
}

pub fn devices_bind(pe_sub: &str, device_sub: &str) -> bool {
    subject_id_bind(pe_sub) == subject_id_bind(device_sub)
}

pub fn allowlist_device(obj: &Value) -> Result<DeviceObject, DeviceError> {
    let map = obj.as_object().ok_or(DeviceError::MissingField("sub"))?;
    let req = |k: &'static str| -> Result<String, DeviceError> {
        map.get(k)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or(DeviceError::MissingField(k))
    };
    let (sub, iss, aud, kid) = (req("sub")?, req("iss")?, req("aud")?, req("kid")?);
    // Optional: a PEP that has the device's token sends it. null is no token.
    let token = match map.get("token") {
        None | Some(Value::Null) => None,
        Some(Value::String(t)) if !t.is_empty() && t.trim() == t => Some(t.clone()),
        Some(_) => return Err(DeviceError::BadToken),
    };
    Ok(DeviceObject {
        sub,
        iss,
        aud,
        kid,
        token,
    })
}

/// A device's entity claims: its signed DeviceCheck token and nothing else.
/// The platform takes a device's class and app only from a token it verifies
/// itself, and binds it to the person by the token's `iss` and
/// `arkavo_account_id`, so no PEP-asserted claim is forwarded beside it.
pub fn device_token_value(token: &str) -> Value {
    json!({ DEVICE_TOKEN_CLAIM: token })
}

/// Environment allowlist: `{region}` plus optional `kind`. Other keys dropped.
pub fn allowlist_environment(obj: &Value) -> Value {
    let mut out = Map::new();
    if let Some(map) = obj.as_object() {
        if let Some(r) = map.get("region") {
            out.insert("region".into(), r.clone());
        }
        if let Some(k) = map.get("kind") {
            out.insert("kind".into(), k.clone());
        }
    }
    Value::Object(out)
}

pub fn devices_from_context(context: &Value) -> Result<Vec<DeviceObject>, DeviceError> {
    let Some(obj) = context.as_object() else {
        return Ok(vec![]);
    };
    let has_device = obj.contains_key("device");
    let has_devices = obj.contains_key("devices");
    if has_device && has_devices {
        return Err(DeviceError::BothDeviceAndDevices);
    }
    if has_device {
        return Ok(vec![allowlist_device(&obj["device"])?]);
    }
    if has_devices {
        let arr = obj["devices"].as_array().ok_or(DeviceError::EmptyDevices)?;
        if arr.is_empty() {
            return Err(DeviceError::EmptyDevices);
        }
        arr.iter().map(allowlist_device).collect()
    } else {
        Ok(vec![])
    }
}

/// `context.agent` fallbacks (COAZ-MCP CWT profile override 3).
pub fn context_agent(claims: &DecodedClaims, platform_audience: Option<&str>) -> Option<String> {
    if let Some(id) = claims.client_id.as_deref().filter(|s| !s.is_empty()) {
        return Some(id.to_string());
    }
    if let Some(rest) = claims.sub.strip_prefix("client:") {
        if !rest.is_empty() {
            return Some(rest.to_string());
        }
    }
    let members: Vec<&str> = match &claims.aud {
        Aud::One(s) => vec![s.as_str()],
        Aud::Many(v) => v.iter().map(String::as_str).collect(),
    };
    let filtered: Vec<&str> = members
        .into_iter()
        .filter(|a| {
            *a != "arkavo" && *a != DEVICECHECK_AUD && platform_audience.is_none_or(|p| *a != p)
        })
        .collect();
    if filtered.len() == 1 {
        Some(filtered[0].to_string())
    } else {
        None
    }
}

/// Lowercase slug matching OpenTDF attribute-value charset.
/// OpenTDF attribute-value charset. Alphanumerics lowercase, `-` is preserved
/// (it is legal in an attribute value and keeps `a-b` distinct from `a.b`), and
/// every other run of characters collapses to a single `_` separator. Dropping
/// those characters outright — as this used to — made distinct identities
/// collide: `.../tenant/a` and `.../tenanta` both slugged to the same value,
/// which an OpenTDF policy would then treat as one server.
///
/// This narrows the collision class but does not eliminate it: separators are
/// not distinguished from one another, so `host:8443` and `host/8443` still
/// share a slug. Closing that needs an encoding the spec has to pin down
/// (draft-arkavo-authzen-cwt-00) — pass an explicit `override_slug` for any
/// identifier that is not a bare `host[:port]` until then.
fn slugify(input: &str) -> String {
    let mut out = String::new();
    let mut pending_sep = false;
    for c in input.trim().chars() {
        if c.is_ascii_alphanumeric() || c == '-' {
            if pending_sep && !out.is_empty() {
                out.push('_');
            }
            pending_sep = false;
            out.push(c.to_ascii_lowercase());
        } else {
            pending_sep = true;
        }
    }
    out.trim_matches('_').to_string()
}

pub fn mcp_server_slug(resource_id: &str, override_slug: Option<&str>) -> String {
    if let Some(s) = override_slug.filter(|s| !s.is_empty()) {
        return slugify(s);
    }
    // strip_prefix on a lowercased copy: trim_start_matches would strip a
    // repeated scheme ("https://https://evil.example" -> "evil.example") and
    // the match must not be case-sensitive ("HTTPS://" is the same server).
    let lower = resource_id.trim().to_ascii_lowercase();
    let stripped = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(lower.as_str());
    slugify(stripped)
}

pub fn tool_value_slug(tool_name: &str) -> String {
    slugify(tool_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oidc_pe() -> DecodedClaims {
        DecodedClaims {
            iss: "https://identity.arkavo.net".into(),
            sub: "arkavo:550e8400-e29b-41d4-a716-446655440000".into(),
            aud: Aud::Many(vec![
                "https://mcp.arkavo.net".into(),
                "https://platform.arkavo.net".into(),
            ]),
            exp: 1_780_000_000,
            iat: 1_779_996_400,
            nbf: None,
            cti: vec![0u8; 16],
            email: Some("a@example.com".into()),
            email_verified: Some(true),
            idp: Some("arkavo".into()),
            arkavo_account_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
            arkavo_roles: Some(vec!["member".into()]),
            arkavo_entitlements: None,
            client_id: None,
            arkavo_patreon: None,
            scope: None,
            auth_time: None,
            agent_marker: false,
            non_device_agent_marker: false,
            arkavo_npe: None,
            cnf: false,
        }
    }

    #[test]
    fn bind_strips_only_arkavo_prefix() {
        assert_eq!(
            subject_id_bind("arkavo:550e8400-e29b-41d4-a716-446655440000"),
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(
            subject_id_bind("550e8400-e29b-41d4-a716-446655440000"),
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(subject_id_bind("apple:abc"), "apple:abc");
        assert_eq!(
            subject_id_bind("client:catalog-node"),
            "client:catalog-node"
        );
        assert!(devices_bind(
            "arkavo:550e8400-e29b-41d4-a716-446655440000",
            "550e8400-e29b-41d4-a716-446655440000"
        ));
        assert!(devices_bind(
            "arkavo:550e8400-e29b-41d4-a716-446655440000",
            "arkavo:550e8400-e29b-41d4-a716-446655440000"
        ));
        assert!(!devices_bind("apple:abc", "abc"));
        assert!(!devices_bind("client:x", "x"));
    }

    #[test]
    fn token_map_text_names_omits_cnf() {
        let v = token_map(&oidc_pe());
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("iss"));
        assert!(obj.contains_key("sub"));
        assert!(obj.contains_key("aud"));
        assert!(obj.contains_key("exp"));
        assert!(obj.contains_key("iat"));
        assert!(obj.contains_key("cti"));
        assert_eq!(obj.get("cnf"), None);
        assert!(!obj.keys().any(|k| k.chars().all(|c| c.is_ascii_digit())));
        assert_eq!(obj["cti"], json!(URL_SAFE_NO_PAD.encode([0u8; 16])));
        assert_eq!(
            obj["sub"],
            json!("arkavo:550e8400-e29b-41d4-a716-446655440000")
        );
        assert!(obj["aud"].as_array().unwrap().len() == 2);
        let mut one = oidc_pe();
        one.aud = Aud::One("arkavo".into());
        assert_eq!(token_map(&one)["aud"], json!("arkavo"));
    }

    #[test]
    fn consumer_patreon_omits_campaign_id() {
        let mut c = oidc_pe();
        c.arkavo_patreon = Some(json!({
            "role": "consumer",
            "patreon_user_id": "12345678",
            "campaign_id": "87654321",
            "memberships": [],
            "verified_at": 1779996400,
            "cache_expires_at": 1780000000
        }));
        let p = token_map(&c)["arkavo_patreon"].clone();
        assert_eq!(p["role"], json!("consumer"));
        assert!(p.get("campaign_id").is_none());
        let mut creator = oidc_pe();
        creator.arkavo_patreon = Some(json!({
            "role": "creator",
            "patreon_user_id": "99990001",
            "campaign_id": "87654321",
            "memberships": [],
            "verified_at": 1779996400,
            "cache_expires_at": 1780000000
        }));
        assert_eq!(
            token_map(&creator)["arkavo_patreon"]["campaign_id"],
            json!("87654321")
        );
    }

    #[test]
    fn subject_keeps_minted_sub() {
        let s = subject(&oidc_pe());
        assert_eq!(s["type"], json!("identity"));
        assert_eq!(
            s["id"],
            json!("arkavo:550e8400-e29b-41d4-a716-446655440000")
        );
        assert_eq!(s["properties"]["iss"], json!("https://identity.arkavo.net"));
    }

    #[test]
    fn device_allowlist_drops_unknown_and_requires_fields() {
        let raw = json!({
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "iss": "https://identity.arkavo.net",
            "aud": "arkavo:devicecheck",
            "kid": "YWxwaGEtZGV2aWNlLWtpZA",
            "email": "nope@example.com",
            "patreon_user_id": "x"
        });
        let d = allowlist_device(&raw).unwrap();
        assert_eq!(d.sub, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(d.token, None);
        assert_eq!(
            allowlist_device(&json!({"sub":"a","iss":"i","aud":"arkavo:devicecheck"})),
            Err(DeviceError::MissingField("kid"))
        );
        // A token does not stand in for the required fields.
        assert_eq!(
            allowlist_device(&json!({"token": "t"})),
            Err(DeviceError::MissingField("sub"))
        );
    }

    #[test]
    fn device_token_is_optional_but_must_be_a_string() {
        let mut raw = json!({
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "iss": "https://identity.arkavo.net",
            "aud": "arkavo:devicecheck",
            "kid": "YWxwaGEtZGV2aWNlLWtpZA",
            "token": "2D2ESqIB"
        });
        assert_eq!(
            allowlist_device(&raw).unwrap().token.as_deref(),
            Some("2D2ESqIB")
        );
        raw["token"] = Value::Null;
        assert_eq!(allowlist_device(&raw).unwrap().token, None);
        for bad in [
            json!(""),
            json!(7),
            json!(["2D2ESqIB"]),
            json!(" 2D2ESqIB"),
            json!("2D2ESqIB\r\n"),
        ] {
            raw["token"] = bad;
            assert_eq!(allowlist_device(&raw), Err(DeviceError::BadToken));
        }
    }

    /// A device reaches the platform as its signed token alone.
    #[test]
    fn device_token_value_is_the_token_alone() {
        assert_eq!(
            device_token_value("2D2ESqIB"),
            json!({"arkavo_device_token": "2D2ESqIB"})
        );
    }

    /// The raw token is a bearer credential: never in a log line, so never in
    /// a `Debug` rendering either.
    #[test]
    fn device_debug_redacts_the_token() {
        let d = allowlist_device(&json!({
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "iss": "https://identity.arkavo.net",
            "aud": "arkavo:devicecheck",
            "kid": "YWxwaGEtZGV2aWNlLWtpZA",
            "token": "SECRET-device-token"
        }))
        .unwrap();
        let shown = format!("{d:?}");
        assert!(!shown.contains("SECRET-device-token"), "{shown}");
        assert!(shown.contains("YWxwaGEtZGV2aWNlLWtpZA"), "{shown}");
    }

    #[test]
    fn devices_from_context_zero_one_many() {
        assert!(devices_from_context(&json!({})).unwrap().is_empty());
        let one = json!({
            "device": {
                "sub": "550e8400-e29b-41d4-a716-446655440000",
                "iss": "https://identity.arkavo.net",
                "aud": "arkavo:devicecheck",
                "kid": "cGhvbmUta2lk"
            }
        });
        assert_eq!(devices_from_context(&one).unwrap().len(), 1);
        let two = json!({
            "devices": [
                {
                    "sub": "550e8400-e29b-41d4-a716-446655440000",
                    "iss": "https://identity.arkavo.net",
                    "aud": "arkavo:devicecheck",
                    "kid": "cGhvbmUta2lk"
                },
                {
                    "sub": "550e8400-e29b-41d4-a716-446655440000",
                    "iss": "https://identity.arkavo.net",
                    "aud": "arkavo:devicecheck",
                    "kid": "d2F0Y2gta2lk"
                }
            ]
        });
        let ds = devices_from_context(&two).unwrap();
        assert_eq!(ds[0].kid, "cGhvbmUta2lk");
        assert_eq!(ds[1].kid, "d2F0Y2gta2lk");
        let both = json!({"device": two["devices"][0], "devices": two["devices"]});
        assert_eq!(
            devices_from_context(&both),
            Err(DeviceError::BothDeviceAndDevices)
        );
        assert_eq!(
            devices_from_context(&json!({"devices": []})),
            Err(DeviceError::EmptyDevices)
        );
    }

    #[test]
    fn environment_allowlist_drops_ers_keys() {
        let env = allowlist_environment(&json!({
            "region": "us-east-1",
            "kind": "environment",
            "sub": "injected",
            "email": "x@y.z",
            "arkavo_patreon": {},
            "patreon_access_token": "t",
            "patreon_user_id": "1",
            "preferred_username": "u"
        }));
        let obj = env.as_object().unwrap();
        assert_eq!(obj["region"], json!("us-east-1"));
        assert_eq!(obj["kind"], json!("environment"));
        assert_eq!(obj.len(), 2);
    }

    #[test]
    fn agent_fallbacks() {
        let mut c = oidc_pe();
        c.client_id = Some("agent-app".into());
        assert_eq!(
            context_agent(&c, Some("https://platform.arkavo.net")).as_deref(),
            Some("agent-app")
        );
        c.client_id = None;
        c.sub = "client:catalog-node".into();
        assert_eq!(
            context_agent(&c, Some("https://platform.arkavo.net")).as_deref(),
            Some("catalog-node")
        );
        c.sub = "arkavo:550e8400-e29b-41d4-a716-446655440000".into();
        // multi-aud minus platform leaves mcp
        assert_eq!(
            context_agent(&c, Some("https://platform.arkavo.net")).as_deref(),
            Some("https://mcp.arkavo.net")
        );
        c.aud = Aud::Many(vec![
            "https://mcp.arkavo.net".into(),
            "https://other.example".into(),
            "https://platform.arkavo.net".into(),
        ]);
        assert_eq!(context_agent(&c, Some("https://platform.arkavo.net")), None);
    }

    #[test]
    fn slugs() {
        assert_eq!(
            mcp_server_slug("https://mcp.arkavo.net", None),
            "mcp_arkavo_net"
        );
        assert_eq!(
            mcp_server_slug("https://mcp.arkavo.net", Some("custom_slug")),
            "custom_slug"
        );
        assert_eq!(tool_value_slug("git.commit"), "git_commit");
        assert_eq!(tool_value_slug("filesystem_read"), "filesystem_read");
    }

    // --- redaction must fail closed (allowlist, not denylist) ---

    #[test]
    fn patreon_redacts_campaign_id_when_role_missing() {
        let mut c = oidc_pe();
        c.arkavo_patreon = Some(json!({
            "campaign_id": "87654321",
            "memberships": []
        }));
        let p = token_map(&c)["arkavo_patreon"].clone();
        assert!(p.get("campaign_id").is_none());
    }

    #[test]
    fn patreon_redacts_campaign_id_for_unknown_role() {
        for role in [json!("Consumer"), json!("subscriber"), json!(7)] {
            let mut c = oidc_pe();
            c.arkavo_patreon = Some(json!({
                "role": role,
                "campaign_id": "87654321"
            }));
            let p = token_map(&c)["arkavo_patreon"].clone();
            assert!(
                p.get("campaign_id").is_none(),
                "campaign_id leaked for role {role:?}"
            );
        }
    }

    // --- slugs must not collide across distinct server identities ---

    #[test]
    fn mcp_slug_distinguishes_path_boundaries() {
        assert_ne!(
            mcp_server_slug("https://mcp.example.net/tenant/a", None),
            mcp_server_slug("https://mcp.example.net/tenanta", None)
        );
    }

    #[test]
    fn mcp_slug_distinguishes_port_and_hyphen() {
        assert_ne!(
            mcp_server_slug("https://mcp.example.net:8443", None),
            mcp_server_slug("https://mcp.example.net8443", None)
        );
        assert_ne!(
            mcp_server_slug("https://mcp-example.net", None),
            mcp_server_slug("https://mcp.example.net", None)
        );
    }

    #[test]
    fn mcp_slug_override_is_sanitized() {
        assert_eq!(
            mcp_server_slug("x", Some("Bad Slug/../evil")),
            "bad_slug_evil"
        );
    }

    #[test]
    fn tool_slug_is_sanitized() {
        assert_eq!(tool_value_slug("git commit --amend"), "git_commit_--amend");
    }

    #[test]
    fn patreon_projection_is_a_field_allowlist() {
        let mut c = oidc_pe();
        c.arkavo_patreon = Some(json!({
            "role": "creator",
            "patreon_user_id": "12345678",
            "campaign_id": "87654321",
            "memberships": [],
            "verified_at": 1779996400,
            "cache_expires_at": 1780000000,
            "patreon_access_token": "SECRET-oauth-token",
            "patreon_refresh_token": "SECRET-refresh",
            "email": "leak@example.com"
        }));
        let p = token_map(&c)["arkavo_patreon"].clone();
        for leaked in ["patreon_access_token", "patreon_refresh_token", "email"] {
            assert!(p.get(leaked).is_none(), "{leaked} must not reach the PDP");
        }
        assert_eq!(p["role"], json!("creator"));
        assert_eq!(p["campaign_id"], json!("87654321"));
    }

    #[test]
    fn token_map_projects_nbf() {
        let mut c = oidc_pe();
        c.nbf = Some(1_779_996_400);
        assert_eq!(token_map(&c)["nbf"], json!(1_779_996_400u64));
    }

    #[test]
    fn mcp_slug_scheme_strip_is_case_insensitive() {
        assert_eq!(
            mcp_server_slug("HTTPS://mcp.example.net", None),
            mcp_server_slug("https://mcp.example.net", None)
        );
    }

    #[test]
    fn mcp_slug_does_not_strip_repeated_schemes() {
        assert_ne!(
            mcp_server_slug("https://https://evil.example", None),
            mcp_server_slug("https://evil.example", None)
        );
    }
}
