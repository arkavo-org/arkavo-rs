//! SARC ↔ OpenTDF v2 proto-JSON (claims-mode entity chain only).

use crate::modules::authzen::cwt_subject::{
    allowlist_environment, device_token_value, devices_bind, devices_from_context,
    sanitize_patreon, sanitize_patreon_entitlements, tool_value_slug, DecodedClaims, DeviceError,
    DEVICECHECK_AUD, MAX_FORWARDED_ENTITLEMENTS,
};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

const MCP_TOOL_FQN_PREFIX: &str = "https://arkavo.net/attr/mcp-tool/value/";
const MCP_SERVER_FQN_PREFIX: &str = "https://arkavo.net/attr/mcp-server/value/";
pub const MAX_CHAIN: usize = 8;
pub const MAX_EVALUATIONS: usize = 500;

/// What the facade read from a device token whose signature, `iss`, `exp` and
/// DeviceCheck `aud` it verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDevice {
    pub sub: String,
    pub iss: String,
    pub arkavo_account_id: Option<String>,
    /// The token carries an agent marker beside its device `arkavo_npe`, so
    /// the platform reads it as an agent's, never a device's.
    pub agent: bool,
}

impl From<&DecodedClaims> for VerifiedDevice {
    fn from(c: &DecodedClaims) -> Self {
        Self {
            sub: c.sub.clone(),
            iss: c.iss.clone(),
            arkavo_account_id: c.arkavo_account_id.clone(),
            agent: c.non_device_agent_marker,
        }
    }
}

/// Each device token the facade verified, keyed by the raw token. A token
/// missing from it did not verify.
pub type VerifiedDevices = HashMap<String, VerifiedDevice>;

/// Entities the chain for `context` needs: the person, every device sent
/// (with a token or not) and the environment, if any. Over `MAX_CHAIN` the
/// request is malformed.
pub fn chain_len(devices: usize, context: Option<&Value>) -> usize {
    let env_present = context
        .and_then(|c| c.get("environment"))
        .is_some_and(|v| !v.is_null());
    1 + devices + usize::from(env_present)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranslateError {
    Malformed(&'static str),
    ChainCap,
    IllegalAction,
    PepFqns,
    IllegalResourceId,
}

impl TranslateError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::Malformed(m) => m,
            Self::ChainCap => "entity chain exceeds 8",
            Self::IllegalAction => "mapped action is not a valid OpenTDF identifier",
            Self::PepFqns => "attribute_value_fqns not allowed for this resource.type",
            Self::IllegalResourceId => "resource.id is not a valid OpenTDF identifier",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainMap {
    Ok(Value),
    DenyClosed(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceMap {
    Fqns {
        ephemeral_id: String,
        fqns: Vec<String>,
    },
    DenyClosed {
        ephemeral_id: String,
        message: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionOut {
    pub ephemeral_id: String,
    pub permit: bool,
    pub required_obligations: Vec<String>,
}

/// OpenTDF identifier charset after lowercasing.
pub fn opentdf_identifier_ok(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() {
        return false;
    }
    let alnum = |c: u8| c.is_ascii_alphanumeric();
    let mid = |c: u8| alnum(c) || c == b'_' || c == b'-';
    if !alnum(b[0]) {
        return false;
    }
    if b.len() == 1 {
        return true;
    }
    alnum(b[b.len() - 1]) && b[1..b.len() - 1].iter().copied().all(mid)
}

pub fn map_action(authzen_name: &str) -> Result<String, TranslateError> {
    if authzen_name.is_empty() {
        return Err(TranslateError::Malformed("action.name"));
    }
    let lower = authzen_name.to_ascii_lowercase();
    let mapped = match lower.as_str() {
        "read" => "read".to_string(),
        "tools/call" | "execute_tool" => "execute_tool".to_string(),
        "tools/list" => "tools_list".to_string(),
        "rewrap" | "decrypt" => "decrypt".to_string(),
        other => {
            if let Some(grant) = other.strip_prefix("issue:cwt:") {
                format!("issue_cwt_{}", grant.replace(['/', ':'], "_"))
            } else {
                other.replace(['/', ':'], "_")
            }
        }
    };
    if !opentdf_identifier_ok(&mapped) {
        return Err(TranslateError::IllegalAction);
    }
    Ok(mapped)
}

fn pep_fqns_present(resource: &Value) -> bool {
    resource
        .get("properties")
        .and_then(|p| p.as_object())
        .is_some_and(|o| o.contains_key("attribute_value_fqns"))
}

fn pep_fqns(resource: &Value) -> Vec<String> {
    resource
        .get("properties")
        .and_then(|p| p.get("attribute_value_fqns"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn tool_attr_value(id: &str) -> Result<String, TranslateError> {
    let slug = tool_value_slug(id);
    let value = match slug.as_str() {
        "device_tap" => "device_management_tap",
        "device_swipe" => "device_management_swipe",
        other => other,
    };
    if !opentdf_identifier_ok(value) {
        return Err(TranslateError::IllegalResourceId);
    }
    Ok(value.to_string())
}

pub fn map_resource(resource: &Value) -> Result<ResourceMap, TranslateError> {
    let rtype = resource
        .get("type")
        .and_then(Value::as_str)
        .ok_or(TranslateError::Malformed("resource.type"))?;
    let id = resource
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(TranslateError::Malformed("resource.id"))?;
    match rtype {
        "tool" => {
            if pep_fqns_present(resource) {
                return Err(TranslateError::PepFqns);
            }
            let value = tool_attr_value(id)?;
            Ok(ResourceMap::Fqns {
                ephemeral_id: id.to_string(),
                fqns: vec![format!("{MCP_TOOL_FQN_PREFIX}{value}")],
            })
        }
        "mcp_server" => {
            if pep_fqns_present(resource) {
                return Err(TranslateError::PepFqns);
            }
            if !opentdf_identifier_ok(id) {
                return Err(TranslateError::IllegalResourceId);
            }
            Ok(ResourceMap::Fqns {
                ephemeral_id: id.to_string(),
                fqns: vec![format!("{MCP_SERVER_FQN_PREFIX}{id}")],
            })
        }
        "catalog_item" => {
            let fqns = pep_fqns(resource);
            if fqns.is_empty() {
                Ok(ResourceMap::DenyClosed {
                    ephemeral_id: id.to_string(),
                    message: "catalog_item missing attribute_value_fqns",
                })
            } else {
                Ok(ResourceMap::Fqns {
                    ephemeral_id: id.to_string(),
                    fqns,
                })
            }
        }
        "tdf" | "kas" => {
            let fqns = pep_fqns(resource);
            if fqns.is_empty() {
                Ok(ResourceMap::DenyClosed {
                    ephemeral_id: id.to_string(),
                    message: "resource missing attribute_value_fqns",
                })
            } else {
                Ok(ResourceMap::Fqns {
                    ephemeral_id: id.to_string(),
                    fqns,
                })
            }
        }
        _ => {
            let fqns = pep_fqns(resource);
            if fqns.is_empty() {
                Ok(ResourceMap::DenyClosed {
                    ephemeral_id: id.to_string(),
                    message: "resource missing attribute_value_fqns",
                })
            } else {
                Ok(ResourceMap::Fqns {
                    ephemeral_id: id.to_string(),
                    fqns,
                })
            }
        }
    }
}

fn claims_entity(ephemeral_id: &str, subject: bool, claims: Value) -> Value {
    json!({
        "ephemeralId": ephemeral_id,
        "category": if subject { "CATEGORY_SUBJECT" } else { "CATEGORY_ENVIRONMENT" },
        "claims": {
            "@type": "type.googleapis.com/google.protobuf.Struct",
            "value": claims,
        },
    })
}

fn pe_claims(subject: &Value) -> Result<Value, TranslateError> {
    let id = subject
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(TranslateError::Malformed("subject.id"))?;
    // NOTE: this forwards a deliberately narrow subset of subject.properties.
    // `cwt_subject::subject()` emits email_verified, idp, arkavo_account_id,
    // arkavo_roles and arkavo_entitlements. arkavo_entitlements is forwarded,
    // filtered to the Patreon definitions the platform's composite `patreon`
    // source owns (pep_assertable). iss and arkavo_account_id are forwarded as
    // sent: the platform binds a device token to the person only when both
    // equal the token's, compared exactly, so neither is ever rewritten.
    // email_verified, idp and arkavo_roles are still dropped (see the explicit
    // assertion in chain_pe_then_devices_then_env_mismatched_prefix_bind). If
    // any OpenTDF subject mapping keys on a dropped claim it can never match,
    // so the two halves need to agree (draft-arkavo-authzen-cwt-00).
    let mut m = Map::new();
    m.insert("sub".into(), json!(id));
    if let Some(props) = subject.get("properties").and_then(Value::as_object) {
        if let Some(iss) = props.get("iss") {
            m.insert("iss".into(), iss.clone());
        }
        if let Some(account) = props
            .get("arkavo_account_id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            m.insert("arkavo_account_id".into(), json!(account));
        }
        if let Some(email) = props.get("email") {
            m.insert("email".into(), email.clone());
        }
        if let Some(patreon) = props.get("arkavo_patreon") {
            // `subject` is PEP-supplied and unsigned, so the same allowlist the
            // CWT->SARC direction applies must apply here. This is the only path
            // that reaches the PDP: without it a PEP can assert campaign_id for
            // a consumer (the catalog policy keys on
            // patreon.arkavo.com/attr/campaign/value/<campaign_id>) and can push
            // OAuth tokens into the upstream request and its decision log.
            let patreon = sanitize_patreon(patreon);
            if let Some(uid) = patreon.get("patreon_user_id") {
                m.insert("patreon_user_id".into(), uid.clone());
            }
            m.insert("arkavo_patreon".into(), patreon);
        }
        if let Some(raw) = props.get("arkavo_entitlements") {
            match sanitize_patreon_entitlements(raw) {
                Ok(Some(ents)) => {
                    m.insert("arkavo_entitlements".into(), ents);
                }
                Ok(None) => {}
                Err(count) => log::warn!(
                    "dropping forwarded arkavo_entitlements for subject {id}: {count} Patreon \
                     entitlements exceeds cap {MAX_FORWARDED_ENTITLEMENTS}"
                ),
            }
        }
    }
    Ok(Value::Object(m))
}

/// Whether the platform binds `device` to the person entity `pe`: the
/// token's `iss` and `arkavo_account_id` are non-empty and exactly equal the
/// person's (opentdf-platform composite `unboundReason`). It never reads `sub`.
fn binds_to_person(device: &VerifiedDevice, pe: &Value) -> bool {
    let equals = |claim: &str, token: &str| {
        !token.is_empty() && pe.get(claim).and_then(Value::as_str) == Some(token)
    };
    equals("iss", &device.iss)
        && device
            .arkavo_account_id
            .as_deref()
            .is_some_and(|a| equals("arkavo_account_id", a))
}

pub fn reconstruct_chain(
    subject: &Value,
    context: Option<&Value>,
    verified: &VerifiedDevices,
) -> Result<ChainMap, TranslateError> {
    let pe = pe_claims(subject)?;
    let pe_sub = pe["sub"].as_str().unwrap_or_default().to_string();
    let devices = match context {
        Some(ctx) => match devices_from_context(ctx) {
            Ok(d) => d,
            Err(DeviceError::MissingField(_)) => {
                return Err(TranslateError::Malformed("device missing required field"));
            }
            Err(DeviceError::BothDeviceAndDevices) => {
                return Err(TranslateError::Malformed(
                    "context.device and context.devices both present",
                ));
            }
            Err(DeviceError::EmptyDevices) => {
                return Err(TranslateError::Malformed("context.devices is empty"));
            }
            Err(DeviceError::BadToken) => {
                return Err(TranslateError::Malformed(
                    "device token must be a non-empty string with no surrounding whitespace",
                ));
            }
        },
        None => vec![],
    };
    let env_present = context
        .and_then(|c| c.get("environment"))
        .is_some_and(|v| !v.is_null());
    let e_count = if env_present { 1 } else { 0 };
    if chain_len(devices.len(), context) > MAX_CHAIN {
        return Err(TranslateError::ChainCap);
    }
    for d in &devices {
        if d.aud != DEVICECHECK_AUD {
            return Ok(ChainMap::DenyClosed(
                "device aud must be arkavo:devicecheck",
            ));
        }
        if !devices_bind(&pe_sub, &d.sub) {
            return Ok(ChainMap::DenyClosed(
                "device sub does not bind to subject.id",
            ));
        }
        // The token is what reaches the platform, so it must be a device's
        // token there, its own verified sub must bind, and it must bind as the
        // platform binds it, or the platform denies the whole chain.
        if let Some(token) = &d.token {
            let Some(device) = verified.get(token) else {
                return Ok(ChainMap::DenyClosed("device token does not verify"));
            };
            if device.agent {
                return Ok(ChainMap::DenyClosed("device token is not a device token"));
            }
            if !devices_bind(&pe_sub, &device.sub) {
                return Ok(ChainMap::DenyClosed(
                    "device token sub does not bind to subject.id",
                ));
            }
            if !binds_to_person(device, &pe) {
                return Ok(ChainMap::DenyClosed(
                    "device token does not bind to subject",
                ));
            }
        }
    }

    // A device reaches the platform as its signed token alone. One without a
    // token is dropped (the facade logs it): the platform would read its
    // claims as a device it cannot bind and deny the whole chain.
    let tokens: Vec<&str> = devices.iter().filter_map(|d| d.token.as_deref()).collect();
    let mut entities = Vec::with_capacity(1 + tokens.len() + e_count);
    entities.push(claims_entity("e0", true, pe));
    for token in tokens {
        entities.push(claims_entity(
            &format!("e{}", entities.len()),
            false,
            device_token_value(token),
        ));
    }
    if env_present {
        let env = allowlist_environment(&context.unwrap()["environment"]);
        entities.push(claims_entity(&format!("e{}", entities.len()), false, env));
    }
    Ok(ChainMap::Ok(json!({
        "ephemeralId": "chain",
        "entities": entities,
    })))
}

pub fn fulfillable_from_context(context: Option<&Value>) -> Vec<String> {
    context
        .and_then(|c| c.get("pep"))
        .and_then(|p| p.get("fulfillable_obligation_fqns"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub fn entity_identifier(chain: &Value) -> Value {
    json!({ "entityChain": chain })
}

pub fn resource_body(ephemeral_id: &str, fqns: &[String]) -> Value {
    json!({
        "ephemeralId": ephemeral_id,
        "attributeValues": { "fqns": fqns },
    })
}

pub fn get_decision_request(
    chain: &Value,
    action: &str,
    ephemeral_id: &str,
    fqns: &[String],
    fulfillable: &[String],
) -> Value {
    json!({
        "entityIdentifier": entity_identifier(chain),
        "action": { "name": action },
        "resource": resource_body(ephemeral_id, fqns),
        "fulfillableObligationFqns": fulfillable,
    })
}

pub fn multi_resource_request(
    chain: &Value,
    action: &str,
    resources: &[(String, Vec<String>)],
    fulfillable: &[String],
) -> Value {
    json!({
        "entityIdentifier": entity_identifier(chain),
        "action": { "name": action },
        "resources": resources.iter().map(|(id, fqns)| resource_body(id, fqns)).collect::<Vec<_>>(),
        "fulfillableObligationFqns": fulfillable,
    })
}

pub fn bulk_request(groups: &[Value]) -> Value {
    json!({ "decisionRequests": groups })
}

pub fn is_permit(decision: &str) -> bool {
    decision == "DECISION_PERMIT"
}

fn obligations_from(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Nested `GetDecisionResponse.decision.decision` (not a top-level enum string).
pub fn parse_get_decision_response(resp: &Value) -> DecisionOut {
    let nested = resp.get("decision");
    let decision = nested
        .and_then(|d| d.get("decision"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let ephemeral_id = nested
        .and_then(|d| d.get("ephemeralResourceId"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    DecisionOut {
        ephemeral_id,
        permit: is_permit(decision),
        required_obligations: obligations_from(nested.and_then(|d| d.get("requiredObligations"))),
    }
}

pub fn parse_resource_decisions(resp: &Value) -> Vec<DecisionOut> {
    resp.get("resourceDecisions")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|d| DecisionOut {
                    ephemeral_id: d
                        .get("ephemeralResourceId")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    permit: is_permit(d.get("decision").and_then(Value::as_str).unwrap_or("")),
                    required_obligations: obligations_from(d.get("requiredObligations")),
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn parse_bulk_responses(resp: &Value) -> Vec<Vec<DecisionOut>> {
    resp.get("decisionResponses")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(parse_resource_decisions).collect())
        .unwrap_or_default()
}

pub fn evaluation_id(rid: &str, index: Option<usize>) -> String {
    match index {
        Some(i) => format!("{rid}:{i}"),
        None => rid.to_string(),
    }
}

pub fn decision_context(
    rid: &str,
    index: Option<usize>,
    obligations: &[String],
    error: Option<Value>,
) -> Value {
    let mut ctx = Map::new();
    ctx.insert("evaluation_id".into(), json!(evaluation_id(rid, index)));
    ctx.insert("obligations".into(), json!({ "required": obligations }));
    if let Some(err) = error {
        ctx.insert("error".into(), err);
    }
    Value::Object(ctx)
}

pub fn authzen_decision(
    permit: bool,
    rid: &str,
    index: Option<usize>,
    obligations: &[String],
    error: Option<Value>,
) -> Value {
    json!({
        "decision": permit,
        "context": decision_context(rid, index, obligations, error),
    })
}

pub fn deny_closed(rid: &str, index: Option<usize>, message: &str) -> Value {
    authzen_decision(false, rid, index, &[], Some(json!({ "message": message })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_subject() -> Value {
        json!({
            "type": "identity",
            "id": "arkavo:550e8400-e29b-41d4-a716-446655440000",
            "properties": {
                "iss": "https://identity.arkavo.net",
                "idp": "arkavo",
                "email": "alice@example.com",
                "email_verified": true,
                "arkavo_account_id": "550e8400-e29b-41d4-a716-446655440000",
                "arkavo_roles": ["user"],
                "arkavo_entitlements": ["tdf:decrypt"],
                "arkavo_patreon": {
                    "role": "consumer",
                    "patreon_user_id": "12345678",
                    "memberships": [{
                        "campaign_id": "87654321",
                        "patron_status": "active_patron",
                        "tier_ids": ["111"],
                        "tier_slugs": ["supporter"]
                    }],
                    "verified_at": 1779996400,
                    "cache_expires_at": 1780000000
                }
            }
        })
    }

    const ACCOUNT: &str = "550e8400-e29b-41d4-a716-446655440000";

    /// A phone carrying its DeviceCheck token (opaque here: the facade
    /// verifies it) and a `class` of the old wire shape, which is never
    /// forwarded.
    fn phone() -> Value {
        json!({
            "sub": ACCOUNT,
            "iss": "https://identity.arkavo.net",
            "aud": "arkavo:devicecheck",
            "kid": "cGhvbmUta2lk",
            "class": "attested",
            "token": "phone-token"
        })
    }

    fn watch() -> Value {
        json!({
            "sub": ACCOUNT,
            "iss": "https://identity.arkavo.net",
            "aud": "arkavo:devicecheck",
            "kid": "d2F0Y2gta2lk",
            "token": "watch-token"
        })
    }

    /// Both tokens verified, each with the person's bare-UUID `sub`.
    /// A verified DeviceCheck token of the person `pe_subject` describes.
    fn person_device(sub: &str) -> VerifiedDevice {
        VerifiedDevice {
            sub: sub.to_string(),
            iss: "https://identity.arkavo.net".to_string(),
            arkavo_account_id: Some(ACCOUNT.to_string()),
            agent: false,
        }
    }

    fn verified() -> VerifiedDevices {
        ["phone-token", "watch-token"]
            .into_iter()
            .map(|t| (t.to_string(), person_device(ACCOUNT)))
            .collect()
    }

    fn chain_entities(chain: &ChainMap) -> Vec<Value> {
        let ChainMap::Ok(chain) = chain else {
            panic!("expected chain, got {chain:?}");
        };
        chain["entities"].as_array().unwrap().clone()
    }

    #[test]
    fn action_registry() {
        assert_eq!(map_action("read").unwrap(), "read");
        assert_eq!(map_action("tools/call").unwrap(), "execute_tool");
        assert_eq!(map_action("execute_tool").unwrap(), "execute_tool");
        assert_eq!(map_action("tools/list").unwrap(), "tools_list");
        assert_eq!(map_action("rewrap").unwrap(), "decrypt");
        assert_eq!(map_action("decrypt").unwrap(), "decrypt");
        assert_eq!(
            map_action("issue:cwt:authorization_code").unwrap(),
            "issue_cwt_authorization_code"
        );
        assert_eq!(map_action("READ").unwrap(), "read");
        assert_eq!(map_action("custom_ok").unwrap(), "custom_ok");
        assert_eq!(
            map_action("foo.bar").unwrap_err(),
            TranslateError::IllegalAction
        );
        assert_eq!(
            map_action("foo/bar.baz").unwrap_err(),
            TranslateError::IllegalAction
        );
        assert_eq!(
            map_action("").unwrap_err(),
            TranslateError::Malformed("action.name")
        );
    }

    #[test]
    fn tool_fqns_derived_not_pep() {
        let r = map_resource(&json!({"type":"tool","id":"git_commit"})).unwrap();
        assert_eq!(
            r,
            ResourceMap::Fqns {
                ephemeral_id: "git_commit".into(),
                fqns: vec!["https://arkavo.net/attr/mcp-tool/value/git_commit".into()],
            }
        );
        let dotted = map_resource(&json!({"type":"tool","id":"git.commit"})).unwrap();
        match dotted {
            ResourceMap::Fqns { fqns, .. } => {
                assert_eq!(fqns[0], "https://arkavo.net/attr/mcp-tool/value/git_commit");
            }
            _ => panic!("expected fqns"),
        }
        assert_eq!(
            map_resource(&json!({"type":"tool","id":"device_tap"})).unwrap(),
            ResourceMap::Fqns {
                ephemeral_id: "device_tap".into(),
                fqns: vec!["https://arkavo.net/attr/mcp-tool/value/device_management_tap".into()],
            }
        );
        assert_eq!(
            map_resource(&json!({
                "type":"tool","id":"git_commit",
                "properties":{"attribute_value_fqns":["https://evil/attr/x/value/y"]}
            }))
            .unwrap_err(),
            TranslateError::PepFqns
        );
    }

    #[test]
    fn mcp_server_derives_and_rejects_pep_fqns() {
        let r = map_resource(&json!({"type":"mcp_server","id":"mcp_arkavo_net"})).unwrap();
        assert_eq!(
            r,
            ResourceMap::Fqns {
                ephemeral_id: "mcp_arkavo_net".into(),
                fqns: vec!["https://arkavo.net/attr/mcp-server/value/mcp_arkavo_net".into()],
            }
        );
        assert_eq!(
            map_resource(&json!({"type":"mcp_server","id":"https://mcp.arkavo.net"})).unwrap_err(),
            TranslateError::IllegalResourceId
        );
        assert_eq!(
            map_resource(&json!({
                "type":"mcp_server","id":"mcp_arkavo_net",
                "properties":{"attribute_value_fqns":[]}
            }))
            .unwrap_err(),
            TranslateError::PepFqns
        );
    }

    #[test]
    fn catalog_item_empty_fqns_deny_closed() {
        let r = map_resource(&json!({"type":"catalog_item","id":"aa"})).unwrap();
        match r {
            ResourceMap::DenyClosed { ephemeral_id, .. } => assert_eq!(ephemeral_id, "aa"),
            _ => panic!("expected deny-closed"),
        }
        let ok = map_resource(&json!({
            "type":"catalog_item",
            "id":"aa",
            "properties":{"attribute_value_fqns":["https://patreon.arkavo.com/attr/tier/value/supporter"]}
        }))
        .unwrap();
        match ok {
            ResourceMap::Fqns { fqns, .. } => assert_eq!(fqns.len(), 1),
            _ => panic!("expected fqns"),
        }
    }

    #[test]
    fn chain_pe_then_devices_then_env_mismatched_prefix_bind() {
        let ctx = json!({
            "devices": [phone(), watch()],
            "environment": {
                "region": "us-east-1",
                "kind": "environment",
                "email": "injected@example.com",
                "patreon_access_token": "nope"
            }
        });
        let ChainMap::Ok(chain) =
            reconstruct_chain(&pe_subject(), Some(&ctx), &verified()).unwrap()
        else {
            panic!("expected chain");
        };
        let ents = chain["entities"].as_array().unwrap();
        assert_eq!(ents.len(), 4);
        assert_eq!(ents[0]["ephemeralId"], json!("e0"));
        assert_eq!(ents[0]["category"], json!("CATEGORY_SUBJECT"));
        assert_eq!(
            ents[0]["claims"]["value"]["sub"],
            json!("arkavo:550e8400-e29b-41d4-a716-446655440000")
        );
        assert_eq!(
            ents[0]["claims"]["value"]["email"],
            json!("alice@example.com")
        );
        assert_eq!(
            ents[0]["claims"]["value"]["patreon_user_id"],
            json!("12345678")
        );
        assert!(ents[0]["claims"]["value"].get("arkavo_roles").is_none());
        // A device is its signed token and nothing else: no PEP-asserted sub,
        // kid or class reaches the platform.
        assert_eq!(ents[1]["ephemeralId"], json!("e1"));
        assert_eq!(ents[1]["category"], json!("CATEGORY_ENVIRONMENT"));
        assert_eq!(
            ents[1]["claims"]["value"],
            json!({"arkavo_device_token": "phone-token"})
        );
        assert_eq!(ents[2]["ephemeralId"], json!("e2"));
        assert_eq!(ents[2]["category"], json!("CATEGORY_ENVIRONMENT"));
        assert_eq!(
            ents[2]["claims"]["value"],
            json!({"arkavo_device_token": "watch-token"})
        );
        assert_eq!(ents[3]["ephemeralId"], json!("e3"));
        assert_eq!(ents[3]["claims"]["value"]["region"], json!("us-east-1"));
        assert_eq!(ents[3]["claims"]["value"]["kind"], json!("environment"));
        assert!(ents[3]["claims"]["value"].get("email").is_none());
        assert!(ents[3]["claims"]["value"]
            .get("patreon_access_token")
            .is_none());
        assert!(chain.get("token").is_none());
    }

    /// The platform denies a whole chain carrying a device it cannot bind, and
    /// it binds only a signed token, so a device without one is dropped.
    #[test]
    fn chain_drops_a_device_without_a_token() {
        let mut bare = phone();
        bare.as_object_mut().unwrap().remove("token");
        let ctx = json!({
            "devices": [bare.clone(), watch()],
            "environment": { "region": "us-east-1" }
        });
        let ents =
            chain_entities(&reconstruct_chain(&pe_subject(), Some(&ctx), &verified()).unwrap());
        assert_eq!(ents.len(), 3);
        assert_eq!(ents[0]["category"], json!("CATEGORY_SUBJECT"));
        assert_eq!(ents[1]["ephemeralId"], json!("e1"));
        assert_eq!(
            ents[1]["claims"]["value"],
            json!({"arkavo_device_token": "watch-token"})
        );
        assert_eq!(ents[2]["ephemeralId"], json!("e2"));
        assert_eq!(ents[2]["claims"]["value"], json!({"region": "us-east-1"}));

        // A null token is no token.
        let mut null_token = phone();
        null_token["token"] = Value::Null;
        for device in [bare, null_token] {
            let ents = chain_entities(
                &reconstruct_chain(
                    &pe_subject(),
                    Some(&json!({ "device": device })),
                    &verified(),
                )
                .unwrap(),
            );
            assert_eq!(ents.len(), 1, "only the person is left");
            assert_eq!(ents[0]["category"], json!("CATEGORY_SUBJECT"));
        }
    }

    #[test]
    fn chain_device_token_must_be_a_non_empty_string() {
        // Whitespace would be verified trimmed but forwarded as sent, which
        // the platform's base64url decoding refuses.
        for token in [
            json!(""),
            json!(42),
            json!({"t": "x"}),
            json!(" phone-token"),
            json!("phone-token\n"),
        ] {
            let mut device = phone();
            device["token"] = token.clone();
            assert_eq!(
                reconstruct_chain(
                    &pe_subject(),
                    Some(&json!({ "device": device })),
                    &verified()
                )
                .unwrap_err(),
                TranslateError::Malformed(
                    "device token must be a non-empty string with no surrounding whitespace"
                ),
                "token {token}"
            );
        }
    }

    /// A token the facade did not verify, or whose verified `sub` is not the
    /// person's, denies the evaluation, as a PEP-asserted unbound `sub` does.
    #[test]
    fn chain_unverified_or_unbound_device_token_is_deny_closed() {
        let ctx = json!({ "devices": [phone(), watch()] });
        let mut only_watch = verified();
        only_watch.remove("phone-token");
        assert_eq!(
            reconstruct_chain(&pe_subject(), Some(&ctx), &only_watch).unwrap(),
            ChainMap::DenyClosed("device token does not verify")
        );
        let mut other = verified();
        other.insert(
            "watch-token".into(),
            person_device("00000000-0000-0000-0000-000000000000"),
        );
        assert_eq!(
            reconstruct_chain(&pe_subject(), Some(&ctx), &other).unwrap(),
            ChainMap::DenyClosed("device token sub does not bind to subject.id")
        );
        // The verified `sub` binds as a PEP-asserted one does: `arkavo:` aside.
        let mut prefixed = verified();
        prefixed.insert(
            "watch-token".into(),
            person_device(&format!("arkavo:{ACCOUNT}")),
        );
        assert!(matches!(
            reconstruct_chain(&pe_subject(), Some(&ctx), &prefixed).unwrap(),
            ChainMap::Ok(_)
        ));
    }

    /// The platform binds a device to the person by the token's `iss` and
    /// `arkavo_account_id`, each non-empty and exactly equal to the person
    /// entity's, and never by `sub`. A chain it would deny is deny-closed here.
    #[test]
    fn chain_device_token_binds_on_iss_and_account_id() {
        let ctx = json!({ "device": phone() });
        let deny = ChainMap::DenyClosed("device token does not bind to subject");
        let with_token = |v: VerifiedDevice| VerifiedDevices::from([("phone-token".into(), v)]);

        let mut other_account = person_device(ACCOUNT);
        other_account.arkavo_account_id = Some("00000000-0000-0000-0000-000000000000".into());
        let mut prefixed_account = person_device(ACCOUNT);
        prefixed_account.arkavo_account_id = Some(format!("arkavo:{ACCOUNT}"));
        let mut no_account = person_device(ACCOUNT);
        no_account.arkavo_account_id = None;
        let mut empty_account = person_device(ACCOUNT);
        empty_account.arkavo_account_id = Some(String::new());
        let mut other_iss = person_device(ACCOUNT);
        other_iss.iss = "https://other.example".into();
        for (why, v) in [
            ("account mismatch", other_account),
            ("prefixed token account", prefixed_account),
            ("token without account", no_account),
            ("token with empty account", empty_account),
            ("iss mismatch", other_iss),
        ] {
            assert_eq!(
                reconstruct_chain(&pe_subject(), Some(&ctx), &with_token(v)).unwrap(),
                deny,
                "{why}"
            );
        }

        // The person's side: missing, prefixed, non-string or a different iss.
        let mut no_subject_account = pe_subject();
        no_subject_account["properties"]
            .as_object_mut()
            .unwrap()
            .remove("arkavo_account_id");
        let mut prefixed_subject = pe_subject();
        prefixed_subject["properties"]["arkavo_account_id"] = json!(format!("arkavo:{ACCOUNT}"));
        let mut numeric_subject = pe_subject();
        numeric_subject["properties"]["arkavo_account_id"] = json!(42);
        let mut other_subject_iss = pe_subject();
        other_subject_iss["properties"]["iss"] = json!("https://other.example");
        let mut no_subject_iss = pe_subject();
        no_subject_iss["properties"]
            .as_object_mut()
            .unwrap()
            .remove("iss");
        for (why, subject) in [
            ("subject without account", no_subject_account),
            ("prefixed subject account", prefixed_subject),
            ("non-string subject account", numeric_subject),
            ("subject iss mismatch", other_subject_iss),
            ("subject without iss", no_subject_iss),
        ] {
            assert_eq!(
                reconstruct_chain(&subject, Some(&ctx), &verified()).unwrap(),
                deny,
                "{why}"
            );
        }

        // Matching iss and account bind.
        let ents =
            chain_entities(&reconstruct_chain(&pe_subject(), Some(&ctx), &verified()).unwrap());
        assert_eq!(
            ents[1]["claims"]["value"],
            json!({"arkavo_device_token": "phone-token"})
        );
    }

    /// A token with an agent marker beside its device `arkavo_npe` is an
    /// agent's to the platform's `KindOf`, never a device, and would deny the
    /// whole chain there.
    #[test]
    fn chain_agent_token_as_device_is_deny_closed() {
        let mut agent = person_device(ACCOUNT);
        agent.agent = true;
        assert_eq!(
            reconstruct_chain(
                &pe_subject(),
                Some(&json!({ "device": phone() })),
                &VerifiedDevices::from([("phone-token".into(), agent)])
            )
            .unwrap(),
            ChainMap::DenyClosed("device token is not a device token")
        );
    }

    #[test]
    fn chain_len_counts_every_device_sent() {
        let mut bare = phone();
        bare.as_object_mut().unwrap().remove("token");
        let ctx = json!({ "devices": [bare, watch()], "environment": { "region": "us-east-1" } });
        assert_eq!(chain_len(2, Some(&ctx)), 4);
        assert_eq!(chain_len(2, Some(&json!({ "environment": null }))), 3);
        assert_eq!(chain_len(0, None), 1);
    }

    #[test]
    fn chain_wrong_aud_and_unbound_are_deny_closed() {
        let bad_aud = json!({"device": {
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "iss": "https://identity.arkavo.net",
            "aud": "arkavo",
            "kid": "YWxwaGEtZGV2aWNlLWtpZA"
        }});
        assert!(matches!(
            reconstruct_chain(&pe_subject(), Some(&bad_aud), &verified()).unwrap(),
            ChainMap::DenyClosed(_)
        ));
        let unbound = json!({"device": {
            "sub": "00000000-0000-0000-0000-000000000000",
            "iss": "https://identity.arkavo.net",
            "aud": "arkavo:devicecheck",
            "kid": "YWxwaGEtZGV2aWNlLWtpZA"
        }});
        assert!(matches!(
            reconstruct_chain(&pe_subject(), Some(&unbound), &verified()).unwrap(),
            ChainMap::DenyClosed(_)
        ));
        // The PEP-asserted checks hold for a device with a verified token too.
        let mut unbound_with_token = phone();
        unbound_with_token["sub"] = json!("00000000-0000-0000-0000-000000000000");
        assert_eq!(
            reconstruct_chain(
                &pe_subject(),
                Some(&json!({ "device": unbound_with_token })),
                &verified()
            )
            .unwrap(),
            ChainMap::DenyClosed("device sub does not bind to subject.id")
        );
    }

    #[test]
    fn chain_missing_device_field_is_malformed() {
        let missing = json!({"device": {
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "iss": "https://identity.arkavo.net",
            "aud": "arkavo:devicecheck"
        }});
        assert_eq!(
            reconstruct_chain(&pe_subject(), Some(&missing), &verified()).unwrap_err(),
            TranslateError::Malformed("device missing required field")
        );
    }

    #[test]
    fn chain_cap_and_both_device_fields() {
        let mut devices = Vec::new();
        for i in 0..7 {
            devices.push(json!({
                "sub": "550e8400-e29b-41d4-a716-446655440000",
                "iss": "https://identity.arkavo.net",
                "aud": "arkavo:devicecheck",
                "kid": format!("kid{i}")
            }));
        }
        let over = json!({
            "devices": devices,
            "environment": { "region": "us-east-1" }
        });
        assert_eq!(
            reconstruct_chain(&pe_subject(), Some(&over), &verified()).unwrap_err(),
            TranslateError::ChainCap
        );
        let both = json!({"device": phone(), "devices": [phone()]});
        assert_eq!(
            reconstruct_chain(&pe_subject(), Some(&both), &verified()).unwrap_err(),
            TranslateError::Malformed("context.device and context.devices both present")
        );
    }

    #[test]
    fn nested_get_decision_not_top_level_string() {
        let nested = json!({
            "decision": {
                "ephemeralResourceId": "git_commit",
                "decision": "DECISION_PERMIT",
                "requiredObligations": ["https://example/obl/x"]
            }
        });
        let out = parse_get_decision_response(&nested);
        assert!(out.permit);
        assert_eq!(out.required_obligations, vec!["https://example/obl/x"]);
        let footgun = json!({ "decision": "DECISION_PERMIT" });
        assert!(!parse_get_decision_response(&footgun).permit);
        let deny = json!({
            "decision": { "decision": "DECISION_DENY", "requiredObligations": [] }
        });
        assert!(!parse_get_decision_response(&deny).permit);
        let missing = json!({});
        assert!(!parse_get_decision_response(&missing).permit);
    }

    #[test]
    fn evaluation_id_and_obligations_shape() {
        assert_eq!(evaluation_id("rid", None), "rid");
        assert_eq!(evaluation_id("rid", Some(1)), "rid:1");
        let ctx = decision_context("rid", Some(0), &["https://o".into()], None);
        assert_eq!(ctx["evaluation_id"], json!("rid:0"));
        assert_eq!(ctx["obligations"]["required"], json!(["https://o"]));
    }

    #[test]
    fn catalog_fixture_multiresource_shape() {
        let req: Value =
            serde_json::from_str(include_str!("fixtures/catalog_evaluations_request.json"))
                .unwrap();
        let expected: Value =
            serde_json::from_str(include_str!("fixtures/catalog_multiresource_request.json"))
                .unwrap();
        // The facade verified the fixture's device token as the person's.
        let token = req["context"]["device"]["token"].as_str().unwrap();
        let verified = VerifiedDevices::from([(token.to_string(), person_device(ACCOUNT))]);
        let ChainMap::Ok(chain) =
            reconstruct_chain(&req["subject"], req.get("context"), &verified).unwrap()
        else {
            panic!("chain");
        };
        let action = map_action(req["action"]["name"].as_str().unwrap()).unwrap();
        let mut resources = Vec::new();
        for ev in req["evaluations"].as_array().unwrap() {
            match map_resource(&ev["resource"]).unwrap() {
                ResourceMap::Fqns { ephemeral_id, fqns } => resources.push((ephemeral_id, fqns)),
                ResourceMap::DenyClosed { .. } => panic!("unexpected deny"),
            }
        }
        let fulfillable = fulfillable_from_context(req.get("context"));
        let body = multi_resource_request(&chain, &action, &resources, &fulfillable);
        assert_eq!(body, expected);
        assert!(body["entityIdentifier"].get("token").is_none());
    }

    #[test]
    fn mcp_fixture_getdecision_shape() {
        let req: Value =
            serde_json::from_str(include_str!("fixtures/mcp_evaluation_request.json")).unwrap();
        let expected: Value =
            serde_json::from_str(include_str!("fixtures/mcp_getdecision_request.json")).unwrap();
        let ChainMap::Ok(chain) =
            reconstruct_chain(&req["subject"], req.get("context"), &VerifiedDevices::new())
                .unwrap()
        else {
            panic!("chain");
        };
        let action = map_action(req["action"]["name"].as_str().unwrap()).unwrap();
        let ResourceMap::Fqns { ephemeral_id, fqns } = map_resource(&req["resource"]).unwrap()
        else {
            panic!("resource");
        };
        let body = get_decision_request(
            &chain,
            &action,
            &ephemeral_id,
            &fqns,
            &fulfillable_from_context(req.get("context")),
        );
        assert_eq!(body, expected);
    }

    fn pe_with_entitlements(ents: Value, role: &str) -> Value {
        let mut s = pe_subject();
        s["properties"]["arkavo_entitlements"] = ents;
        s["properties"]["arkavo_patreon"]["role"] = json!(role);
        s
    }

    #[test]
    fn pe_claims_forwards_patreon_entitlements_only() {
        let subject = pe_with_entitlements(
            json!([
                "https://patreon.arkavo.com/attr/campaign/value/13167240",
                "https://patreon.arkavo.com/attr/campaign-tier/value/13167240_supporter",
                "https://patreon.arkavo.com/attr/campaign-tier/value/13167240_tier-555",
                "https://patreon.arkavo.com/attr/campaign-tier/value/7237273_Supporter",
                "tdf:decrypt",
                "https://arkavo.ai/attr/tdf/value/decrypt",
                "https://patreon.arkavo.com/attr/arkavo-creator/value/publish",
                42,
                "HTTPS://PATREON.ARKAVO.COM/attr/campaign/value/7237273",
                "https://patreon.arkavo.com/attr/campaign/value/abc",
                "https://patreon.arkavo.com/attr/campaign-tier/value/7237273",
                "https://patreon.arkavo.com.evil/attr/campaign/value/1",
                "https://patreon.arkavo.com/attrs/campaign/value/1",
                "https://patreon.arkavo.com/attr/campaign/value/1/2",
                "http://patreon.arkavo.com/attr/campaign/value/1",
                "https://patreon.arkavo.com/attr/campaign/value/13167240"
            ]),
            "consumer",
        );
        let claims = pe_claims(&subject).unwrap();
        assert_eq!(
            claims["arkavo_entitlements"],
            json!([
                "https://patreon.arkavo.com/attr/campaign/value/13167240",
                "https://patreon.arkavo.com/attr/campaign-tier/value/13167240_supporter",
                "https://patreon.arkavo.com/attr/campaign-tier/value/13167240_tier-555",
                "https://patreon.arkavo.com/attr/campaign-tier/value/7237273_supporter",
                "https://patreon.arkavo.com/attr/campaign/value/7237273"
            ])
        );
    }

    #[test]
    fn pe_claims_omits_entitlements_when_none_allowed() {
        let claims = pe_claims(&pe_subject()).unwrap();
        assert!(claims.get("arkavo_entitlements").is_none());

        let subject = pe_with_entitlements(
            json!("https://patreon.arkavo.com/attr/campaign/value/1"),
            "consumer",
        );
        let claims = pe_claims(&subject).unwrap();
        assert!(claims.get("arkavo_entitlements").is_none());
    }

    #[test]
    fn pe_claims_entitlement_cap() {
        let fqns = |n: usize| -> Value {
            Value::Array(
                (0..n)
                    .map(|i| {
                        json!(format!(
                            "https://patreon.arkavo.com/attr/campaign/value/{i}"
                        ))
                    })
                    .collect(),
            )
        };
        let at_cap = pe_claims(&pe_with_entitlements(fqns(256), "consumer")).unwrap();
        assert_eq!(at_cap["arkavo_entitlements"].as_array().unwrap().len(), 256);
        let over = pe_claims(&pe_with_entitlements(fqns(257), "consumer")).unwrap();
        assert!(over.get("arkavo_entitlements").is_none());

        // The cap counts de-duplicated survivors: a duplicate and non-Patreon
        // entries on top of 256 distinct valid ones do not push it over.
        let mut padded = fqns(256).as_array().unwrap().clone();
        padded.push(json!("https://patreon.arkavo.com/attr/campaign/value/0"));
        padded.push(json!("tdf:decrypt"));
        padded.push(json!(
            "https://patreon.arkavo.com/attr/arkavo-creator/value/publish"
        ));
        let deduped = pe_claims(&pe_with_entitlements(Value::Array(padded), "consumer")).unwrap();
        assert_eq!(
            deduped["arkavo_entitlements"].as_array().unwrap().len(),
            256
        );
    }

    #[test]
    fn pe_claims_entitlements_are_role_blind() {
        let ents = json!([
            "https://patreon.arkavo.com/attr/campaign/value/13167240",
            "https://patreon.arkavo.com/attr/campaign-tier/value/13167240_supporter"
        ]);
        let consumer = pe_claims(&pe_with_entitlements(ents.clone(), "consumer")).unwrap();
        let creator = pe_claims(&pe_with_entitlements(ents, "creator")).unwrap();
        assert!(consumer.get("arkavo_entitlements").is_some());
        assert_eq!(
            consumer["arkavo_entitlements"],
            creator["arkavo_entitlements"]
        );
    }

    /// The platform binds a device token to the person by exact `iss` and
    /// `arkavo_account_id`, so both reach the subject entity as the PEP sent
    /// them: a rewritten value would never bind.
    #[test]
    fn pe_claims_forwards_iss_and_account_id_verbatim() {
        let claims = pe_claims(&pe_subject()).unwrap();
        assert_eq!(claims["iss"], json!("https://identity.arkavo.net"));
        assert_eq!(
            claims["arkavo_account_id"],
            json!("550e8400-e29b-41d4-a716-446655440000")
        );
        let mut prefixed = pe_subject();
        prefixed["properties"]["arkavo_account_id"] =
            json!("arkavo:550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(
            pe_claims(&prefixed).unwrap()["arkavo_account_id"],
            json!("arkavo:550e8400-e29b-41d4-a716-446655440000"),
            "arkavo_account_id is forwarded, never normalised"
        );
    }

    #[test]
    fn pe_claims_forwards_account_id_only_as_a_non_empty_string() {
        for bad in [json!(""), json!(42), json!(null), json!(["x"])] {
            let mut subject = pe_subject();
            subject["properties"]["arkavo_account_id"] = bad.clone();
            assert!(
                pe_claims(&subject)
                    .unwrap()
                    .get("arkavo_account_id")
                    .is_none(),
                "{bad}"
            );
        }
    }

    /// `context`/`subject` are PEP-supplied and unsigned. The patreon redaction
    /// must apply here too — this is the only path that reaches the PDP.
    #[test]
    fn pe_claims_sanitizes_pep_supplied_patreon() {
        let subject = json!({
            "type": "identity",
            "id": "arkavo:u1",
            "properties": {
                "iss": "https://identity.arkavo.net",
                "arkavo_patreon": {
                    "role": "consumer",
                    "campaign_id": "87654321",
                    "patreon_user_id": "12345678",
                    "patreon_access_token": "SECRET-oauth-token"
                }
            }
        });
        let claims = pe_claims(&subject).unwrap();
        let p = &claims["arkavo_patreon"];
        assert!(
            p.get("campaign_id").is_none(),
            "a consumer must not carry campaign_id to the PDP"
        );
        assert!(
            p.get("patreon_access_token").is_none(),
            "OAuth tokens must not reach the PDP or its decision log"
        );
        assert_eq!(p["role"], json!("consumer"));
    }
}
