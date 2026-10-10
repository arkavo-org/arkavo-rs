//! TDF manifest → the content keys plus the policy they are bound to.
//!
//! Profile v1: exactly one wrapped key for this KAS with an intact binding.
//! Profile v2 (arkavo-ios ADR-0055): a policy listing `arkavo:components`,
//! and one wrapped 16-byte key per component, each with an intact binding
//! and a `keyBinding` naming its component. Both need at least one data
//! attribute, every one of them well formed.

use super::strict_json::has_unique_keys;
use super::LicenseError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use rsa::{Oaep, RsaPrivateKey};
use serde_json::Value;
use sha1::Sha1;
use sha2::Sha256;

/// The policy member that makes a manifest profile v2 (ADR-0055 §3).
pub const COMPONENTS_KEY: &str = "arkavo:components";
/// `keyBinding` = HMAC-SHA256(key, this prefix + id) (ADR-0055 §3).
const KEY_BINDING_PREFIX: &str = "arkavo:fps:component:v1:";

/// A profile v2 component kind. Version 2 lists `video`, then optionally
/// `audio`, each with its kind as its id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentKind {
    Video,
    Audio,
}

impl ComponentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ComponentKind::Video => "video",
            ComponentKind::Audio => "audio",
        }
    }
}

/// One profile v2 component whose key unwrapped, verified its policy binding
/// and matched its `keyBinding`.
pub struct CheckedComponent {
    pub id: String,
    pub kind: ComponentKind,
    /// Never log it.
    pub key: [u8; 16],
}

/// The checked content keys. Never log them.
pub enum PolicyKeys {
    /// Profile v1: the whole DEK, 16 or 32 bytes.
    Single(Vec<u8>),
    /// Profile v2: one key per component, in the policy's order.
    Components(Vec<CheckedComponent>),
}

pub struct CheckedPolicy {
    pub keys: PolicyKeys,
    pub policy_uuid: String,
    pub fqns: Vec<String>,
    /// Recording's content IV from `encryptionInformation.method.iv`; the
    /// FairPlay CKC carries it (ADR-0050).
    pub content_iv: [u8; 16],
}

/// scheme://host[:non-default-port][/path], lower-cased by `url`, with a
/// trailing "/" and one trailing "/kas" segment removed.
pub fn normalize_kas_url(raw: &str) -> Option<String> {
    let u = url::Url::parse(raw.trim()).ok()?;
    let host = u.host_str()?;
    let mut path = u.path().trim_end_matches('/').to_string();
    if let Some(p) = path.strip_suffix("/kas") {
        path = p.to_string();
    }
    let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
    Some(format!("{}://{}{}{}", u.scheme(), host, port, path))
}

const FORBIDDEN_MANIFEST: LicenseError = LicenseError::Forbidden("manifest refused");

pub fn check_manifest(
    manifest_json: &[u8],
    rsa: &RsaPrivateKey,
    kas_urls: &[String],
) -> Result<CheckedPolicy, LicenseError> {
    let m: Value = serde_json::from_slice(manifest_json)
        .map_err(|_| LicenseError::BadRequest("manifest is not JSON"))?;
    let ei = m.get("encryptionInformation").ok_or(FORBIDDEN_MANIFEST)?;
    // A broken package, not an authorization outcome: 400, so the viewer
    // does not tell the person they lack access. The IV is not secret.
    let content_iv = ei
        .pointer("/method/iv")
        .and_then(Value::as_str)
        .and_then(|s| STANDARD.decode(s.trim()).ok())
        .and_then(|iv| <[u8; 16]>::try_from(iv).ok())
        .ok_or(LicenseError::BadRequest("content iv must be 16 bytes"))?;
    let kaos = ei
        .get("keyAccess")
        .and_then(Value::as_array)
        .ok_or(FORBIDDEN_MANIFEST)?;
    let policy_b64 = ei
        .get("policy")
        .and_then(Value::as_str)
        .ok_or(FORBIDDEN_MANIFEST)?;
    // Read before any key is unwrapped, to choose the profile. Nothing read
    // here is acted on until every binding over `policy_b64` has verified.
    let policy_bytes = STANDARD
        .decode(policy_b64)
        .map_err(|_| FORBIDDEN_MANIFEST)?;
    let policy: Value = serde_json::from_slice(&policy_bytes).map_err(|_| FORBIDDEN_MANIFEST)?;
    let keys = match policy.get(COMPONENTS_KEY) {
        None => PolicyKeys::Single(check_single_key(kaos, policy_b64, rsa, kas_urls)?),
        Some(list) => {
            // serde_json keeps the last of repeated keys and the viewer refuses
            // them, so refusing them here means both read one document.
            if !has_unique_keys(manifest_json) || !has_unique_keys(&policy_bytes) {
                return Err(LicenseError::Forbidden("duplicate JSON key"));
            }
            PolicyKeys::Components(check_components(list, kaos, policy_b64, rsa, kas_urls)?)
        }
    };
    let (policy_uuid, fqns) = policy_subject(&policy)?;
    Ok(CheckedPolicy {
        keys,
        policy_uuid,
        fqns,
        content_iv,
    })
}

/// Profile v1: exactly one wrapped key, 16 or 32 bytes. Its binding is
/// checked with the whole key, before any FairPlay truncation.
fn check_single_key(
    kaos: &[Value],
    policy_b64: &str,
    rsa: &RsaPrivateKey,
    kas_urls: &[String],
) -> Result<Vec<u8>, LicenseError> {
    let [kao] = kaos else {
        return Err(LicenseError::Forbidden(
            "exactly one key access object required",
        ));
    };
    let dek = unwrap_key(kao, rsa, kas_urls)?;
    if dek.len() != 16 && dek.len() != 32 {
        return Err(LicenseError::Forbidden("unexpected key size"));
    }
    verify_policy_binding(kao, &dek, policy_b64)?;
    Ok(dek)
}

/// Profile v2 (ADR-0055 §7 steps 1 to 3): the list's shape, one key access
/// per component, and for each its unwrap, size, policy binding and
/// `keyBinding`; then no two components may share a key.
fn check_components(
    list: &Value,
    kaos: &[Value],
    policy_b64: &str,
    rsa: &RsaPrivateKey,
    kas_urls: &[String],
) -> Result<Vec<CheckedComponent>, LicenseError> {
    let shape = component_shape(list)?;
    if kaos.len() != shape.len() {
        return Err(LicenseError::Forbidden(
            "one key access object per component required",
        ));
    }
    let mut checked: Vec<CheckedComponent> = Vec::with_capacity(shape.len());
    for ((kind, key_binding), kao) in shape.into_iter().zip(kaos) {
        let key: [u8; 16] = unwrap_key(kao, rsa, kas_urls)?
            .as_slice()
            .try_into()
            .map_err(|_| LicenseError::Forbidden("component key must be 16 bytes"))?;
        verify_policy_binding(kao, &key, policy_b64)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).map_err(|_| FORBIDDEN_MANIFEST)?;
        mac.update(KEY_BINDING_PREFIX.as_bytes());
        mac.update(kind.as_str().as_bytes());
        mac.verify_slice(&key_binding)
            .map_err(|_| LicenseError::Forbidden("key binding mismatch"))?;
        // keyBinding covers the id, so one key under two ids passes it.
        if checked.iter().any(|c| c.key == key) {
            return Err(LicenseError::Forbidden("components share a key"));
        }
        checked.push(CheckedComponent {
            id: kind.as_str().to_string(),
            kind,
            key,
        });
    }
    Ok(checked)
}

/// Version 2's list (ADR-0055 §3): `video` first, then optionally `audio`,
/// each exactly `{id, kind, keyBinding}` with its kind as its id and a
/// 32-byte `keyBinding` in standard base64. Returns each kind and binding.
fn component_shape(list: &Value) -> Result<Vec<(ComponentKind, Vec<u8>)>, LicenseError> {
    const VERSION_2: [ComponentKind; 2] = [ComponentKind::Video, ComponentKind::Audio];
    let entries = list
        .as_array()
        .ok_or(LicenseError::Forbidden("components must be a list"))?;
    if entries.is_empty() || entries.len() > VERSION_2.len() {
        return Err(LicenseError::Forbidden("unsupported component list"));
    }
    entries
        .iter()
        .zip(VERSION_2)
        .map(|(entry, kind)| {
            let object = entry
                .as_object()
                .filter(|o| o.len() == 3)
                .ok_or(LicenseError::Forbidden("malformed component"))?;
            let name = Some(kind.as_str());
            if object.get("id").and_then(Value::as_str) != name
                || object.get("kind").and_then(Value::as_str) != name
            {
                return Err(LicenseError::Forbidden("unsupported component"));
            }
            let binding = object
                .get("keyBinding")
                .and_then(Value::as_str)
                .and_then(|b| STANDARD.decode(b).ok())
                .filter(|b| b.len() == 32)
                .ok_or(LicenseError::Forbidden("malformed component"))?;
            Ok((kind, binding))
        })
        .collect()
}

/// A `wrapped` key access for an accepted KAS, unwrapped with RSA-OAEP-SHA1.
fn unwrap_key(
    kao: &Value,
    rsa: &RsaPrivateKey,
    kas_urls: &[String],
) -> Result<Vec<u8>, LicenseError> {
    if kao.get("type").and_then(Value::as_str) != Some("wrapped") {
        return Err(LicenseError::Forbidden("key access type must be wrapped"));
    }
    let url = kao
        .get("url")
        .and_then(Value::as_str)
        .and_then(normalize_kas_url);
    if !url.is_some_and(|u| kas_urls.contains(&u)) {
        return Err(LicenseError::Forbidden("key access names another KAS"));
    }
    let wrapped = kao
        .get("wrappedKey")
        .and_then(Value::as_str)
        .ok_or(FORBIDDEN_MANIFEST)?;
    let wrapped = STANDARD.decode(wrapped).map_err(|_| FORBIDDEN_MANIFEST)?;
    rsa.decrypt_blinded(&mut OsRng, Oaep::new::<Sha1>(), &wrapped)
        .map_err(|_| LicenseError::Forbidden("key unwrap failed"))
}

/// The key access's binding, as a string or `{hash}`, must be
/// `base64(HMAC-SHA256(key, base64 policy string))`.
fn verify_policy_binding(kao: &Value, key: &[u8], policy_b64: &str) -> Result<(), LicenseError> {
    let binding = match kao.get("policyBinding") {
        Some(Value::String(s)) => s.as_str(),
        Some(Value::Object(o)) => o
            .get("hash")
            .and_then(Value::as_str)
            .ok_or(FORBIDDEN_MANIFEST)?,
        _ => return Err(FORBIDDEN_MANIFEST),
    };
    let expected = STANDARD
        .decode(binding.trim())
        .map_err(|_| FORBIDDEN_MANIFEST)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| FORBIDDEN_MANIFEST)?;
    mac.update(policy_b64.as_bytes());
    mac.verify_slice(&expected)
        .map_err(|_| LicenseError::Forbidden("policy binding mismatch"))
}

/// The policy uuid and its data attribute FQNs: at least one, all well formed.
fn policy_subject(policy: &Value) -> Result<(String, Vec<String>), LicenseError> {
    let policy_uuid = policy
        .get("uuid")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(LicenseError::Forbidden("policy has no uuid"))?
        .to_string();
    let fqns: Vec<String> = policy
        .pointer("/body/dataAttributes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|d| {
                    d.get("attribute")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .ok_or(LicenseError::Forbidden(
                            "policy has a malformed data attribute",
                        ))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    if fqns.is_empty() {
        return Err(LicenseError::Forbidden("policy has no data attributes"));
    }
    Ok((policy_uuid, fqns))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::DecodePrivateKey;
    use serde_json::{json, Value};

    use crate::modules::license::fixtures::fixtures;

    fn key() -> rsa::RsaPrivateKey {
        rsa::RsaPrivateKey::from_pkcs8_pem(&fixtures().key_pem).unwrap()
    }
    fn kas() -> Vec<String> {
        vec![normalize_kas_url("https://platform.arkavo.net").unwrap()]
    }
    fn allowed() -> Value {
        serde_json::from_str(&fixtures().manifest_allowed).unwrap()
    }
    fn check(v: &Value) -> Result<CheckedPolicy, LicenseError> {
        check_manifest(v.to_string().as_bytes(), &key(), &kas())
    }

    #[test]
    fn allowed_manifest_passes() {
        let p = check(&allowed()).unwrap();
        assert_eq!(p.policy_uuid, "3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b");
        assert_eq!(
            p.fqns,
            vec!["https://patreon.arkavo.com/attr/campaign-tier/value/11111111_gold"]
        );
        let PolicyKeys::Single(dek) = &p.keys else {
            panic!("a policy without components is profile v1");
        };
        assert_eq!(
            hex::encode(dek),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        assert_eq!(
            hex::encode(p.content_iv),
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        );
    }

    #[test]
    fn content_iv_must_be_16_bytes() {
        let twelve = STANDARD.encode([7u8; 12]);
        let seventeen = STANDARD.encode([7u8; 17]);
        for iv in [
            json!(""),
            json!(twelve),
            json!(seventeen),
            json!("not base64!"),
            json!(16),
        ] {
            let mut m = allowed();
            m["encryptionInformation"]["method"]["iv"] = iv.clone();
            assert!(
                matches!(
                    check(&m),
                    Err(LicenseError::BadRequest("content iv must be 16 bytes"))
                ),
                "{iv}"
            );
        }
        let mut m = allowed();
        m["encryptionInformation"]["method"]
            .as_object_mut()
            .unwrap()
            .remove("iv");
        assert!(matches!(
            check(&m),
            Err(LicenseError::BadRequest("content iv must be 16 bytes"))
        ));
    }

    #[test]
    fn string_form_binding_passes() {
        let mut m = allowed();
        let h = m["encryptionInformation"]["keyAccess"][0]["policyBinding"]["hash"].clone();
        m["encryptionInformation"]["keyAccess"][0]["policyBinding"] = h;
        assert!(check(&m).is_ok());
    }

    fn set_binding(m: &mut Value, hash: &str) {
        m["encryptionInformation"]["keyAccess"][0]["policyBinding"]["hash"] = json!(hash.trim());
    }

    #[test]
    fn refusals_are_403() {
        let mut cases: Vec<Value> = Vec::new();
        let mut m = allowed();
        set_binding(&mut m, &fixtures().binding_hex);
        cases.push(m);
        let mut m = allowed();
        set_binding(&mut m, &fixtures().binding_raw_json);
        cases.push(m);
        // Edited policy (binding no longer matches).
        let mut m = allowed();
        let edited = base64::engine::general_purpose::STANDARD.encode(
            r#"{"uuid":"3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b","body":{"dataAttributes":[{"attribute":"https://patreon.arkavo.com/attr/campaign/value/1"}],"dissem":[]}}"#);
        m["encryptionInformation"]["policy"] = json!(edited);
        cases.push(m);
        // Two key-access objects.
        let mut m = allowed();
        let kao = m["encryptionInformation"]["keyAccess"][0].clone();
        m["encryptionInformation"]["keyAccess"] = json!([kao.clone(), kao]);
        cases.push(m);
        // Foreign KAS.
        let mut m = allowed();
        m["encryptionInformation"]["keyAccess"][0]["url"] = json!("https://evil.example/kas");
        cases.push(m);
        // Not "wrapped".
        let mut m = allowed();
        m["encryptionInformation"]["keyAccess"][0]["type"] = json!("remote");
        cases.push(m);
        // Swapped wrappedKey (garbage ciphertext of the right size).
        let mut m = allowed();
        m["encryptionInformation"]["keyAccess"][0]["wrappedKey"] =
            json!(base64::engine::general_purpose::STANDARD.encode([7u8; 256]));
        cases.push(m);
        for (i, c) in cases.iter().enumerate() {
            assert!(
                matches!(check(c), Err(LicenseError::Forbidden(_))),
                "case {i}"
            );
        }
    }

    #[test]
    fn not_json_is_400() {
        assert!(matches!(
            check_manifest(b"nope", &key(), &kas()),
            Err(LicenseError::BadRequest(_))
        ));
    }

    #[test]
    fn kas_url_normalisation() {
        let n = |s| normalize_kas_url(s).unwrap();
        assert_eq!(
            n("https://platform.arkavo.net"),
            n("https://PLATFORM.arkavo.net:443/kas/")
        );
        assert_eq!(
            n("https://platform.arkavo.net/"),
            n("https://platform.arkavo.net/kas")
        );
        assert_ne!(
            n("https://platform.arkavo.net"),
            n("http://platform.arkavo.net")
        );
        assert_ne!(
            n("https://platform.arkavo.net"),
            n("https://platform.arkavo.net:8443")
        );
        assert!(normalize_kas_url("not a url").is_none());
    }

    fn rebind(policy_json: &str) -> Value {
        use hmac::{Hmac, Mac};
        let mut m = allowed();
        let b64 = base64::engine::general_purpose::STANDARD.encode(policy_json);
        let dek = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&dek).unwrap();
        mac.update(b64.as_bytes());
        let hash = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        m["encryptionInformation"]["policy"] = json!(b64);
        set_binding(&mut m, &hash);
        m
    }

    #[test]
    fn policy_shape_refusals() {
        let no_attrs = rebind(
            r#"{"uuid":"3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b","body":{"dataAttributes":[],"dissem":[]}}"#,
        );
        let no_uuid = rebind(
            r#"{"body":{"dataAttributes":[{"attribute":"https://patreon.arkavo.com/attr/campaign/value/1"}]}}"#,
        );
        let empty_body = rebind(r#"{"uuid":"3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b","body":{}}"#);
        for m in [no_attrs, no_uuid, empty_body] {
            assert!(matches!(check(&m), Err(LicenseError::Forbidden(_))));
        }
    }

    /// One good attribute must not carry a malformed sibling past the check.
    #[test]
    fn any_malformed_data_attribute_is_refused() {
        let good = r#"{"attribute":"https://patreon.arkavo.com/attr/campaign/value/1"}"#;
        for bad in [
            r#"{}"#,
            r#"{"attribute":""}"#,
            r#"{"attribute":7}"#,
            r#""x""#,
        ] {
            let m = rebind(&format!(
                r#"{{"uuid":"3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b","body":{{"dataAttributes":[{good},{bad}],"dissem":[]}}}}"#
            ));
            assert_eq!(
                check(&m).err(),
                Some(LicenseError::Forbidden(
                    "policy has a malformed data attribute"
                )),
                "entry {bad}"
            );
        }
    }

    // ---- Profile v2 (arkavo-ios ADR-0055) ----

    /// The shared test vectors' keys (arkavo-ios FairPlay profile v2 plan).
    fn video_key() -> [u8; 16] {
        std::array::from_fn(|i| i as u8)
    }
    fn audio_key() -> [u8; 16] {
        std::array::from_fn(|i| 0x10 + i as u8)
    }

    /// The shared vectors' policy after `arkavo:components`.
    const POLICY_REST: &str = r#""arkavo:classification":{"filter":"passed","flagged":[],"v":1},"body":{"dataAttributes":[{"attribute":"https://patreon.arkavo.com/attr/campaign-tier/value/13167240_24457368"}],"dissem":[]},"uuid":"3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b"}"#;
    /// The shared vectors' policy once the producer has inserted the list.
    const POLICY_AFTER: &str = r#"{"arkavo:components":[{"id":"video","kind":"video","keyBinding":"9n5YWFmN3MC7g9kJH/tZ98P5JMMEGIz1C+zwHbchEB4="},{"id":"audio","kind":"audio","keyBinding":"rVO1aH+bdtNnKvDGX38OaorFTRMJsPMGbMJNGKKLU3Q="}],"arkavo:classification":{"filter":"passed","flagged":[],"v":1},"body":{"dataAttributes":[{"attribute":"https://patreon.arkavo.com/attr/campaign-tier/value/13167240_24457368"}],"dissem":[]},"uuid":"3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b"}"#;

    fn v2() -> Value {
        serde_json::from_str(&fixtures().manifest_v2).unwrap()
    }

    fn hmac_b64(key: &[u8], data: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(data);
        STANDARD.encode(mac.finalize().into_bytes())
    }

    fn key_binding(key: &[u8], id: &str) -> String {
        hmac_b64(key, format!("arkavo:fps:component:v1:{id}").as_bytes())
    }

    /// One `arkavo:components` entry whose `keyBinding` is computed from `key`.
    fn component(id: &str, kind: &str, key: &[u8]) -> String {
        format!(
            r#"{{"id":"{id}","kind":"{kind}","keyBinding":"{}"}}"#,
            key_binding(key, id)
        )
    }

    /// The shared vectors' policy with `components` (JSON text) as its list.
    fn policy_with(components: &str) -> String {
        format!(r#"{{"arkavo:components":{components},{POLICY_REST}"#)
    }

    /// A manifest over `policy` with one key access per key, each wrapped to the
    /// test KAS key and bound to `policy` with its own key. Built here, not by
    /// openssl, so a test can pair any keys with any component list.
    fn v2_manifest(policy: &str, keys: &[&[u8]]) -> Value {
        let b64 = STANDARD.encode(policy);
        let public = rsa::RsaPublicKey::from(&key());
        let kaos: Vec<Value> = keys
            .iter()
            .map(|k| {
                let wrapped = public.encrypt(&mut OsRng, Oaep::new::<Sha1>(), k).unwrap();
                json!({"type": "wrapped", "url": "https://platform.arkavo.net/kas", "protocol": "kas",
                       "wrappedKey": STANDARD.encode(wrapped),
                       "policyBinding": {"alg": "HS256", "hash": hmac_b64(k, b64.as_bytes())}})
            })
            .collect();
        let mut m = v2();
        m["encryptionInformation"]["policy"] = json!(b64);
        m["encryptionInformation"]["keyAccess"] = json!(kaos);
        m
    }

    fn components(p: CheckedPolicy) -> Vec<CheckedComponent> {
        match p.keys {
            PolicyKeys::Components(c) => c,
            PolicyKeys::Single(_) => panic!("a policy with components is profile v2"),
        }
    }

    /// The fixture (made by openssl) and these helpers agree with the vectors
    /// every repository pins.
    #[test]
    fn v2_fixture_carries_the_shared_vectors() {
        assert_eq!(
            key_binding(&video_key(), "video"),
            "9n5YWFmN3MC7g9kJH/tZ98P5JMMEGIz1C+zwHbchEB4="
        );
        assert_eq!(
            key_binding(&audio_key(), "audio"),
            "rVO1aH+bdtNnKvDGX38OaorFTRMJsPMGbMJNGKKLU3Q="
        );
        assert_eq!(
            key_binding(&audio_key(), "video"),
            "4WqNpABYVXOM11ru1ClCNaEZZ8HOCCY+Ag0tppvil80="
        );
        let list = format!(
            "[{},{}]",
            component("video", "video", &video_key()),
            component("audio", "audio", &audio_key())
        );
        assert_eq!(policy_with(&list), POLICY_AFTER);
        let m = v2();
        let ei = &m["encryptionInformation"];
        let policy = STANDARD.decode(ei["policy"].as_str().unwrap()).unwrap();
        assert_eq!(String::from_utf8(policy).unwrap(), POLICY_AFTER);
        assert_eq!(
            ei["keyAccess"][0]["policyBinding"]["hash"],
            "YfWHFTZaDRIdmvAJhng0YHwLLHeKeEYNGKXCXd9wWqc="
        );
        assert_eq!(
            ei["keyAccess"][1]["policyBinding"]["hash"],
            "BYwGfQat7pK/d/NCvjZZqIryPOUA72NPx+1O/oBXF5A="
        );
        // The video-only policy and its binding under the video key.
        let video_only = policy_with(&format!("[{}]", component("video", "video", &video_key())));
        assert_eq!(
            video_only,
            format!(
                r#"{{"arkavo:components":[{{"id":"video","kind":"video","keyBinding":"9n5YWFmN3MC7g9kJH/tZ98P5JMMEGIz1C+zwHbchEB4="}}],{POLICY_REST}"#
            )
        );
        assert_eq!(
            hmac_b64(&video_key(), STANDARD.encode(&video_only).as_bytes()),
            "gzj4O10aZXXETOaFvB+qGPqBV48CYTEtDdPXk8azn8o="
        );
    }

    #[test]
    fn v2_manifest_yields_one_checked_key_per_component() {
        let p = check(&v2()).unwrap();
        assert_eq!(p.policy_uuid, "3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b");
        assert_eq!(
            p.fqns,
            vec!["https://patreon.arkavo.com/attr/campaign-tier/value/13167240_24457368"]
        );
        assert_eq!(
            hex::encode(p.content_iv),
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        );
        let c = components(p);
        assert_eq!(c.len(), 2);
        assert_eq!(
            (c[0].id.as_str(), c[0].kind, c[0].key),
            ("video", ComponentKind::Video, video_key())
        );
        assert_eq!(
            (c[1].id.as_str(), c[1].kind, c[1].key),
            ("audio", ComponentKind::Audio, audio_key())
        );
    }

    /// A recording without sound is packaged with the video component only.
    #[test]
    fn v2_video_only_manifest_passes() {
        let list = format!("[{}]", component("video", "video", &video_key()));
        let c = components(check(&v2_manifest(&policy_with(&list), &[&video_key()])).unwrap());
        assert_eq!(c.len(), 1);
        assert_eq!(
            (c[0].id.as_str(), c[0].kind, c[0].key),
            ("video", ComponentKind::Video, video_key())
        );
    }

    /// Both policy bindings still verify after a swap; only keyBinding refuses
    /// issuing the audio key under the video component's terms.
    #[test]
    fn v2_swapped_key_access_is_refused() {
        let mut m = v2();
        m["encryptionInformation"]["keyAccess"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert_eq!(
            check(&m).err(),
            Some(LicenseError::Forbidden("key binding mismatch"))
        );
    }

    #[test]
    fn v2_components_may_not_share_a_key() {
        let list = format!(
            "[{},{}]",
            component("video", "video", &video_key()),
            component("audio", "audio", &video_key())
        );
        let m = v2_manifest(&policy_with(&list), &[&video_key(), &video_key()]);
        assert_eq!(
            check(&m).err(),
            Some(LicenseError::Forbidden("components share a key"))
        );
    }

    #[test]
    fn v2_needs_one_key_access_per_component() {
        let mut short = v2();
        short["encryptionInformation"]["keyAccess"]
            .as_array_mut()
            .unwrap()
            .truncate(1);
        let mut none = v2();
        none["encryptionInformation"]["keyAccess"] = json!([]);
        let list = format!("[{}]", component("video", "video", &video_key()));
        let extra = v2_manifest(&policy_with(&list), &[&video_key(), &audio_key()]);
        for m in [short, none, extra] {
            assert_eq!(
                check(&m).err(),
                Some(LicenseError::Forbidden(
                    "one key access object per component required"
                ))
            );
        }
    }

    /// Profile v2 never truncates: a 32-byte key is refused, not cut to 16.
    #[test]
    fn v2_component_keys_must_be_16_bytes() {
        let long: [u8; 32] = std::array::from_fn(|i| i as u8);
        let list = format!("[{}]", component("video", "video", &long));
        let m = v2_manifest(&policy_with(&list), &[&long]);
        assert_eq!(
            check(&m).err(),
            Some(LicenseError::Forbidden("component key must be 16 bytes"))
        );
    }

    /// Any other list, `null` included, is refused and never read as profile v1.
    /// Each list has exactly one refusal reason.
    #[test]
    fn v2_component_list_shape_is_closed() {
        const NOT_A_LIST: &str = "components must be a list";
        const BAD_LIST: &str = "unsupported component list";
        const MALFORMED: &str = "malformed component";
        const UNSUPPORTED: &str = "unsupported component";
        let v = component("video", "video", &video_key());
        let a = component("audio", "audio", &audio_key());
        let binding = key_binding(&video_key(), "video");
        let entry = |b: &str| format!(r#"[{{"id":"video","kind":"video","keyBinding":"{b}"}}]"#);
        let cases: Vec<(String, &str)> = vec![
            ("null".to_string(), NOT_A_LIST),
            ("{}".to_string(), NOT_A_LIST),
            (r#""video""#.to_string(), NOT_A_LIST),
            ("[]".to_string(), BAD_LIST),
            (format!("[{v},{a},{a}]"), BAD_LIST),
            (format!("[{a}]"), UNSUPPORTED),
            (format!("[{a},{v}]"), UNSUPPORTED),
            (format!("[{v},{v}]"), UNSUPPORTED),
            (
                format!("[{v},{}]", component("image", "image", &audio_key())),
                UNSUPPORTED,
            ),
            (
                format!("[{}]", component("main", "video", &video_key())),
                UNSUPPORTED,
            ),
            (
                format!("[{}]", component("Video", "video", &video_key())),
                UNSUPPORTED,
            ),
            (
                format!("[{}]", component("video", "Video", &video_key())),
                UNSUPPORTED,
            ),
            (
                format!(r#"[{{"id":"video","kind":"video","keyBinding":"{binding}","x":1}}]"#),
                MALFORMED,
            ),
            (r#"[{"id":"video","kind":"video"}]"#.to_string(), MALFORMED),
            (r#"["video"]"#.to_string(), MALFORMED),
            (entry(&STANDARD.encode([0u8; 31])), MALFORMED),
            (entry(&hex::encode([0u8; 32])), MALFORMED),
            (entry("not base64!"), MALFORMED),
            (
                r#"[{"id":"video","kind":"video","keyBinding":32}]"#.to_string(),
                MALFORMED,
            ),
        ];
        for (list, reason) in cases {
            let m = v2_manifest(&policy_with(&list), &[&video_key(), &audio_key()]);
            assert_eq!(
                check(&m).err(),
                Some(LicenseError::Forbidden(reason)),
                "{list}"
            );
        }
    }

    /// The audio key's binding computed for the id `video` (the shared swap
    /// vector) does not bind the audio key to `audio`.
    #[test]
    fn v2_key_binding_names_its_component() {
        let list = format!(
            r#"[{},{{"id":"audio","kind":"audio","keyBinding":"4WqNpABYVXOM11ru1ClCNaEZZ8HOCCY+Ag0tppvil80="}}]"#,
            component("video", "video", &video_key())
        );
        let m = v2_manifest(&policy_with(&list), &[&video_key(), &audio_key()]);
        assert_eq!(
            check(&m).err(),
            Some(LicenseError::Forbidden("key binding mismatch"))
        );
    }

    /// Each of these passes every other check: serde_json keeps the last of a
    /// repeated key, and the bindings are computed over the repeated text.
    #[test]
    fn v2_duplicate_json_keys_are_refused() {
        let dup_manifest = v2().to_string().replacen('{', r#"{"payload":{},"#, 1);
        let dup_uuid = v2_manifest(
            &POLICY_AFTER.replacen('{', r#"{"uuid":"00000000-0000-0000-0000-000000000000","#, 1),
            &[&video_key(), &audio_key()],
        )
        .to_string();
        let dup_list = v2_manifest(
            &POLICY_AFTER.replacen('{', r#"{"arkavo:components":[],"#, 1),
            &[&video_key(), &audio_key()],
        )
        .to_string();
        for text in [dup_manifest, dup_uuid, dup_list] {
            assert_eq!(
                check_manifest(text.as_bytes(), &key(), &kas()).err(),
                Some(LicenseError::Forbidden("duplicate JSON key")),
                "{text}"
            );
        }
    }

    /// The second key access gets every check the first does.
    #[test]
    fn v2_every_key_access_is_checked() {
        let video_hash =
            v2()["encryptionInformation"]["keyAccess"][0]["policyBinding"]["hash"].clone();
        let cases = [
            (
                "url",
                json!("https://evil.example/kas"),
                "key access names another KAS",
            ),
            ("type", json!("remote"), "key access type must be wrapped"),
            (
                "wrappedKey",
                json!(STANDARD.encode([7u8; 256])),
                "key unwrap failed",
            ),
            (
                "policyBinding",
                json!({"alg": "HS256", "hash": video_hash}),
                "policy binding mismatch",
            ),
        ];
        for (field, value, reason) in cases {
            let mut m = v2();
            m["encryptionInformation"]["keyAccess"][1][field] = value;
            assert_eq!(
                check(&m).err(),
                Some(LicenseError::Forbidden(reason)),
                "{field}"
            );
        }
    }

    #[test]
    fn v2_policy_needs_data_attributes() {
        let list = format!("[{}]", component("video", "video", &video_key()));
        let policy = policy_with(&list).replace(
            r#"[{"attribute":"https://patreon.arkavo.com/attr/campaign-tier/value/13167240_24457368"}]"#,
            "[]",
        );
        let m = v2_manifest(&policy, &[&video_key()]);
        assert_eq!(
            check(&m).err(),
            Some(LicenseError::Forbidden("policy has no data attributes"))
        );
    }
}
