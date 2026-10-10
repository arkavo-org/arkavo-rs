//! TDF manifest → the DEK plus the policy it is bound to. Refuses anything
//! that is not exactly one wrapped key for this KAS with an intact binding
//! and at least one data attribute, every one of them well formed.

use super::LicenseError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use rsa::{Oaep, RsaPrivateKey};
use serde_json::Value;
use sha1::Sha1;
use sha2::Sha256;

pub struct CheckedPolicy {
    /// Full unwrapped DEK (16 or 32 bytes). Never log it.
    pub dek: Vec<u8>,
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
    let kaos = ei
        .get("keyAccess")
        .and_then(Value::as_array)
        .ok_or(FORBIDDEN_MANIFEST)?;
    let [kao] = kaos.as_slice() else {
        return Err(LicenseError::Forbidden(
            "exactly one key access object required",
        ));
    };
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
    let dek = rsa
        .decrypt_blinded(&mut OsRng, Oaep::new::<Sha1>(), &wrapped)
        .map_err(|_| LicenseError::Forbidden("key unwrap failed"))?;
    if dek.len() != 16 && dek.len() != 32 {
        return Err(LicenseError::Forbidden("unexpected key size"));
    }

    let policy_b64 = ei
        .get("policy")
        .and_then(Value::as_str)
        .ok_or(FORBIDDEN_MANIFEST)?;
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
    // Binding is checked with the full DEK, before any FairPlay truncation.
    let mut mac = Hmac::<Sha256>::new_from_slice(&dek).map_err(|_| FORBIDDEN_MANIFEST)?;
    mac.update(policy_b64.as_bytes());
    mac.verify_slice(&expected)
        .map_err(|_| LicenseError::Forbidden("policy binding mismatch"))?;

    let policy_bytes = STANDARD
        .decode(policy_b64)
        .map_err(|_| FORBIDDEN_MANIFEST)?;
    let policy: Value = serde_json::from_slice(&policy_bytes).map_err(|_| FORBIDDEN_MANIFEST)?;
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
    let content_iv = ei
        .pointer("/method/iv")
        .and_then(Value::as_str)
        .and_then(|s| STANDARD.decode(s.trim()).ok())
        .and_then(|iv| <[u8; 16]>::try_from(iv).ok())
        .ok_or(LicenseError::Forbidden("content iv must be 16 bytes"))?;
    Ok(CheckedPolicy {
        dek,
        policy_uuid,
        fqns,
        content_iv,
    })
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
        assert_eq!(
            hex::encode(&p.dek),
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
                    Err(LicenseError::Forbidden("content iv must be 16 bytes"))
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
            Err(LicenseError::Forbidden("content iv must be 16 bytes"))
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
}
