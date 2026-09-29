//! Bearer CWT → verified person. Allowlist: the passkey auth token only
//! (aud contains both "arkavo" and the platform audience, person-shaped sub,
//! no agent marker). Everything else is refused.

use super::LicenseError;
use crate::modules::authzen::cose_keys::CoseKeyCache;
use crate::modules::authzen::cwt_subject::Aud;
use crate::modules::authzen::cwt_verify::{
    header_kid, verify_header_token, VerifyError, VerifyOpts,
};
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;

const PASSKEY_AUD: &str = "arkavo";

#[derive(Debug, Clone)]
pub struct Person {
    pub sub: String,
    /// The raw bearer, forwarded to the platform as the decision entity.
    pub token: String,
}

pub struct PersonTokenVerifier {
    keys: CoseKeyCache,
    issuer: String,
    platform_aud: String,
}

pub fn is_person_sub(sub: &str) -> bool {
    for prefix in ["arkavo:", "apple:", "google:"] {
        if let Some(rest) = sub.strip_prefix(prefix) {
            return !rest.is_empty();
        }
    }
    uuid::Uuid::parse_str(sub).is_ok()
}

fn aud_contains(aud: &Aud, want: &str) -> bool {
    match aud {
        Aud::One(s) => s == want,
        Aud::Many(v) => v.iter().any(|s| s == want),
    }
}

impl PersonTokenVerifier {
    pub fn new(keys: CoseKeyCache, issuer: String, platform_aud: String) -> Self {
        Self {
            keys,
            issuer,
            platform_aud,
        }
    }

    pub async fn verify(&self, headers: &HeaderMap, now: i64) -> Result<Person, LicenseError> {
        let token = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|a| {
                a.strip_prefix("Bearer ")
                    .or_else(|| a.strip_prefix("bearer "))
            })
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or(LicenseError::Unauthenticated("missing bearer token"))?;
        let kid =
            header_kid(token).map_err(|_| LicenseError::Unauthenticated("malformed token"))?;
        let key = match self.keys.resolve(&kid).await {
            Ok(k) => k,
            Err(VerifyError::KeySet) => {
                return Err(LicenseError::Unavailable("identity keys unavailable"))
            }
            Err(_) => return Err(LicenseError::Unauthenticated("unknown signing key")),
        };
        let claims = verify_header_token(
            token,
            &key,
            VerifyOpts {
                expected_iss: Some(&self.issuer),
                expected_aud: Some(&self.platform_aud),
                expected_kid: Some(kid.as_slice()),
                now,
            },
        )
        .map_err(|_| LicenseError::Unauthenticated("invalid token"))?;
        if !aud_contains(&claims.aud, PASSKEY_AUD) {
            return Err(LicenseError::Forbidden("not a person token"));
        }
        if !is_person_sub(&claims.sub) {
            return Err(LicenseError::Forbidden("not a person subject"));
        }
        if claims.agent_marker {
            return Err(LicenseError::Forbidden("agent token"));
        }
        Ok(Person {
            sub: claims.sub,
            token: token.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::*;
    use crate::modules::authzen::cose_keys::CoseKeyCache;
    use crate::modules::authzen::cwt_verify::test_support::{keypair, mint_map, other_keypair};
    use crate::modules::license::LicenseError;
    use axum::http::{HeaderMap, HeaderValue};
    use ciborium::value::Value;

    const ISS: &str = "https://identity.test";
    const PLATFORM: &str = "https://platform.arkavo.net";
    const KID: &[u8] = b"kid-1";
    const NOW: i64 = 1_900_000_000;
    const SUB: &str = "550e8400-e29b-41d4-a716-446655440000";

    /// Mirrors authnz-rs `claims_to_cbor` for a passkey auth token: numeric
    /// labels, aud as a list of "arkavo" + platform, and a cnf (label 8).
    fn person_entries(sub: &str, aud: Value, extra: Vec<(Value, Value)>) -> Vec<(Value, Value)> {
        let mut v = vec![
            (Value::Integer(1.into()), Value::Text(ISS.into())),
            (Value::Integer(2.into()), Value::Text(sub.into())),
            (Value::Integer(3.into()), aud),
            (
                Value::Integer(4.into()),
                Value::Integer((NOW + 3600).into()),
            ),
            (Value::Integer(6.into()), Value::Integer(NOW.into())),
            (Value::Integer(7.into()), Value::Bytes(vec![7u8; 16])),
            (
                Value::Integer(8.into()),
                Value::Map(vec![(
                    Value::Integer(2.into()),
                    Value::Bytes(b"pk".to_vec()),
                )]),
            ),
            (Value::Text("idp".into()), Value::Text("webauthn".into())),
        ];
        v.extend(extra);
        v
    }

    fn both_aud() -> Value {
        Value::Array(vec![
            Value::Text("arkavo".into()),
            Value::Text(PLATFORM.into()),
        ])
    }

    fn verifier() -> (PersonTokenVerifier, p256::ecdsa::SigningKey) {
        let (sk, vk) = keypair();
        let keys = CoseKeyCache::with_static_keys(vec![(KID.to_vec(), vk)]);
        (
            PersonTokenVerifier::new(keys, ISS.into(), PLATFORM.into()),
            sk,
        )
    }

    fn bearer(t: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {t}")).unwrap(),
        );
        h
    }

    #[tokio::test]
    async fn accepts_passkey_person_token() {
        let (v, sk) = verifier();
        let t = mint_map(&sk, KID, person_entries(SUB, both_aud(), vec![]));
        let p = v.verify(&bearer(&t), NOW).await.unwrap();
        assert_eq!(p.sub, SUB);
        assert_eq!(p.token, t);
    }

    #[tokio::test]
    async fn missing_or_bad_token_is_401() {
        let (v, _) = verifier();
        assert!(matches!(
            v.verify(&HeaderMap::new(), NOW).await,
            Err(LicenseError::Unauthenticated(_))
        ));
        assert!(matches!(
            v.verify(&bearer("not-a-cwt"), NOW).await,
            Err(LicenseError::Unauthenticated(_))
        ));
        let (other, _) = other_keypair();
        let t = mint_map(&other, KID, person_entries(SUB, both_aud(), vec![]));
        assert!(matches!(
            v.verify(&bearer(&t), NOW).await,
            Err(LicenseError::Unauthenticated(_))
        ));
    }

    #[tokio::test]
    async fn expired_is_401() {
        let (v, sk) = verifier();
        let t = mint_map(&sk, KID, person_entries(SUB, both_aud(), vec![]));
        assert!(matches!(
            v.verify(&bearer(&t), NOW + 7200).await,
            Err(LicenseError::Unauthenticated(_))
        ));
    }

    #[tokio::test]
    async fn missing_platform_aud_is_401() {
        // The registration token has aud "arkavo" only; expected_aud fails in
        // the verifier, which is an authentication failure (sign in again).
        let (v, sk) = verifier();
        let t = mint_map(
            &sk,
            KID,
            person_entries(SUB, Value::Text("arkavo".into()), vec![]),
        );
        assert!(matches!(
            v.verify(&bearer(&t), NOW).await,
            Err(LicenseError::Unauthenticated(_))
        ));
    }

    #[tokio::test]
    async fn non_person_is_403() {
        let (v, sk) = verifier();
        let platform_only = Value::Array(vec![Value::Text(PLATFORM.into())]);
        let rp = Value::Array(vec![
            Value::Text("mcp-edge".into()),
            Value::Text(PLATFORM.into()),
        ]);
        let cases = vec![
            person_entries(SUB, platform_only, vec![]),
            person_entries(SUB, rp, vec![]),
            person_entries("client:catalog-node", both_aud(), vec![]),
            person_entries(
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                both_aud(),
                vec![],
            ),
            person_entries(
                SUB,
                both_aud(),
                vec![(
                    Value::Text("arkavo_npe".into()),
                    Value::Map(vec![(
                        Value::Text("type".into()),
                        Value::Text("device".into()),
                    )]),
                )],
            ),
            person_entries(
                SUB,
                both_aud(),
                vec![(Value::Text("arkavo_swarm".into()), Value::Text("s".into()))],
            ),
        ];
        for entries in cases {
            let t = mint_map(&sk, KID, entries);
            assert!(matches!(
                v.verify(&bearer(&t), NOW).await,
                Err(LicenseError::Forbidden(_))
            ));
        }
    }

    #[test]
    fn person_sub_shapes() {
        assert!(is_person_sub(SUB));
        assert!(is_person_sub("arkavo:u1"));
        assert!(is_person_sub("apple:001234.abcd"));
        assert!(is_person_sub("google:1234"));
        assert!(!is_person_sub("arkavo:"));
        assert!(!is_person_sub("client:x"));
        assert!(!is_person_sub("did:key:z6Mk"));
        assert!(!is_person_sub(""));
    }
}
