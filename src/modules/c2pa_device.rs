//! Device attestation for C2PA signing (arkavo-rs#133, C2PA Level 1 O.2).
//!
//! With `C2PA_REQUIRE_DEVICE` on, `/c2pa/v1/sign` also needs `X-Entity-Token`: the
//! DeviceCheck CWT identity mints after an App Attest assertion. It is accepted only
//! when all of these hold:
//! - it is signed by an identity COSE key under its `kid` (ES256), with the expected
//!   `iss`, an unexpired `exp`, and an `aud` naming `arkavo:devicecheck`;
//! - `arkavo_npe` is a device's (`type` = `device`), `cnf` is present, and it carries
//!   no other agent marker;
//! - `arkavo_npe.app_id_hash` (the App Attest rpIdHash: lowercase hex SHA-256 of
//!   `<TeamID>.<bundle id>`, authnz-rs#114) is one of `C2PA_DEVICE_APP_IDS`. Identity
//!   includes it only for an app it accepts, so a token without it is refused;
//! - it binds to the person as the platform binds a device: its `iss` and
//!   `arkavo_account_id` equal the passkey token's.

use crate::modules::authzen::cose_keys::CoseKeyCache;
use crate::modules::authzen::cwt_subject::DEVICECHECK_AUD;
use crate::modules::authzen::cwt_verify::{
    header_kid, verify_header_token, VerifyError, VerifyOpts,
};
use crate::modules::license::person_token::Person;
use axum::http::HeaderMap;
use std::collections::HashSet;

pub const DEVICE_TOKEN_HEADER: &str = "x-entity-token";

#[derive(Debug, PartialEq, Eq)]
pub enum DeviceRefusal {
    /// No usable device token, or one that fails a check: 403
    Refused(&'static str),
    /// The identity key set could not be fetched: 503
    Unavailable,
}

pub struct DeviceTokenVerifier {
    keys: CoseKeyCache,
    issuer: String,
    app_ids: HashSet<String>,
}

impl DeviceTokenVerifier {
    pub fn new(keys: CoseKeyCache, issuer: String, app_ids: HashSet<String>) -> Self {
        Self {
            keys,
            issuer,
            app_ids,
        }
    }

    /// Checks the request's device token against `person`. The reason in a refusal
    /// is for the log only; the client sees one generic error.
    pub async fn verify(
        &self,
        headers: &HeaderMap,
        person: &Person,
        now: i64,
    ) -> Result<(), DeviceRefusal> {
        let token = headers
            .get(DEVICE_TOKEN_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or(DeviceRefusal::Refused("no device token"))?;
        let kid =
            header_kid(token).map_err(|_| DeviceRefusal::Refused("malformed device token"))?;
        let key = match self.keys.resolve(&kid).await {
            Ok(key) => key,
            Err(VerifyError::KeySet) => return Err(DeviceRefusal::Unavailable),
            Err(_) => return Err(DeviceRefusal::Refused("unknown device token key")),
        };
        let claims = verify_header_token(
            token,
            &key,
            VerifyOpts {
                expected_iss: Some(&self.issuer),
                expected_aud: Some(DEVICECHECK_AUD),
                expected_kid: Some(kid.as_slice()),
                now,
            },
        )
        .map_err(|_| DeviceRefusal::Refused("device token does not verify"))?;

        let npe = claims
            .arkavo_npe
            .as_ref()
            .filter(|npe| npe.get("type").and_then(|t| t.as_str()) == Some("device"))
            .ok_or(DeviceRefusal::Refused("not a device token"))?;
        if claims.non_device_agent_marker {
            return Err(DeviceRefusal::Refused(
                "device token carries an agent marker",
            ));
        }
        if !claims.cnf {
            return Err(DeviceRefusal::Refused("device token has no cnf"));
        }
        let app_id_hash = npe
            .get("app_id_hash")
            .and_then(|a| a.as_str())
            .ok_or(DeviceRefusal::Refused("device token names no app"))?;
        if !self.app_ids.contains(&app_id_hash.to_ascii_lowercase()) {
            return Err(DeviceRefusal::Refused("device token is for another app"));
        }
        let account = claims
            .arkavo_account_id
            .as_deref()
            .filter(|a| !a.is_empty())
            .ok_or(DeviceRefusal::Refused("device token names no account"))?;
        if claims.iss != person.iss || person.arkavo_account_id.as_deref() != Some(account) {
            return Err(DeviceRefusal::Refused(
                "device token is for another account",
            ));
        }
        Ok(())
    }
}

/// `C2PA_DEVICE_APP_IDS`: comma-separated `<TeamID>.<bundle id>` values, or their
/// rpIdHash as 64 hex digits. Returns the set of lowercase hex hashes that
/// `arkavo_npe.app_id_hash` is compared with.
pub fn parse_app_ids(raw: &str) -> HashSet<String> {
    use sha2::{Digest, Sha256};
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|entry| {
            if entry.len() == 64 && entry.bytes().all(|b| b.is_ascii_hexdigit()) {
                entry.to_ascii_lowercase()
            } else {
                hex::encode(Sha256::digest(entry.as_bytes()))
            }
        })
        .collect()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::modules::authzen::cwt_verify::test_support::{keypair, mint_map, other_keypair};
    use axum::http::HeaderValue;
    use ciborium::value::Value as Cbor;

    const ISS: &str = "https://identity.arkavo.net";
    const KID: &[u8] = b"test-kid";
    const ACCOUNT: &str = "550e8400-e29b-41d4-a716-446655440000";
    pub const CREATOR: &str = "ABCDE12345.com.arkavo.Creator";

    /// The rpIdHash identity puts in `app_id_hash` for an app id
    fn app_hash(app_id: &str) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(app_id.as_bytes()))
    }

    #[test]
    fn app_ids_are_hashed_or_taken_as_hashes() {
        let creator = "ea2defc9e7bf14b832b0fb5e4ada8f0af0e114dca9fc7741cda17d875cf1bc01";
        assert_eq!(
            parse_app_ids(" M8GS7ZT95Y.com.arkavo.ArkavoCreator ,"),
            [creator.to_string()].into()
        );
        assert_eq!(
            parse_app_ids(&creator.to_ascii_uppercase()),
            [creator.to_string()].into()
        );
    }

    fn verifier() -> DeviceTokenVerifier {
        let (_, vk) = keypair();
        DeviceTokenVerifier::new(
            CoseKeyCache::with_static_keys(vec![(KID.to_vec(), vk)]),
            ISS.into(),
            parse_app_ids(&format!(" {CREATOR} ,ZZZ.other.app")),
        )
    }

    fn person() -> Person {
        Person {
            sub: format!("arkavo:{ACCOUNT}"),
            entitlements: vec![],
            iss: ISS.into(),
            arkavo_account_id: Some(ACCOUNT.into()),
            token: "passkey".into(),
        }
    }

    /// A DeviceCheck token as authnz-rs mints one, with `app_id_hash` (authnz-rs#114).
    /// `edit` changes the claims before signing.
    fn device_token(edit: impl FnOnce(&mut Vec<(Cbor, Cbor)>)) -> String {
        mint_device_token(ISS, KID, ACCOUNT, CREATOR, edit)
    }

    /// A DeviceCheck token for `account` and `app_id`, signed with the test key under `kid`.
    pub fn mint_device_token(
        iss: &str,
        kid: &[u8],
        account: &str,
        app_id: &str,
        edit: impl FnOnce(&mut Vec<(Cbor, Cbor)>),
    ) -> String {
        let now = chrono::Utc::now().timestamp();
        let mut claims = vec![
            (Cbor::Integer(1.into()), Cbor::Text(iss.into())),
            (Cbor::Integer(2.into()), Cbor::Text(account.into())),
            (
                Cbor::Integer(3.into()),
                Cbor::Array(vec![
                    Cbor::Text("arkavo:devicecheck".into()),
                    Cbor::Text("https://platform.arkavo.net".into()),
                ]),
            ),
            (Cbor::Integer(4.into()), Cbor::Integer((now + 3600).into())),
            (Cbor::Integer(6.into()), Cbor::Integer(now.into())),
            (Cbor::Integer(7.into()), Cbor::Bytes(vec![9u8; 16])),
            (
                Cbor::Integer(8.into()),
                Cbor::Map(vec![(
                    Cbor::Integer(3.into()),
                    Cbor::Bytes(b"key".to_vec()),
                )]),
            ),
            (
                Cbor::Text("arkavo_account_id".into()),
                Cbor::Text(account.into()),
            ),
            (
                Cbor::Text("arkavo_npe".into()),
                Cbor::Map(vec![
                    (Cbor::Text("type".into()), Cbor::Text("device".into())),
                    (Cbor::Text("class".into()), Cbor::Text("attested".into())),
                    (
                        Cbor::Text("app_id_hash".into()),
                        Cbor::Text(app_hash(app_id)),
                    ),
                ]),
            ),
        ];
        edit(&mut claims);
        let (sk, _) = keypair();
        mint_map(&sk, kid, claims)
    }

    fn headers(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(DEVICE_TOKEN_HEADER, HeaderValue::from_str(token).unwrap());
        h
    }

    async fn check(token: &str) -> Result<(), DeviceRefusal> {
        verifier()
            .verify(&headers(token), &person(), chrono::Utc::now().timestamp())
            .await
    }

    fn set(claims: &mut [(Cbor, Cbor)], key: &str, value: Cbor) {
        let slot = claims
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some(key))
            .unwrap();
        slot.1 = value;
    }

    fn npe(app_id: Option<&str>, kind: &str) -> Cbor {
        let mut members = vec![(Cbor::Text("type".into()), Cbor::Text(kind.into()))];
        if let Some(app) = app_id {
            members.push((Cbor::Text("app_id_hash".into()), Cbor::Text(app_hash(app))));
        }
        Cbor::Map(members)
    }

    #[tokio::test]
    async fn creator_device_token_for_the_same_account_passes() {
        assert_eq!(check(&device_token(|_| {})).await, Ok(()));
    }

    #[tokio::test]
    async fn missing_or_blank_header_is_refused() {
        let r = verifier()
            .verify(&HeaderMap::new(), &person(), chrono::Utc::now().timestamp())
            .await;
        assert_eq!(r, Err(DeviceRefusal::Refused("no device token")));
        assert_eq!(
            check("   ").await,
            Err(DeviceRefusal::Refused("no device token"))
        );
    }

    #[tokio::test]
    async fn token_that_does_not_verify_is_refused() {
        let (other, _) = other_keypair();
        let forged = mint_map(&other, KID, vec![]);
        assert!(matches!(
            check(&forged).await,
            Err(DeviceRefusal::Refused(_))
        ));
        // A passkey-shaped token: no arkavo:devicecheck audience
        let wrong_aud = device_token(|c| {
            c.retain(|(k, _)| k != &Cbor::Integer(3.into()));
            c.push((Cbor::Integer(3.into()), Cbor::Text("arkavo".into())));
        });
        assert_eq!(
            check(&wrong_aud).await,
            Err(DeviceRefusal::Refused("device token does not verify"))
        );
    }

    #[tokio::test]
    async fn another_app_or_no_app_is_refused() {
        let other = device_token(|c| {
            set(
                c,
                "arkavo_npe",
                npe(Some("ABCDE12345.com.arkavo.Viewer"), "device"),
            )
        });
        assert_eq!(
            check(&other).await,
            Err(DeviceRefusal::Refused("device token is for another app"))
        );
        let none = device_token(|c| set(c, "arkavo_npe", npe(None, "device")));
        assert_eq!(
            check(&none).await,
            Err(DeviceRefusal::Refused("device token names no app"))
        );
    }

    #[tokio::test]
    async fn non_device_npe_or_missing_cnf_is_refused() {
        let agent = device_token(|c| set(c, "arkavo_npe", npe(Some(CREATOR), "agent")));
        assert_eq!(
            check(&agent).await,
            Err(DeviceRefusal::Refused("not a device token"))
        );
        let no_cnf = device_token(|c| c.retain(|(k, _)| k != &Cbor::Integer(8.into())));
        assert_eq!(
            check(&no_cnf).await,
            Err(DeviceRefusal::Refused("device token has no cnf"))
        );
        let swarm =
            device_token(|c| c.push((Cbor::Text("arkavo_swarm".into()), Cbor::Text("s".into()))));
        assert_eq!(
            check(&swarm).await,
            Err(DeviceRefusal::Refused(
                "device token carries an agent marker"
            ))
        );
    }

    #[tokio::test]
    async fn device_of_another_account_is_refused() {
        let other = device_token(|c| {
            set(
                c,
                "arkavo_account_id",
                Cbor::Text("11111111-2222-3333-4444-555555555555".into()),
            )
        });
        assert_eq!(
            check(&other).await,
            Err(DeviceRefusal::Refused(
                "device token is for another account"
            ))
        );
        let mut someone_else = person();
        someone_else.arkavo_account_id = None;
        let r = verifier()
            .verify(
                &headers(&device_token(|_| {})),
                &someone_else,
                chrono::Utc::now().timestamp(),
            )
            .await;
        assert_eq!(
            r,
            Err(DeviceRefusal::Refused(
                "device token is for another account"
            ))
        );
    }
}
