//! Who is calling: a signed-in Arkavo account, from its `identity.arkavo.net`
//! session CWT (`Authorization: Bearer <base64url CWT>`).

use crate::modules::authzen::cose_keys::CoseKeyCache;
use crate::modules::authzen::cwt_subject::{subject_id_bind, DecodedClaims};
use crate::modules::authzen::cwt_verify::{
    header_kid, verify_header_token, VerifyError, VerifyOpts,
};
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// No credential, or one that does not verify, or not a person's session.
    Unauthenticated,
    /// A valid session that is not allowed here.
    Forbidden,
    /// The issuer's key set could not be fetched.
    KeySet,
}

pub struct SessionVerifier {
    pub issuer: String,
    /// Required in the token's `aud`; the passkey auth CWT carries `arkavo`.
    pub audience: String,
    pub keys: CoseKeyCache,
}

impl SessionVerifier {
    /// The account behind a person's session token. Service accounts, agents
    /// and OIDC access tokens are refused: a report comes from a person who
    /// signed in to the app.
    pub async fn person(&self, headers: &HeaderMap) -> Result<String, AuthError> {
        let token = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|a| {
                a.strip_prefix("Bearer ")
                    .or_else(|| a.strip_prefix("bearer "))
            })
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or(AuthError::Unauthenticated)?;
        let kid = header_kid(token).map_err(|_| AuthError::Unauthenticated)?;
        let key = match self.keys.resolve(&kid).await {
            Ok(k) => k,
            Err(VerifyError::KeySet) => return Err(AuthError::KeySet),
            Err(_) => return Err(AuthError::Unauthenticated),
        };
        let claims = verify_header_token(
            token,
            &key,
            VerifyOpts {
                expected_iss: Some(&self.issuer),
                expected_aud: Some(&self.audience),
                expected_kid: Some(kid.as_slice()),
                now: chrono::Utc::now().timestamp(),
            },
        )
        .map_err(|_| AuthError::Unauthenticated)?;
        person_subject(&claims).ok_or(AuthError::Unauthenticated)
    }
}

/// The account ID of a person's passkey session, or `None` for any other
/// kind of token. The `arkavo:` prefix is dropped so both subject forms
/// name the same account.
pub fn person_subject(claims: &DecodedClaims) -> Option<String> {
    if claims.sub.starts_with("client:") || claims.client_id.is_some() {
        return None;
    }
    // authnz-rs never sets `scope` or `auth_time` on a passkey auth CWT;
    // every OIDC access token carries `scope`.
    if claims.scope.is_some() || claims.auth_time.is_some() {
        return None;
    }
    let non_person = claims
        .arkavo_roles
        .as_ref()
        .is_some_and(|r| r.iter().any(|x| x == "service-account" || x == "agent"));
    if non_person {
        return None;
    }
    let sub = subject_id_bind(&claims.sub);
    (!sub.is_empty()).then(|| sub.to_string())
}

/// Moderator account IDs, from a comma-separated list. Entries may carry the
/// `arkavo:` prefix.
pub fn parse_moderators(raw: &str) -> HashSet<String> {
    raw.split(',')
        .map(|s| subject_id_bind(s.trim()).to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::authzen::cwt_subject::Aud;

    fn person() -> DecodedClaims {
        DecodedClaims {
            iss: "https://identity.arkavo.net".into(),
            sub: "550e8400-e29b-41d4-a716-446655440000".into(),
            aud: Aud::Many(vec!["arkavo".into(), "https://platform.arkavo.net".into()]),
            exp: 2,
            iat: 1,
            nbf: None,
            cti: vec![1; 16],
            email: None,
            email_verified: None,
            idp: None,
            arkavo_account_id: None,
            arkavo_roles: None,
            arkavo_entitlements: None,
            client_id: None,
            arkavo_patreon: None,
            scope: None,
            auth_time: None,
        }
    }

    #[test]
    fn a_passkey_session_is_a_person() {
        assert_eq!(
            person_subject(&person()).as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
        let mut prefixed = person();
        prefixed.sub = "arkavo:550e8400-e29b-41d4-a716-446655440000".into();
        assert_eq!(person_subject(&prefixed), person_subject(&person()));
    }

    #[test]
    fn other_tokens_are_not_people() {
        let mut c = person();
        c.sub = "client:catalog-node".into();
        assert_eq!(person_subject(&c), None);
        let mut c = person();
        c.client_id = Some("mcp-edge".into());
        assert_eq!(person_subject(&c), None);
        let mut c = person();
        c.scope = Some("openid".into());
        assert_eq!(person_subject(&c), None);
        let mut c = person();
        c.auth_time = Some(1);
        assert_eq!(person_subject(&c), None);
        for role in ["service-account", "agent"] {
            let mut c = person();
            c.arkavo_roles = Some(vec!["member".into(), role.into()]);
            assert_eq!(person_subject(&c), None, "{role}");
        }
    }

    #[test]
    fn moderators_list_normalises_prefix() {
        let m = parse_moderators(" arkavo:a , b,, ");
        assert_eq!(m, HashSet::from(["a".to_string(), "b".to_string()]));
    }
}
