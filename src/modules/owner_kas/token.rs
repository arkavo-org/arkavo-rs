//! The receiver's credentials on the owner-KAS routes (arkavo-rs#163).
//!
//! - The **owner-KAS token** (authnz-rs#146, `docs/owner-kas-token.md`): CBOR
//!   tag 61 around a COSE_Sign1 ES256 by identity, protected content type
//!   `application/owner-kas+cwt`, payload exactly `iss`, `sub`, `aud`
//!   (`owner-kas:<route_id>`), `exp`, `iat`, `cti`, `cnf` and
//!   `arkavo_handle`. A port of authnz-rs's reference `owner_kas_token::verify`.
//!   arks' union CWT verifier is not used: it checks neither the content
//!   type nor this exact payload.
//! - The Rewrap's **signed request token**: an ES256 JWT (JOSE, OpenTDF's
//!   wire format) signed by the token's `cnf` key, with `exp` no later than
//!   the token's. Only its signature and `exp` are read.

use crate::modules::authzen::cose_keys::CoseKeyCache;
use crate::modules::authzen::cwt_verify::VerifyError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ciborium::value::Value;
use coset::{iana, CborSerializable};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::Signature;

/// The protected header's `content type` (label 3).
pub const CONTENT_TYPE: &str = "application/owner-kas+cwt";
/// `aud` is this prefix followed by the route id.
pub const AUDIENCE_PREFIX: &str = "owner-kas:";
pub const HANDLE_CLAIM: &str = "arkavo_handle";
/// `exp - iat` at most.
pub const LIFETIME_SECONDS: i64 = 900;
/// Clock skew allowed on `iat` and `exp`.
pub const SKEW_SECS: i64 = 60;

const CWT_TAG_PREFIX: [u8; 2] = [0xD8, 0x3D];
const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// A bearer larger than this is not an owner-KAS token.
const MAX_TOKEN_CHARS: usize = 2048;

/// A canonical ULID: 26 uppercase Crockford base-32 characters, the first
/// `0`–`7`. Never normalized.
pub fn is_route_id(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 26 && (b'0'..=b'7').contains(&b[0]) && b.iter().all(|c| CROCKFORD.contains(c))
}

/// A bare lowercase hyphenated UUID, the form identity's passkey CWT uses
/// for `sub`. Subjects are compared byte for byte.
pub fn is_bare_subject(s: &str) -> bool {
    uuid::Uuid::parse_str(s)
        .map(|u| u.hyphenated().to_string() == s)
        .unwrap_or(false)
}

/// A new request ID: a ULID (48-bit milliseconds, 80 random bits).
pub fn new_ulid(now_ms: u64) -> String {
    let random = uuid::Uuid::new_v4();
    let mut n: u128 = (now_ms as u128 & ((1u128 << 48) - 1)) << 80;
    n |= u128::from_be_bytes(*random.as_bytes()) & ((1u128 << 80) - 1);
    let mut out = [0u8; 26];
    for (i, c) in out.iter_mut().enumerate() {
        let shift = 5 * (25 - i);
        *c = CROCKFORD[((n >> shift) & 0x1f) as usize];
    }
    String::from_utf8(out.to_vec()).expect("ascii")
}

/// A verified owner-KAS token's claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerKasToken {
    pub sub: String,
    /// `aud` without its prefix.
    pub route_id: String,
    pub iat: i64,
    pub exp: i64,
    /// The receiver's request key (P-256).
    pub x: [u8; 32],
    pub y: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// Not a valid owner-KAS token: 401.
    Invalid,
    /// Identity's key set could not be fetched: 503.
    KeySet,
}

pub struct OwnerKasVerifier {
    pub issuer: String,
    pub keys: CoseKeyCache,
}

impl OwnerKasVerifier {
    /// Steps 1–3 of `docs/owner-kas-token.md`: the tag, ES256, the content
    /// type, no `crit`, a `kid` in identity's key set, the signature, exactly
    /// the contract's payload, `iss`, `exp - iat` ≤ 900, and the time.
    ///
    /// `grace_secs` extends `exp` beyond the ±60 s skew. It is 0 on every
    /// route except the receiver's poll, which takes the bearer until the
    /// request is deleted so a late poll gets 410, not 401.
    pub async fn verify(
        &self,
        token_b64: &str,
        now: i64,
        grace_secs: i64,
    ) -> Result<OwnerKasToken, TokenError> {
        if token_b64.len() > MAX_TOKEN_CHARS {
            return Err(TokenError::Invalid);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(token_b64.trim())
            .map_err(|_| TokenError::Invalid)?;
        let inner = bytes
            .strip_prefix(&CWT_TAG_PREFIX)
            .ok_or(TokenError::Invalid)?;
        let sign1 = coset::CoseSign1::from_slice(inner).map_err(|_| TokenError::Invalid)?;
        let header = &sign1.protected.header;
        if header.alg != Some(coset::Algorithm::Assigned(iana::Algorithm::ES256))
            || header.content_type != Some(coset::ContentType::Text(CONTENT_TYPE.into()))
            || !header.crit.is_empty()
            || header.key_id.is_empty()
            || !sign1.unprotected.is_empty()
        {
            return Err(TokenError::Invalid);
        }
        let key = match self.keys.resolve(&header.key_id).await {
            Ok(k) => k,
            Err(VerifyError::KeySet) => return Err(TokenError::KeySet),
            Err(_) => return Err(TokenError::Invalid),
        };
        sign1
            .verify_signature(b"", |sig, data| {
                let sig = Signature::from_slice(sig).map_err(|_| ())?;
                key.verify(data, &sig).map_err(|_| ())
            })
            .map_err(|_| TokenError::Invalid)?;
        let t = parse_payload(sign1.payload.as_deref().ok_or(TokenError::Invalid)?)
            .ok_or(TokenError::Invalid)?;
        if t.0 != self.issuer {
            return Err(TokenError::Invalid);
        }
        let t = t.1;
        if t.iat > t.exp || t.exp - t.iat > LIFETIME_SECONDS {
            return Err(TokenError::Invalid);
        }
        if t.exp + grace_secs <= now - SKEW_SECS || t.iat > now + SKEW_SECS {
            return Err(TokenError::Invalid);
        }
        if !is_bare_subject(&t.sub) {
            return Err(TokenError::Invalid);
        }
        Ok(t)
    }
}

/// `(iss, token)`, or `None` unless the payload is exactly the contract's.
fn parse_payload(bytes: &[u8]) -> Option<(String, OwnerKasToken)> {
    let value: Value = ciborium::de::from_reader(bytes).ok()?;
    let Value::Map(entries) = value else {
        return None;
    };
    if entries.len() != 8 {
        return None;
    }
    let get = |want: &Value| entries.iter().find(|(k, _)| k == want).map(|(_, v)| v);
    let int = |n: i64| Value::Integer(n.into());
    let text = |v: &Value| v.as_text().map(str::to_string);
    let number = |v: &Value| v.as_integer().and_then(|i| i64::try_from(i).ok());

    let iss = text(get(&int(1))?)?;
    let sub = text(get(&int(2))?)?;
    let route_id = text(get(&int(3))?)?
        .strip_prefix(AUDIENCE_PREFIX)
        .filter(|r| is_route_id(r))?
        .to_string();
    let exp = number(get(&int(4))?)?;
    let iat = number(get(&int(6))?)?;
    let cti = get(&int(7))?.as_bytes()?;
    if cti.len() != 16 {
        return None;
    }
    let (x, y) = parse_cnf(get(&int(8))?)?;
    text(get(&Value::Text(HANDLE_CLAIM.into()))?)?;
    Some((
        iss,
        OwnerKasToken {
            sub,
            route_id,
            iat,
            exp,
            x,
            y,
        },
    ))
}

fn parse_cnf(v: &Value) -> Option<([u8; 32], [u8; 32])> {
    let [(k, key)] = v.as_map()?.as_slice() else {
        return None;
    };
    if *k != Value::Integer(1.into()) {
        return None;
    }
    let params = key.as_map().filter(|m| m.len() == 4)?;
    let param = |label: i64| {
        params
            .iter()
            .find(|(k, _)| *k == Value::Integer(label.into()))
            .map(|(_, v)| v)
    };
    if *param(iana::KeyParameter::Kty as i64)? != Value::Integer((iana::KeyType::EC2 as i64).into())
        || *param(iana::Ec2KeyParameter::Crv as i64)?
            != Value::Integer((iana::EllipticCurve::P_256 as i64).into())
    {
        return None;
    }
    let coord =
        |label: i64| -> Option<[u8; 32]> { param(label)?.as_bytes()?.as_slice().try_into().ok() };
    let (x, y) = (
        coord(iana::Ec2KeyParameter::X as i64)?,
        coord(iana::Ec2KeyParameter::Y as i64)?,
    );
    // Refuse a point off the curve.
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&x);
    sec1[33..].copy_from_slice(&y);
    p256::PublicKey::from_sec1_bytes(&sec1).ok()?;
    Some((x, y))
}

/// Sign an ES256 compact JWS (`header.payload.signature`, raw `r‖s`).
pub fn sign_es256_jws(
    key: &p256::ecdsa::SigningKey,
    header: &serde_json::Value,
    claims: &serde_json::Value,
) -> String {
    use p256::ecdsa::signature::Signer;
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let sig: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// Verify an ES256 compact JWS under `key` and return its claims. The
/// header must say `alg` ES256 and mark nothing critical.
pub fn verify_es256_jws(token: &str, key: &p256::ecdsa::VerifyingKey) -> Option<serde_json::Value> {
    let mut parts = token.split('.');
    let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).ok()?).ok()?;
    if header.get("alg")?.as_str()? != "ES256" || header.get("crit").is_some() {
        return None;
    }
    let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(s).ok()?).ok()?;
    key.verify(format!("{h}.{p}").as_bytes(), &sig).ok()?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).ok()?).ok()
}

/// The Rewrap body's top-level `signed_request_token`, verified as an ES256
/// JWT under the bearer's `cnf` key, with an `exp` no later than the
/// bearer's and not past. Nothing else in the body is read.
pub fn verify_signed_request(body: &[u8], bearer: &OwnerKasToken, now: i64) -> bool {
    #[derive(serde::Deserialize)]
    struct Envelope {
        signed_request_token: String,
    }
    let Ok(envelope) = serde_json::from_slice::<Envelope>(body) else {
        return false;
    };
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&bearer.x);
    sec1[33..].copy_from_slice(&bearer.y);
    let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1) else {
        return false;
    };
    let Some(claims) = verify_es256_jws(&envelope.signed_request_token, &key) else {
        return false;
    };
    match claims.get("exp").and_then(serde_json::Value::as_i64) {
        Some(exp) => exp <= bearer.exp && exp > now - SKEW_SECS,
        None => false,
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use coset::{CoseSign1Builder, HeaderBuilder};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;

    pub const ISS: &str = "https://identity.arkavo.net";
    pub const KID: &[u8] = b"identity-test";
    pub const ROUTE: &str = "01JC5Z8Q4M7N2P3R6S9T0V1W2X";
    pub const SUB: &str = "0a1b2c3d-0000-4000-8000-000000000001";

    pub fn identity_key() -> SigningKey {
        SigningKey::from_slice(&[7u8; 32]).unwrap()
    }

    pub fn request_key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    pub fn verifier() -> OwnerKasVerifier {
        OwnerKasVerifier {
            issuer: ISS.into(),
            keys: CoseKeyCache::with_static_keys(vec![(
                KID.to_vec(),
                *identity_key().verifying_key(),
            )]),
        }
    }

    pub struct Mint<'a> {
        pub sub: &'a str,
        pub aud: String,
        pub iat: i64,
        pub exp: i64,
        pub content_type: &'a str,
        pub request_key: SigningKey,
        pub signer: SigningKey,
    }

    impl<'a> Mint<'a> {
        pub fn new(route: &str, now: i64) -> Self {
            Self {
                sub: SUB,
                aud: format!("{AUDIENCE_PREFIX}{route}"),
                iat: now,
                exp: now + LIFETIME_SECONDS,
                content_type: CONTENT_TYPE,
                request_key: request_key(3),
                signer: identity_key(),
            }
        }

        /// The token as identity mints it: unpadded base64url.
        pub fn token(&self) -> String {
            let int = |n: i64| Value::Integer(n.into());
            let point = self.request_key.verifying_key().to_encoded_point(false);
            let cnf = Value::Map(vec![(
                int(1),
                Value::Map(vec![
                    (int(1), int(2)),
                    (int(-1), int(1)),
                    (int(-2), Value::Bytes(point.x().unwrap().to_vec())),
                    (int(-3), Value::Bytes(point.y().unwrap().to_vec())),
                ]),
            )]);
            let payload = Value::Map(vec![
                (int(1), Value::Text(ISS.into())),
                (int(2), Value::Text(self.sub.into())),
                (int(3), Value::Text(self.aud.clone())),
                (int(4), int(self.exp)),
                (int(6), int(self.iat)),
                (int(7), Value::Bytes(vec![9; 16])),
                (int(8), cnf),
                (
                    Value::Text(HANDLE_CLAIM.into()),
                    Value::Text("alice.arkavo.social".into()),
                ),
            ]);
            let mut bytes = Vec::new();
            ciborium::ser::into_writer(&payload, &mut bytes).unwrap();
            let protected = HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .key_id(KID.to_vec())
                .content_type(self.content_type.to_string())
                .build();
            let signer = self.signer.clone();
            let inner = CoseSign1Builder::new()
                .protected(protected)
                .payload(bytes)
                .create_signature(b"", |m| {
                    let s: Signature = signer.sign(m);
                    s.to_bytes().to_vec()
                })
                .build()
                .to_vec()
                .unwrap();
            let mut out = CWT_TAG_PREFIX.to_vec();
            out.extend_from_slice(&inner);
            URL_SAFE_NO_PAD.encode(out)
        }

        /// A Rewrap body whose signed request token the request key signs.
        pub fn rewrap_body(&self, exp: i64, extra: &str) -> Vec<u8> {
            let jwt = sign_es256_jws(
                &self.request_key,
                &serde_json::json!({ "alg": "ES256", "typ": "JWT" }),
                &serde_json::json!({ "requestBody": format!("{{\"x\":\"{extra}\"}}"), "exp": exp }),
            );
            serde_json::to_vec(&serde_json::json!({ "signed_request_token": jwt })).unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    const NOW: i64 = 1_900_000_000;

    #[test]
    fn route_ids_are_canonical_ulids_only() {
        assert!(is_route_id(ROUTE));
        assert!(is_route_id("7ZZZZZZZZZZZZZZZZZZZZZZZZZ"));
        for bad in [
            "",
            "01JC000000000000000000000",
            "01JC00000000000000000000000",
            "81JC0000000000000000000000",
            "01jc0000000000000000000000",
            "01JC000000000000000000000I",
            "01JC000000000000000000000L",
            "01JC000000000000000000000O",
            "01JC000000000000000000000U",
            "01JC00000000000000000000-0",
        ] {
            assert!(!is_route_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn new_request_ids_are_ulids_in_time_order() {
        let a = new_ulid(1_700_000_000_000);
        let b = new_ulid(1_700_000_000_001);
        assert!(is_route_id(&a) && is_route_id(&b));
        assert!(a < b);
    }

    #[test]
    fn subjects_are_bare_lowercase_uuids() {
        assert!(is_bare_subject(SUB));
        assert!(!is_bare_subject(&SUB.to_uppercase()));
        assert!(!is_bare_subject(&format!("arkavo:{SUB}")));
        assert!(!is_bare_subject(&SUB.replace('-', "")));
    }

    #[tokio::test]
    async fn a_minted_token_verifies() {
        let t = verifier()
            .verify(&Mint::new(ROUTE, NOW).token(), NOW, 0)
            .await
            .unwrap();
        assert_eq!((t.sub.as_str(), t.route_id.as_str()), (SUB, ROUTE));
        assert_eq!(t.exp, NOW + LIFETIME_SECONDS);
    }

    #[tokio::test]
    async fn the_contract_is_enforced() {
        let v = verifier();
        let check = |m: Mint<'static>| {
            let token = m.token();
            let v = &v;
            async move { v.verify(&token, NOW, 0).await }
        };
        let mut m = Mint::new(ROUTE, NOW);
        m.content_type = "application/cwt";
        assert_eq!(check(m).await, Err(TokenError::Invalid), "content type");
        let mut m = Mint::new(ROUTE, NOW);
        m.aud = "arkavo".into();
        assert_eq!(check(m).await, Err(TokenError::Invalid), "audience");
        let mut m = Mint::new(ROUTE, NOW);
        m.aud = format!("{AUDIENCE_PREFIX}{}", ROUTE.to_lowercase());
        assert_eq!(check(m).await, Err(TokenError::Invalid), "route form");
        let mut m = Mint::new(ROUTE, NOW);
        m.exp = NOW + LIFETIME_SECONDS + 1;
        assert_eq!(check(m).await, Err(TokenError::Invalid), "lifetime");
        let mut m = Mint::new(ROUTE, NOW);
        m.signer = request_key(9);
        assert_eq!(check(m).await, Err(TokenError::Invalid), "signature");
        let mut m = Mint::new(ROUTE, NOW);
        m.sub = "arkavo:0a1b2c3d-0000-4000-8000-000000000001";
        assert_eq!(check(m).await, Err(TokenError::Invalid), "subject form");
    }

    #[tokio::test]
    async fn time_is_checked_with_skew_and_optional_grace() {
        let v = verifier();
        let token = Mint::new(ROUTE, NOW).token();
        let exp = NOW + LIFETIME_SECONDS;
        assert!(v.verify(&token, exp + SKEW_SECS - 1, 0).await.is_ok());
        assert!(v.verify(&token, exp + SKEW_SECS, 0).await.is_err());
        assert!(v.verify(&token, exp + 600, 600).await.is_ok());
        assert!(v.verify(&token, NOW - SKEW_SECS - 1, 0).await.is_err());
    }

    #[tokio::test]
    async fn a_passkey_session_cwt_is_not_an_owner_kas_token() {
        use crate::modules::authzen::cwt_verify::test_support::mint;
        // An identity session CWT signed with the same key and kid.
        let session = mint(
            &identity_key(),
            KID,
            ISS,
            SUB,
            "arkavo",
            NOW,
            NOW + 3600,
            &[1; 16],
        );
        assert_eq!(
            verifier().verify(&session, NOW, 0).await,
            Err(TokenError::Invalid)
        );
    }

    #[tokio::test]
    async fn the_signed_request_must_be_signed_by_cnf_and_end_by_the_bearer() {
        let m = Mint::new(ROUTE, NOW);
        let t = verifier().verify(&m.token(), NOW, 0).await.unwrap();
        assert!(verify_signed_request(&m.rewrap_body(t.exp, "a"), &t, NOW));
        assert!(!verify_signed_request(
            &m.rewrap_body(t.exp + 1, "a"),
            &t,
            NOW
        ));
        assert!(!verify_signed_request(
            &m.rewrap_body(NOW - SKEW_SECS - 1, "a"),
            &t,
            NOW
        ));
        let mut other = Mint::new(ROUTE, NOW);
        other.request_key = request_key(4);
        assert!(!verify_signed_request(
            &other.rewrap_body(t.exp, "a"),
            &t,
            NOW
        ));
        assert!(!verify_signed_request(b"{}", &t, NOW));
        assert!(!verify_signed_request(b"not json", &t, NOW));
    }
}
