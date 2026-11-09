//! The owner's route record (design §4.3): admitted at `PUT
//! /owner-kas/v1/routes/{route_id}` when its passkey chain holds, as
//! tdf-iroh-s3 admits catalog v2 pointers (ADR-0061).
//!
//! The body is catalog v2's bundle with `record` in place of `pointer`:
//!
//! ```json
//! { "record": "<b64url record bytes>",
//!   "assertion": { "credentialId", "authenticatorData", "clientDataJSON", "signature" },
//!   "credential": "<b64url identity attestation>" }
//! ```
//!
//! - **Record**: deterministic CBOR, a map with exactly the text keys `v`
//!   (1), `route_id`, `owner_sub`, `kas_key` (65-byte SEC1), `kas_kid`,
//!   `service_key` (65-byte SEC1), `seq` (1..2^53-1) and `issued_at` (unix s).
//! - **Assertion**: WebAuthn, RP `identity.arkavo.net`, challenge SHA-256 of
//!   the record bytes, user present and verified.
//! - **Credential**: identity's COSE_Sign1 binding the credential ID and its
//!   public key to `sub`.
//!
//! Admission of a record is not an access decision: receivers check the same
//! chain themselves.

use crate::modules::authzen::cose_keys::CoseKeyCache;
use crate::modules::authzen::cwt_verify::VerifyError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ciborium::value::Value;
use coset::{iana, CborSerializable, TaggedCborSerializable};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use super::token::{is_bare_subject, is_route_id};

pub const CREDENTIAL_CONTENT_TYPE: &str = "application/arkavo-passkey-credential+cbor";
pub const PASSKEY_CREDENTIAL_TYP: &str = "arkavo-passkey-credential";
pub const MAX_SEQ: u64 = 9_007_199_254_740_991;

const MAX_RECORD_BYTES: usize = 1024;
const MAX_KID_BYTES: usize = 128;
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;
const MAX_AUTHENTICATOR_DATA_BYTES: usize = 4096;
const MAX_CLIENT_DATA_BYTES: usize = 4096;
const MAX_SIGNATURE_BYTES: usize = 80;
const MAX_ATTESTATION_BYTES: usize = 4096;
/// Largest `PUT /routes/{id}` body.
pub const MAX_BUNDLE_BYTES: usize = 16 * 1024;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const SKEW_SECS: i64 = 60;

/// The relying party owners sign with.
#[derive(Debug, Clone)]
pub struct Passkeys {
    pub rp_id: String,
    pub origin: String,
}

impl Passkeys {
    pub fn for_rp(rp_id: &str) -> Self {
        Self {
            rp_id: rp_id.to_string(),
            origin: format!("https://{rp_id}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub record: String,
    pub assertion: Assertion,
    pub credential: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    #[serde(rename = "credentialId")]
    pub credential_id: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub signature: String,
}

/// A parsed route record. Keys are kept as bytes; the relay uses none of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRecord {
    pub route_id: String,
    pub owner_sub: String,
    pub seq: u64,
    pub issued_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// The bundle does not hold: 422 with the reason.
    Invalid(String),
    /// Identity's key set could not be fetched: 503.
    KeySet,
}

fn invalid(reason: impl Into<String>) -> RecordError {
    RecordError::Invalid(reason.into())
}

/// A bundle whose chain verified.
#[derive(Debug, Clone)]
pub struct VerifiedRecord {
    pub record: RouteRecord,
    pub credential_id: Vec<u8>,
}

fn b64(field: &str, value: &str, max: usize) -> Result<Vec<u8>, RecordError> {
    if value.len() > max.div_ceil(3) * 4 {
        return Err(invalid(format!("{field} too large")));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid(format!("{field} is not unpadded base64url")))?;
    if bytes.is_empty() || bytes.len() > max {
        return Err(invalid(format!("{field} must be 1-{max} bytes")));
    }
    Ok(bytes)
}

/// Parse record bytes: exactly the eight keys, each of its type.
pub fn parse_record(bytes: &[u8]) -> Result<RouteRecord, String> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(format!("record larger than {MAX_RECORD_BYTES} bytes"));
    }
    let value: Value = ciborium::de::from_reader(bytes).map_err(|_| "record is not CBOR")?;
    let Value::Map(entries) = value else {
        return Err("record is not a map".into());
    };
    let mut seen = HashSet::new();
    let (mut v, mut route, mut owner, mut kas_key, mut kas_kid, mut service_key, mut seq, mut at) =
        (None, None, None, None, None, None, None, None);
    let uint = |n: ciborium::value::Integer| u64::try_from(n).ok();
    let point = |b: &[u8]| b.len() == 65 && p256::PublicKey::from_sec1_bytes(b).is_ok();
    for (k, val) in entries {
        let Value::Text(k) = k else {
            return Err("record keys must be text".into());
        };
        if !seen.insert(k.clone()) {
            return Err(format!("record repeats {k}"));
        }
        match (k.as_str(), val) {
            ("v", Value::Integer(n)) => v = uint(n),
            ("route_id", Value::Text(s)) => route = Some(s),
            ("owner_sub", Value::Text(s)) => owner = Some(s),
            ("kas_key", Value::Bytes(b)) if point(&b) => kas_key = Some(()),
            ("kas_kid", Value::Text(s)) if !s.is_empty() && s.len() <= MAX_KID_BYTES => {
                kas_kid = Some(())
            }
            ("service_key", Value::Bytes(b)) if point(&b) => service_key = Some(()),
            ("seq", Value::Integer(n)) => seq = uint(n),
            ("issued_at", Value::Integer(n)) => at = uint(n),
            (other, _) => return Err(format!("record has unexpected or invalid {other}")),
        }
    }
    if v != Some(1) {
        return Err("record v must be 1".into());
    }
    let route_id = route
        .filter(|r| is_route_id(r))
        .ok_or("record route_id must be a canonical ULID")?;
    let owner_sub = owner
        .filter(|s| is_bare_subject(s))
        .ok_or("record owner_sub must be a bare lowercase UUID")?;
    kas_key.ok_or("record kas_key must be a P-256 SEC1 uncompressed point")?;
    kas_kid.ok_or("record kas_kid is missing or invalid")?;
    service_key.ok_or("record service_key must be a P-256 SEC1 uncompressed point")?;
    let seq = seq
        .filter(|s| (1..=MAX_SEQ).contains(s))
        .ok_or(format!("record seq must be 1-{MAX_SEQ}"))?;
    let issued_at = at.ok_or("record issued_at must be unix seconds")?;
    Ok(RouteRecord {
        route_id,
        owner_sub,
        seq,
        issued_at,
    })
}

/// Verify the chain for the route in the path and the session's `sub`:
/// identity's attestation, its subject equal to `owner_sub` and to the
/// session's, the passkey assertion over the record bytes, and the record.
/// The credential's status at identity and `seq` are the caller's.
pub async fn verify_bundle(
    bundle: &Bundle,
    route_id: &str,
    session_sub: &str,
    keys: &CoseKeyCache,
    issuer: &str,
    passkeys: &Passkeys,
    now: i64,
) -> Result<VerifiedRecord, RecordError> {
    let record_bytes = b64("record", &bundle.record, MAX_RECORD_BYTES)?;
    let record = parse_record(&record_bytes).map_err(invalid)?;
    if record.route_id != route_id {
        return Err(invalid("record route_id does not match the path"));
    }
    if record.owner_sub != session_sub {
        return Err(invalid("record owner_sub is not the session's subject"));
    }

    let attestation = b64("credential", &bundle.credential, MAX_ATTESTATION_BYTES)?;
    let credential = verify_credential(&attestation, keys, issuer, now).await?;
    if credential.sub != record.owner_sub {
        return Err(invalid("credential subject is not the record's owner_sub"));
    }
    if credential.rp_id != passkeys.rp_id {
        return Err(invalid("credential rpId is not this relying party"));
    }
    let credential_id = b64(
        "assertion.credentialId",
        &bundle.assertion.credential_id,
        MAX_CREDENTIAL_ID_BYTES,
    )?;
    if credential_id != credential.credential_id {
        return Err(invalid(
            "assertion credentialId does not match the attested credential",
        ));
    }
    verify_assertion(
        &record_bytes,
        &bundle.assertion,
        &credential.public_key,
        passkeys,
    )?;
    Ok(VerifiedRecord {
        record,
        credential_id,
    })
}

struct Credential {
    sub: String,
    credential_id: Vec<u8>,
    public_key: VerifyingKey,
    rp_id: String,
}

/// Identity's COSE_Sign1 attestation (tag 18 or untagged), ES256 under its
/// key set, with the attestation content type.
async fn verify_credential(
    bytes: &[u8],
    keys: &CoseKeyCache,
    issuer: &str,
    now: i64,
) -> Result<Credential, RecordError> {
    let sign1 = if bytes.first() == Some(&0xD2) {
        coset::CoseSign1::from_tagged_slice(bytes)
    } else {
        coset::CoseSign1::from_slice(bytes)
    }
    .map_err(|_| invalid("credential is not a COSE_Sign1"))?;
    let h = &sign1.protected.header;
    if h.content_type != Some(coset::ContentType::Text(CREDENTIAL_CONTENT_TYPE.into())) {
        return Err(invalid(format!(
            "credential content type must be \"{CREDENTIAL_CONTENT_TYPE}\""
        )));
    }
    if h.alg != Some(coset::Algorithm::Assigned(iana::Algorithm::ES256)) {
        return Err(invalid("credential must be ES256"));
    }
    if !h.crit.is_empty() || h.key_id.is_empty() {
        return Err(invalid("credential header is malformed"));
    }
    let key = match keys.resolve(&h.key_id).await {
        Ok(k) => k,
        Err(VerifyError::KeySet) => return Err(RecordError::KeySet),
        Err(_) => return Err(invalid("credential signed by an unknown key")),
    };
    sign1
        .verify_signature(b"", |sig, data| {
            let sig = Signature::from_slice(sig).map_err(|_| ())?;
            key.verify(data, &sig).map_err(|_| ())
        })
        .map_err(|_| invalid("credential signature does not verify"))?;
    let payload = sign1
        .payload
        .as_deref()
        .ok_or_else(|| invalid("credential has no payload"))?;
    let (iss, iat, credential) = parse_credential(payload).map_err(invalid)?;
    if iss != issuer {
        return Err(invalid("credential issuer mismatch"));
    }
    if iat > now + SKEW_SECS {
        return Err(invalid("credential issued in the future"));
    }
    Ok(credential)
}

fn p256_from_cose_key(v: &Value) -> Result<VerifyingKey, String> {
    let map = v.as_map().ok_or("not a map")?;
    let get = |label: i64| {
        map.iter()
            .find(|(k, _)| *k == Value::Integer(label.into()))
            .map(|(_, v)| v)
    };
    if get(iana::KeyParameter::Kty as i64)
        != Some(&Value::Integer((iana::KeyType::EC2 as i64).into()))
        || get(iana::Ec2KeyParameter::Crv as i64)
            != Some(&Value::Integer((iana::EllipticCurve::P_256 as i64).into()))
    {
        return Err("not an EC2 P-256 key".into());
    }
    let coord = |label: i64| {
        get(label)
            .and_then(Value::as_bytes)
            .filter(|b| b.len() == 32)
            .ok_or("bad coordinate")
    };
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(coord(iana::Ec2KeyParameter::X as i64)?);
    sec1.extend_from_slice(coord(iana::Ec2KeyParameter::Y as i64)?);
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| "point not on the curve".into())
}

/// Exactly the text keys `typ`, `iss`, `sub`, `credentialId`, `publicKey`,
/// `rpId` and `iat`. Returns `(iss, iat, credential)`.
fn parse_credential(payload: &[u8]) -> Result<(String, i64, Credential), String> {
    let value: Value =
        ciborium::de::from_reader(payload).map_err(|_| "credential payload is not CBOR")?;
    let Value::Map(entries) = value else {
        return Err("credential payload is not a map".into());
    };
    let mut seen = HashSet::new();
    let (mut typ, mut iss, mut sub, mut id, mut key, mut rp, mut iat) =
        (None, None, None, None, None, None, None);
    for (k, v) in entries {
        let Value::Text(k) = k else {
            return Err("credential keys must be text".into());
        };
        if !seen.insert(k.clone()) {
            return Err(format!("credential repeats {k}"));
        }
        match (k.as_str(), v) {
            ("typ", Value::Text(s)) => typ = Some(s),
            ("iss", Value::Text(s)) => iss = Some(s),
            ("sub", Value::Text(s)) => sub = Some(s),
            ("credentialId", Value::Bytes(b)) => id = Some(b),
            ("publicKey", m @ Value::Map(_)) => {
                key =
                    Some(p256_from_cose_key(&m).map_err(|e| format!("credential publicKey: {e}"))?)
            }
            ("rpId", Value::Text(s)) => rp = Some(s),
            ("iat", Value::Integer(n)) => {
                iat = Some(i64::try_from(n).map_err(|_| "credential iat")?);
            }
            (other, _) => return Err(format!("credential has unexpected or mistyped {other}")),
        }
    }
    if typ.as_deref() != Some(PASSKEY_CREDENTIAL_TYP) {
        return Err(format!(
            "credential typ must be \"{PASSKEY_CREDENTIAL_TYP}\""
        ));
    }
    let missing = |name: &str| format!("credential is missing {name}");
    Ok((
        iss.ok_or_else(|| missing("iss"))?,
        iat.ok_or_else(|| missing("iat"))?,
        Credential {
            sub: sub
                .filter(|s| !s.is_empty())
                .ok_or_else(|| missing("sub"))?,
            credential_id: id
                .filter(|b| !b.is_empty())
                .ok_or_else(|| missing("credentialId"))?,
            public_key: key.ok_or_else(|| missing("publicKey"))?,
            rp_id: rp.ok_or_else(|| missing("rpId"))?,
        },
    ))
}

/// WebAuthn L2 §7.2 for a stored key: `webauthn.get`, challenge =
/// SHA-256(record bytes), this origin, not cross-origin, this RP's ID hash,
/// UP and UV, and an ES256 (DER) signature over `authenticatorData ||
/// SHA-256(clientDataJSON)`. The signature counter is ignored (synced
/// passkeys report 0).
fn verify_assertion(
    record_bytes: &[u8],
    assertion: &Assertion,
    key: &VerifyingKey,
    passkeys: &Passkeys,
) -> Result<(), RecordError> {
    let auth_data = b64(
        "assertion.authenticatorData",
        &assertion.authenticator_data,
        MAX_AUTHENTICATOR_DATA_BYTES,
    )?;
    let client_data = b64(
        "assertion.clientDataJSON",
        &assertion.client_data_json,
        MAX_CLIENT_DATA_BYTES,
    )?;
    let signature = b64(
        "assertion.signature",
        &assertion.signature,
        MAX_SIGNATURE_BYTES,
    )?;
    let cd: serde_json::Value =
        serde_json::from_slice(&client_data).map_err(|_| invalid("clientDataJSON is not JSON"))?;
    if cd.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return Err(invalid("clientDataJSON type must be webauthn.get"));
    }
    let challenge = cd
        .get("challenge")
        .and_then(|v| v.as_str())
        .and_then(|c| URL_SAFE_NO_PAD.decode(c).ok())
        .ok_or_else(|| invalid("clientDataJSON challenge missing or not base64url"))?;
    if challenge != Sha256::digest(record_bytes).as_slice() {
        return Err(invalid("assertion challenge is not SHA-256 of the record"));
    }
    if cd.get("origin").and_then(|v| v.as_str()) != Some(passkeys.origin.as_str()) {
        return Err(invalid("clientDataJSON origin is not this relying party"));
    }
    if cd.get("crossOrigin").and_then(|v| v.as_bool()) == Some(true) {
        return Err(invalid("cross-origin assertions are refused"));
    }
    if auth_data.len() < 37 {
        return Err(invalid("authenticatorData too short"));
    }
    if auth_data[..32] != Sha256::digest(passkeys.rp_id.as_bytes())[..] {
        return Err(invalid(
            "authenticatorData rpIdHash is not this relying party",
        ));
    }
    let flags = auth_data[32];
    if flags & FLAG_UP == 0 || flags & FLAG_UV == 0 {
        return Err(invalid(
            "assertion must have user presence and verification",
        ));
    }
    let signature = Signature::from_der(&signature)
        .map_err(|_| invalid("assertion signature is not DER ECDSA"))?;
    let mut signed = auth_data;
    signed.extend_from_slice(&Sha256::digest(&client_data));
    key.verify(&signed, &signature)
        .map_err(|_| invalid("assertion signature does not verify"))
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A bundle built the way the app and identity build one.
    use super::*;
    use crate::modules::owner_kas::token::test_support::{identity_key, ISS, KID};
    use coset::{CoseSign1Builder, HeaderBuilder};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;

    pub const RP: &str = "identity.arkavo.net";
    pub const CREDENTIAL_ID: &[u8] = b"credential-1";

    pub fn passkey() -> SigningKey {
        SigningKey::from_slice(&[5u8; 32]).unwrap()
    }

    fn sec1(seed: u8) -> Vec<u8> {
        SigningKey::from_slice(&[seed; 32])
            .unwrap()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    pub fn record_bytes(route: &str, owner: &str, seq: u64) -> Vec<u8> {
        let t = |s: &str| Value::Text(s.into());
        let map = Value::Map(vec![
            (t("v"), Value::Integer(1.into())),
            (t("route_id"), t(route)),
            (t("owner_sub"), t(owner)),
            (t("kas_key"), Value::Bytes(sec1(11))),
            (t("kas_kid"), t("k1")),
            (t("service_key"), Value::Bytes(sec1(12))),
            (t("seq"), Value::Integer(seq.into())),
            (t("issued_at"), Value::Integer(1_900_000_000.into())),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&map, &mut out).unwrap();
        out
    }

    pub fn attestation(sub: &str) -> Vec<u8> {
        let point = passkey().verifying_key().to_encoded_point(false);
        let int = |n: i64| Value::Integer(n.into());
        let t = |s: &str| Value::Text(s.into());
        let payload = Value::Map(vec![
            (t("typ"), t(PASSKEY_CREDENTIAL_TYP)),
            (t("iss"), t(ISS)),
            (t("sub"), t(sub)),
            (t("credentialId"), Value::Bytes(CREDENTIAL_ID.to_vec())),
            (
                t("publicKey"),
                Value::Map(vec![
                    (int(1), int(2)),
                    (int(-1), int(1)),
                    (int(-2), Value::Bytes(point.x().unwrap().to_vec())),
                    (int(-3), Value::Bytes(point.y().unwrap().to_vec())),
                ]),
            ),
            (t("rpId"), t(RP)),
            (t("iat"), int(1_700_000_000)),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut bytes).unwrap();
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(KID.to_vec())
            .content_type(CREDENTIAL_CONTENT_TYPE.to_string())
            .build();
        CoseSign1Builder::new()
            .protected(protected)
            .payload(bytes)
            .create_signature(b"", |m| {
                let s: Signature = identity_key().sign(m);
                s.to_bytes().to_vec()
            })
            .build()
            .to_tagged_vec()
            .unwrap()
    }

    pub fn bundle_for(record: &[u8], attested_sub: &str, flags: u8) -> Bundle {
        let enc = |b: &[u8]| URL_SAFE_NO_PAD.encode(b);
        let client_data = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.get",
            "challenge": enc(&Sha256::digest(record)),
            "origin": format!("https://{RP}"),
        }))
        .unwrap();
        let mut auth_data = Sha256::digest(RP.as_bytes()).to_vec();
        auth_data.push(flags);
        auth_data.extend_from_slice(&[0, 0, 0, 0]);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let sig: Signature = passkey().sign(&signed);
        Bundle {
            record: enc(record),
            assertion: Assertion {
                credential_id: enc(CREDENTIAL_ID),
                authenticator_data: enc(&auth_data),
                client_data_json: enc(&client_data),
                signature: enc(sig.to_der().as_bytes()),
            },
            credential: enc(&attestation(attested_sub)),
        }
    }

    pub fn bundle(route: &str, owner: &str, seq: u64) -> Bundle {
        bundle_for(&record_bytes(route, owner, seq), owner, FLAG_UP | FLAG_UV)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::modules::owner_kas::token::test_support::{identity_key, ISS, KID, ROUTE, SUB};

    const OTHER: &str = "0a1b2c3d-0000-4000-8000-000000000002";

    fn keys() -> CoseKeyCache {
        CoseKeyCache::with_static_keys(vec![(KID.to_vec(), *identity_key().verifying_key())])
    }

    async fn check(b: &Bundle, route: &str, sub: &str) -> Result<VerifiedRecord, RecordError> {
        verify_bundle(
            b,
            route,
            sub,
            &keys(),
            ISS,
            &Passkeys::for_rp(RP),
            1_900_000_000,
        )
        .await
    }

    #[tokio::test]
    async fn a_good_bundle_verifies() {
        let v = check(&bundle(ROUTE, SUB, 3), ROUTE, SUB).await.unwrap();
        assert_eq!(v.record.seq, 3);
        assert_eq!(v.record.owner_sub, SUB);
        assert_eq!(v.credential_id, CREDENTIAL_ID);
    }

    #[tokio::test]
    async fn the_chain_is_bound_to_the_route_and_the_session() {
        let b = bundle(ROUTE, SUB, 1);
        assert!(check(&b, "01JC0000000000000000000000", SUB).await.is_err());
        assert!(check(&b, ROUTE, OTHER).await.is_err());
        // Attested to someone else.
        let b = bundle_for(&record_bytes(ROUTE, SUB, 1), OTHER, FLAG_UP | FLAG_UV);
        assert!(check(&b, ROUTE, SUB).await.is_err());
        // No user verification.
        let b = bundle_for(&record_bytes(ROUTE, SUB, 1), SUB, FLAG_UP);
        assert!(check(&b, ROUTE, SUB).await.is_err());
        // A record other than the one the passkey signed.
        let mut b = bundle(ROUTE, SUB, 1);
        b.record = URL_SAFE_NO_PAD.encode(record_bytes(ROUTE, SUB, 2));
        assert!(check(&b, ROUTE, SUB).await.is_err());
    }

    #[test]
    fn records_are_exactly_the_contract() {
        assert!(parse_record(&record_bytes(ROUTE, SUB, 1)).is_ok());
        assert!(parse_record(&record_bytes(ROUTE, SUB, 0)).is_err());
        assert!(parse_record(&record_bytes(ROUTE, &SUB.to_uppercase(), 1)).is_err());
        assert!(parse_record(&record_bytes(&ROUTE.to_lowercase(), SUB, 1)).is_err());
        let mut extra: Value = ciborium::de::from_reader(&record_bytes(ROUTE, SUB, 1)[..]).unwrap();
        if let Value::Map(m) = &mut extra {
            m.push((Value::Text("x".into()), Value::Bool(true)));
        }
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&extra, &mut bytes).unwrap();
        assert!(parse_record(&bytes).is_err());
    }
}
