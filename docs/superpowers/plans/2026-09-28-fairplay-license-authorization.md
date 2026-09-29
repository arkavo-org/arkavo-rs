# FairPlay License Authorization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** arks issues a FairPlay CKC only to an authenticated person whose TDF policy binding is intact and whom the OpenTDF platform permits.

**Architecture:**
- A new `src/modules/license/` module holds four pieces, each tested alone:
  - a person-token verifier;
  - a TDF manifest and policy checker;
  - a platform `GetDecision` client with a cached service token;
  - a `LicenseIssuer` trait that hides the FairPlay SDK.
- `media_api.rs` wires them into the `/media/v1` routes.
- The FairPlay SDK sits behind the trait, so the whole authorization pipeline is tested without the `fairplay` feature. CI runs `cargo test` without that feature.

**Tech Stack:** Rust, Axum 0.7, tokio, `ciborium`/`coset`/`p256` (existing CWT verifier), `rsa` + `sha1` (OAEP), `hmac` 0.12 + `sha2`, `reqwest`, `wiremock` (tests), Redis (session manager; CI provides it), `openssl` CLI (fixture generation only).

**Spec:** `docs/superpowers/specs/2026-09-28-fairplay-license-authorization-design.md`

## Global Constraints

- Never modify `vendor/fpssdk/`. Format with `cargo fmt --package arkavo-rs --package fairplay-wrapper`, never `--all`.
- Lint gate (same as CI): `cargo clippy --package arkavo-rs --lib --bin arks -- -D warnings -A mismatched-lifetime-syntaxes -A unexpected-cfgs`. Feature typecheck: `cargo check --release --bin arks --features fairplay,c2pa_signing`.
- Tests: `cargo test --bin arks <filter>`. Default features only; Redis on `redis://localhost:6379`.
- Policy binding: `base64(HMAC-SHA256(key=DEK, msg=<base64 policy string exactly as in the manifest>))`. The hex form and a raw-JSON HMAC are refused.
- DEK wrapping: RSA-OAEP with SHA-1 (MGF1 SHA-1).
- Token audience must contain **both** `https://platform.arkavo.net` (`MEDIA_PLATFORM_AUDIENCE`) and `arkavo`. `sub` must be person-shaped: `arkavo:`, `apple:` or `google:` prefix, or a UUID. Any agent marker is refused.
- Status codes:
  - 401 only for a missing, expired, bad-signature or wrong-issuer token;
  - 403 for a non-person subject, session mismatch, bad manifest, or deny;
  - 503 when the platform, identity or service token is unavailable.
- Never log a token, SPC, CKC, wrapped key or DEK.
- Lease: `MEDIA_FPS_LEASE_SECONDS`, default `3600`. License type is always streaming; `offline-hls` is never sent.
- Accepted KAS URLs: `MEDIA_KAS_URLS` (comma list), default `https://platform.arkavo.net`. Matching is normalised.
- Service credential: `ARKS_MEDIA_CLIENT_ID` (default `arks-media`) and `ARKS_MEDIA_CLIENT_SECRET`. Token endpoint `{OIDC_ISSUER}/oauth/token`, HTTP Basic auth. `OIDC_ISSUER` defaults to `https://identity.arkavo.net`.
- `production/` is gitignored. Never commit it.

## File Structure

| File | Responsibility |
|---|---|
| `src/modules/authzen/cwt_subject.rs` (modify) | `DecodedClaims` gains `agent_marker: bool` |
| `src/modules/authzen/cwt_verify.rs` (modify) | `parse_claims` sets `agent_marker` |
| `src/modules/license/mod.rs` (create) | Module root, `LicenseError` |
| `src/modules/license/person_token.rs` (create) | Bearer CWT → verified person (`Person`) |
| `src/modules/license/tdf_policy.rs` (create) | Manifest → `CheckedPolicy` (DEK, policy uuid, FQNs) |
| `src/modules/license/pdp.rs` (create) | `GetDecision` client and service-token cache |
| `src/modules/license/issuer.rs` (create) | `LicenseIssuer` trait and the FairPlay implementation |
| `src/modules/license/config.rs` (create) | Build the above from env |
| `src/modules/license/fixtures/` (create) | generator script (fixtures are produced at test time, never committed) and `src/modules/license/fixtures.rs` test helper |
| `src/modules/mod.rs` (modify) | `pub mod license;` |
| `crates/fairplay-wrapper/src/lib.rs` (modify) | Lease duration in the request; SPC `asset-id` in the response |
| `src/modules/fairplay.rs` (modify) | Pass the lease, return `IssuedLicense` |
| `src/modules/media_api.rs` (modify) | Auth on routes, the license pipeline, TDF3 off, `tdfWrappedKey` removed |
| `src/bin/main.rs` (modify) | Wire the license state into `MediaApiState` |
| `Cargo.toml` (modify) | Add `hmac = "0.12"` |
| `CLAUDE.md`, `docs/standard_tdf_fairplay_integration.md`, `docs/fairplay.md` (modify) | Env vars and the new request contract |

---

### Task 1: Agent-marker parsing in the CWT verifier

**Files:**
- Modify: `src/modules/authzen/cwt_subject.rs:25-42` (struct) and the test literals in that file that build `DecodedClaims { … }`
- Modify: `src/modules/authzen/cwt_verify.rs:144-258` (`parse_claims`)
- Test: `src/modules/authzen/cwt_verify.rs` (`mod tests`)

**Interfaces:**
- Produces: `DecodedClaims.agent_marker: bool`. It is true when the token carries `arkavo_npe` (any value), `arkavo_swarm`, `arkavo_state_version`, or an `arkavo_roles` list containing `"agent"`.

- [ ] **Step 1: Write the failing tests** (append inside `mod tests` in `cwt_verify.rs`)

```rust
    fn base_entries(extra: Vec<(Value, Value)>) -> Vec<(Value, Value)> {
        let mut v = vec![
            (Value::Integer(1.into()), Value::Text("https://identity.test".into())),
            (Value::Integer(2.into()), Value::Text("550e8400-e29b-41d4-a716-446655440000".into())),
            (Value::Integer(3.into()), Value::Text("arkavo".into())),
            (Value::Integer(4.into()), Value::Integer((NOW + 3600).into())),
            (Value::Integer(6.into()), Value::Integer(NOW.into())),
            (Value::Integer(7.into()), Value::Bytes(vec![9u8; 16])),
        ];
        v.extend(extra);
        v
    }

    #[test]
    fn agent_marker_false_for_plain_person() {
        let (sk, vk) = keypair();
        let t = mint_map(&sk, KID, base_entries(vec![]));
        assert!(!verify_header_token(&t, &vk, opts()).unwrap().agent_marker);
    }

    #[test]
    fn agent_marker_set_by_each_claim() {
        let cases: Vec<(Value, Value)> = vec![
            (Value::Text("arkavo_npe".into()), Value::Map(vec![(Value::Text("type".into()), Value::Text("agent".into()))])),
            (Value::Text("arkavo_npe".into()), Value::Text("garbage".into())),
            (Value::Text("arkavo_swarm".into()), Value::Text("s1".into())),
            (Value::Text("arkavo_state_version".into()), Value::Integer(0.into())),
            (Value::Text("arkavo_roles".into()), Value::Array(vec![Value::Text("reader".into()), Value::Text("agent".into())])),
        ];
        let (sk, vk) = keypair();
        for (k, v) in cases {
            let t = mint_map(&sk, KID, base_entries(vec![(k.clone(), v)]));
            assert!(verify_header_token(&t, &vk, opts()).unwrap().agent_marker, "{k:?}");
        }
    }
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test --bin arks agent_marker`
Expected: compile error, "no field `agent_marker` on type `DecodedClaims`".

- [ ] **Step 3: Implement**

In `cwt_subject.rs`, add the last field to `DecodedClaims`:

```rust
    pub arkavo_patreon: Option<Value>,
    /// Any agent marker (arkavo_npe, arkavo_swarm, arkavo_state_version, or
    /// the `agent` role). Presence alone counts, whatever the value.
    pub agent_marker: bool,
```

Add `agent_marker: false,` to every `DecodedClaims { … }` literal in `cwt_subject.rs` tests (`grep -n "DecodedClaims {" src/modules/authzen/cwt_subject.rs`).

In `cwt_verify.rs` `parse_claims`, add `let mut agent_marker = false;` beside the other locals. In the `Value::Text(key)` arm, add these arms **before** `_ => {}`, and extend the roles arm:

```rust
                ("arkavo_roles", Value::Array(a)) => {
                    let roles = text_array(a)?;
                    if roles.iter().any(|r| r == "agent") {
                        agent_marker = true;
                    }
                    arkavo_roles = Some(roles);
                }
                ("arkavo_npe", _) | ("arkavo_swarm", _) | ("arkavo_state_version", _) => {
                    agent_marker = true;
                }
```

(This replaces the existing `("arkavo_roles", Value::Array(a))` arm.) Add `agent_marker,` to the returned `DecodedClaims`.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `cargo test --bin arks cwt_`
Expected: all `cwt_verify` and `cwt_subject` tests pass, including the two new ones.

- [ ] **Step 5: Commit**

```bash
git add src/modules/authzen/cwt_verify.rs src/modules/authzen/cwt_subject.rs
git commit -m "feat(cwt): flag agent-marker claims on verified tokens"
```

---

### Task 2: License module skeleton and `LicenseError`

**Files:**
- Create: `src/modules/license/mod.rs`
- Modify: `src/modules/mod.rs` (add `pub mod license;` after `pub mod http_rewrap;`)

**Interfaces:**
- Produces:
  - `crate::modules::license::LicenseError { Unauthenticated(&'static str), Forbidden(&'static str), Unavailable(&'static str), BadRequest(&'static str) }`;
  - `LicenseError::status(&self) -> axum::http::StatusCode`;
  - `LicenseError::error_code(&self) -> &'static str`: `"authentication_failed"`, `"forbidden"`, `"service_unavailable"` or `"invalid_request"`;
  - `LicenseError::reason(&self) -> &'static str`.

- [ ] **Step 1: Write the failing test**

Create `src/modules/license/mod.rs`:

```rust
//! FairPlay license authorization: who may receive a content key, and for
//! which TDF policy. See docs/superpowers/specs/2026-09-28-fairplay-license-authorization-design.md.

use axum::http::StatusCode;

/// A refusal, carrying only a sanitized reason (never token or key material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseError {
    /// 401: the app deletes its token and prompts sign-in (ARK-110).
    Unauthenticated(&'static str),
    /// 403: valid caller, but not allowed (non-person, deny, bad manifest).
    Forbidden(&'static str),
    /// 503: the platform, identity or service credential is unavailable.
    Unavailable(&'static str),
    /// 400: the request is malformed before any authorization step.
    BadRequest(&'static str),
}

impl LicenseError {
    pub fn status(&self) -> StatusCode {
        match self {
            LicenseError::Unauthenticated(_) => StatusCode::UNAUTHORIZED,
            LicenseError::Forbidden(_) => StatusCode::FORBIDDEN,
            LicenseError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            LicenseError::BadRequest(_) => StatusCode::BAD_REQUEST,
        }
    }

    pub fn error_code(&self) -> &'static str {
        match self {
            LicenseError::Unauthenticated(_) => "authentication_failed",
            LicenseError::Forbidden(_) => "forbidden",
            LicenseError::Unavailable(_) => "service_unavailable",
            LicenseError::BadRequest(_) => "invalid_request",
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            LicenseError::Unauthenticated(r)
            | LicenseError::Forbidden(r)
            | LicenseError::Unavailable(r)
            | LicenseError::BadRequest(r) => r,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_and_code_mapping() {
        assert_eq!(LicenseError::Unauthenticated("x").status(), StatusCode::UNAUTHORIZED);
        assert_eq!(LicenseError::Forbidden("x").status(), StatusCode::FORBIDDEN);
        assert_eq!(LicenseError::Unavailable("x").status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(LicenseError::BadRequest("x").status(), StatusCode::BAD_REQUEST);
        assert_eq!(LicenseError::Forbidden("x").error_code(), "forbidden");
        assert_eq!(LicenseError::Unavailable("why").reason(), "why");
    }
}
```

Add `pub mod license;` to `src/modules/mod.rs`.

- [ ] **Step 2: Run the test and confirm it passes**

Run: `cargo test --bin arks license::tests`
Expected: PASS. It is a pure mapping, and the test pins it.

- [ ] **Step 3: Commit**

```bash
git add src/modules/license/mod.rs src/modules/mod.rs
git commit -m "feat(license): module root and LicenseError status mapping"
```

---

### Task 3: Person-token verifier

**Files:**
- Create: `src/modules/license/person_token.rs`
- Modify: `src/modules/license/mod.rs` (add `pub mod person_token;`)

**Interfaces:**
- Consumes:
  - `authzen::cwt_verify::{header_kid, verify_header_token, VerifyError, VerifyOpts}`;
  - `authzen::cose_keys::CoseKeyCache`;
  - `authzen::cwt_subject::Aud`;
  - `DecodedClaims.agent_marker` (Task 1);
  - `LicenseError` (Task 2).
- Produces:
  - `pub struct Person { pub sub: String, pub token: String }`;
  - `pub struct PersonTokenVerifier`, constructed with `PersonTokenVerifier::new(keys: CoseKeyCache, issuer: String, platform_aud: String)`;
  - `pub async fn verify(&self, headers: &axum::http::HeaderMap, now: i64) -> Result<Person, LicenseError>`;
  - `pub fn is_person_sub(sub: &str) -> bool`.

- [ ] **Step 1: Write the failing tests**

Create `src/modules/license/person_token.rs` with just the test module first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::authzen::cose_keys::CoseKeyCache;
    use crate::modules::authzen::cwt_verify::test_support::{keypair, mint_map, other_keypair};
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
            (Value::Integer(4.into()), Value::Integer((NOW + 3600).into())),
            (Value::Integer(6.into()), Value::Integer(NOW.into())),
            (Value::Integer(7.into()), Value::Bytes(vec![7u8; 16])),
            (Value::Integer(8.into()), Value::Map(vec![(Value::Integer(2.into()), Value::Bytes(b"pk".to_vec()))])),
            (Value::Text("idp".into()), Value::Text("webauthn".into())),
        ];
        v.extend(extra);
        v
    }

    fn both_aud() -> Value {
        Value::Array(vec![Value::Text("arkavo".into()), Value::Text(PLATFORM.into())])
    }

    fn verifier() -> (PersonTokenVerifier, p256::ecdsa::SigningKey) {
        let (sk, vk) = keypair();
        let keys = CoseKeyCache::with_static_keys(vec![(KID.to_vec(), vk)]);
        (PersonTokenVerifier::new(keys, ISS.into(), PLATFORM.into()), sk)
    }

    fn bearer(t: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", HeaderValue::from_str(&format!("Bearer {t}")).unwrap());
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
        assert!(matches!(v.verify(&HeaderMap::new(), NOW).await, Err(LicenseError::Unauthenticated(_))));
        assert!(matches!(v.verify(&bearer("not-a-cwt"), NOW).await, Err(LicenseError::Unauthenticated(_))));
        let (other, _) = other_keypair();
        let t = mint_map(&other, KID, person_entries(SUB, both_aud(), vec![]));
        assert!(matches!(v.verify(&bearer(&t), NOW).await, Err(LicenseError::Unauthenticated(_))));
    }

    #[tokio::test]
    async fn expired_is_401() {
        let (v, sk) = verifier();
        let t = mint_map(&sk, KID, person_entries(SUB, both_aud(), vec![]));
        assert!(matches!(v.verify(&bearer(&t), NOW + 7200).await, Err(LicenseError::Unauthenticated(_))));
    }

    #[tokio::test]
    async fn missing_platform_aud_is_401() {
        // The registration token has aud "arkavo" only; expected_aud fails in
        // the verifier, which is an authentication failure (sign in again).
        let (v, sk) = verifier();
        let t = mint_map(&sk, KID, person_entries(SUB, Value::Text("arkavo".into()), vec![]));
        assert!(matches!(v.verify(&bearer(&t), NOW).await, Err(LicenseError::Unauthenticated(_))));
    }

    #[tokio::test]
    async fn non_person_is_403() {
        let (v, sk) = verifier();
        let platform_only = Value::Array(vec![Value::Text(PLATFORM.into())]);
        let rp = Value::Array(vec![Value::Text("mcp-edge".into()), Value::Text(PLATFORM.into())]);
        let cases = vec![
            person_entries(SUB, platform_only, vec![]),
            person_entries(SUB, rp, vec![]),
            person_entries("client:catalog-node", both_aud(), vec![]),
            person_entries("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", both_aud(), vec![]),
            person_entries(SUB, both_aud(), vec![(Value::Text("arkavo_npe".into()), Value::Map(vec![(Value::Text("type".into()), Value::Text("device".into()))]))]),
            person_entries(SUB, both_aud(), vec![(Value::Text("arkavo_swarm".into()), Value::Text("s".into()))]),
        ];
        for entries in cases {
            let t = mint_map(&sk, KID, entries);
            assert!(matches!(v.verify(&bearer(&t), NOW).await, Err(LicenseError::Forbidden(_))));
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
```

Add `pub mod person_token;` to `license/mod.rs`.

- [ ] **Step 2: Run the tests and watch them fail**

Run: `cargo test --bin arks person_token`
Expected: compile errors, because `PersonTokenVerifier` and `is_person_sub` are undefined.

- [ ] **Step 3: Implement** (above the test module)

```rust
//! Bearer CWT → verified person. Allowlist: the passkey auth token only
//! (aud contains both "arkavo" and the platform audience, person-shaped sub,
//! no agent marker). Everything else is refused.

use super::LicenseError;
use crate::modules::authzen::cose_keys::CoseKeyCache;
use crate::modules::authzen::cwt_subject::Aud;
use crate::modules::authzen::cwt_verify::{header_kid, verify_header_token, VerifyError, VerifyOpts};
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
        Self { keys, issuer, platform_aud }
    }

    pub async fn verify(&self, headers: &HeaderMap, now: i64) -> Result<Person, LicenseError> {
        let token = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|a| a.strip_prefix("Bearer ").or_else(|| a.strip_prefix("bearer ")))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or(LicenseError::Unauthenticated("missing bearer token"))?;
        let kid = header_kid(token).map_err(|_| LicenseError::Unauthenticated("malformed token"))?;
        let key = match self.keys.resolve(&kid).await {
            Ok(k) => k,
            Err(VerifyError::KeySet) => return Err(LicenseError::Unavailable("identity keys unavailable")),
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
        Ok(Person { sub: claims.sub, token: token.to_string() })
    }
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `cargo test --bin arks person_token`
Expected: 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/modules/license/
git commit -m "feat(license): person-token verifier (passkey CWT allowlist)"
```

---

### Task 4: openssl manifest fixtures

**Files:**
- Create: `src/modules/license/fixtures/gen_fixtures.sh`
- Create: `src/modules/license/fixtures.rs` (`#[cfg(test)]`): a `OnceLock` helper that runs
  `gen_fixtures.sh <tempdir>` on first use and returns `key_pem`, `manifest_allowed`,
  `binding_hex` and `binding_raw_json`. It panics with the script's stderr plus a hint
  ("needs OpenSSL 3 on PATH or OPENSSL=...") if the script fails.
- Generated at test time into a temp dir and gitignored (never committed): the test RSA key,
  `manifest_allowed.json`, `binding_hex.txt`, `binding_raw_json.txt`.
- Create: `src/modules/license/fixtures/README.md`

**Interfaces:**
- Produces fixture constants used by Task 5:
  - DEK hex `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`;
  - policy uuid `3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b`;
  - FQN `https://patreon.arkavo.com/attr/campaign-tier/value/11111111_gold`;
  - KAS URL `https://platform.arkavo.net/kas`.

- [ ] **Step 1: Write the generator**

`src/modules/license/fixtures/gen_fixtures.sh`:

```bash
#!/usr/bin/env bash
# Regenerates the FairPlay license fixtures with openssl only, so arks'
# verifier is checked against an independent producer of the binding and
# the RSA-OAEP-SHA1 wrap. TEST KEY ONLY — never a real KAS key.
set -euo pipefail
cd "$(dirname "$0")"
# macOS /usr/bin/openssl is LibreSSL, which lacks rsa_oaep_md / -mac HMAC.
openssl version | grep -q "^OpenSSL 3" || { echo "need OpenSSL 3 (brew install openssl@3; put it first on PATH)"; exit 1; }

DEK_HEX=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
UUID=3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b
FQN=https://patreon.arkavo.com/attr/campaign-tier/value/11111111_gold
KAS_URL=https://platform.arkavo.net/kas

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test_kas_rsa_private.pem 2>/dev/null
openssl pkey -in test_kas_rsa_private.pem -pubout -out /tmp/arks_fixture_pub.pem

printf '%s' "$DEK_HEX" | xxd -r -p > /tmp/arks_fixture_dek.bin
WRAPPED=$(openssl pkeyutl -encrypt -pubin -inkey /tmp/arks_fixture_pub.pem \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 \
  -in /tmp/arks_fixture_dek.bin | base64 | tr -d '\n')

POLICY="{\"uuid\":\"$UUID\",\"body\":{\"dataAttributes\":[{\"attribute\":\"$FQN\"}],\"dissem\":[]}}"
POLICY_B64=$(printf '%s' "$POLICY" | base64 | tr -d '\n')

# Correct form: base64(HMAC-SHA256(DEK, base64 policy string)).
BINDING=$(printf '%s' "$POLICY_B64" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$DEK_HEX -binary | base64 | tr -d '\n')
# Legacy hex bug: base64(hex(HMAC(...))).
printf '%s' "$POLICY_B64" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$DEK_HEX -hex | awk '{print $NF}' | tr -d '\n' | base64 | tr -d '\n' > binding_hex.txt
# Wrong input: HMAC over the raw policy JSON.
printf '%s' "$POLICY" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$DEK_HEX -binary | base64 | tr -d '\n' > binding_raw_json.txt

cat > manifest_allowed.json <<EOF
{"payload":{"type":"reference","url":"0.payload","protocol":"zip","isEncrypted":true},
 "encryptionInformation":{"type":"split","policy":"$POLICY_B64",
  "keyAccess":[{"type":"wrapped","url":"$KAS_URL","protocol":"kas","wrappedKey":"$WRAPPED",
   "policyBinding":{"alg":"HS256","hash":"$BINDING"}}],
  "method":{"algorithm":"AES-256-GCM","isStreamable":true,"iv":""},
  "integrityInformation":{"rootSignature":{"alg":"HS256","sig":""},"segmentHashAlg":"GMAC","segments":[]}}}
EOF
rm -f /tmp/arks_fixture_pub.pem /tmp/arks_fixture_dek.bin
echo "fixtures regenerated"
```

The script takes an output directory argument, honours an optional `OPENSSL` env var, keeps the OpenSSL 3 guard, uses `mktemp` for scratch files and needs no `xxd` (hex to binary via bash `printf` `\x` escapes).

`README.md`: explains that no key material is committed, that the fixtures are generated at test time by the helper, and that OpenSSL 3 must be on PATH (or `OPENSSL=...`).

- [ ] **Step 2: Generate and check**

Run: `d=$(mktemp -d) && bash src/modules/license/fixtures/gen_fixtures.sh "$d" && python3 -m json.tool "$d/manifest_allowed.json" >/dev/null && echo ok`
Expected: `fixtures regenerated` then `ok`.

- [ ] **Step 3: Commit**

```bash
git add src/modules/license/fixtures.rs src/modules/license/fixtures/ .gitignore
git commit -m "test(license): openssl-generated TDF manifest fixtures (generated at test time)"
```

---

### Task 5: TDF manifest and policy checker

**Files:**
- Create: `src/modules/license/tdf_policy.rs`
- Modify: `src/modules/license/mod.rs` (add `pub mod tdf_policy;`)
- Modify: `Cargo.toml` (in `[dependencies]`, after `sha2`: `hmac = "0.12"`)

**Interfaces:**
- Consumes: `LicenseError` (Task 2) and the fixtures (Task 4).
- Produces:
  - `pub struct CheckedPolicy { pub dek: Vec<u8>, pub policy_uuid: String, pub fqns: Vec<String> }`;
  - `pub fn normalize_kas_url(url: &str) -> Option<String>`;
  - `pub fn check_manifest(manifest_json: &[u8], rsa: &rsa::RsaPrivateKey, kas_urls: &[String]) -> Result<CheckedPolicy, LicenseError>`. `kas_urls` are already normalised.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::DecodePrivateKey;
    use serde_json::{json, Value};

    use crate::modules::license::fixtures::fixtures; // key_pem, manifest_allowed, binding_hex, binding_raw_json

    fn key() -> rsa::RsaPrivateKey {
        rsa::RsaPrivateKey::from_pkcs8_pem(&fixtures().key_pem).unwrap()
    }
    fn kas() -> Vec<String> {
        vec![normalize_kas_url("https://platform.arkavo.net").unwrap()]
    }
    fn allowed() -> Value {
        serde_json::from_str(ALLOWED).unwrap()
    }
    fn check(v: &Value) -> Result<CheckedPolicy, LicenseError> {
        check_manifest(v.to_string().as_bytes(), &key(), &kas())
    }

    #[test]
    fn allowed_manifest_passes() {
        let p = check(&allowed()).unwrap();
        assert_eq!(p.policy_uuid, "3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b");
        assert_eq!(p.fqns, vec!["https://patreon.arkavo.com/attr/campaign-tier/value/11111111_gold"]);
        assert_eq!(hex::encode(&p.dek), "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
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
        let mut m = allowed(); set_binding(&mut m, HEX_BINDING); cases.push(m);
        let mut m = allowed(); set_binding(&mut m, RAW_JSON_BINDING); cases.push(m);
        // Edited policy (binding no longer matches).
        let mut m = allowed();
        let edited = base64::engine::general_purpose::STANDARD.encode(
            r#"{"uuid":"3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b","body":{"dataAttributes":[{"attribute":"https://patreon.arkavo.com/attr/campaign/value/1"}],"dissem":[]}}"#);
        m["encryptionInformation"]["policy"] = json!(edited); cases.push(m);
        // Two key-access objects.
        let mut m = allowed();
        let kao = m["encryptionInformation"]["keyAccess"][0].clone();
        m["encryptionInformation"]["keyAccess"] = json!([kao.clone(), kao]); cases.push(m);
        // Foreign KAS.
        let mut m = allowed();
        m["encryptionInformation"]["keyAccess"][0]["url"] = json!("https://evil.example/kas"); cases.push(m);
        // Not "wrapped".
        let mut m = allowed();
        m["encryptionInformation"]["keyAccess"][0]["type"] = json!("remote"); cases.push(m);
        // Swapped wrappedKey (garbage ciphertext of the right size).
        let mut m = allowed();
        m["encryptionInformation"]["keyAccess"][0]["wrappedKey"] =
            json!(base64::engine::general_purpose::STANDARD.encode([7u8; 256])); cases.push(m);
        for (i, c) in cases.iter().enumerate() {
            assert!(matches!(check(c), Err(LicenseError::Forbidden(_))), "case {i}");
        }
    }

    #[test]
    fn not_json_is_400() {
        assert!(matches!(check_manifest(b"nope", &key(), &kas()), Err(LicenseError::BadRequest(_))));
    }

    #[test]
    fn kas_url_normalisation() {
        let n = |s| normalize_kas_url(s).unwrap();
        assert_eq!(n("https://platform.arkavo.net"), n("https://PLATFORM.arkavo.net:443/kas/"));
        assert_eq!(n("https://platform.arkavo.net/"), n("https://platform.arkavo.net/kas"));
        assert_ne!(n("https://platform.arkavo.net"), n("http://platform.arkavo.net"));
        assert_ne!(n("https://platform.arkavo.net"), n("https://platform.arkavo.net:8443"));
        assert!(normalize_kas_url("not a url").is_none());
    }
}
```

The "empty attributes" and "missing uuid" cases need a binding recomputed over a new policy. Cover them with this test, which uses the `hmac` crate only to *build* the input. The verifier's correct-form acceptance is already pinned by the openssl fixture above:

```rust
    fn rebind(policy_json: &str) -> Value {
        use hmac::{Hmac, Mac};
        let mut m = allowed();
        let b64 = base64::engine::general_purpose::STANDARD.encode(policy_json);
        let dek = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&dek).unwrap();
        mac.update(b64.as_bytes());
        let hash = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        m["encryptionInformation"]["policy"] = json!(b64);
        set_binding(&mut m, &hash);
        m
    }

    #[test]
    fn policy_shape_refusals() {
        let no_attrs = rebind(r#"{"uuid":"3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b","body":{"dataAttributes":[],"dissem":[]}}"#);
        let no_uuid = rebind(r#"{"body":{"dataAttributes":[{"attribute":"https://patreon.arkavo.com/attr/campaign/value/1"}]}}"#);
        let empty_body = rebind(r#"{"uuid":"3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b","body":{}}"#);
        for m in [no_attrs, no_uuid, empty_body] {
            assert!(matches!(check(&m), Err(LicenseError::Forbidden(_))));
        }
    }
```

Add `pub mod tdf_policy;` to `license/mod.rs` and `hmac = "0.12"` to `Cargo.toml`.

- [ ] **Step 2: Run the tests and watch them fail**

Run: `cargo test --bin arks tdf_policy`
Expected: compile errors, because `check_manifest` and `normalize_kas_url` are undefined.

- [ ] **Step 3: Implement** (above the tests)

```rust
//! TDF manifest → the DEK plus the policy it is bound to. Refuses anything
//! that is not exactly one wrapped key for this KAS with an intact binding
//! and at least one data attribute.

use super::LicenseError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rsa::{Oaep, RsaPrivateKey};
use serde_json::Value;
use sha1::Sha1;
use sha2::Sha256;

pub struct CheckedPolicy {
    /// Full unwrapped DEK (16 or 32 bytes). Never log it.
    pub dek: Vec<u8>,
    pub policy_uuid: String,
    pub fqns: Vec<String>,
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
    let kaos = ei.get("keyAccess").and_then(Value::as_array).ok_or(FORBIDDEN_MANIFEST)?;
    let [kao] = kaos.as_slice() else {
        return Err(LicenseError::Forbidden("exactly one key access object required"));
    };
    if kao.get("type").and_then(Value::as_str) != Some("wrapped") {
        return Err(LicenseError::Forbidden("key access type must be wrapped"));
    }
    let url = kao.get("url").and_then(Value::as_str).and_then(normalize_kas_url);
    if !url.is_some_and(|u| kas_urls.contains(&u)) {
        return Err(LicenseError::Forbidden("key access names another KAS"));
    }
    let wrapped = kao.get("wrappedKey").and_then(Value::as_str).ok_or(FORBIDDEN_MANIFEST)?;
    let wrapped = STANDARD.decode(wrapped).map_err(|_| FORBIDDEN_MANIFEST)?;
    let dek = rsa
        .decrypt(Oaep::new::<Sha1>(), &wrapped)
        .map_err(|_| LicenseError::Forbidden("key unwrap failed"))?;
    if dek.len() != 16 && dek.len() != 32 {
        return Err(LicenseError::Forbidden("unexpected key size"));
    }

    let policy_b64 = ei.get("policy").and_then(Value::as_str).ok_or(FORBIDDEN_MANIFEST)?;
    let binding = match kao.get("policyBinding") {
        Some(Value::String(s)) => s.as_str(),
        Some(Value::Object(o)) => o.get("hash").and_then(Value::as_str).ok_or(FORBIDDEN_MANIFEST)?,
        _ => return Err(FORBIDDEN_MANIFEST),
    };
    let expected = STANDARD.decode(binding.trim()).map_err(|_| FORBIDDEN_MANIFEST)?;
    // Binding is checked with the full DEK, before any FairPlay truncation.
    let mut mac = Hmac::<Sha256>::new_from_slice(&dek).map_err(|_| FORBIDDEN_MANIFEST)?;
    mac.update(policy_b64.as_bytes());
    mac.verify_slice(&expected)
        .map_err(|_| LicenseError::Forbidden("policy binding mismatch"))?;

    let policy_bytes = STANDARD.decode(policy_b64).map_err(|_| FORBIDDEN_MANIFEST)?;
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
                .filter_map(|d| d.get("attribute").and_then(Value::as_str))
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if fqns.is_empty() {
        return Err(LicenseError::Forbidden("policy has no data attributes"));
    }
    Ok(CheckedPolicy { dek, policy_uuid, fqns })
}
```

`verify_slice` compares in constant time. The hex and raw-JSON forms both fail `verify_slice`: hex decodes to 64 bytes, not 32, and the raw-JSON HMAC is a different MAC.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `cargo test --bin arks tdf_policy`
Expected: 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/modules/license/
git commit -m "feat(license): TDF manifest check (single wrapped KAO, binding, attributes)"
```

(`Cargo.lock` is gitignored in this repo, so `git add` ignores it silently.)

---

### Task 6: Platform decision client

**Files:**
- Create: `src/modules/license/pdp.rs`
- Modify: `src/modules/license/mod.rs` (add `pub mod pdp;`)

**Interfaces:**
- Consumes: `authzen::translate::parse_get_decision_response(&Value) -> DecisionOut` (`.permit: bool`), and `LicenseError`.
- Produces:
  - `pub struct PlatformPdp`, constructed with `PlatformPdp::new(platform_url: &str, token_url: String, client_id: String, client_secret: String) -> Result<Self, String>`;
  - `pub async fn decide(&self, user_token: &str, resource_id: &str, fqns: &[String], rid: &str) -> Result<(), LicenseError>`: `Ok(())` means permit;
  - `pub fn decision_request(user_token: &str, resource_id: &str, fqns: &[String]) -> serde_json::Value`;
  - `pub fn map_connect_error(http_status: u16, body: &serde_json::Value) -> LicenseError`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const GD: &str = "/authorization.v2.AuthorizationService/GetDecision";

    async fn token_mock(server: &MockServer, times: u64) {
        Mock::given(method("POST")).and(path("/oauth/token"))
            .and(header("authorization", expected.as_str())) // "Basic " + base64(id:secret), computed from a per-run generated secret
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":"svc-1","expires_in":3600,"token_type":"Bearer"})))
            .expect(times)
            .mount(server).await;
    }

    fn pdp(server: &MockServer) -> PlatformPdp {
        PlatformPdp::new(&server.uri(), format!("{}/oauth/token", server.uri()), CLIENT_ID.into(), test_secret().into()).unwrap()
    }

    #[test]
    fn request_shape_uses_token_entity() {
        let v = decision_request("user-cwt", "uuid-1", &["https://a/attr/x/value/y".into()]);
        assert_eq!(v["entityIdentifier"]["token"]["jwt"], "user-cwt");
        assert_eq!(v["action"]["name"], "read");
        assert_eq!(v["resource"]["ephemeralId"], "uuid-1");
        assert_eq!(v["resource"]["attributeValues"]["fqns"][0], "https://a/attr/x/value/y");
    }

    #[tokio::test]
    async fn permit_and_deny() {
        let server = MockServer::start().await;
        token_mock(&server, 1).await; // cached across both calls
        Mock::given(method("POST")).and(path(GD)).and(header("authorization", "Bearer svc-1"))
            .and(body_partial_json(json!({"resource":{"ephemeralId":"permit-me"}})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"decision":{"decision":"DECISION_PERMIT"}})))
            .mount(&server).await;
        Mock::given(method("POST")).and(path(GD))
            .and(body_partial_json(json!({"resource":{"ephemeralId":"deny-me"}})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"decision":{"decision":"DECISION_DENY"}})))
            .mount(&server).await;
        let p = pdp(&server);
        assert_eq!(p.decide("u", "permit-me", &["f".into()], "r").await, Ok(()));
        assert!(matches!(p.decide("u", "deny-me", &["f".into()], "r").await, Err(LicenseError::Forbidden(_))));
    }

    #[tokio::test]
    async fn stale_service_token_is_reminted_once() {
        let server = MockServer::start().await;
        token_mock(&server, 2).await;
        Mock::given(method("POST")).and(path(GD))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({"code":"unauthenticated"})))
            .up_to_n_times(1).mount(&server).await;
        Mock::given(method("POST")).and(path(GD))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"decision":{"decision":"DECISION_PERMIT"}})))
            .mount(&server).await;
        assert_eq!(pdp(&server).decide("u", "x", &["f".into()], "r").await, Ok(()));
    }

    #[tokio::test]
    async fn platform_down_is_503() {
        let p = PlatformPdp::new("http://127.0.0.1:9", "http://127.0.0.1:9/oauth/token".into(), "a".into(), "b".into()).unwrap();
        assert!(matches!(p.decide("u", "x", &["f".into()], "r").await, Err(LicenseError::Unavailable(_))));
    }

    #[test]
    fn connect_error_mapping() {
        for code in ["invalid_argument", "not_found", "permission_denied", "failed_precondition"] {
            assert!(matches!(map_connect_error(400, &json!({"code": code})), LicenseError::Forbidden(_)), "{code}");
        }
        for code in ["unavailable", "deadline_exceeded", "internal", "unknown", "unauthenticated"] {
            assert!(matches!(map_connect_error(503, &json!({"code": code})), LicenseError::Unavailable(_)), "{code}");
        }
        assert!(matches!(map_connect_error(502, &json!(null)), LicenseError::Unavailable(_)));
    }
}
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `cargo test --bin arks license::pdp`
Expected: compile errors, because `PlatformPdp` is undefined.

- [ ] **Step 3: Implement** (above the tests)

```rust
//! OpenTDF `GetDecision` with the viewer's own token as the entity, called
//! as the `arks-media` service client. Only DECISION_PERMIT allows.

use super::LicenseError;
use crate::modules::authzen::translate::parse_get_decision_response;
use reqwest::redirect::Policy;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const REFRESH_MARGIN: Duration = Duration::from_secs(60);

pub struct PlatformPdp {
    platform_url: String,
    token_url: String,
    client_id: String,
    client_secret: String,
    http: reqwest::Client,
    service_token: Mutex<Option<(String, Instant)>>,
}

pub fn decision_request(user_token: &str, resource_id: &str, fqns: &[String]) -> Value {
    json!({
        "entityIdentifier": {"token": {"ephemeralId": "viewer", "jwt": user_token}},
        "action": {"name": "read"},
        "resource": {"ephemeralId": resource_id, "attributeValues": {"fqns": fqns}},
    })
}

/// Connect error codes: bad input / not found / not allowed → 403; anything
/// that means "could not decide" → 503. Never a 500.
pub fn map_connect_error(http_status: u16, body: &Value) -> LicenseError {
    match body.get("code").and_then(Value::as_str) {
        Some("invalid_argument" | "not_found" | "permission_denied" | "failed_precondition" | "out_of_range") => {
            LicenseError::Forbidden("platform refused the decision request")
        }
        _ => {
            log::warn!("license pdp: platform HTTP {http_status}");
            LicenseError::Unavailable("platform decision unavailable")
        }
    }
}

impl PlatformPdp {
    pub fn new(platform_url: &str, token_url: String, client_id: String, client_secret: String) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .redirect(Policy::none())
            .build()
            .map_err(|e| format!("license pdp http client: {e}"))?;
        Ok(Self {
            platform_url: platform_url.trim_end_matches('/').to_string(),
            token_url,
            client_id,
            client_secret,
            http,
            service_token: Mutex::new(None),
        })
    }

    async fn service_token(&self, force: bool) -> Result<String, LicenseError> {
        let mut guard = self.service_token.lock().await;
        if !force {
            if let Some((t, exp)) = guard.as_ref() {
                if Instant::now() + REFRESH_MARGIN < *exp {
                    return Ok(t.clone());
                }
            }
        }
        let resp = self
            .http
            .post(&self.token_url)
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&[("grant_type", "client_credentials")])
            .send()
            .await
            .map_err(|_| LicenseError::Unavailable("identity unreachable"))?;
        if !resp.status().is_success() {
            log::error!("license pdp: service token HTTP {}", resp.status());
            return Err(LicenseError::Unavailable("service credential rejected"));
        }
        let body: Value = resp.json().await.map_err(|_| LicenseError::Unavailable("bad token response"))?;
        let token = body.get("access_token").and_then(Value::as_str)
            .ok_or(LicenseError::Unavailable("bad token response"))?.to_string();
        let ttl = body.get("expires_in").and_then(Value::as_u64).unwrap_or(300);
        *guard = Some((token.clone(), Instant::now() + Duration::from_secs(ttl)));
        Ok(token)
    }

    pub async fn decide(&self, user_token: &str, resource_id: &str, fqns: &[String], rid: &str) -> Result<(), LicenseError> {
        let body = decision_request(user_token, resource_id, fqns);
        let url = format!("{}/authorization.v2.AuthorizationService/GetDecision", self.platform_url);
        let mut force = false;
        for _ in 0..2 {
            let bearer = self.service_token(force).await?;
            let resp = self.http.post(&url)
                .header("content-type", "application/json")
                .header("connect-protocol-version", "1")
                .header("x-request-id", rid)
                .bearer_auth(&bearer)
                .json(&body)
                .send().await
                .map_err(|_| LicenseError::Unavailable("platform unreachable"))?;
            let status = resp.status();
            if status.as_u16() == 401 && !force {
                force = true;
                continue;
            }
            let json: Value = resp.json().await.unwrap_or(Value::Null);
            if !status.is_success() {
                return Err(map_connect_error(status.as_u16(), &json));
            }
            return if parse_get_decision_response(&json).permit {
                Ok(())
            } else {
                Err(LicenseError::Forbidden("platform denied"))
            };
        }
        Err(LicenseError::Unavailable("service credential rejected"))
    }
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `cargo test --bin arks license::pdp`
Expected: 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/modules/license/
git commit -m "feat(license): platform GetDecision client with cached service token"
```

---

### Task 7: FairPlay wrapper lease and response asset id

**Files:**
- Modify: `crates/fairplay-wrapper/src/lib.rs:103-165` (`process_spc`), `:198-217` (`SpcRequest`, `CkcResponse`)

**Interfaces:**
- Produces:
  - `SpcRequest.lease_duration_secs: Option<u32>`;
  - `CkcResponse.asset_id: Option<String>`;
  - `pub fn build_request_json(req: &SpcRequest) -> serde_json::Value`;
  - `pub fn parse_response(resp: &serde_json::Value) -> Result<CkcResponse, FairPlayError>`.

- [ ] **Step 1: Write the failing tests** (add to the crate's `#[cfg(test)] mod tests`, or create one at the end of `lib.rs`)

```rust
#[cfg(test)]
mod request_json_tests {
    use super::*;

    fn req(lease: Option<u32>) -> SpcRequest {
        SpcRequest { content_id: "c".into(), spc_data: vec![1, 2], asset_id: "a".into(), content_key: vec![0; 16], lease_duration_secs: lease }
    }

    #[test]
    fn lease_is_sent_and_never_offline() {
        let v = build_request_json(&req(Some(3600)));
        let item = &v["fairplay-streaming-request"]["create-ckc"][0];
        assert_eq!(item["lease-duration"], 3600);
        assert!(item.get("offline-hls").is_none());
        let v = build_request_json(&req(None));
        assert!(v["fairplay-streaming-request"]["create-ckc"][0].get("lease-duration").is_none());
    }

    #[test]
    fn response_asset_id_is_returned() {
        let ckc = base64::engine::general_purpose::STANDARD.encode([9u8; 4]);
        let v = serde_json::json!({"fairplay-streaming-response":{"create-ckc":[{"id":1,"ckc":ckc,"asset-id":"uuid-1"}]}});
        let r = parse_response(&v).unwrap();
        assert_eq!(r.ckc_data, vec![9u8; 4]);
        assert_eq!(r.asset_id.as_deref(), Some("uuid-1"));
    }
}
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `cargo test -p fairplay-wrapper request_json_tests`
Expected: compile errors, because the new field and functions are missing.

- [ ] **Step 3: Implement**
  - Add `pub lease_duration_secs: Option<u32>,` to `SpcRequest` (doc comment: "CKC lease in seconds; None sends no lease. Streaming licence type only; `offline-hls` is never requested.").
  - Add `pub asset_id: Option<String>,` to `CkcResponse` (doc comment: "Asset ID the device put in the SPC, as echoed by the SDK.").
  - Extract two functions and call them from `process_spc`:

```rust
pub fn build_request_json(request: &SpcRequest) -> serde_json::Value {
    let mut item = serde_json::json!({
        "id": 1,
        "content-id": request.content_id,
        "spc": base64::engine::general_purpose::STANDARD.encode(&request.spc_data),
        "asset-id": request.asset_id,
        "ck": base64::engine::general_purpose::STANDARD.encode(&request.content_key),
    });
    if let Some(secs) = request.lease_duration_secs {
        item["lease-duration"] = serde_json::json!(secs);
    }
    serde_json::json!({ "fairplay-streaming-request": { "create-ckc": [item] } })
}

pub fn parse_response(response: &serde_json::Value) -> Result<CkcResponse, FairPlayError> {
    let item = response
        .get("fairplay-streaming-response")
        .and_then(|r| r.get("create-ckc"))
        .and_then(|c| c.get(0))
        .ok_or(FairPlayError::InvalidResponse)?;
    let ckc_base64 = item.get("ckc").and_then(|c| c.as_str()).ok_or(FairPlayError::InvalidResponse)?;
    let ckc_data = base64::engine::general_purpose::STANDARD.decode(ckc_base64)?;
    let asset_id = item.get("asset-id").and_then(|a| a.as_str()).map(str::to_string);
    Ok(CkcResponse { ckc_data, asset_id })
}
```

In `process_spc`:
  - replace the inline `json!` with `let json_request = build_request_json(&request);`;
  - replace the CKC extraction after `serde_json::from_str(&response_str)?` with `let parsed = parse_response(&response);`;
  - call `fpssdk::fpsDisposeResponse(...)` **before** returning `parsed`, so the memory is always freed;
  - return `parsed`.

  Delete the `log::trace!` lines that print the request and response JSON: they contain the content key and the CKC.

- [ ] **Step 4: Run the tests and confirm they pass**

Required: in `src/modules/fairplay.rs`, add `lease_duration_secs: None,` to the existing `SpcRequest { … }` literal, so the tree stays green. Task 8 replaces that code.

Run: `cargo test -p fairplay-wrapper && cargo check --bin arks && cargo check --release --bin arks --features fairplay,c2pa_signing`
Expected: all pass.

Note: `cargo test -p fairplay-wrapper` links `libfpscrypto`, so it runs only on a machine with the FairPlay SDK installed. CI does not run it, so a green CI does not cover these tests. Run them locally.

- [ ] **Step 5: Commit**

```bash
git add crates/fairplay-wrapper/src/lib.rs src/modules/fairplay.rs
git commit -m "feat(fairplay-wrapper): CKC lease duration and SPC asset-id; stop logging key material"
```

---

### Task 8: `LicenseIssuer` trait and FairPlay implementation

**Files:**
- Create: `src/modules/license/issuer.rs`
- Modify: `src/modules/license/mod.rs` (add `pub mod issuer;`)
- Modify: `src/modules/fairplay.rs:74-127` (`process_key_request`)

**Interfaces:**
- Produces:
  - `pub struct IssuedLicense { pub ckc: Vec<u8>, pub spc_asset_id: Option<String> }`;
  - `#[async_trait::async_trait] pub trait LicenseIssuer: Send + Sync { async fn issue(&self, spc: Vec<u8>, content_key: [u8; 16], asset_id: &str, lease_secs: u32) -> Result<IssuedLicense, String>; }`. `asset_id` is the TDF policy uuid, sent to the SDK as both `content-id` and `asset-id`.;
  - `impl LicenseIssuer for crate::modules::fairplay::FairPlayHandler`, under `cfg(feature = "fairplay")`.

- [ ] **Step 1: Write the trait and a test double** (`issuer.rs`)

```rust
//! The one step that needs the Apple SDK, behind a trait so the whole
//! authorization pipeline is tested without the `fairplay` feature.

pub struct IssuedLicense {
    pub ckc: Vec<u8>,
    /// The asset id inside the SPC (client-chosen); logged, never trusted.
    pub spc_asset_id: Option<String>,
}

#[async_trait::async_trait]
pub trait LicenseIssuer: Send + Sync {
    async fn issue(&self, spc: Vec<u8>, content_key: [u8; 16], asset_id: &str, lease_secs: u32) -> Result<IssuedLicense, String>;
}

#[cfg(feature = "fairplay")]
#[async_trait::async_trait]
impl LicenseIssuer for crate::modules::fairplay::FairPlayHandler {
    async fn issue(&self, spc: Vec<u8>, content_key: [u8; 16], asset_id: &str, lease_secs: u32) -> Result<IssuedLicense, String> {
        self.process_key_request(spc, content_key.to_vec(), asset_id.to_string(), lease_secs)
            .await
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use std::sync::Mutex;

    /// Records the key it was asked to issue and returns a fixed CKC.
    pub struct FakeIssuer {
        pub seen_key: Mutex<Option<[u8; 16]>>,
        pub seen_lease: Mutex<Option<u32>>,
        pub spc_asset_id: Option<String>,
    }

    impl FakeIssuer {
        pub fn new(spc_asset_id: Option<&str>) -> Self {
            Self { seen_key: Mutex::new(None), seen_lease: Mutex::new(None), spc_asset_id: spc_asset_id.map(str::to_string) }
        }
    }

    #[async_trait::async_trait]
    impl LicenseIssuer for FakeIssuer {
        async fn issue(&self, _spc: Vec<u8>, content_key: [u8; 16], _asset_id: &str, lease_secs: u32) -> Result<IssuedLicense, String> {
            *self.seen_key.lock().unwrap() = Some(content_key);
            *self.seen_lease.lock().unwrap() = Some(lease_secs);
            Ok(IssuedLicense { ckc: b"fake-ckc".to_vec(), spc_asset_id: self.spc_asset_id.clone() })
        }
    }
}
```

- [ ] **Step 2: Change `FairPlayHandler::process_key_request`** (`fairplay.rs`, feature branch) to:

```rust
    #[cfg(feature = "fairplay")]
    pub async fn process_key_request(
        &self,
        spc_data: Vec<u8>,
        content_key: Vec<u8>,
        asset_id: String,
        lease_secs: u32,
    ) -> Result<crate::modules::license::issuer::IssuedLicense, Box<dyn std::error::Error + Send + Sync>> {
        let request = SpcRequest {
            content_id: asset_id.clone(),
            spc_data,
            asset_id,
            content_key,
            lease_duration_secs: Some(lease_secs),
        };
        let key_server = self.key_server.clone();
        let response = tokio::task::spawn_blocking(move || key_server.process_spc(request)).await??;
        Ok(crate::modules::license::issuer::IssuedLicense { ckc: response.ckc_data, spc_asset_id: response.asset_id })
    }
```

Update the `#[cfg(not(feature = "fairplay"))]` stub to the same signature, returning `Err("FairPlay support not compiled in".into())`. Remove the `#[allow(dead_code)]` attributes that are no longer needed.

**Required call-site edit, so the tree stays green:** in `media_api.rs` `handle_fairplay_key_request`, change the SDK call to

```rust
    let ckc_data_result: Result<Vec<u8>, String> = match fairplay_handler
        .process_key_request(spc_data, content_key_16, payload.asset_id.clone(), 3600)
        .await
    {
        Ok(issued) => Ok(issued.ckc),
        Err(e) => Err(e.to_string()),
    };
```

Task 9 deletes this function. The edit only keeps the feature build compiling in between.

- [ ] **Step 3: Check both feature sets**

Run: `cargo check --bin arks && cargo check --release --bin arks --features fairplay,c2pa_signing`
Expected: both compile.

- [ ] **Step 4: Commit**

```bash
git add src/modules/license/ src/modules/fairplay.rs src/modules/media_api.rs
git commit -m "feat(license): LicenseIssuer trait; FairPlay handler issues leased CKCs"
```

---

### Task 9: Config, state wiring and the FairPlay key-request pipeline

**Files:**
- Create: `src/modules/license/config.rs`
- Modify: `src/modules/license/mod.rs` (add `pub mod config;`)
- Modify: `src/modules/media_api.rs`:
  - `MediaApiState` (`:50-61`);
  - `ErrorResponse::into_response` (`:131-143`);
  - `media_key_request` (both cfg variants, `:500-563`);
  - replace `handle_fairplay_key_request` (`:697-988`);
  - delete `extract_dek_from_tdf_manifest` / `extract_dek_from_wrapped_key` (`:165-254`) and their tests in `tdf_manifest_tests`.
- Modify: `src/bin/main.rs:831-841` (`MediaApiState` construction)

**Interfaces:**
- Consumes: Tasks 3, 5, 6 and 8.
- Produces:
  - `pub struct LicenseAuthz { pub pdp: PlatformPdp, pub kas_urls: Vec<String>, pub lease_secs: u32 }`;
  - `pub fn person_verifier_from_env() -> PersonTokenVerifier`;
  - `pub fn license_authz_from_env(platform_url: Option<&str>) -> Result<Option<LicenseAuthz>, String>`;
  - `MediaApiState` gains `pub person_tokens: Arc<PersonTokenVerifier>`, `pub license: Option<Arc<LicenseAuthz>>` and `pub issuer: Option<Arc<dyn LicenseIssuer>>`;
  - `pub async fn authorize_license(state: &MediaApiState, person: &Person, payload: &MediaKeyRequest, rid: &str) -> Result<IssuedLicense, LicenseError>`.

- [ ] **Step 1: Write `config.rs`**

```rust
//! Env → license state. Missing credentials fail closed (key requests 503),
//! they never fall back to issuing unauthorized keys.

use super::pdp::PlatformPdp;
use super::person_token::PersonTokenVerifier;
use super::tdf_policy::normalize_kas_url;
use crate::modules::authzen::cose_keys::CoseKeyCache;

pub struct LicenseAuthz {
    pub pdp: PlatformPdp,
    pub kas_urls: Vec<String>,
    pub lease_secs: u32,
}

fn issuer() -> String {
    std::env::var("OIDC_ISSUER").unwrap_or_else(|_| "https://identity.arkavo.net".to_string())
}

pub fn person_verifier_from_env() -> PersonTokenVerifier {
    let iss = issuer();
    let keys_url = format!("{}/.well-known/cose-keys", iss.trim_end_matches('/'));
    let aud = std::env::var("MEDIA_PLATFORM_AUDIENCE")
        .unwrap_or_else(|_| "https://platform.arkavo.net".to_string());
    PersonTokenVerifier::new(CoseKeyCache::new(keys_url), iss, aud)
}

pub fn license_authz_from_env(platform_url: Option<&str>) -> Result<Option<LicenseAuthz>, String> {
    let Some(platform_url) = platform_url else {
        log::warn!("FairPlay licensing disabled: OPENTDF_PLATFORM_URL is unset");
        return Ok(None);
    };
    let Ok(secret) = std::env::var("ARKS_MEDIA_CLIENT_SECRET") else {
        log::warn!("FairPlay licensing disabled: ARKS_MEDIA_CLIENT_SECRET is unset");
        return Ok(None);
    };
    let client_id = std::env::var("ARKS_MEDIA_CLIENT_ID").unwrap_or_else(|_| "arks-media".to_string());
    let token_url = format!("{}/oauth/token", issuer().trim_end_matches('/'));
    let raw_kas = std::env::var("MEDIA_KAS_URLS").unwrap_or_else(|_| "https://platform.arkavo.net".to_string());
    let kas_urls = raw_kas
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| normalize_kas_url(s).ok_or_else(|| format!("invalid MEDIA_KAS_URLS entry: {s}")))
        .collect::<Result<Vec<_>, _>>()?;
    let lease_secs = match std::env::var("MEDIA_FPS_LEASE_SECONDS") {
        Ok(s) => s.parse::<u32>().map_err(|_| format!("invalid MEDIA_FPS_LEASE_SECONDS: {s}"))?,
        Err(_) => 3600,
    };
    if lease_secs == 0 {
        return Err("MEDIA_FPS_LEASE_SECONDS must be > 0 (0 means no lease)".into());
    }
    let pdp = PlatformPdp::new(platform_url, token_url, client_id, secret)?;
    Ok(Some(LicenseAuthz { pdp, kas_urls, lease_secs }))
}
```

- [ ] **Step 2: Write the failing pipeline tests** (new `#[cfg(test)] mod license_pipeline_tests` in `media_api.rs`)

```rust
#[cfg(test)]
mod license_pipeline_tests {
    use super::*;
    use crate::modules::authzen::cose_keys::CoseKeyCache;
    use crate::modules::license::issuer::test_support::FakeIssuer;
    use crate::modules::license::pdp::PlatformPdp;
    use crate::modules::license::person_token::{Person, PersonTokenVerifier};
    use crate::modules::license::config::LicenseAuthz;
    use rsa::pkcs8::DecodePrivateKey;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // manifest and key come from crate::modules::license::fixtures::fixtures() (generated at test time)

    async fn platform(decision: &str) -> MockServer {
        let s = MockServer::start().await;
        Mock::given(method("POST")).and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":"svc","expires_in":3600})))
            .mount(&s).await;
        Mock::given(method("POST")).and(path("/authorization.v2.AuthorizationService/GetDecision"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"decision":{"decision":decision}})))
            .mount(&s).await;
        s
    }

    fn state(server: &MockServer, issuer: Arc<FakeIssuer>) -> MediaApiState {
        let redis = redis::Client::open(std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into())).unwrap();
        let rsa = rsa::RsaPrivateKey::from_pkcs8_pem(&fixtures().key_pem).unwrap();
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        MediaApiState {
            rewrap_state: Arc::new(RewrapState {
                kas_ec_private_key: secret,
                kas_ec_public_key_pem: String::new(),
                kas_rsa_private_key: Some(rsa),
                kas_rsa_public_key_pem: None,
                oauth_public_key_pem: None,
                chain_validator: None,
            }),
            session_manager: Arc::new(SessionManager::new(Arc::new(redis), Some(100))),
            media_metrics: Arc::new(MediaMetrics::new(None, false)),
            chain_validator: None,
            fairplay_certificate_data: None,
            person_tokens: Arc::new(PersonTokenVerifier::new(CoseKeyCache::with_static_keys(vec![]), "i".into(), "a".into())),
            license: Some(Arc::new(LicenseAuthz {
                pdp: PlatformPdp::new(&server.uri(), format!("{}/oauth/token", server.uri()), "arks-media".into(), "s".into()).unwrap(),
                kas_urls: vec![crate::modules::license::tdf_policy::normalize_kas_url("https://platform.arkavo.net").unwrap()],
                lease_secs: 3600,
            })),
            issuer: Some(issuer),
        }
    }

    fn payload(manifest: &str) -> MediaKeyRequest {
        serde_json::from_value(json!({
            "sessionId": "s", "userId": "ignored", "assetId": "a",
            "spcData": base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3]),
            "tdfManifest": base64::engine::general_purpose::STANDARD.encode(manifest),
        })).unwrap()
    }

    fn person() -> Person {
        Person { sub: "550e8400-e29b-41d4-a716-446655440000".into(), token: "user-cwt".into() }
    }

    #[tokio::test]
    async fn permit_issues_with_truncated_key_and_lease() {
        let server = platform("DECISION_PERMIT").await;
        let fake = Arc::new(FakeIssuer::new(Some("3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b")));
        let st = state(&server, fake.clone());
        let out = authorize_license(&st, &person(), &payload(MANIFEST), "rid").await.unwrap();
        assert_eq!(out.ckc, b"fake-ckc");
        // First 16 bytes of the fixture DEK, and only after the binding passed on all 32.
        assert_eq!(fake.seen_key.lock().unwrap().unwrap(), [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]);
        assert_eq!(*fake.seen_lease.lock().unwrap(), Some(3600));
    }

    #[tokio::test]
    async fn deny_never_reaches_issuer() {
        let server = platform("DECISION_DENY").await;
        let fake = Arc::new(FakeIssuer::new(None));
        let st = state(&server, fake.clone());
        let err = authorize_license(&st, &person(), &payload(MANIFEST), "rid").await.err().unwrap();
        assert!(matches!(err, LicenseError::Forbidden(_)));
        assert!(fake.seen_key.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn missing_manifest_is_400_and_wrapped_key_is_ignored() {
        let server = platform("DECISION_PERMIT").await;
        let st = state(&server, Arc::new(FakeIssuer::new(None)));
        let p: MediaKeyRequest = serde_json::from_value(json!({
            "sessionId":"s","userId":"u","assetId":"a","spcData":"AQID","tdfWrappedKey":"AAAA"})).unwrap();
        assert!(matches!(authorize_license(&st, &person(), &p, "rid").await, Err(LicenseError::BadRequest(_))));
    }

    #[tokio::test]
    async fn unconfigured_licensing_is_503() {
        let server = platform("DECISION_PERMIT").await;
        let mut st = state(&server, Arc::new(FakeIssuer::new(None)));
        st.license = None;
        assert!(matches!(authorize_license(&st, &person(), &payload(MANIFEST), "rid").await, Err(LicenseError::Unavailable(_))));
    }
}
```

Before writing this, check the `MediaMetrics::new` signature (`grep -n "pub fn new" src/media_metrics.rs`) and adapt the constructor call to it.

- [ ] **Step 3: Run the tests and watch them fail**

Run: `cargo test --bin arks license_pipeline_tests`
Expected: compile errors, because `authorize_license` and the new state fields are missing.

- [ ] **Step 4: Implement**

`MediaApiState` gains:

```rust
    /// Verifies the viewer's passkey CWT on every /media/v1 call except /certificate.
    pub person_tokens: Arc<crate::modules::license::person_token::PersonTokenVerifier>,
    /// None → FairPlay key requests fail closed with 503.
    pub license: Option<Arc<crate::modules::license::config::LicenseAuthz>>,
    /// None when the fairplay feature is off.
    pub issuer: Option<Arc<dyn crate::modules::license::issuer::LicenseIssuer>>,
```

Remove the `fairplay_handler` field and the `tdf_wrapped_key` field of `MediaKeyRequest`. Unknown JSON fields are ignored, so old clients still parse.

`ErrorResponse::into_response`: add `"forbidden" => StatusCode::FORBIDDEN` and `"service_unavailable" => StatusCode::SERVICE_UNAVAILABLE`. Add this helper:

```rust
impl From<crate::modules::license::LicenseError> for ErrorResponse {
    fn from(e: crate::modules::license::LicenseError) -> Self {
        ErrorResponse { error: e.error_code().to_string(), message: e.reason().to_string() }
    }
}
```

The pipeline, feature-independent:

```rust
use crate::modules::license::issuer::IssuedLicense;
use crate::modules::license::person_token::Person;
use crate::modules::license::LicenseError;

pub async fn authorize_license(
    state: &MediaApiState,
    person: &Person,
    payload: &MediaKeyRequest,
    rid: &str,
) -> Result<IssuedLicense, LicenseError> {
    let license = state.license.as_ref().ok_or(LicenseError::Unavailable("licensing not configured"))?;
    let issuer = state.issuer.as_ref().ok_or(LicenseError::Unavailable("FairPlay not available"))?;
    let rsa = state.rewrap_state.kas_rsa_private_key.as_ref()
        .ok_or(LicenseError::Unavailable("KAS RSA key not configured"))?;
    let manifest_b64 = payload.tdf_manifest.as_deref().ok_or(LicenseError::BadRequest("tdfManifest is required"))?;
    let manifest = base64::engine::general_purpose::STANDARD.decode(manifest_b64)
        .map_err(|_| LicenseError::BadRequest("tdfManifest is not base64"))?;
    let spc_b64 = payload.spc_data.as_deref().ok_or(LicenseError::BadRequest("spcData is required"))?;
    if spc_b64.len() > MAX_SPC_DATA_SIZE * 4 / 3 {
        return Err(LicenseError::BadRequest("spcData too large"));
    }
    let spc = base64::engine::general_purpose::STANDARD.decode(spc_b64)
        .map_err(|_| LicenseError::BadRequest("spcData is not base64"))?;

    let policy = crate::modules::license::tdf_policy::check_manifest(&manifest, rsa, &license.kas_urls)?;
    license.pdp.decide(&person.token, &policy.policy_uuid, &policy.fqns, rid).await?;

    let mut key = [0u8; 16];
    key.copy_from_slice(&policy.dek[..16]);
    let issued = issuer.issue(spc, key, &policy.policy_uuid, license.lease_secs).await.map_err(|e| {
        error!("FairPlay SDK refused SPC: {e}");
        LicenseError::Forbidden("SPC rejected")
    })?;
    if issued.spc_asset_id.as_deref() != Some(policy.policy_uuid.as_str()) {
        warn!("license: SPC asset id does not match policy uuid {}", policy.policy_uuid);
    }
    Ok(issued)
}
```

Move `MAX_SPC_DATA_SIZE` out from behind `#[cfg(feature = "fairplay")]`. Drop the `cfg` on the `base64::Engine` import.

Replace **both** `media_key_request` variants with one, feature-independent:

```rust
pub async fn media_key_request(
    State(state): State<Arc<MediaApiState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<MediaKeyRequest>,
) -> Result<Json<MediaKeyResponse>, ErrorResponse> {
    let timer = RequestTimer::start();
    let rid = Uuid::new_v4().to_string();
    let person = state.person_tokens.verify(&headers, Utc::now().timestamp()).await?;
    match detect_protocol(&payload) {
        Some(MediaProtocol::FairPlay) => {}
        Some(MediaProtocol::TDF3) => {
            return Err(LicenseError::Forbidden("TDF3 media keys are disabled pending policy enforcement").into())
        }
        None => return Err(LicenseError::BadRequest("spcData is required").into()),
    }
    let session = require_owned_session(&state, &payload.session_id, &person).await?;
    if session.protocol != MediaProtocol::FairPlay {
        return Err(LicenseError::BadRequest("session protocol is not fairplay").into());
    }
    // A key request (including AVFoundation lease renewal) keeps the session
    // alive, as the old validate_session did; phase 2 adds explicit heartbeats.
    state
        .session_manager
        .heartbeat(&payload.session_id, None, payload.segment_index)
        .await
        .map_err(|_| LicenseError::Unavailable("session store unavailable"))?;
    let result = authorize_license(&state, &person, &payload, &rid).await;
    let outcome = match &result {
        Ok(_) => KeyRequestResult::Success,
        Err(LicenseError::Forbidden(_)) => KeyRequestResult::PolicyDenied,
        Err(LicenseError::Unauthenticated(_)) => KeyRequestResult::AuthenticationFailed,
        Err(_) => KeyRequestResult::InvalidRequest,
    };
    let event = MediaEvent::KeyRequest {
        session_id: payload.session_id.clone(),
        user_id: person.sub.clone(),
        asset_id: payload.asset_id.clone(),
        segment_index: payload.segment_index,
        result: outcome,
        latency_ms: timer.elapsed_ms(),
        timestamp: Utc::now().timestamp(),
    };
    state.media_metrics.publish_event(event.clone()).await;
    state.media_metrics.log_event(&event);
    let issued = result?;
    Ok(Json(MediaKeyResponse {
        session_public_key: String::new(),
        wrapped_key: base64::engine::general_purpose::STANDARD.encode(&issued.ckc),
        status: "success".to_string(),
        metadata: Some(serde_json::json!({ "protocol": "fairplay", "lease_seconds": state.license.as_ref().map(|l| l.lease_secs) })),
    }))
}

async fn require_owned_session(
    state: &MediaApiState,
    session_id: &str,
    person: &Person,
) -> Result<PlaybackSession, LicenseError> {
    match state.session_manager.get_session(session_id).await {
        Ok(Some(s)) if s.user_id == person.sub => Ok(s),
        Ok(_) => Err(LicenseError::Forbidden("session not found for this subject")),
        Err(_) => Err(LicenseError::Unavailable("session store unavailable")),
    }
}
```

Then delete:
- `handle_fairplay_key_request`, `handle_fairplay_key_request_router` (both variants) and `handle_tdf3_key_request`;
- `validate_session`, `validate_chain_session` and `log_key_request_error`, if they are now unused (`cargo clippy` will say);
- `process_nanotdf_header` and its helpers, only if nothing else uses them;
- `extract_dek_from_*` and the `tdf_manifest_tests` module.

Keep `detect_protocol` and drop its `#[allow(dead_code)]`.

In `main.rs`, the construction becomes:

```rust
    let license_authz = modules::license::config::license_authz_from_env(env::var("OPENTDF_PLATFORM_URL").ok().as_deref())
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    #[cfg(feature = "fairplay")]
    let license_issuer: Option<Arc<dyn modules::license::issuer::LicenseIssuer>> = Some(fairplay_handler.clone());
    #[cfg(not(feature = "fairplay"))]
    let license_issuer: Option<Arc<dyn modules::license::issuer::LicenseIssuer>> = None;

    let media_api_state = Arc::new(media_api::MediaApiState {
        rewrap_state: rewrap_state.clone(),
        session_manager: session_manager.clone(),
        media_metrics: media_metrics.clone(),
        chain_validator: chain_validator.clone(),
        fairplay_certificate_data,
        person_tokens: Arc::new(modules::license::config::person_verifier_from_env()),
        license: license_authz.map(Arc::new),
        issuer: license_issuer,
    });
```

Check the type of `fairplay_handler` in `main.rs` (`grep -n "let fairplay_handler" -A12 src/bin/main.rs`). If it's an `Arc<FairPlayHandler>`, the `.clone()` above coerces. If it's a bare `FairPlayHandler`, wrap it in `Arc::new`.

- [ ] **Step 5: Run the tests, lint and feature check**

Run:
```bash
cargo test --bin arks license_pipeline_tests
cargo clippy --package arkavo-rs --lib --bin arks -- -D warnings -A mismatched-lifetime-syntaxes -A unexpected-cfgs
cargo check --release --bin arks --features fairplay,c2pa_signing
```
Expected: 4 tests pass, clippy is clean, and the feature build compiles.

- [ ] **Step 6: Commit**

```bash
git add src/modules/license/ src/modules/media_api.rs src/bin/main.rs src/modules/fairplay.rs
git commit -m "feat(media): authorize FairPlay licenses (person token, TDF policy, platform decision)"
```

---

### Task 10: Authenticate the session routes

**Files:**
- Modify: `src/modules/media_api.rs` (`session_start`, `session_heartbeat`, `session_terminate`)
- Test: `src/modules/media_api.rs` (new `mod session_auth_tests`)

**Interfaces:**
- Consumes: `state.person_tokens`, `require_owned_session`, `LicenseError` → `ErrorResponse`.
- Produces: `session_start` stores `user_id = person.sub`, ignoring the body `userId`. Heartbeat and delete require the same `sub` (403 otherwise).

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod session_auth_tests {
    use super::*;
    use crate::modules::authzen::cose_keys::CoseKeyCache;
    use crate::modules::authzen::cwt_verify::test_support::{keypair, mint_map};
    use crate::modules::license::person_token::PersonTokenVerifier;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{delete, post};
    use axum::Router;
    use ciborium::value::Value;
    use serde_json::json;
    use tower::ServiceExt;

    const ISS: &str = "https://identity.test";
    const PLATFORM: &str = "https://platform.arkavo.net";
    const KID: &[u8] = b"kid-1";

    fn token(sub: &str) -> String {
        let (sk, _) = keypair();
        let now = Utc::now().timestamp();
        mint_map(&sk, KID, vec![
            (Value::Integer(1.into()), Value::Text(ISS.into())),
            (Value::Integer(2.into()), Value::Text(sub.into())),
            (Value::Integer(3.into()), Value::Array(vec![Value::Text("arkavo".into()), Value::Text(PLATFORM.into())])),
            (Value::Integer(4.into()), Value::Integer((now + 3600).into())),
            (Value::Integer(6.into()), Value::Integer(now.into())),
            (Value::Integer(7.into()), Value::Bytes(Uuid::new_v4().as_bytes().to_vec())),
        ])
    }

    fn app() -> Router {
        let (_, vk) = keypair();
        let redis = redis::Client::open(std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into())).unwrap();
        let st = Arc::new(MediaApiState {
            rewrap_state: Arc::new(RewrapState {
                kas_ec_private_key: p256::SecretKey::random(&mut rand_core::OsRng),
                kas_ec_public_key_pem: String::new(),
                kas_rsa_private_key: None,
                kas_rsa_public_key_pem: None,
                oauth_public_key_pem: None,
                chain_validator: None,
            }),
            session_manager: Arc::new(SessionManager::new(Arc::new(redis), Some(100))),
            media_metrics: Arc::new(MediaMetrics::new(None, false)),
            chain_validator: None,
            fairplay_certificate_data: None,
            person_tokens: Arc::new(PersonTokenVerifier::new(CoseKeyCache::with_static_keys(vec![(KID.to_vec(), vk)]), ISS.into(), PLATFORM.into())),
            license: None,
            issuer: None,
        });
        Router::new()
            .route("/start", post(session_start))
            .route("/s/:session_id/heartbeat", post(session_heartbeat))
            .route("/s/:session_id", delete(session_terminate))
            .with_state(st)
    }

    async fn send(app: &Router, method: &str, uri: &str, tok: Option<&str>, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let mut b = Request::builder().method(method).uri(uri).header("content-type", "application/json");
        if let Some(t) = tok { b = b.header("authorization", format!("Bearer {t}")); }
        let mut req = b.body(Body::from(body.to_string())).unwrap();
        req.extensions_mut().insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9))));
        let res = app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    #[tokio::test]
    async fn start_requires_token_and_binds_sub() {
        let app = app();
        let body = json!({"userId": "someone-else", "assetId": "a", "protocol": "fairplay"});
        assert_eq!(send(&app, "POST", "/start", None, body.clone()).await.0, StatusCode::UNAUTHORIZED);
        let sub = Uuid::new_v4().to_string();
        let (st, v) = send(&app, "POST", "/start", Some(&token(&sub)), body).await;
        assert_eq!(st, StatusCode::OK);
        let sid = v["sessionId"].as_str().unwrap().to_string();
        assert!(sid.starts_with(&sub), "session is keyed by the verified sub");

        // Owner may heartbeat; another person may not.
        let hb = format!("/s/{}/heartbeat", urlencoding_path(&sid));
        assert_eq!(send(&app, "POST", &hb, Some(&token(&sub)), json!({})).await.0, StatusCode::OK);
        let other = Uuid::new_v4().to_string();
        assert_eq!(send(&app, "POST", &hb, Some(&token(&other)), json!({})).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, "DELETE", &format!("/s/{}", urlencoding_path(&sid)), Some(&token(&other)), json!(null)).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, "DELETE", &format!("/s/{}", urlencoding_path(&sid)), Some(&token(&sub)), json!(null)).await.0, StatusCode::NO_CONTENT);
    }

    fn urlencoding_path(s: &str) -> String {
        s.replace(':', "%3A")
    }
}
```

Check that `tower` is available for `ServiceExt::oneshot`. The AuthZEN contract tests already use it: `grep -n "ServiceExt" src/modules/authzen/contract.rs`.

- [ ] **Step 2: Run the tests and watch them fail**

Run: `cargo test --bin arks session_auth_tests`
Expected: FAIL. With no token, the response is 200 instead of 401.

- [ ] **Step 3: Implement**
  - `session_start`: add a `headers: axum::http::HeaderMap` extractor, placed before `Json`. Its first line is `let person = state.person_tokens.verify(&headers, Utc::now().timestamp()).await?;`. Use `person.sub` everywhere `payload.user_id` was used: the session id, `PlaybackSession.user_id`, and the event `user_id`. Rename the `SessionStartRequest.user_id` field to `_user_id` with `#[serde(rename = "userId", default)]`, so old clients still parse but the value is unused.
  - `session_heartbeat`: add a `headers` extractor. Verify the person, then call `require_owned_session(&state, &session_id, &person).await?`, then run the existing heartbeat logic.
  - `session_terminate`: the same two calls first. Keep the existing event logic.

- [ ] **Step 4: Run all media and license tests**

Run: `cargo test --bin arks session_auth_tests license`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/modules/media_api.rs
git commit -m "feat(media): session routes require a person token; sessions keyed by sub"
```

---

### Task 11: Docs and env contract

**Files:**
- Modify: `CLAUDE.md` (Configuration block and notes; "Media DRM Endpoints")
- Modify: `docs/standard_tdf_fairplay_integration.md` (request contract, security note at `:183-187`, API reference at `:374-391`)
- Modify: `docs/fairplay.md` (`:151-227` request JSON, `:346` JWT note)

- [ ] **Step 1: Update `CLAUDE.md`**

Add to the env block, under "Media DRM Configuration":

```bash
export ARKS_MEDIA_CLIENT_ID=arks-media                 # authnz-rs service client used for GetDecision
export ARKS_MEDIA_CLIENT_SECRET=...                    # PDP-equivalent secret; start.sh env only
export MEDIA_PLATFORM_AUDIENCE=https://platform.arkavo.net  # viewer CWT must carry this AND "arkavo"
export MEDIA_KAS_URLS=https://platform.arkavo.net      # accepted TDF key-access URLs (normalised)
export MEDIA_FPS_LEASE_SECONDS=3600                    # CKC lease; streaming licences only
```

Add a note under the endpoints:
- all `/media/v1/*` routes except `/certificate` require `Authorization: Bearer <passkey CWT>`;
- FairPlay key requests need the full `tdfManifest`, and `tdfWrappedKey` is gone;
- TDF3 media key requests are disabled;
- errors are 401, 403 and 503 as in the spec.

- [ ] **Step 2: Update the two FairPlay docs**
  - Replace the "no caller authentication" warning with the new contract.
  - Remove `tdfWrappedKey` from the request tables.
  - Add the `Authorization` header to the Swift and curl examples.
  - Document `skd://<policy uuid>` and the binding form `base64(HMAC-SHA256(DEK, base64 policy))`.

- [ ] **Step 3: Final gate**

Run:
```bash
cargo fmt --package arkavo-rs --package fairplay-wrapper
cargo test --bin arks
cargo test -p fairplay-wrapper
cargo clippy --package arkavo-rs --lib --bin arks -- -D warnings -A mismatched-lifetime-syntaxes -A unexpected-cfgs
cargo check --release --bin arks --features fairplay,c2pa_signing
```
Expected: everything passes. Note any pre-existing failures that also fail on `main`.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md docs/standard_tdf_fairplay_integration.md docs/fairplay.md
git commit -m "docs: FairPlay license authorization contract and env vars"
```

---

## Deployment notes (not tasks; for the PR description)

- **Deploy only after authnz-rs has registered `arks-media`.** Set `ARKS_MEDIA_CLIENT_SECRET` in `production/start.sh`, and don't commit it.
- Without the secret, FairPlay key requests return 503. That is the intended fail-closed behaviour.
- Creator and the Arkavo app must send the bearer token and the full manifest, and Creator must re-package with the corrected binding and real attributes. Until then, playback fails with 401/403. That's expected under the hard cutover.
- **Post-deploy smoke checks:**
  - `POST /media/v1/session/start` with no token returns 401;
  - `GET /media/v1/certificate` returns 200.
