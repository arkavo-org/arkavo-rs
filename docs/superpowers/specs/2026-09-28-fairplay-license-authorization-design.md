# FairPlay license authorization (arks) — design

**Status:** Approved in brainstorming, 2026-09-28
**Scope:** phase 1 of the FPS license service in arks. Phase 2 (lease renewal, heartbeat, termination contract) is out of scope.
**Client contract:** arkavo-ios ADR-0023, `specs/fairplay-playback.spec.yaml` (ARK-109, ARK-110), `docs/contracts/first-release.md` ("FPS license service" row).

## Problem

`POST /media/v1/key-request` with `spcData` issues a FairPlay CKC for any TDF manifest, to anyone:

- There is no caller authentication. `userId` in the body is self-asserted, and sessions trust it.
- The DEK is RSA-unwrapped with arks' KAS key (the same key as the platform's `r1`), but the TDF policy is never read and `policyBinding` is never checked.
- `tdfWrappedKey` skips the manifest entirely. Debug builds fall back to an all-zero key.
- The TDF3 media key path has the same gap for NanoTDF.

Patreon content is for humans only and is protected with FairPlay L1. Agents must never receive it, even when their owner delegates it.

## Decisions

| Topic | Decision |
|---|---|
| Where the decision is made | arks enforces; the platform decides (`authorization.v2` `GetDecision`). arks does not re-implement attribute rules. |
| Why not platform KAS Rewrap | Person CWTs may carry a passkey-bound `cnf`. The platform then requires a DPoP proof that arks cannot produce. |
| arks → platform credential | New authnz-rs client `arks-media` (service-account role, aud `https://platform.arkavo.net`), `client_credentials`. The secret is PDP-equivalent; it goes in `production/start.sh` env only. |
| FairPlay asset id | `skd://<TDF policy uuid>`. The uuid is inside the policy, which the policy binding covers. |
| Policy binding | `base64(HMAC-SHA256(key=DEK, msg=<base64 policy string>))` (the OpenTDF spec). The hex form `base64(hex(HMAC))` is a bug from an old SDK. An HMAC over the raw policy JSON is also wrong. Both are refused here and fixed everywhere in the same cutover. |
| DEK wrapping | RSA-OAEP with SHA-1 (the OpenTDF default; already used by the platform KAS, arks, the Go SDK and ArkavoMediaKit). |
| Passkey-bound (`cnf`) tokens | Accepted as bearer tokens in phase 1. This is **weaker than the platform's KAS path**: with #49 the platform verifies DPoP whenever `cnf` is present, even with `enforceDPoP: false` (`authn.go:536-546`). Recorded as a known phase-1 gap; closing it needs a proof-of-possession design for FPS requests. |
| Rollout | Hard cutover. The product is not live. |

## Components

### `media_auth`: person-token check

- Reads `Authorization: Bearer <cwt>` and verifies it with the existing `authzen::cwt_verify` and a `CoseKeyCache`:
  - ES256 signature;
  - `iss == OIDC_ISSUER`;
  - exp, iat and nbf, with the existing skew allowance.
- **Allowlist, not denylist.**
  - `aud` must contain both `https://platform.arkavo.net` and `arkavo`. That pair marks the passkey auth CWT, which both apps use (arkavo-ios ADR-0006).
  - `sub` must be person-shaped: `arkavo:`, `apple:` or `google:` prefix, or a UUID. Passkey auth tokens carry the account UUID (authnz-rs `authn.rs:654`); agent tokens carry a `did:key` (`agent.rs:1157`).
  - **Second layer:** refuse any agent marker: `arkavo_npe` of any type (a person has none), `arkavo_swarm`, `arkavo_state_version`, or `agent` in `arkavo_roles`. Agent token audiences are configurable, so the audience alone does not tell a person from an agent. `cwt_verify::parse_claims` is extended to read these claims.
  - This refuses:
    - `client:` service tokens;
    - agents' `did:key` subjects;
    - tokens that other sign-in clients obtain for a person (so an agent can't go through one);
    - DeviceCheck tokens;
    - the long-lived registration token (aud `arkavo` only).
- Its state does not depend on `AUTHZEN_FACADE`. Media gets its own `CoseKeyCache`, or one shared cache built whenever media is on.
- Output: the verified `sub` and the raw token.

### `tdf_policy`: manifest check

- `encryptionInformation.keyAccess` has exactly one entry, `type == "wrapped"`, and a `url` that names this KAS.
  - The comparison is normalised: scheme and host lower-cased, default port dropped, trailing `/` and a trailing `/kas` path segment ignored.
  - The accepted URLs come from `MEDIA_KAS_URLS` (default `https://platform.arkavo.net`), matching the platform's registered KAS URI.
- RSA-OAEP-SHA1 unwrap, using the existing `extract_dek_*` code.
- `policyBinding`: accept the string form or `{alg: "HS256", hash}`. `hash` must be `base64(HMAC-SHA256(DEK, <the base64 policy string exactly as it appears in the manifest>))`, compared in constant time. The hex form and a raw-JSON HMAC are refused.
- **Ordering:** the binding is checked with the full unwrapped DEK, *before* the existing 32→16-byte truncation for FairPlay.
- Decode `encryptionInformation.policy` (base64 JSON). It must have a `uuid` and a non-empty `body.dataAttributes[].attribute`. A policy without attributes would be released with no decision, so it is refused.
- Output: the DEK (never logged), the policy uuid and the attribute FQNs.

### `platform_pdp`: decision client

- Caches the `arks-media` service CWT, renews it shortly before `exp`, and re-mints once on a 401.
- `POST {OPENTDF_PLATFORM_URL}/authorization.v2.AuthorizationService/GetDecision` with:
  - `entityIdentifier.token = {ephemeralId, jwt: <user CWT>}`;
  - `action.name = "read"`;
  - `resource.attributeValues.fqns = <policy FQNs>`.
- The token entity takes the platform's token path (`CreateEntityChainsFromTokens`). That runs the #51 agent gate in arkavo mode and the #53 withhold in patreon mode.
- The ERS does not re-verify the token's signature, so `media_auth` must run first.
- Only `DECISION_PERMIT` allows.
- It shares the HTTP call with the AuthZEN facade's `post_connect` if that's cheap. That refactor must not block this work.

### `media_api` changes

- `media_auth` runs on `session/start`, `session/:id/heartbeat`, `DELETE session/:id` and `key-request`. `GET /media/v1/certificate` stays public.
- `PlaybackSession` gains the verified `sub`. Sessions are keyed by it and used for concurrency and leases, not for authentication. The body `userId` is ignored.
- FairPlay key request, in order:
  1. token check;
  2. session (its `sub` must match);
  3. manifest check;
  4. `GetDecision`;
  5. the FPS SDK issues the CKC with `lease-duration = MEDIA_FPS_LEASE_SECONDS` (default 3600), license type always `streaming`, never `offline-hls`;
  6. log whether the SPC `asset-id` matches the policy uuid. This is a consistency check only: the client chooses that value.
  7. return the CKC.
- Removed: `tdfWrappedKey` and the debug zero-key fallback.
- The TDF3 media key path (`nanotdf_header`) is switched off (403) until it gets the same decision check.
- `crates/fairplay-wrapper` sends `lease-duration` and the license type, and returns the response `asset-id`. `vendor/fpssdk` is not modified.

### REST KAS routes

`production/start.sh` now fixes `KAS_PROXY_MODE=both`. That closed the local `/kas/v2/rewrap` hole (unverified JWT, no policy check). It also made REST `kas_public_key` return 401, because the platform has no REST routes.

arks will always serve `GET /kas/v2/kas_public_key` locally, since the key is public, and forward `rewrap` to the platform.

## Errors

| Condition | Status |
|---|---|
| Token missing, expired, bad signature or wrong issuer | 401. The app deletes the token and prompts sign-in (ARK-110). |
| Token lacks the platform audience (e.g. the long-lived registration token) | 401. The verifier's audience check fails, so the app signs in again for a proper auth token. |
| Token valid but not a person (no `arkavo` audience, non-person subject, agent marker) | 403 |
| Session unknown or `sub` mismatch | 403 |
| Manifest invalid, binding mismatch, foreign KAS, no attributes | 403 |
| Platform decision is not permit, or its Connect code means bad input or not found | 403 |
| Platform or identity unavailable, timeout, network error, or the service token can't be obtained | 503 |

The Connect code the platform returns for an unknown attribute FQN is recorded during implementation, and the mapping follows it. `post_connect`'s blanket 500 is not used.

**Logging:** a sanitized reason per step. No token, SPC, CKC, wrapped key or DEK is logged (ADR-0023 §8). Media metrics still record the outcome.

## Lease behaviour (phase 1)

- The CKC lease is 3600 s by default.
- When the lease expires, playback stops. AVFoundation's renewal is an ordinary key request, so it succeeds while the app holds a valid token.
- The CWT also lasts one hour, so in practice the app goes through ARK-110: sign in again, then retry once.
- A cancelled Patreon membership stops playing within one lease.

Phase 2 defines renewal, heartbeat and termination.

## Testing

**Independent fixtures.** arks' own code does not generate the test inputs its verifier checks.

- **Manifests:**
  - No current producer makes the correct binding form (see the cutover table), so the allowed fixture is built with `openssl`:
    - `openssl pkeyutl` with `rsa_padding_mode:oaep` and `rsa_oaep_md:sha1` wraps the DEK;
    - `openssl dgst -sha256 -mac HMAC` over the base64 policy string produces the binding.
    - This is independent of arks' code. A script in `tests/fixtures/` regenerates it.
  - After the cutover, add one manifest produced by the fixed Creator packager.
  - Tampered copies of it: hex binding, edited policy, swapped `wrappedKey`, two key-access entries, foreign KAS URL, empty attributes, missing uuid.
- **Tokens:**
  - The valid token copies identity's real layout: numeric labels 1/2/3/4/6/7, `aud` as a list containing `arkavo` and the platform audience, a protected `kid`, and a `cnf` present.
  - A mutant of it for each refusal case.
  - The facade's `mint_user` helper (aud `arkavo` only) is not reused for positive cases.

**Unit tests:** `media_auth`, `tdf_policy`, `platform_pdp` (request shape, service-token caching and refresh, response mapping).

**Handler tests,** with wiremock standing in for the platform and identity:
- permit and deny;
- 401 versus 403 versus 503;
- `sub` mismatch;
- `tdfWrappedKey` refused;
- TDF3 key request switched off;

**REST KAS routes** (shipped separately in #74, which had no automated test): checked after deploy with curl. `GET /kas/v2/kas_public_key` without a token returns 200, and `POST /kas/v2/rewrap` without a token returns 401.

**Release proof** (ADR-0023): one allowed and one denied playback on a physical device, after the dependent repos ship.

## Cross-repo cutover (one release)

| Repo | Change |
|---|---|
| arkavo-rs | This spec. |
| opentdf-platform | KAS `verifyPolicyBinding` accepts only `base64(HMAC)`. `sdk/tdf.go` and `sdk/experimental/tdf/key_access.go` produce it. Switch ERS to arkavo mode (`agent_status`, zero subject mappings, `allow_direct_entitlements`). |
| opentdf-rs | `calculate_policy_binding` produces `base64(HMAC)`. New tag; bump arks' dependency. |
| authnz-rs | Register the `arks-media` client. Mint Patreon `campaign`/`campaign-tier` values into `arkavo_entitlements`: active memberships only, numeric campaign ids, slugified tiers; `role=creator` gets its campaign plus every tier. Stop minting `arkavo_patreon`. Never delegate `patreon.arkavo.com` values to agents. Confirm `OIDC_PLATFORM_AUDIENCE` is set. |
| app (Creator, ArkavoMediaKit) and arkavo-ios | Send the bearer CWT and the full manifest. Use `skd://<policy uuid>`. HMAC the base64 policy string (today `HLSTDFPackager.swift:149` and `StandardTDFSegmentCrypto.swift:100` HMAC the raw JSON). **Write the `campaign`/`campaign-tier` attributes into `body.dataAttributes`**: today the packager writes an empty body, which is refused. Re-package test content. |
| OpenTDFKit | `TDFCrypto.policyBinding` callers HMAC the base64 policy string, not the raw JSON (`TDFProcessor.swift:109,220,314`). `wrapSymmetricKeyWithRSA` and `unwrapSymmetricKeyWithRSA` switch from OAEP-SHA256 to OAEP-SHA1 (`TDFCrypto.swift:156,173`). New revision; bump ArkavoKit's pin. |

## Out of scope

- Phase 2: renewal, heartbeat and termination semantics; maximum-lease negotiation.
- A decision check on the TDF3 (NanoTDF) media path. It stays switched off.
- DPoP for `cnf`-bound tokens.
- Offline or persistent licenses.
