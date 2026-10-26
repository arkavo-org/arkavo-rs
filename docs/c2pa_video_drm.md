# C2PA Video DRM Integration

## Overview

This document describes the integration of C2PA (Coalition for Content Provenance and Authenticity) with OpenTDF-based media DRM in arkavo-rs. The system enables content authenticity verification and provenance tracking for TDF3-encrypted video content.

## Architecture

### Client-Server Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│ Client (c2pa-opentdf-rs)                                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. Parse MP4/MOV video container                                │
│  2. Compute SHA-256 hash with exclusion ranges                   │
│  3. Prepare metadata (creator, title, AI flag, etc.)             │
│                                                                   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ POST /c2pa/v1/sign
                            │ {hash, exclusion_ranges, metadata}
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ Server (arkavo-rs KAS)                                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. Validate creator (if allowlist configured)                   │
│  2. Validate hash format (64 hex chars)                          │
│  3. Build C2PA manifest with assertions                          │
│  4. Sign manifest using ES256 (ECDSA + SHA-256)                  │
│  5. Return signed JUMBF box (base64-encoded)                     │
│                                                                   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ Response: {manifest, manifest_hash}
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ Client                                                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. Embed signed C2PA manifest in video (uuid box)               │
│  2. Encrypt video as TDF3 object                                 │
│  3. Upload to CDN / distribute                                   │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Playback Workflow with C2PA Validation

```
┌─────────────────────────────────────────────────────────────────┐
│ Player (Client)                                                   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ 1. Start session
                            │ POST /media/v1/session/start
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ KAS Server                                                        │
│  - Create playback session                                        │
│  - Check concurrency limits                                       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ 2. Request segment key
                            │ POST /media/v1/key-request
                            │ {session_id, nanotdf_header, ...}
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ KAS Server - Media Policy Validation                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. Extract C2PA manifest from TDF3 metadata                     │
│  2. Validate C2PA signature chain                                │
│  3. Check creator against allowlist (if configured)              │
│  4. Verify AI-generated disclosure (if required)                 │
│  5. Check edit count limits (if configured)                      │
│  6. Validate other media policies (subscription, geo, etc.)      │
│                                                                   │
│  If validation passes:                                            │
│    - Rewrap DEK and return to client                             │
│    - Track C2PA metadata in session                              │
│    - Publish analytics event: c2pa_validation_success            │
│                                                                   │
│  If validation fails:                                             │
│    - Deny access                                                  │
│    - Publish analytics event: c2pa_policy_denial                 │
│                                                                   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ 3. Continue playback
                            │ Periodic heartbeats
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ Player decrypts segments and plays video                         │
└─────────────────────────────────────────────────────────────────┘
```

## API Endpoints

### C2PA Signing Endpoints

#### POST /c2pa/v1/sign

Sign a C2PA manifest with a pre-computed content hash.

**Who may sign:** only a signed-in person. The request needs `Authorization: Bearer <passkey CWT>`, the identity.arkavo.net token, verified the same way as `/media/v1`: `aud` must contain `arkavo` and `MEDIA_PLATFORM_AUDIENCE`, the `sub` must be person-shaped, and agent tokens are refused. A missing or invalid token gets 401, and a non-person token 403. The manifest's creator (`org.arkavo.recording`) is the token's `sub`; `metadata.creator` is ignored. `C2PA_ALLOWED_CREATORS`, if set, filters on `sub`. With `C2PA_REQUIRE_ENTITLEMENT=true`, only creator members may sign: the token's `arkavo_entitlements` must include `https://patreon.arkavo.com/attr/arkavo-creator/value/publish`, the attribute publishing requires. Otherwise the request gets 403 with `"error": "signing entitlement required"` and `required_entitlement` naming the attribute. Like every refusal, it uses none of the subject's quota. Each subject may make `C2PA_SIGN_LIMIT_PER_HOUR` requests per hour (default 120); over the limit gets 429 with `Retry-After`. Every request is logged with its `sub`, content hash and exclusion range.

**Manifest contents:** the claim follows C2PA spec 2.2, the version c2pa-rs 0.91 generates, and passes the C2PA Conformance Program's spec 2.2 and integrity rubrics.
- **Generator:** `claim_generator_info` names the product, "Arkavo Creator", with `specVersion` `2.2.0`. It includes the product's version when `metadata.software` is `Arkavo Creator <version>`, and the signing service as `org.arkavo.signer`.
- **Created assertions** (attributed to the signer):
  - `c2pa.actions.v2`: a `c2pa.created` action, with `allActionsIncluded` from `metadata.all_actions_included`. It defaults to false; send true only when that action is the asset's whole history.
  - `org.arkavo.recording`: the creator and the optional description.
  - The `c2pa.hash.data` hard binding.
- **Instance ID:** each manifest gets its own `xmp:iid:` instanceID.

**Exclusion rule:** `exclusion_ranges` must be exactly one range with `box_type: "uuid"`, and its length must equal the C2PA manifest box the client will embed: 45 bytes of box header (size, type, UUID, version/flags, `manifest\0`, Merkle offset) plus the JUMBF length. That way only the manifest box itself is unhashed, and no media bytes are.

The server first measures the manifest box without signing it: a sizing pass with a stand-in signature of the reserved size and no timestamp (c2pa pads every signature to that reserve, so the length is exact). On a mismatch it returns `422` with `required_exclusion_length`, having spent no KMS signature and no timestamp. The client repeats the request with that length; this usually settles on the second pass, but the exclusion offsets are part of the manifest, so it can take one more. Only the request at the settled length is signed and timestamped, so each file costs one timestamp (arkavo-rs#119). Any other shape of `exclusion_ranges` gets `400`. When `metadata.timestamp` is absent, the server uses the current time in whole seconds, so the length doesn't shift between passes.

**Request:**
```json
{
  "content_hash": "a1b2c3d4...hex64chars", // SHA-256 of the file with the manifest box excluded
  "exclusion_ranges": [
    {
      "start": 7375,      // where the manifest box will sit (e.g. appended at end of file)
      "end": 11420,       // start + 45 + JUMBF length
      "box_type": "uuid"  // required
    }
  ],
  "container_format": "mp4", // or "mov", "avi"
  "metadata": {
    "title": "My Video",
    "creator": "ignored",       // the token's sub is the author
    "description": "Optional description",
    "timestamp": "2025-10-26T00:00:00Z", // ISO 8601
    "ai_generated": false,
    "digital_source_type": "screenCapture", // optional IPTC term, see below
    "software": "Arkavo Creator 1.4.2",
    "all_actions_included": false // optional; true only if the actions are the whole history
  }
}
```

`digital_source_type` is the `c2pa.created` action's [IPTC digital source type](https://cv.iptc.org/newscodes/digitalsourcetype/), as a term such as `screenCapture` or its full URI. A term c2pa-rs doesn't know gets `400`. So does an `ai_generated` that disagrees with the type: it must be true exactly for `trainedAlgorithmicMedia`, `compositeWithTrainedAlgorithmicMedia` and `trainedAlgorithmicData`. Clients send both fields so that older servers, which ignore `digital_source_type`, still get the AI flag. Without a type, `ai_generated: true` gives `trainedAlgorithmicMedia` and anything else `digitalCapture` (arkavo-rs#129).

**Response (Success):**
```json
{
  "manifest": "base64_encoded_jumbf_box",
  "manifest_hash": "sha256_hex_hash_of_manifest",
  "status": "success"
}
```

**Response (Denied - Creator Not Allowed):**
```json
{
  "error": "Creator not authorized",
  "status": "denied"
}
```

**Response (Error):**
```json
{
  "error": "Invalid content hash format (expected 64 hex chars)",
  "status": "error"
}
```

#### POST /c2pa/v1/validate

Validate a C2PA manifest against a content hash.

**Request:**
```json
{
  "manifest": "base64_encoded_jumbf_data",
  "content_hash": "a1b2c3d4...hex64chars",
  "exclusion_ranges": [{ "start": 7375, "end": 21457, "box_type": "uuid" }] // optional
}
```

`exclusion_ranges` is where the client found the manifest box. Send it: when given, it must equal the exclusion the manifest was signed with, or the response is `valid: false` with an `Exclusion mismatch` error. Without it, a box that grew or moved after signing leaves the hash of the other bytes unchanged while the media offsets point at different bytes, and validation can't tell.

**Response:**
```json
{
  "valid": true,
  "errors": [],
  "creator": "user@example.com",
  "ai_generated": false,
  "digital_source_type": "digitalCapture",
  "provenance_chain": [
    {
      "action": "created",
      "actor": "user@example.com",
      "timestamp": "2025-10-26T00:00:00Z",
      "software": "Arkavo Client v1.0"
    }
  ]
}
```

`signed_at` is the timestamp's signing time, and is present only when the manifest has one (see [Timestamps](#timestamps)). `creator` comes from the `org.arkavo.recording` assertion, and `ai_generated`, `digital_source_type` and `provenance_chain` come from the `c2pa.actions` assertion. `digital_source_type` is the `c2pa.created` action's term, in the form the sign request takes. The server never has the asset, so it skips `assertion.dataHash.mismatch` and compares `content_hash` with `org.arkavo.c2pa.content_hash` instead. Only the configured trust anchors are trusted (see `C2PA_TRUST_ANCHORS_PATH`). By default that is the CA in our own signing chain, so a manifest arks signed returns `valid: true`. A manifest signed under any other CA, including CAs on the public C2PA trust list, returns `valid: false` with `signingCredential.untrusted`.

## Configuration

### Environment Variables

```bash
# C2PA Signing Configuration
export C2PA_SIGNER=kms                        # required: kms (production) or file (development)
export C2PA_KMS_KEY_ID=arn:aws:kms:us-east-1:<account>:key/<id>   # with C2PA_SIGNER=kms
export C2PA_SIGNING_KEY_PATH=/path/to/c2pa_private_key.pem        # with C2PA_SIGNER=file
export C2PA_SIGNING_CERT_PATH=/path/to/c2pa_cert_chain.pem      # signer certificate, then the CA
export C2PA_REQUIRE_VALIDATION=true  # Enforce C2PA in media policy
export C2PA_ALLOWED_CREATORS=arkavo:<uuid-1>,arkavo:<uuid-2>  # token subjects (sub), not emails
export C2PA_REQUIRE_ENTITLEMENT=true  # only creator members (the publish entitlement) may sign; default false; true/false, 1/0 or yes/no, anything else stops startup
# Optional: PEM bundle /c2pa/v1/validate trusts. Default: the certificates after the
# end-entity in C2PA_SIGNING_CERT_PATH (our own CA). List a retired CA here during a rotation.
export C2PA_TRUST_ANCHORS_PATH=/path/to/c2pa_trust_anchors.pem
# Optional: RFC 3161 timestamp authority (see "Timestamps" below). Unset signs without one.
# Use a TSA on the C2PA TSA trust list, or validators report timeStamp.untrusted.
export C2PA_TSA_URL=https://ts-c2pa.ssl.com
# Optional: PEM roots of that TSA, trusted by /c2pa/v1/validate for timestamps only:
# the C2PA TSA trust list (conformance-public trust-list/C2PA-TSA-TRUST-LIST.pem).
export C2PA_TSA_TRUST_ANCHORS_PATH=/path/to/C2PA-TSA-TRUST-LIST.pem

# Existing Media DRM Configuration
export MAX_CONCURRENT_STREAMS=5
export ENABLE_MEDIA_ANALYTICS=true
export MEDIA_METRICS_SUBJECT=media.metrics
```

### Signing key in AWS KMS

In production, the claim-signing key is an AWS KMS `ECC_NIST_P256` key: it is non-exportable, every signature is logged in CloudTrail, and access is scoped by IAM. No private key file sits on the server. arks computes the SHA-256 of the COSE `Sig_structure`, calls KMS `Sign` (`ECDSA_SHA_256`, message type `DIGEST`), and converts the DER signature KMS returns into the raw `r||s` form COSE ES256 needs. Each call is bounded at 5 s, within the 15 s limit for the whole sign request.

- **Choosing the backend:** `C2PA_SIGNER` must be set. Use `kms` in production and `file` only for development and tests. If it's unset or has another value, C2PA signing stays disabled at startup.
- **Startup check:** arks calls KMS `GetPublicKey` and refuses to enable signing unless the key matches the public key in the signer certificate (the first certificate in `C2PA_SIGNING_CERT_PATH`).
- **Credentials:** the standard AWS chain (`AWS_PROFILE`, environment, SSO). The identity needs only `kms:Sign` and `kms:GetPublicKey` on this one key.

**Setup.** The key is generated inside KMS. Our own CA issues the signer certificate directly from the KMS public key, so no CSR is needed:

```bash
aws kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY \
  --description "Arkavo C2PA claim signing"
aws kms get-public-key --key-id <key-id> --query PublicKey --output text \
  | base64 -d | openssl pkey -pubin -inform DER -out c2pa_kms_pub.pem

printf "keyUsage=critical,digitalSignature\nbasicConstraints=CA:FALSE\nextendedKeyUsage=emailProtection\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n" > ee.cnf
openssl x509 -new -force_pubkey c2pa_kms_pub.pem \
  -subj "/CN=Arkavo C2PA Signer/O=Arkavo/C=US/ST=Maryland/L=Columbia" \
  -CA c2pa_ca_cert.pem -CAkey c2pa_ca_key.pem -days 365 \
  -set_serial 0x$(openssl rand -hex 16) -extfile ee.cnf -out c2pa_cert.pem
cat c2pa_cert.pem c2pa_ca_cert.pem > c2pa_cert_chain.pem
export C2PA_SIGNING_CERT_PATH=/path/to/c2pa_cert_chain.pem
```

Point `C2PA_SIGNING_CERT_PATH` at the chain, not `c2pa_cert.pem`: the CA after the signer certificate is what `/c2pa/v1/validate` trusts by default.

`openssl` here is an operator tool (OpenSSL 3); C2PA signing does not use it. A CA on the C2PA trust list will instead want a CSR signed by the KMS key.

### Timestamps

Without a trusted timestamp, a verifier checks the signer certificate against the current time. So once "Arkavo C2PA Signer" expires, every manifest signed so far reports `signingCredential.expired`, not just new ones.

- With `C2PA_TSA_URL` set, arks gets an RFC 3161 timestamp for every manifest. If the TSA fails or doesn't answer within 15 s, the sign request fails (500 or 504); arks never returns an untimestamped manifest instead. The request goes through c2pa's `ureq` client over rustls.
- A timestamp only counts if its TSA is trusted. Tested with a signer certificate that expired after signing, `/c2pa/v1/validate` gives:

  | Manifest | Result |
  |---|---|
  | No timestamp | `valid: false`, `signingCredential.expired` |
  | Timestamp, TSA root in `C2PA_TSA_TRUST_ANCHORS_PATH` | `valid: true`, `signed_at` set |
  | Timestamp, TSA root not trusted | `valid: false`, `signingCredential.untrusted` + `signingCredential.expired` |

- `C2PA_TSA_TRUST_ANCHORS_PATH` is a trust list separate from the manifest anchors, so a TSA root never vouches for a signing certificate.
- Choosing a TSA: use one on the [C2PA TSA trust list](https://github.com/c2pa-org/conformance-public/tree/main/trust-list). The C2PA conformance checks need a trusted timestamp, and so does a manifest outliving its signer certificate for third-party verifiers.
  - SSL.com's `https://ts-c2pa.ssl.com` chains to "SSL.com C2PA ECC Root CA 2025", which is on the list. On 2026-10-25 it issued timestamps without an API key, and manifests signed with it passed the conformance rubrics with `timeStamp.trusted`. Its plans meter timestamps (the free C2PA tier lists 2,500 a year); each signed file uses one. Production uses it since 2026-10-26.
  - DigiCert's public TSA (`http://timestamp.digicert.com`) is free and needs no account, but it chains to "DigiCert Trusted Root G4", which is **not** on the C2PA TSA trust list. `c2patool` and other C2PA validators report `timeStamp.untrusted` for it. DigiCert's C2PA TSA hierarchy is on the list, but has no public endpoint.
- Latency: one DigiCert timestamp added about 270 ms to signing (measured 2026-10-24).

### Generating C2PA Signing Certificates

C2PA uses ES256 (ECDSA with SHA-256) for signing. **Important:** c2pa-rs rejects self-signed certificates. You must generate a CA + end-entity certificate chain with the `emailProtection` Extended Key Usage.

arks signs with c2pa-rs's pure-Rust crypto backend (`rust_native_crypto`, RustCrypto `p256`), so C2PA signing uses no OpenSSL. (On Linux the binary still links OpenSSL through `reqwest`'s default `native-tls`.) The backend only reads PKCS#8 keys, so arks converts a SEC1 `EC PRIVATE KEY` (what `openssl ecparam` writes) to PKCS#8 when it loads the key. Either format works for `C2PA_SIGNING_KEY_PATH`.

```bash
# 1. Generate CA key and self-signed CA certificate
openssl ecparam -genkey -name prime256v1 -noout -out c2pa_ca_key.pem
openssl req -new -x509 -key c2pa_ca_key.pem -out c2pa_ca_cert.pem -days 365 \
  -subj "/CN=My C2PA CA/O=My Org/C=US" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# 2. Generate end-entity signing key and CSR
openssl ecparam -genkey -name prime256v1 -noout -out c2pa_private_key.pem
openssl req -new -key c2pa_private_key.pem -out c2pa_csr.pem \
  -subj "/CN=My C2PA Signer/O=My Org/C=US"

# 3. Create extensions config (emailProtection EKU required by c2pa-rs)
cat > c2pa_ext.cnf << 'EOF'
keyUsage=critical,digitalSignature
basicConstraints=CA:FALSE
extendedKeyUsage=emailProtection
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF

# 4. Sign end-entity cert with CA
openssl x509 -req -in c2pa_csr.pem \
  -CA c2pa_ca_cert.pem -CAkey c2pa_ca_key.pem -CAcreateserial \
  -out c2pa_cert.pem -days 365 -extfile c2pa_ext.cnf

# 5. Create cert chain (end-entity first, then CA)
cat c2pa_cert.pem c2pa_ca_cert.pem > c2pa_cert_chain.pem

# 6. Verify
openssl x509 -in c2pa_cert.pem -noout -subject -issuer -ext extendedKeyUsage
# Should show: E-mail Protection

# 7. Set permissions
chmod 600 c2pa_private_key.pem c2pa_ca_key.pem

# 8. Clean up
rm c2pa_csr.pem c2pa_ext.cnf c2pa_ca_cert.srl
```

**Certificate requirements:**
- End-entity cert must NOT be self-signed (c2pa-rs rejects these)
- Must have `extendedKeyUsage=emailProtection` (or `timeStamping` or `ocspSigning`)
- Must have `keyUsage=digitalSignature`
- Chain file: end-entity cert first, CA cert(s) after

**Environment variables:**
```bash
export C2PA_SIGNER=file
export C2PA_SIGNING_KEY_PATH=/path/to/c2pa_private_key.pem
export C2PA_SIGNING_CERT_PATH=/path/to/c2pa_cert_chain.pem  # chain, not single cert
```

**Production:** Obtain certificates from a recognized Certificate Authority listed in the [C2PA Trust List](https://contentcredentials.org/trust-list). Self-issued CAs will produce `signingCredential.untrusted` validation warnings.

## Media Policy Integration

### C2PA Policy Contract

The `c2pa_policy_contract` provides granular control over content authenticity requirements:

```rust
pub struct ContentPolicy {
    pub require_c2pa: bool,                  // C2PA manifest required
    pub allowed_creators: Vec<[u8; 64]>,     // Whitelist of trusted creators
    pub ai_disclosure_policy: AiDisclosurePolicy,
    pub max_edit_count: Option<u32>,         // Maximum allowed edits
    pub require_timestamp: bool,             // Creation timestamp required
}

pub enum AiDisclosurePolicy {
    Required,    // AI-generated flag must be present if content is AI-generated
    Prohibited,  // AI-generated content not allowed
    Optional,    // No AI disclosure requirements
}
```

### Media Policy Contract Extension

The `media_policy_contract` has been extended to include C2PA validation:

```rust
pub struct ContentMetadata {
    // ... existing fields ...
    pub c2pa_manifest: Option<C2paManifestInfo>,
    pub require_c2pa: bool, // Whether C2PA validation is required
}

pub struct C2paManifestInfo {
    pub is_valid: bool,
    pub creator: Option<[u8; 64]>,
    pub ai_generated: Option<bool>,
    pub edit_count: u32,
}
```

**Validation Flow:**
1. If `require_c2pa` is true, manifest must be present
2. If manifest is present, signature must be valid
3. Creator must be in allowlist (if configured)
4. AI disclosure must comply with policy
5. Edit count must be within limits

**Error Cases:**
- `Error::C2paRequired` - No C2PA manifest found but required
- `Error::C2paValidationFailed` - Manifest signature invalid

## Analytics Events

C2PA validation events are published to NATS for monitoring:

### Event Types

**1. C2PA Validation Success**
```json
{
  "type": "c2pa_validation_success",
  "session_id": "sess_123",
  "user_id": "user_456",
  "asset_id": "asset_789",
  "creator": "creator@example.com",
  "ai_generated": false,
  "timestamp": 1635523200
}
```
**NATS Subject:** `media.metrics.c2pa_validation_success`

**2. C2PA Validation Failure**
```json
{
  "type": "c2pa_validation_failure",
  "session_id": "sess_123",
  "user_id": "user_456",
  "asset_id": "asset_789",
  "error": "Signature verification failed",
  "timestamp": 1635523200
}
```
**NATS Subject:** `media.metrics.c2pa_validation_failure`

**3. C2PA Policy Denial**
```json
{
  "type": "c2pa_policy_denial",
  "session_id": "sess_123",
  "user_id": "user_456",
  "asset_id": "asset_789",
  "reason": "creator_not_allowed",
  "timestamp": 1635523200
}
```
**NATS Subject:** `media.metrics.c2pa_policy_denial`

### Monitoring Analytics

Subscribe to all C2PA events:
```bash
nats sub "media.metrics.c2pa_*"
```

Subscribe to specific event types:
```bash
nats sub "media.metrics.c2pa_validation_success"
nats sub "media.metrics.c2pa_policy_denial"
```

## Session Metadata

Playback sessions track C2PA validation results:

```rust
pub struct C2paSessionMetadata {
    pub validation_status: String, // "valid", "invalid", "missing"
    pub creator: Option<String>,
    pub ai_generated: Option<bool>,
    pub edit_count: Option<u32>,
    pub validated_timestamp: i64,
}

pub struct PlaybackSession {
    // ... existing fields ...
    pub c2pa_metadata: Option<C2paSessionMetadata>,
}
```

This metadata is:
- Stored in Redis with session data
- Available for analytics queries
- Used for audit trails
- Accessible via session management APIs

## Security Considerations

### Private Key Protection

- Production keeps the claim-signing key in AWS KMS (`C2PA_SIGNER=kms`, see [Signing key in AWS KMS](#signing-key-in-aws-kms)); key files are for development only
- Keep the Arkavo C2PA CA key offline, away from the signing host
- Rotate keys periodically
- Never commit private keys to version control

### Creator Allowlist

```bash
# Restrict signing to trusted creators
export C2PA_ALLOWED_CREATORS=arkavo:<uuid-1>,arkavo:<uuid-2>  # token subjects (sub)
```

Benefits:
- Prevents unauthorized content signing
- Enables trusted creator ecosystems
- Supports content authenticity policies

### Validation Enforcement

```bash
# Require C2PA validation for all media content
export C2PA_REQUIRE_VALIDATION=true
```

When enabled:
- All key requests must include valid C2PA manifests
- Content without C2PA is denied access
- Enforces provenance requirements

## Hash Exclusion Ranges (ISOBMFF)

For MP4/MOV containers, C2PA uses box-based exclusion ranges to avoid circular dependencies:

```json
{
  "exclusion_ranges": [
    {
      "start": 1024,
      "end": 2048,
      "box_type": "uuid" // C2PA manifest box location
    }
  ]
}
```

### How It Works

1. Client parses MP4 structure
2. Identifies boxes to exclude (C2PA manifest location)
3. Computes SHA-256 hash over all bytes except exclusion ranges
4. Sends hash + exclusion ranges to server for signing
5. Embeds signed manifest in excluded region
6. Result: Deterministic hash that includes entire file except manifest

**Reference:** [C2PA Specification - ISOBMFF Binding](https://c2pa.org/specifications/)

## Testing

### Quick Start

**Base URL:** `https://platform.arkavo.net` (production) or `http://localhost:8443` (local)

**1. Sign a manifest:**
```bash
curl -s -X POST https://platform.arkavo.net/c2pa/v1/sign \
  -H "Content-Type: application/json" \
  -d '{
    "content_hash": "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
    "exclusion_ranges": [{"start": 100, "end": 500, "box_type": "uuid"}],
    "container_format": "mp4",
    "metadata": {
      "title": "My Video",
      "creator": "user@example.com",
      "ai_generated": false,
      "software": "My App v1.0"
    }
  }'
```

Response:
```json
{
  "manifest": "<base64-encoded JUMBF>",
  "manifest_hash": "<sha256 hex>",
  "status": "success"
}
```

**2. Validate a manifest (sign-then-validate round-trip):**
```bash
# Sign and capture manifest
MANIFEST=$(curl -s -X POST https://platform.arkavo.net/c2pa/v1/sign \
  -H "Content-Type: application/json" \
  -d '{
    "content_hash": "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
    "exclusion_ranges": [{"start": 100, "end": 500, "box_type": "uuid"}],
    "container_format": "mp4",
    "metadata": {
      "title": "Test Video",
      "creator": "test@example.com",
      "ai_generated": false
    }
  }' | python3 -c "import sys,json; print(json.load(sys.stdin)['manifest'])")

# Validate
curl -s -X POST https://platform.arkavo.net/c2pa/v1/validate \
  -H "Content-Type: application/json" \
  -d "{
    \"manifest\": \"$MANIFEST\",
    \"content_hash\": \"a1b2c3d4e5f67890123456789012345678901234567890123456789012345678\"
  }" | python3 -m json.tool
```

**3. Validate with c2patool (local interop):**
```bash
# Decode JUMBF and validate with c2patool
echo "$MANIFEST" | base64 -d > manifest.c2pa
c2patool manifest.c2pa --detailed
```

### Validation Status Codes

The `/c2pa/v1/validate` endpoint uses c2pa-rs `Reader` for cryptographic verification. Expected validation statuses:

| Status | Meaning | Action Required |
|--------|---------|-----------------|
| `claimSignature.validated` | COSE signature verified | None (success) |
| `claimSignature.insideValidity` | Cert within validity period | None (success) |
| `assertion.hashedURI.match` | Assertion integrity verified | None (success) |
| `signingCredential.untrusted` | Signing CA is not a trust anchor | From `/c2pa/v1/validate`: signed under a CA other than ours, or `C2PA_TRUST_ANCHORS_PATH` is missing it. From `c2patool`: pass the Arkavo CA with `trust --trust_anchors` |
| `assertion.dataHash.mismatch` | Asset hash doesn't match | Expected for server-side validation (no asset present) |
| `signingCredential.expired` | Signer certificate expired and no trusted timestamp | Renew the signer certificate; set `C2PA_TSA_URL` and `C2PA_TSA_TRUST_ANCHORS_PATH` so manifests outlive it |
| `timeStamp.untrusted` | The TSA's root is not a TSA anchor | Add the TSA root to `C2PA_TSA_TRUST_ANCHORS_PATH` |

**Note on `valid` field:** Server-side validation verifies the COSE signature chain, assertion integrity and trust in our own CA. It skips `assertion.dataHash.mismatch` because the asset is not present. Clients should check the asset-hash binding locally after embedding the JUMBF.

### Client Integration Workflow

```
1. Client: Hash video content (SHA-256) with exclusion ranges
2. Client: POST /c2pa/v1/sign with hash + metadata
3. Server: Returns signed JUMBF manifest (base64)
4. Client: Decode base64 → embed JUMBF into video container (uuid box)
5. Client: Verify by re-hashing with exclusion ranges → should match
6. Distribution: Upload signed video to CDN
7. Playback: Extract JUMBF → POST /c2pa/v1/validate → display provenance
```

### Automated Tests

- **Unit tests:** `cargo test --features c2pa_signing` — 8 tests covering sign/validate round-trip, hash mismatch, JUMBF format, AI flag, invalid input, c2patool interop
- **Smoke tests:** `tests/c2pa_video_tests.rs` — 24 tests for JSON structure, policy logic, analytics events
- **Live integration:** `curl` against `https://platform.arkavo.net/c2pa/v1/sign` and `/validate`

## Manifest Format

The `/c2pa/v1/sign` endpoint returns a **base64-encoded JUMBF** (JPEG Universal Metadata Box Format) manifest. This is the standard C2PA binary format, not JSON.

**What's inside the JUMBF:**
- COSE-signed claim with ES256 signature
- Manifest `title` from `metadata.title`
- Assertion store:
  - `c2pa.actions.v2`: a single `c2pa.created` action with `when` (`metadata.timestamp`), `softwareAgent.name` (`metadata.software`) and `digitalSourceType` (`metadata.digital_source_type`; without it, `trainedAlgorithmicMedia` when `metadata.ai_generated` is true, otherwise `digitalCapture`)
  - `stds.schema-org.CreativeWork`: `author: [{"@type": "Person", "name": metadata.creator}]` and `metadata.description`
  - `c2pa.hash.data` and `org.arkavo.c2pa.content_hash`
- Claim v2 requires the first action to be `c2pa.created` or `c2pa.opened`. The manifests signed before arkavo-rs#98 used custom `c2pa.created` / `c2pa.claim.creator` / `c2pa.ai_generated` / `dc.title` labels and fail `c2patool` with `assertion.action.malformed`. `/c2pa/v1/validate` no longer reads those labels
- Certificate chain (end-entity + CA)
- Data hash binding with exclusion ranges

**Interop:** The output is compatible with:
- `c2patool` (Adobe/CAI CLI tool)
- `c2pa-rs` Reader API
- Any C2PA-compliant verifier

## Limitations

### Current Implementation

- **Video formats:** MP4, MOV, AVI container formats accepted (JUMBF output is format-independent)
- **Signing algorithm:** ES256 (ECDSA with P-256/SHA-256) only
- **Manifest delivery:** Client-side embedding (server generates signed JUMBF, client embeds in container)
- **Hash computation:** Client-side (server signs the client-provided hash)
- **Trust:** `/c2pa/v1/validate` trusts only our own CA. Third-party verifiers such as `c2patool` report `signingCredential.untrusted` until the CA is on the C2PA trust list or passed as a trust anchor

### Future Enhancements

- [ ] Support for additional C2PA signing algorithms (ES384, ES512)
- [ ] `c2pa.actions` assertion with "created" action (resolves `assertion.action.malformed`)
- [ ] Server-side video parsing and hashing (for trusted environments)
- [ ] Sidecar manifest storage (external .c2pa files)
- [ ] Support for MXF, MKV containers
- [ ] C2PA manifest caching/CDN integration
- [ ] Timestamp Authority (TSA) integration for trusted timestamps

## Troubleshooting

### C2PA Signing Disabled

**Symptom:** Server logs `C2PA signing disabled: ...`, for example `C2PA_SIGNING_CERT_PATH not set`, `C2PA_SIGNER not set` (a key-file setup from before `C2PA_SIGNER` existed), `KMS GetPublicKey failed` or `The KMS key does not match the signer certificate's public key`. See [Signing key in AWS KMS](#signing-key-in-aws-kms) for the KMS cases.

**Solution:**
```bash
export C2PA_SIGNER=kms C2PA_KMS_KEY_ID=<key arn>     # production
# or, for development: export C2PA_SIGNER=file C2PA_SIGNING_KEY_PATH=/path/to/c2pa_private_key.pem
export C2PA_SIGNING_CERT_PATH=/path/to/c2pa_cert_chain.pem
```

### Creator Not Authorized

**Symptom:** API returns: `{"error": "Creator not authorized", "status": "denied"}`

**Solution:**
- Add the creator's token subject to the allowlist: `export C2PA_ALLOWED_CREATORS=arkavo:<uuid>`
- Or remove allowlist to allow all creators (development only)

### C2PA Signing Fails: "the certificate was self-signed"

**Symptom:** Sign endpoint returns error about self-signed certificate.

**Solution:** c2pa-rs rejects self-signed certificates. You must use a CA + end-entity chain. See "Generating C2PA Signing Certificates" above.

### C2PA Signing Fails: "the certificate is invalid"

**Symptom:** Sign endpoint returns error about invalid certificate.

**Solution:** The end-entity certificate must have the `emailProtection` Extended Key Usage. Verify with:
```bash
openssl x509 -in c2pa_cert.pem -noout -ext extendedKeyUsage
# Must show: E-mail Protection
```

If it shows `Code Signing` or another EKU, regenerate the cert with `extendedKeyUsage=emailProtection`.

### Invalid Hash Format

**Symptom:** API returns: `{"error": "Invalid content hash format (expected 64 hex chars)"}`

**Solution:** Ensure hash is a 64-character lowercase hex string (SHA-256 output):
```bash
# Correct format (64 hex chars):
"a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"

# Incorrect formats:
"sha256:a1b2..."  # Remove prefix
"A1B2C3..."       # Use lowercase
"abc123"          # Must be exactly 64 chars
```

### C2PA Validation Failed in Playback

**Symptom:** Key request denied with `Error::C2paValidationFailed`

**Check:**
1. Manifest signature is valid
2. Content hash matches embedded hash in manifest
3. Creator is in allowlist (if configured)
4. AI disclosure policy is satisfied

**Debug:** Check analytics events:
```bash
nats sub "media.metrics.c2pa_*"
```

## References

- [C2PA Specification 2.2](https://c2pa.org/specifications/)
- [C2PA ISOBMFF Binding](https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html)
- [c2pa-rs SDK](https://github.com/contentauth/c2pa-rs)
- [OpenTDF Specification](https://github.com/opentdf/spec)
- [arkavo-rs Repository](https://github.com/arkavo-org/arkavo-rs)
- [c2pa-opentdf-rs Repository](https://github.com/arkavo-org/c2pa-opentdf-rs)
