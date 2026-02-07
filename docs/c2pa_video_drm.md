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

**Request:**
```json
{
  "content_hash": "a1b2c3d4...hex64chars", // SHA-256 hash of video
  "exclusion_ranges": [
    {
      "start": 100,
      "end": 500,
      "box_type": "uuid" // Optional ISOBMFF box type
    }
  ],
  "container_format": "mp4", // or "mov", "avi"
  "metadata": {
    "title": "My Video",
    "creator": "user@example.com",
    "description": "Optional description",
    "timestamp": "2025-10-26T00:00:00Z", // ISO 8601
    "ai_generated": false,
    "software": "Arkavo Client v1.0"
  }
}
```

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
  "content_hash": "a1b2c3d4...hex64chars"
}
```

**Response:**
```json
{
  "valid": true,
  "errors": [],
  "creator": "user@example.com",
  "ai_generated": false,
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

## Configuration

### Environment Variables

```bash
# C2PA Signing Configuration
export C2PA_SIGNING_KEY_PATH=/path/to/c2pa_private_key.pem
export C2PA_SIGNING_CERT_PATH=/path/to/c2pa_cert.pem
export C2PA_REQUIRE_VALIDATION=true  # Enforce C2PA in media policy
export C2PA_ALLOWED_CREATORS=creator1@example.com,creator2@example.com

# Existing Media DRM Configuration
export MAX_CONCURRENT_STREAMS=5
export ENABLE_MEDIA_ANALYTICS=true
export MEDIA_METRICS_SUBJECT=media.metrics
```

### Generating C2PA Signing Certificates

C2PA uses ES256 (ECDSA with SHA-256) for signing. **Important:** c2pa-rs rejects self-signed certificates. You must generate a CA + end-entity certificate chain with the `emailProtection` Extended Key Usage.

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

- C2PA signing keys must be protected with strict file permissions
- Consider using Hardware Security Modules (HSM) or KMS for production
- Rotate keys periodically
- Never commit private keys to version control

### Creator Allowlist

```bash
# Restrict signing to trusted creators
export C2PA_ALLOWED_CREATORS=verified1@example.com,verified2@example.com
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

**Base URL:** `https://100.arkavo.net` (production) or `http://localhost:8443` (local)

**1. Sign a manifest:**
```bash
curl -s -X POST https://100.arkavo.net/c2pa/v1/sign \
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
MANIFEST=$(curl -s -X POST https://100.arkavo.net/c2pa/v1/sign \
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
curl -s -X POST https://100.arkavo.net/c2pa/v1/validate \
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
| `signingCredential.untrusted` | CA not in C2PA trust store | Use recognized CA for production |
| `assertion.dataHash.mismatch` | Asset hash doesn't match | Expected for server-side validation (no asset present) |

**Note on `valid` field:** Server-side validation verifies the COSE signature chain and assertion integrity. The `assertion.dataHash.mismatch` and `signingCredential.untrusted` statuses are expected when validating without the actual asset or with a self-issued CA. Clients should perform full asset-hash binding verification locally after embedding the JUMBF.

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
- **Live integration:** `curl` against `https://100.arkavo.net/c2pa/v1/sign` and `/validate`

## Manifest Format

The `/c2pa/v1/sign` endpoint returns a **base64-encoded JUMBF** (JPEG Universal Metadata Box Format) manifest. This is the standard C2PA binary format, not JSON.

**What's inside the JUMBF:**
- COSE-signed claim with ES256 signature
- Assertion store: `c2pa.created`, `c2pa.claim.creator`, `dc.title`, `c2pa.ai_generated`, `stds.exif`, `c2pa.hash.data`, `org.arkavo.c2pa.content_hash`
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
- **Trust:** Self-issued CA produces `signingCredential.untrusted` — use a C2PA-recognized CA for production

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

**Symptom:** Server logs: `C2PA signing disabled: C2PA_SIGNING_KEY_PATH not set`

**Solution:**
```bash
export C2PA_SIGNING_KEY_PATH=/path/to/c2pa_private_key.pem
export C2PA_SIGNING_CERT_PATH=/path/to/c2pa_cert.pem
```

### Creator Not Authorized

**Symptom:** API returns: `{"error": "Creator not authorized", "status": "denied"}`

**Solution:**
- Add creator to allowlist: `export C2PA_ALLOWED_CREATORS=creator@example.com`
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
