# Terminal Link - NanoTDF Authentication Tokens

## Overview

**Terminal Link** replaces traditional JWT Bearer tokens with NanoTDF-wrapped authentication tokens for:
- **Policy binding** - Cryptographic policy enforcement
- **Provenance tracking** - Verifiable token origin
- **Optional confidentiality** - Encrypted payload
- **DPoP binding** - Proof-of-possession prevents token theft

## Wire Format

```
Authorization: NTDF <Z85-encoded-nanotdf>
```

**Example:**
```
Authorization: NTDF rGN.bK+V#7c@{h...}
```

## Token Structure

### NanoTDF Container

Terminal Link uses the standard NanoTDF format with a custom payload schema:

```
┌─────────────────────────────────────────────────┐
│ Magic Number (3 bytes): "L1N"                   │
│ Version (1 byte): 0x13                          │
├─────────────────────────────────────────────────┤
│ KAS Resource Locator                            │
│   - Protocol (1 byte): HTTPS=0x01, WSS=0x03     │
│   - Length (1 byte)                             │
│   - URL (variable)                              │
├─────────────────────────────────────────────────┤
│ ECC Mode (1 byte)                               │
│   - Use ECDSA Binding: false                    │
│   - Curve: SECP256R1 (P-256)                    │
├─────────────────────────────────────────────────┤
│ Payload Config (1 byte)                         │
│   - Cipher: AES-256-GCM                         │
│   - Has Signature: true (Ed25519)               │
├─────────────────────────────────────────────────┤
│ Policy                                          │
│   - Type (1 byte): Remote=0x00 or Embedded=0x01 │
│   - Policy ID (16 bytes): UUID or SHA-256 hash  │
│   - Binding (8 bytes): GMAC                     │
├─────────────────────────────────────────────────┤
│ Ephemeral Public Key (33 bytes)                 │
│   - Compressed P-256 point                      │
├─────────────────────────────────────────────────┤
│ Encrypted Payload                               │
│   - Length (3 bytes)                            │
│   - Ciphertext (variable)                       │
│   - Auth Tag (16 bytes)                         │
├─────────────────────────────────────────────────┤
│ Signature (64 bytes)                            │
│   - Ed25519 over (Header||Policy||Payload)      │
└─────────────────────────────────────────────────┘
```

### Payload Schema

The decrypted payload contains authentication claims:

```rust
struct TerminalLinkPayload {
    sub_id: [u8; 16],          // Subject UUID
    flags: u64,                // Capability bitfield
    scopes: Vec<String>,       // OAuth scopes
    attrs: Vec<(u8, u32)>,     // Custom attributes
    dpop_jti: Option<[u8; 16]>, // DPoP binding
    iat: i64,                  // Issued at (Unix timestamp)
    exp: i64,                  // Expiration (Unix timestamp)
    aud: String,               // Audience (target service)
    session_id: Option<[u8; 16]>, // Session tracking
    device_id: Option<String>, // Device identifier
    did: Option<String>,       // Decentralized Identifier
}
```

### Capability Flags

```rust
const PROFILE: u64          = 1 << 0;  // Profile access
const OPENID: u64           = 1 << 1;  // OpenID Connect
const EMAIL: u64            = 1 << 2;  // Email access
const OFFLINE_ACCESS: u64   = 1 << 3;  // Refresh token
const DEVICE_ATTESTED: u64  = 1 << 4;  // Device attestation present
const BIOMETRIC_AUTH: u64   = 1 << 5;  // Biometric used
const WEBAUTHN: u64         = 1 << 6;  // WebAuthn/Passkey
const PLATFORM_SECURE: u64  = 1 << 7;  // Not jailbroken/rooted
```

### Attribute Types

```rust
enum AttributeType {
    Age = 0,               // Age for content rating
    SubscriptionTier = 1,  // free=0, basic=1, premium=2
    SecurityLevel = 2,     // baseline=0, main=1, high=2
    PlatformCode = 3,      // iOS=0, Android=1, macOS=2, etc.
}
```

## Size Characteristics

**Minimum size:** ~380 bytes raw (~500 Z85 characters)
**Typical size:** ~450-550 bytes raw (~600-730 Z85 characters)

**Breakdown:**
- Header + Policy: ~60-100 bytes
- Ephemeral key: 33 bytes
- Encrypted payload: 150-300 bytes (depends on scopes/attrs)
- Auth tag: 16 bytes
- Signature: 64 bytes
- Z85 overhead: ~25% increase

**Note:** Not universally smaller than JWT. The value proposition is **policy binding + provenance + optional confidentiality**, not byte size.

## DPoP Binding

Terminal Link integrates with DPoP (RFC 9449) to prevent token theft:

### Flow

1. **Client generates DPoP proof**:
   ```
   DPoP: eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Aran...
   ```

2. **Client includes DPoP JTI in Terminal Link payload**:
   ```rust
   payload.dpop_jti = Some(dpop_proof.jti);
   ```

3. **Server validates**:
   ```
   a. Decode and unwrap Terminal Link NTDF
   b. Validate DPoP proof (method, URI, timestamp, signature)
   c. Compute ath = SHA256(NTDFZ85_raw_bytes)
   d. Verify DPoP.ath == ath
   e. Verify Terminal Link.dpop_jti == DPoP.jti
   ```

### Critical: `ath` Computation

The `ath` (access token hash) in the DPoP proof **MUST** be computed over the **raw Z85-encoded bytes** of the Terminal Link token, not the decoded NanoTDF:

```rust
// CORRECT
let z85_token = "rGN.bK+V#7c@{h...";
let ath = base64url(SHA256(z85_token.as_bytes()));

// WRONG
let nanotdf_bytes = z85::decode(&z85_token)?;
let ath = base64url(SHA256(&nanotdf_bytes)); // ❌
```

## Token Lifecycle

### 1. Generation (authnz-rs)

```rust
// After WebAuthn authentication
let payload = TerminalLinkPayload {
    sub_id: user_uuid,
    flags: WEBAUTHN | PLATFORM_SECURE,
    scopes: vec!["openid", "profile"],
    attrs: vec![(Age, 25), (SubscriptionTier, 2)],
    dpop_jti: Some(dpop_jti),
    iat: Utc::now().timestamp(),
    exp: Utc::now().timestamp() + 3600,
    aud: "https://kas.example.com",
    session_id: Some(session_uuid),
    device_id: Some("iPhone14,2"),
    did: Some("did:key:z6Mk..."),
};

let nanotdf = create_terminal_link(payload, kas_url, policy_id)?;
let z85_token = z85::encode(&nanotdf);

// Return to client
response.headers.insert("Authorization", format!("NTDF {}", z85_token));
```

### 2. Validation (arkavo-rs)

```rust
// Extract from Authorization header
let auth_header = headers.get("Authorization")?;
let z85_token = auth_header.strip_prefix("NTDF ")?;

// Decode Z85
let nanotdf_bytes = z85::decode(z85_token)?;

// Parse NanoTDF header
let mut parser = BinaryParser::new(&nanotdf_bytes);
let header = parser.parse_header()?;

// Perform ECDH and decrypt payload
let shared_secret = perform_ecdh(&header.ephemeral_key, &kas_private_key)?;
let decrypted = decrypt_payload(&header, &parser, &shared_secret)?;

// Deserialize payload
let payload = TerminalLinkPayload::from_bytes(&decrypted)?;

// Validate claims
if payload.exp < Utc::now().timestamp() {
    return Err("Token expired");
}
if payload.aud != expected_audience {
    return Err("Invalid audience");
}

// If DPoP enabled, validate binding
if let Some(dpop_jti) = payload.dpop_jti {
    validate_dpop_binding(dpop_header, z85_token, &dpop_jti)?;
}
```

### 3. DPoP Validation

```rust
fn validate_dpop_binding(
    dpop_header: &str,
    z85_token: &str,
    expected_jti: &[u8; 16],
) -> Result<(), Error> {
    // Validate DPoP proof per RFC 9449
    let dpop = validate_dpop_proof(dpop_header, "POST", "/kas/v2/rewrap", None, 60)?;

    match dpop {
        DPoPValidationResult::Valid { jti, .. } => {
            // Verify JTI match
            if jti.as_bytes() != expected_jti {
                return Err("DPoP JTI mismatch");
            }

            // Verify ath (access token hash)
            let expected_ath = base64url(SHA256(z85_token.as_bytes()));
            if dpop.ath != Some(expected_ath) {
                return Err("DPoP ath mismatch");
            }

            Ok(())
        }
        _ => Err("DPoP validation failed"),
    }
}
```

## Security Considerations

### 1. Token Confidentiality

The payload is encrypted with AES-256-GCM. Even if intercepted, the attacker cannot read claims without:
- Performing ECDH with the KAS private key
- Having the correct policy binding

### 2. Token Binding

**Without DPoP:** Token can be stolen and replayed (like JWT).
**With DPoP:** Token is cryptographically bound to the client's ephemeral key pair.

### 3. Policy Enforcement

The GMAC policy binding ensures:
- Token cannot be used with a different policy
- Policy changes invalidate existing tokens
- KAS can enforce policy at unwrap time

### 4. Signature Verification

Ed25519 signature over the entire token ensures:
- Token integrity
- Non-repudiation
- Origin authentication

### 5. Lifetime Management

- `iat` prevents premature use
- `exp` enforces expiration
- `session_id` enables server-side revocation via Redis

## Migration from JWT

### Old (JWT Bearer)

```
Authorization: Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0...
```

**Vulnerabilities:**
- ❌ No proof-of-possession (easily stolen)
- ❌ No policy binding
- ❌ No confidentiality
- ❌ Signature only validates issuer, not binding

### New (Terminal Link)

```
Authorization: NTDF rGN.bK+V#7c@{h...}
DPoP: eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Aran...
```

**Improvements:**
- ✅ DPoP proof-of-possession prevents theft
- ✅ Policy binding enforced at KAS
- ✅ Optional payload confidentiality
- ✅ Provenance tracking with Ed25519 signature
- ✅ Server-side revocation via session_id

## Implementation Status

### arkavo-rs (KAS/DRM Server)

- ✅ Terminal Link payload schema (`terminal_link_ntdf.rs`)
- ✅ Payload serialization/deserialization
- ✅ Z85 dependency added
- ⏳ NanoTDF unwrapping integration
- ⏳ DPoP binding validation with NTDFZ85 hash
- ⏳ Authorization header parsing

### authnz-rs (Authentication Server)

- ⏳ Terminal Link generation after WebAuthn
- ⏳ NanoTDF creation with policy binding
- ⏳ Ed25519 signing
- ⏳ DPoP JTI injection

### Swift App (Client)

- ⏳ Receive Terminal Link from authnz-rs
- ⏳ Store Terminal Link securely (Keychain)
- ⏳ Send `Authorization: NTDF <token>` header
- ⏳ Generate DPoP proofs with ath binding

## References

- [OpenTDF NanoTDF Specification](https://github.com/opentdf/spec/blob/main/schema/NanoTDF.md)
- [RFC 9449: DPoP](https://datatracker.ietf.org/doc/html/rfc9449)
- [Z85 Encoding (ZeroMQ)](https://rfc.zeromq.org/spec/32/)
- [Ed25519 Signatures](https://ed25519.cr.yp.to/)
