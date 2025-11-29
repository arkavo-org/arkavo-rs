# Chain-Driven KAS Migration Guide

## Overview

This document describes the migration from the standalone Policy Decision Point (PDP) architecture to the Chain-Driven Policy Enforcement Point (PEP) architecture for the Arkavo KAS (Key Access Service).

### Architectural Change

**Before (PDP):** KAS evaluates ABAC policies locally using embedded contracts (geofence, content rating, simple ABAC).

**After (PEP):** KAS queries the `arkavo-node` blockchain for `SessionGrant` data and verifies Proof-of-Possession (PoP) signatures before releasing keys. Policy decisions are made on-chain.

## Protocol Changes

### HTTP REST API (`/kas/v2/rewrap`)

The `UnsignedRewrapRequest` payload (inside the JWT `requestBody`) now includes optional chain validation fields:

```json
{
  "clientPublicKey": "-----BEGIN PUBLIC KEY-----...",
  "requests": [...],
  "chainSessionId": "abc123...def456",
  "chainSignature": "base64-encoded-ecdsa-signature",
  "chainNonce": 12345,
  "chainAlgorithm": "ES256"
}
```

#### New Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `chainSessionId` | string | Yes* | Hex-encoded 32-byte session ID from chain |
| `chainSignature` | string | Yes* | Base64-encoded ECDSA signature |
| `chainNonce` | integer | Yes* | Monotonically increasing nonce for replay prevention |
| `chainAlgorithm` | string | No | Signing algorithm: `ES256` (default), `ES384` |

*Required when chain validation is enabled on the server.

#### Signature Computation

The client must sign the following message with their session ephemeral private key:

```
message = SHA256(session_id_bytes || resource_id_bytes || nonce_le_bytes)
```

Where:
- `session_id_bytes`: 32-byte session ID (hex-decoded)
- `resource_id_bytes`: Policy/resource ID (hex-decoded)
- `nonce_le_bytes`: 8-byte little-endian nonce

### Media API (`/media/v1/key-request`)

The `MediaKeyRequest` payload now includes the same chain validation fields:

```json
{
  "sessionId": "user:asset:uuid",
  "userId": "user123",
  "assetId": "asset456",
  "segmentIndex": 0,
  "clientPublicKey": "-----BEGIN PUBLIC KEY-----...",
  "nanotdfHeader": "base64-encoded-header",
  "chainSessionId": "abc123...def456",
  "chainSignature": "base64-encoded-ecdsa-signature",
  "chainNonce": 12345,
  "chainAlgorithm": "ES256"
}
```

### WebSocket Binary Protocol

The WebSocket protocol uses a type-byte prefix for message routing:

| Type | Name | Direction | Description |
|------|------|-----------|-------------|
| `0x01` | PublicKey | C→S | Client sends ephemeral public key for ECDH |
| `0x02` | KasPublicKey | S→C | Server responds with KAS public key |
| `0x03` | Rewrap | C→S | Client requests key rewrap (NanoTDF header) |
| `0x04` | RewrappedKey | S→C | Server responds with rewrapped DEK |
| `0x05` | Nats | Bi | NATS message passthrough |
| `0x06` | Event | C→S | FlatBuffers event (UserEvent, CacheEvent, RouteEvent) |
| `0xFF` | Error | S→C | Error response |

#### Proposed: Chain-Validated Rewrap (`0x07`)

To support chain validation over WebSocket, we propose a new message type:

**Option A: Extended Binary Format**

```
Type: 0x07 (ChainRewrap)

Request Format:
+--------+----------------+----------------+-------------+-----------+
| 0x07   | NanoTDF Header | Chain Session  | Signature   | Nonce     |
| 1 byte | variable       | 32 bytes       | 64/96 bytes | 8 bytes   |
+--------+----------------+----------------+-------------+-----------+

Response Format (same as RewrappedKey):
+--------+-------------------+-------+-------------+
| 0x04   | Ephemeral Key     | Nonce | Wrapped DEK |
| 1 byte | 33 bytes          | 12    | 32 bytes    |
+--------+-------------------+-------+-------------+
```

**Option B: CBOR-Encoded Messages**

Migrate to CBOR encoding for structured data with better extensibility:

```cbor
{
  "type": "chain_rewrap",
  "header": <nanotdf_header_bytes>,
  "chain": {
    "session_id": <32_bytes>,
    "signature": <signature_bytes>,
    "nonce": <uint64>,
    "algorithm": "ES256"
  }
}
```

**Option C: FlatBuffer Extension**

Extend the existing FlatBuffer schema with a new `ChainRewrapEvent`:

```flatbuffers
// In event.fbs

table ChainValidation {
  session_id: [ubyte];      // 32 bytes chain session ID
  signature: [ubyte];       // ECDSA signature (64 or 96 bytes)
  nonce: ulong;             // Replay prevention nonce
  algorithm: string;        // "ES256", "ES384"
}

table ChainRewrapEvent {
  nanotdf_header: [ubyte];  // NanoTDF header bytes
  chain: ChainValidation;   // Chain validation data
}

// Update union
union EventData { UserEvent, CacheEvent, RouteEvent, ChainRewrapEvent }
```

### Recommendation

We recommend **Option B (CBOR)** for the following reasons:

1. **Schema Evolution**: CBOR maps allow adding fields without breaking existing parsers
2. **Compact Encoding**: CBOR is more compact than FlatBuffers for small messages
3. **Cross-Platform**: Excellent library support in Swift, Rust, TypeScript
4. **Self-Describing**: Optional schema validation without requiring schema distribution
5. **NanoTDF Alignment**: NanoTDF already uses CBOR for policy encoding

### Migration Path

#### Phase 1: HTTP/Media API (Current)
- Chain validation fields added to JSON payloads
- Backward compatible (fields are optional when chain validator not configured)
- **Status: Complete**

#### Phase 2: CBOR Message Envelope
- Add new message type `0x08` for CBOR-encoded messages
- All structured data uses CBOR encoding
- Existing binary types (`0x01`-`0x07`) remain for backward compatibility

```
CBOR Message Format:
+--------+------------------+
| 0x08   | CBOR Payload     |
| 1 byte | variable         |
+--------+------------------+
```

#### Phase 3: Chain-Validated Rewrap
- Implement `chain_rewrap` CBOR message type
- Remove local policy evaluation from WebSocket handler
- Deprecate `0x03` (Rewrap) in favor of `0x08` + CBOR

#### Phase 4: Full CBOR Migration
- Convert remaining binary types to CBOR
- Deprecate legacy binary protocol
- Update client SDKs

## Client SDK Changes

### iOS/Swift (OpenTDFKit)

```swift
// Before
let rewrapRequest = RewrapRequest(
    clientPublicKey: publicKey,
    requests: keyAccessObjects
)

// After
let rewrapRequest = RewrapRequest(
    clientPublicKey: publicKey,
    requests: keyAccessObjects,
    chainSessionId: sessionGrant.id.hexString,
    chainSignature: sign(message: computeSigningMessage()),
    chainNonce: nextNonce(),
    chainAlgorithm: "ES256"
)
```

### TypeScript/Web

```typescript
// Before
const rewrapRequest = {
  clientPublicKey: publicKeyPem,
  requests: keyAccessObjects,
};

// After
const rewrapRequest = {
  clientPublicKey: publicKeyPem,
  requests: keyAccessObjects,
  chainSessionId: sessionGrant.id,
  chainSignature: await signMessage(computeSigningMessage()),
  chainNonce: getNextNonce(),
  chainAlgorithm: 'ES256',
};
```

## Error Handling

New error responses for chain validation failures:

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| `policy_denied` | 403 | Session not found, expired, or revoked |
| `authentication_failed` | 401 | Invalid signature or nonce replay |
| `invalid_request` | 400 | Missing required chain fields |
| `internal_error` | 500 | Chain query or cache failure |

## Testing

### Integration Test Checklist

- [ ] Valid chain session with correct signature succeeds
- [ ] Expired session returns `policy_denied`
- [ ] Revoked session returns `policy_denied`
- [ ] Invalid signature returns `authentication_failed`
- [ ] Replayed nonce returns `authentication_failed`
- [ ] Missing chain fields returns `invalid_request` (when chain enabled)
- [ ] Graceful degradation when chain RPC unavailable

### Load Test Considerations

- Cache hit rate should be >95% for repeat sessions
- Chain RPC latency budget: 50ms P99
- Nonce check latency (Redis): <5ms P99

## Configuration

### Server Environment Variables

```bash
# Chain RPC endpoint (required for chain validation)
CHAIN_RPC_URL=ws://chain.arkavo.net

# Cache configuration
CHAIN_CACHE_TTL_SECONDS=6  # One Substrate block time
CHAIN_CACHE_MAX_SIZE=10000

# Redis for nonce tracking
REDIS_URL=redis://localhost:6379
```

## Rollback Plan

If issues arise during migration:

1. Set `CHAIN_RPC_URL` to empty string to disable chain validation
2. Server will fall back to accepting requests without chain fields
3. Local policy evaluation in WebSocket handler remains functional

## Timeline

| Phase | Target | Status |
|-------|--------|--------|
| Chain infrastructure | Week 1 | Complete |
| HTTP/Media API integration | Week 1 | Complete |
| CBOR message envelope | Week 2 | Planned |
| WebSocket chain rewrap | Week 3 | Planned |
| Client SDK updates | Week 4 | Planned |
| Full CBOR migration | Week 5-6 | Planned |
