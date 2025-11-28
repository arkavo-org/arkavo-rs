# CBOR Protocol Specification

## Overview

This document specifies the CBOR-based message protocol for Arkavo WebSocket communication. CBOR (Concise Binary Object Representation, RFC 8949) provides a compact, schema-flexible binary encoding.

## Message Envelope

All CBOR messages use message type `0x08`:

```
+--------+------------------+
| 0x08   | CBOR Payload     |
| 1 byte | variable         |
+--------+------------------+
```

The CBOR payload is a map with a required `type` field:

```cddl
message = {
  type: tstr,          ; Message type identifier
  * tstr => any        ; Type-specific fields
}
```

## Message Types

### Key Exchange

#### `key_exchange` (Client → Server)

Initiates ECDH key agreement.

```cddl
key_exchange_request = {
  type: "key_exchange",
  public_key: bstr,    ; SEC1-encoded P-256 public key (33 or 65 bytes)
}
```

#### `key_exchange_response` (Server → Client)

```cddl
key_exchange_response = {
  type: "key_exchange_response",
  kas_public_key: bstr,      ; SEC1-encoded KAS public key
  session_salt: bstr,        ; Random salt for session key derivation
}
```

### Chain-Validated Rewrap

#### `chain_rewrap` (Client → Server)

Requests DEK rewrap with chain validation.

```cddl
chain_validation = {
  session_id: bstr,          ; 32-byte chain session ID
  header_hash: bstr,         ; 32-byte SHA256 of header bytes (DPoP binding)
  signature: bstr,           ; ECDSA signature (64 or 96 bytes)
  nonce: uint,               ; Replay prevention nonce
  ? algorithm: tstr,         ; "ES256" (default), "ES384"
}

chain_rewrap_request = {
  type: "chain_rewrap",
  header: bstr,              ; NanoTDF header bytes
  chain: chain_validation,
}
```

#### `rewrapped_key` (Server → Client)

```cddl
rewrapped_key_response = {
  type: "rewrapped_key",
  ephemeral_key: bstr,       ; TDF ephemeral public key (33 bytes)
  nonce: bstr,               ; AES-GCM nonce (12 bytes)
  wrapped_dek: bstr,         ; Encrypted DEK (32 bytes + 16 byte tag)
}
```

### Media Key Request

#### `media_key_request` (Client → Server)

Optimized key request for streaming media.

```cddl
media_key_request = {
  type: "media_key_request",
  session_id: tstr,          ; Playback session ID
  user_id: tstr,             ; User identifier
  asset_id: tstr,            ; Asset identifier
  ? segment_index: uint,     ; Optional segment number

  ; TDF3 fields (for NanoTDF)
  ? client_public_key: tstr, ; PEM-encoded public key
  ? nanotdf_header: bstr,    ; NanoTDF header bytes

  ; FairPlay fields
  ? spc_data: bstr,          ; Server Playback Context

  ; Chain validation
  chain: chain_validation,
}
```

#### `media_key_response` (Server → Client)

```cddl
media_key_response = {
  type: "media_key_response",
  session_public_key: tstr,  ; PEM-encoded session public key
  wrapped_key: bstr,         ; Nonce + encrypted DEK
  status: tstr,              ; "success" or "denied"
  ? metadata: any,           ; Optional metadata
}
```

### Events

#### `user_event` (Client → Server)

```cddl
entity_type = "stream_profile" / "account_profile" / "server"
attribute_type = "time" / "location"

user_event = {
  type: "user_event",
  source_type: entity_type,
  target_type: entity_type,
  source_id: bstr,           ; 32-byte public ID
  target_id: bstr,           ; 32-byte public ID
  ? attribute_types: [* attribute_type],
  ? entity_type: entity_type,
}
```

#### `cache_event` (Client → Server)

```cddl
cache_event = {
  type: "cache_event",
  target_id: bstr,           ; 32-byte public ID
  payload: bstr,             ; Binary payload (TDF)
  ? ttl: uint,               ; Time-to-live in seconds
  ? one_time_access: bool,   ; One-time access flag
}
```

#### `route_event` (Client → Server)

```cddl
route_event = {
  type: "route_event",
  target_type: entity_type,
  target_id: bstr,           ; 32-byte public ID
  source_type: entity_type,
  source_id: bstr,           ; 32-byte public ID
  payload: bstr,             ; Binary payload
  ? attribute_type: attribute_type,
  ? entity_type: entity_type,
}
```

### Errors

#### `error` (Server → Client)

```cddl
error_response = {
  type: "error",
  code: tstr,                ; Error code (e.g., "policy_denied")
  message: tstr,             ; Human-readable message
  ? details: any,            ; Optional structured details
}
```

## Error Codes

| Code | Description |
|------|-------------|
| `invalid_format` | Malformed CBOR or missing required fields |
| `authentication_failed` | Invalid signature or nonce replay |
| `policy_denied` | Session not found, expired, or revoked |
| `internal_error` | Server-side error (chain, cache, crypto) |
| `not_implemented` | Requested feature not available |

## Encoding Examples

### Chain Rewrap Request (Diagnostic Notation)

```cbor-diag
{
  "type": "chain_rewrap",
  "header": h'18010001...',  ; NanoTDF header
  "chain": {
    "session_id": h'abcd1234...',  ; 32 bytes
    "header_hash": h'e3b0c442...',  ; SHA256(header), 32 bytes (DPoP binding)
    "signature": h'3045022100...',  ; DER or raw r||s
    "nonce": 12345,
    "algorithm": "ES256"
  }
}
```

### Hex Encoding

```hex
A3                                      # map(3)
   64                                   # text(4)
      74797065                          # "type"
   6C                                   # text(12)
      636861696E5F726577726170          # "chain_rewrap"
   66                                   # text(6)
      686561646572                      # "header"
   58 80                                # bytes(128)
      18010001...                       # NanoTDF header bytes
   65                                   # text(5)
      636861696E                        # "chain"
   A4                                   # map(4)
      6A                                # text(10)
         73657373696F6E5F6964           # "session_id"
      58 20                             # bytes(32)
         abcd1234...                    # session ID
      69                                # text(9)
         7369676E6174757265             # "signature"
      58 40                             # bytes(64)
         3045022100...                  # signature
      65                                # text(5)
         6E6F6E6365                     # "nonce"
      19 3039                           # unsigned(12345)
      69                                # text(9)
         616C676F726974686D             # "algorithm"
      65                                # text(5)
         455332353636                   # "ES256"
```

## Implementation Notes

### Rust (ciborium)

```rust
use ciborium::{de, ser};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Message {
    ChainRewrap {
        header: Vec<u8>,
        chain: ChainValidation,
    },
    RewrappedKey {
        ephemeral_key: Vec<u8>,
        nonce: Vec<u8>,
        wrapped_dek: Vec<u8>,
    },
    Error {
        code: String,
        message: String,
    },
}

#[derive(Serialize, Deserialize)]
struct ChainValidation {
    session_id: Vec<u8>,
    header_hash: Vec<u8>,  // SHA256 of header bytes (DPoP binding)
    signature: Vec<u8>,
    nonce: u64,
    #[serde(default = "default_algorithm")]
    algorithm: String,
}

fn default_algorithm() -> String {
    "ES256".to_string()
}

// Encoding
let msg = Message::ChainRewrap { ... };
let mut bytes = Vec::new();
bytes.push(0x08);  // CBOR message type
ser::into_writer(&msg, &mut bytes)?;

// Decoding
if payload[0] == 0x08 {
    let msg: Message = de::from_reader(&payload[1..])?;
}
```

### Swift (SwiftCBOR)

```swift
import SwiftCBOR

struct ChainRewrapRequest: CBOREncodable {
    let type = "chain_rewrap"
    let header: Data
    let chain: ChainValidation

    func encode() -> CBOR {
        return .map([
            "type": .utf8String(type),
            "header": .byteString(Array(header)),
            "chain": chain.encode()
        ])
    }
}

struct ChainValidation: CBOREncodable {
    let sessionId: Data
    let headerHash: Data  // SHA256 of header bytes (DPoP binding)
    let signature: Data
    let nonce: UInt64
    let algorithm: String

    func encode() -> CBOR {
        return .map([
            "session_id": .byteString(Array(sessionId)),
            "header_hash": .byteString(Array(headerHash)),
            "signature": .byteString(Array(signature)),
            "nonce": .unsignedInt(nonce),
            "algorithm": .utf8String(algorithm)
        ])
    }
}
```

### TypeScript (cbor-x)

```typescript
import { encode, decode } from 'cbor-x';

interface ChainRewrapRequest {
  type: 'chain_rewrap';
  header: Uint8Array;
  chain: {
    session_id: Uint8Array;
    header_hash: Uint8Array;  // SHA256 of header bytes (DPoP binding)
    signature: Uint8Array;
    nonce: bigint;
    algorithm?: string;
  };
}

// Encoding
const headerHash = new Uint8Array(
  await crypto.subtle.digest('SHA-256', nanotdfHeader)
);
const request: ChainRewrapRequest = {
  type: 'chain_rewrap',
  header: nanotdfHeader,
  chain: {
    session_id: sessionId,
    header_hash: headerHash,  // DPoP binding
    signature: signature,
    nonce: BigInt(nextNonce()),
    algorithm: 'ES256',
  },
};

const cborPayload = encode(request);
const message = new Uint8Array([0x08, ...cborPayload]);
websocket.send(message);

// Decoding
const messageType = response[0];
if (messageType === 0x08) {
  const decoded = decode(response.slice(1));
  // Handle response
}
```

## Versioning

The CBOR protocol is designed for forward compatibility:

1. **Unknown fields are ignored**: Parsers skip unrecognized map keys
2. **Optional fields**: Use `?` prefix in CDDL for optional fields
3. **Type field required**: All messages must have a `type` field
4. **New types additive**: New message types can be added without version bump

For breaking changes, introduce a new message type rather than modifying existing ones.

## Security Considerations

1. **Size limits**: Enforce maximum message sizes to prevent DoS
2. **Depth limits**: Limit CBOR nesting depth (recommended: 16)
3. **String validation**: Validate UTF-8 strings
4. **Binary validation**: Validate expected lengths for cryptographic material
5. **Replay prevention**: Nonce must be monotonically increasing per session
6. **DPoP Header Binding**: The `header_hash` field in `chain_validation` MUST be the SHA256 of the actual header bytes. The server verifies this matches before signature validation. This prevents header substitution attacks where an attacker might try to reuse a valid signature with a different header. Clients MUST:
   - Compute `header_hash = SHA256(header_bytes)` locally
   - Include `header_hash` in the signature: `SIGN(SHA256(session_id || header_hash || nonce))`
   - Send both `header` and `header_hash` in the request
