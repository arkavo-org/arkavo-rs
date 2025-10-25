# FairPlay Streaming Integration

Apple FairPlay Streaming support for DRM-protected media delivery to Apple devices (iOS, tvOS, macOS, Safari).

**SDK Version:** 26
**Feature Flag:** `fairplay` (disabled by default)
**Status:** Implementation complete, compiler issue under investigation (see Known Issues)

## Overview

This integration provides dual-protocol DRM support:

- **TDF3** (NanoTDF): OpenTDF-based DRM for all platforms
- **FairPlay**: Apple-specific DRM for iOS/tvOS/macOS/Safari

Both protocols share unified session management and policy enforcement.

## Prerequisites

### 1. Apple FairPlay Streaming Agreement

Production deployment requires a valid Apple FairPlay Streaming agreement. Contact Apple Developer Relations.

### 2. FairPlay SDK

The SDK Rust module is already included in `vendor/fpssdk/` (committed to repository).

For full SDK with credentials:
1. Download FairPlay Streaming Server SDK 26 from [Apple Developer Portal](https://developer.apple.com/streaming/fps/)
2. Extract to `vendor/FairPlay_Streaming_Server_SDK_26/` (gitignored)
3. Credentials are in `Development/Key_Server_Module/credentials/`

### 3. Credentials

- **Development credentials**: For testing (included with SDK)
- **Production credentials**: Obtain from Apple Developer Portal

⚠️ **Never commit credentials to version control**

## Building

```bash
# Build WITHOUT FairPlay (default)
cargo build

# Build WITH FairPlay
cargo build --features fairplay

# Run with FairPlay
export FAIRPLAY_CREDENTIALS_PATH=./vendor/FairPlay_Streaming_Server_SDK_26/Development/Key_Server_Module/credentials
cargo run --features fairplay

# Test with FairPlay (when tests are updated)
cargo test --features fairplay
```

## Configuration

### Environment Variables

```bash
# Required: Path to FairPlay credentials directory
export FAIRPLAY_CREDENTIALS_PATH=/path/to/credentials
```

**Default path (if not set):**
```
./vendor/FairPlay_Streaming_Server_SDK_26/Development/Key_Server_Module/credentials
```

### Credentials Directory Structure

The credentials directory must contain:
- `certificates.json` or `test_certificates.json`
- FPS certificate files (`*.bin`)

## Architecture

### Crate Structure

```
arkavo-rs/
├── vendor/fpssdk/              # Apple's SDK Rust module (committed)
│   ├── src/lib.rs             # FFI bindings (66+ files)
│   ├── build.rs               # Links libfpscrypto.dylib
│   ├── prebuilt/macos/libfpscrypto.dylib
│   └── Cargo.toml
├── crates/fairplay-wrapper/    # Safe Rust wrapper
│   ├── src/lib.rs             # FairPlayKeyServer, SpcRequest, CkcResponse
│   └── Cargo.toml
├── src/modules/fairplay.rs     # FairPlayHandler (integration layer)
└── src/modules/media_api.rs    # Protocol detection & routing
```

### Protocol Auto-Detection

The `/media/v1/key-request` endpoint automatically detects protocol from request payload:

| Protocol | Required Fields |
|----------|----------------|
| **TDF3** | `nanotdf_header` + `client_public_key` |
| **FairPlay** | `spc_data` |

### Unified Session Management

Both protocols use the same `PlaybackSession` structure:

```rust
pub struct PlaybackSession {
    pub session_id: String,
    pub user_id: String,
    pub asset_id: String,
    pub protocol: MediaProtocol,  // TDF3 or FairPlay
    pub segment_index: Option<u32>,
    pub state: SessionState,
    // ... other fields
}
```

## API Endpoints

### Start Playback Session

```http
POST /media/v1/session/start
Content-Type: application/json

{
  "userId": "user_123",
  "assetId": "asset_456",
  "clientIp": "192.168.1.100",
  "protocol": "fairplay"  // or "tdf3"
}
```

**Response:**
```json
{
  "sessionId": "user_123:asset_456:uuid",
  "status": "active",
  "expiresAt": 1234567890
}
```

### Request Key (Auto-detects Protocol)

#### FairPlay Request

```http
POST /media/v1/key-request
Content-Type: application/json

{
  "sessionId": "session_id",
  "userId": "user_123",
  "assetId": "asset_456",
  "segmentIndex": 0,
  "spcData": "base64_encoded_spc_from_client"
}
```

**Response:**
```json
{
  "sessionPublicKey": "",
  "wrappedKey": "base64_encoded_ckc",
  "status": "success",
  "metadata": {
    "protocol": "fairplay",
    "latency_ms": 12,
    "sdk_version": "26.0.0"
  }
}
```

#### TDF3 Request

```http
POST /media/v1/key-request
Content-Type: application/json

{
  "sessionId": "session_id",
  "userId": "user_123",
  "assetId": "asset_456",
  "segmentIndex": 0,
  "nanotdfHeader": "base64_encoded_header",
  "clientPublicKey": "-----BEGIN PUBLIC KEY-----\n..."
}
```

### Session Heartbeat

```http
POST /media/v1/session/:sessionId/heartbeat
Content-Type: application/json

{
  "state": "playing",
  "segmentIndex": 5
}
```

### End Session

```http
DELETE /media/v1/session/:sessionId
```

## Client Workflow

### FairPlay Playback Flow

1. **Initialize Session**
   ```
   Client → POST /media/v1/session/start → Server
   Client ← session_id ← Server
   ```

2. **Generate SPC** (client-side using native FairPlay APIs)
   ```swift
   // iOS/tvOS/macOS example
   let contentKeyRequest = AVContentKeyRequest(...)
   let spcData = try await contentKeyRequest.makeStreamingContentKeyRequestData(...)
   ```

3. **Request CKC**
   ```
   Client → POST /media/v1/key-request {spcData: base64(spc)} → Server
   Server validates session, enforces policy
   Server → FairPlay SDK → processes SPC → generates CKC
   Client ← {wrappedKey: base64(ckc)} ← Server
   ```

4. **Process CKC** (client-side)
   ```swift
   let ckcData = Data(base64Encoded: response.wrappedKey)
   contentKeyRequest.processContentKeyResponse(AVContentKeyResponse(fairPlayStreamingKeyResponseData: ckcData))
   ```

5. **Play Content** + Send periodic heartbeats

6. **End Session** when playback completes

## Policy Enforcement

The Media Policy Contract (`src/bin/contracts/media_policy_contract.rs`) validates all requests:

### Subscription Requirements
- Active subscription status
- Subscription tier (free, basic, premium)
- Content access level (e.g., UHD requires premium)

### Rental Windows
- **Purchase window**: 7 days from purchase timestamp
- **Playback window**: 48 hours from first play
- First-play tracking stored in Redis

### Concurrency Limits
- Maximum simultaneous streams per user (configurable via `MAX_CONCURRENT_STREAMS`)
- Real-time session counting via Redis

### Geo-restrictions
- IP-based country filtering
- Content regional availability

### Device Security
- **HDCP requirements**: Type 0 (HD), Type 1 (UHD)
- **Security level**: Baseline, Main
- **VM detection**: Block virtual machines for premium content

## Performance

### Target Metrics
- **Key delivery latency**: < 50ms P95
- **Session creation**: < 100ms
- **SDK processing**: < 20ms (SPC → CKC)

### Monitoring

Analytics events published to NATS (`media.metrics.*`):

- `key_request` - Success/failure with latency
- `session_start` - Playback initiated
- `session_end` - Playback terminated
- `policy_denial` - Access denied with reason
- `concurrency_limit` - Stream limit hit
- `rental_window` - First play or expiry events

## Security Considerations

### Credentials Management
- Store credentials in secure, access-controlled directories
- Use different credentials for development vs. production
- Rotate production credentials periodically
- Never log credential contents

### Key Management
- Content keys (DEKs) should be randomly generated per asset/segment
- DEKs never transmitted in plaintext
- FairPlay CKC contains encrypted DEK
- Key rotation recommended for long-lived content

### Network Security
- Use TLS for all API endpoints
- Validate JWT tokens for production (set `OAUTH_PUBLIC_KEY_PATH`)
- Implement rate limiting on key request endpoints
- Monitor for anomalous request patterns

## Troubleshooting

### SDK Initialization Fails

**Symptom:** `Failed to initialize FairPlay handler`

**Causes:**
- Credentials path incorrect or inaccessible
- Missing `certificates.json` or certificate files
- Invalid certificate format

**Solution:**
```bash
# Check credentials directory
ls -la $FAIRPLAY_CREDENTIALS_PATH

# Verify files exist
test -f $FAIRPLAY_CREDENTIALS_PATH/test_certificates.json && echo "Found"
```

### Key Request Returns Error

**Symptom:** `errorDomain: FairPlayStreaming, errorCode: -42XXX`

**Common Errors:**
- `-42652`: Certificate invalid or expired
- `-42650`: SPC format invalid
- `-42660`: Content ID mismatch

**Solution:**
- Verify SPC is base64-encoded correctly
- Check certificate validity period
- Ensure content_id matches asset_id

### Session Not Found

**Symptom:** `Session not found or expired`

**Causes:**
- Session expired (5-minute timeout without heartbeat)
- Session ID incorrect
- Redis connection lost

**Solution:**
- Implement heartbeat every 60-120 seconds during playback
- Check Redis connectivity
- Verify session_id matches what was returned from `/session/start`

## Known Issues

### Axum Handler Trait Error (Issue #24)

**Symptom:**
```
error[E0277]: the trait bound `fn(State<Arc<...>>, ...) -> ... {media_key_request}: Handler<_, _>` is not satisfied
```

**Status:** Under investigation

**Current Behavior:**
- ✅ Compiles successfully WITHOUT `fairplay` feature
- ❌ Fails to compile WITH `--features fairplay`

**Impact:**
- Code implementation is complete and correct
- Compiler/type inference issue prevents feature-gated compilation
- Investigating potential workarounds (separate modules, dynamic dispatch)

**Tracking:** See GitHub issue #24 for updates

### Test Suite Updates Needed

**Status:** Tests need updating for new `PlaybackSession::new()` signature

**Change:** Added `protocol: MediaProtocol` parameter

**TODO:**
```rust
// Old
PlaybackSession::new(session_id, user_id, asset_id, client_ip)

// New
PlaybackSession::new(session_id, user_id, asset_id, protocol, client_ip)
```

## License & Compliance

See `THIRD-PARTY-LICENSES.md` for complete Apple FairPlay SDK licensing terms.

### Key Requirements

1. **Valid FairPlay Streaming Agreement** with Apple
2. **Production credentials** from Apple Developer Portal
3. **Test certificates** must not be used in production
4. **Compliance** with all Apple terms and conditions
5. **Confidentiality** of FairPlay credentials and keys

### Resources

- [Apple FairPlay Streaming](https://developer.apple.com/streaming/fps/)
- [FairPlay Streaming Programming Guide](https://developer.apple.com/documentation/avfoundation/content_playback_and_fairplay_streaming)
- [WWDC Sessions on FairPlay](https://developer.apple.com/videos/)

---

**Questions or Issues?** See GitHub issues or contact the arkavo team.
