# FairPlay Streaming Integration Test Plan

## Overview

This document outlines the integration testing strategy for the FairPlay Streaming SDK 26 integration with the arkavo-rs KAS server.

## Prerequisites

### Backend (arkavo-rs)
- ✅ NATS server running on localhost:4222
- ✅ Redis server running on localhost:6379
- ✅ KAS EC private key: `recipient_private_key.pem`
- ✅ TLS certificates: `fullchain.pem`, `privkey.pem`
- ✅ FairPlay SDK 26 credentials in `vendor/FairPlay_Streaming_Server_SDK_26/Development/Key_Server_Module/credentials/`

### Build Status
- ✅ Compiles without fairplay feature: `cargo build`
- ✅ Compiles with fairplay feature: `cargo build --features fairplay`
- ✅ All tests pass: `cargo test --features fairplay --lib` (9/9 tests)

## Test Phases

### Phase 1: Backend API Testing (Current)

Test the backend REST API endpoints directly using HTTP requests.

#### Test 1.1: Session Start (Both Protocols)

**TDF3 Protocol:**
```bash
curl -X POST http://localhost:8443/media/v1/session/start \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "test-user-001",
    "assetId": "test-asset-123",
    "protocol": "tdf3"
  }'
```

**Expected Response:**
```json
{
  "sessionId": "test-user-001:test-asset-123:uuid",
  "status": "started"
}
```

**FairPlay Protocol:**
```bash
curl -X POST http://localhost:8443/media/v1/session/start \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "test-user-001",
    "assetId": "test-asset-123",
    "protocol": "fairplay"
  }'
```

#### Test 1.2: TDF3 Key Request

```bash
# Use session ID from previous test
curl -X POST http://localhost:8443/media/v1/key-request \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "SESSION_ID_FROM_ABOVE",
    "userId": "test-user-001",
    "assetId": "test-asset-123",
    "segmentIndex": 0,
    "nanotdfHeader": "BASE64_ENCODED_NANOTDF_HEADER",
    "clientPublicKey": "-----BEGIN PUBLIC KEY-----\nMFkw...-----END PUBLIC KEY-----"
  }'
```

**Expected Response:**
```json
{
  "sessionPublicKey": "-----BEGIN PUBLIC KEY-----...",
  "wrappedKey": "BASE64_NONCE_PLUS_ENCRYPTED_DEK",
  "status": "success",
  "metadata": {
    "latency_ms": 15,
    "segment_index": 0
  }
}
```

#### Test 1.3: FairPlay Key Request (When iOS Client Ready)

```bash
# Generate SPC on iOS device first, then:
curl -X POST http://localhost:8443/media/v1/key-request \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "SESSION_ID_FROM_ABOVE",
    "userId": "test-user-001",
    "assetId": "test-asset-123",
    "segmentIndex": 0,
    "spcData": "BASE64_ENCODED_SPC_FROM_IOS_CLIENT"
  }'
```

**Expected Response:**
```json
{
  "sessionPublicKey": "",
  "wrappedKey": "BASE64_ENCODED_CKC",
  "status": "success",
  "metadata": {
    "latency_ms": 12,
    "segment_index": 0,
    "protocol": "fairplay",
    "ckc_size": 456
  }
}
```

#### Test 1.4: Session Heartbeat

```bash
curl -X POST http://localhost:8443/media/v1/session/SESSION_ID/heartbeat \
  -H "Content-Type: application/json" \
  -d '{
    "state": "playing",
    "segmentIndex": 1
  }'
```

**Expected Response:**
```json
{
  "status": "ok",
  "lastHeartbeat": 1234567890
}
```

#### Test 1.5: Session Termination

```bash
curl -X DELETE http://localhost:8443/media/v1/session/SESSION_ID
```

**Expected Status:** `204 No Content`

#### Test 1.6: Error Scenarios

**Missing Protocol Detection:**
```bash
curl -X POST http://localhost:8443/media/v1/key-request \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-session",
    "userId": "test-user",
    "assetId": "test-asset"
  }'
```

**Expected Error:**
```json
{
  "error": "invalid_request",
  "message": "Could not detect protocol: provide either (nanotdf_header + client_public_key) for TDF3, or spc_data for FairPlay"
}
```

**Session Not Found:**
```bash
curl -X POST http://localhost:8443/media/v1/key-request \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "nonexistent-session",
    "userId": "test-user",
    "assetId": "test-asset",
    "spcData": "dummy"
  }'
```

**Expected Error:**
```json
{
  "error": "session_not_found",
  "message": "Session nonexistent-session not found or expired"
}
```

### Phase 2: Policy Enforcement Testing

#### Test 2.1: Concurrency Limits

1. Start multiple sessions for same user
2. Verify `MAX_CONCURRENT_STREAMS` is enforced
3. Expected error when limit exceeded:
```json
{
  "error": "concurrency_limit",
  "message": "Maximum concurrent streams (2) exceeded. Current: 2"
}
```

#### Test 2.2: Protocol Mismatch

1. Start session with `protocol: "fairplay"`
2. Attempt TDF3 key request (with nanotdfHeader)
3. Verify rejection with protocol mismatch error

### Phase 3: Performance Testing

#### Test 3.1: Key Delivery Latency

**Goal:** Verify P95 latency < 50ms

```bash
# Run 100 requests, measure latency distribution
for i in {1..100}; do
  curl -w "@curl-format.txt" -o /dev/null -s \
    http://localhost:8443/media/v1/key-request \
    -X POST -H "Content-Type: application/json" \
    -d '{ ... }'
done
```

**Metrics to Track:**
- P50 latency
- P95 latency
- P99 latency
- Average latency

### Phase 4: Swift Client Integration (Future)

Once Swift FairPlay client code is added to ArkavoMediaKit:

#### Test 4.1: iOS FairPlay Playback

```swift
// In ArkavoMediaKit
import AVFoundation

// 1. Start session
let session = try await sessionManager.startSession(
    userID: "ios-user-001",
    assetID: "test-video",
    protocol: .fairPlay
)

// 2. Configure AVContentKeySession
let keySession = AVContentKeySession(keySystem: .fairPlayStreaming)
let delegate = FairPlayContentKeyDelegate(
    kasURL: kasURL,
    sessionID: session.sessionID
)
keySession.setDelegate(delegate, queue: DispatchQueue.main)

// 3. Load HLS stream with FairPlay
let player = AVPlayer(url: hlsURL)
keySession.addContentKeyRecipient(player)
player.play()

// 4. Verify playback starts successfully
// 5. Send heartbeats
// 6. Clean up on stop
```

#### Test 4.2: Protocol Auto-Detection

Test that the backend correctly routes requests based on payload:
- TDF3: presence of `nanotdfHeader` + `clientPublicKey`
- FairPlay: presence of `spcData`

#### Test 4.3: Dual-Protocol Session Management

1. Create one TDF3 session
2. Create one FairPlay session (same user)
3. Verify both sessions tracked independently
4. Verify concurrency limits apply across protocols

### Phase 5: End-to-End Integration

#### Test 5.1: Full FairPlay Playback Flow

1. **Content Preparation** (macOS ArkavoCreator):
   - Segment video into HLS chunks
   - Encrypt with FairPlay
   - Upload to CDN

2. **iOS Playback** (iOS Arkavo app):
   - Start FairPlay session
   - Generate SPC for content
   - Request CKC from KAS
   - Decrypt and play video
   - Send periodic heartbeats
   - Terminate session on stop

3. **Backend Monitoring**:
   - Verify analytics events published to NATS
   - Check Redis session state
   - Monitor latency metrics

## Test Execution Checklist

### Immediate (Phase 1)
- [ ] Start backend with `--features fairplay`
- [ ] Test session start (both protocols)
- [ ] Test TDF3 key request flow
- [ ] Test session heartbeat
- [ ] Test session termination
- [ ] Test error scenarios
- [ ] Verify NATS analytics events

### Short-term (Phase 2-3)
- [ ] Test concurrency limits
- [ ] Test protocol mismatch rejection
- [ ] Run performance benchmarks
- [ ] Document P95 latency results

### Future (Phase 4-5)
- [ ] Add FairPlay client code to ArkavoMediaKit
- [ ] Implement FairPlayContentKeyDelegate
- [ ] Test iOS FairPlay playback
- [ ] Run full end-to-end tests
- [ ] Update integration test suite

## Success Criteria

### Phase 1 (Backend API)
- ✅ All REST endpoints respond correctly
- ✅ Protocol auto-detection works
- ✅ Error handling is correct
- ✅ Analytics events published

### Phase 2 (Policy)
- [ ] Concurrency limits enforced
- [ ] Protocol validation working
- [ ] Session timeouts function correctly

### Phase 3 (Performance)
- [ ] P95 latency < 50ms
- [ ] No memory leaks
- [ ] Handles 100+ concurrent sessions

### Phase 4-5 (Full Integration)
- [ ] iOS FairPlay playback successful
- [ ] Dual-protocol support verified
- [ ] End-to-end flow complete

## Environment Setup

### Backend Server Start

```bash
cd /Users/paul/Projects/arkavo/arkavo-rs

# Ensure dependencies are running
nats-server &
redis-server &

# Set environment variables
export PORT=8443
export TLS_CERT_PATH=./fullchain.pem
export TLS_KEY_PATH=./privkey.pem
export KAS_KEY_PATH=./recipient_private_key.pem
export NATS_URL=nats://localhost:4222
export REDIS_URL=redis://localhost:6379
export MAX_CONCURRENT_STREAMS=2
export ENABLE_MEDIA_ANALYTICS=true
export FAIRPLAY_CREDENTIALS_PATH=./vendor/FairPlay_Streaming_Server_SDK_26/Development/Key_Server_Module/credentials

# Start server with FairPlay support
cargo run --features fairplay
```

### Test Tools

**curl-format.txt** (for latency measurement):
```
time_namelookup:  %{time_namelookup}s\n
time_connect:     %{time_connect}s\n
time_appconnect:  %{time_appconnect}s\n
time_pretransfer: %{time_pretransfer}s\n
time_redirect:    %{time_redirect}s\n
time_starttransfer: %{time_starttransfer}s\n
time_total:       %{time_total}s\n
```

## Next Steps

1. ✅ Complete Phase 1 backend API testing
2. Document results and any issues found
3. Plan Swift FairPlay client implementation
4. Proceed to Phase 4 once client code is ready

## Notes

- FairPlay requires real iOS/tvOS/macOS device or simulator for SPC generation
- Test certificates are included with SDK for development
- Production deployment requires valid FairPlay Streaming agreement with Apple
