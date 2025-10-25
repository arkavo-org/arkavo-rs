/// FairPlay Streaming Integration Tests (Phase 1: Backend API)
///
/// These tests verify the HTTP REST API endpoints for FairPlay and TDF3 media sessions.
///
/// **Prerequisites:**
/// - Server must be running with FairPlay support on http://localhost:9443
/// - Redis must be running on localhost:6379
/// - NATS must be running on localhost:4222
///
/// **To run these tests:**
/// ```bash
/// # Start the server in one terminal:
/// DYLD_FALLBACK_LIBRARY_PATH=$(pwd)/vendor/fpssdk/prebuilt/macos \
/// HTTP_PORT=9443 WS_PORT=9444 \
/// MAX_CONCURRENT_STREAMS=2 \
/// ENABLE_MEDIA_ANALYTICS=true \
/// FAIRPLAY_CREDENTIALS_PATH=./vendor/FairPlay_Streaming_Server_SDK_26/Development/Key_Server_Module/credentials \
/// cargo run --features fairplay
///
/// # Run tests in another terminal:
/// cargo test --features fairplay --test fairplay_integration_tests -- --ignored --test-threads=1
/// ```
///
/// These tests are marked #[ignore] because they require external services.
use reqwest;
use serde_json::Value;

const BASE_URL: &str = "http://localhost:9443";

/// Helper struct for session start requests
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionStartRequest {
    user_id: String,
    asset_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
}

/// Helper struct for session heartbeat requests
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionHeartbeatRequest {
    state: String,
    segment_index: u32,
}

/// Helper struct for key request
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyRequest {
    session_id: String,
    user_id: String,
    asset_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    nanotdf_header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    spc_data: Option<String>,
}

#[tokio::test]
#[ignore] // Requires running server
async fn test_1_1a_session_start_tdf3() {
    let client = reqwest::Client::new();

    let request = SessionStartRequest {
        user_id: "test-user-001".to_string(),
        asset_id: "test-asset-123".to_string(),
        protocol: Some("tdf3".to_string()),
    };

    let response = client
        .post(&format!("{}/media/v1/session/start", BASE_URL))
        .json(&request)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        response.status(),
        200,
        "Expected HTTP 200 for session start"
    );

    let body: Value = response.json().await.expect("Failed to parse JSON");

    // Verify response structure
    assert!(body.get("sessionId").is_some(), "Missing sessionId field");
    assert_eq!(
        body.get("status").and_then(|v| v.as_str()),
        Some("started"),
        "Expected status 'started'"
    );

    // Verify session ID format: userId:assetId:uuid
    let session_id = body["sessionId"].as_str().expect("sessionId not a string");
    assert!(
        session_id.starts_with("test-user-001:test-asset-123:"),
        "Session ID has incorrect format"
    );

    println!("✅ Test 1.1a PASS: TDF3 session created: {}", session_id);
}

#[tokio::test]
#[ignore] // Requires running server
async fn test_1_1b_session_start_fairplay() {
    let client = reqwest::Client::new();

    let request = SessionStartRequest {
        user_id: "test-user-002".to_string(),
        asset_id: "test-asset-456".to_string(),
        protocol: Some("fairplay".to_string()),
    };

    let response = client
        .post(&format!("{}/media/v1/session/start", BASE_URL))
        .json(&request)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        response.status(),
        200,
        "Expected HTTP 200 for session start"
    );

    let body: Value = response.json().await.expect("Failed to parse JSON");

    // Verify response structure
    assert!(body.get("sessionId").is_some(), "Missing sessionId field");
    assert_eq!(
        body.get("status").and_then(|v| v.as_str()),
        Some("started"),
        "Expected status 'started'"
    );

    // Verify session ID format
    let session_id = body["sessionId"].as_str().expect("sessionId not a string");
    assert!(
        session_id.starts_with("test-user-002:test-asset-456:"),
        "Session ID has incorrect format"
    );

    println!(
        "✅ Test 1.1b PASS: FairPlay session created: {}",
        session_id
    );
}

#[tokio::test]
#[ignore] // Requires running server
async fn test_1_4_session_heartbeat() {
    let client = reqwest::Client::new();

    // First create a session
    let session_request = SessionStartRequest {
        user_id: "test-user-heartbeat".to_string(),
        asset_id: "test-asset-heartbeat".to_string(),
        protocol: Some("tdf3".to_string()),
    };

    let session_response = client
        .post(&format!("{}/media/v1/session/start", BASE_URL))
        .json(&session_request)
        .send()
        .await
        .expect("Failed to create session");

    let session_body: Value = session_response
        .json()
        .await
        .expect("Failed to parse session response");
    let session_id = session_body["sessionId"]
        .as_str()
        .expect("Missing sessionId");

    // Send heartbeat
    let heartbeat_request = SessionHeartbeatRequest {
        state: "playing".to_string(),
        segment_index: 1,
    };

    let response = client
        .post(&format!(
            "{}/media/v1/session/{}/heartbeat",
            BASE_URL, session_id
        ))
        .json(&heartbeat_request)
        .send()
        .await
        .expect("Failed to send heartbeat");

    assert_eq!(response.status(), 200, "Expected HTTP 200 for heartbeat");

    let body: Value = response.json().await.expect("Failed to parse JSON");

    // Verify response
    assert_eq!(
        body.get("status").and_then(|v| v.as_str()),
        Some("ok"),
        "Expected status 'ok'"
    );
    assert!(
        body.get("lastHeartbeat").is_some(),
        "Missing lastHeartbeat field"
    );

    println!("✅ Test 1.4 PASS: Session heartbeat successful");
}

#[tokio::test]
#[ignore] // Requires running server
async fn test_1_5_session_termination() {
    let client = reqwest::Client::new();

    // First create a session
    let session_request = SessionStartRequest {
        user_id: "test-user-terminate".to_string(),
        asset_id: "test-asset-terminate".to_string(),
        protocol: Some("fairplay".to_string()),
    };

    let session_response = client
        .post(&format!("{}/media/v1/session/start", BASE_URL))
        .json(&session_request)
        .send()
        .await
        .expect("Failed to create session");

    let session_body: Value = session_response
        .json()
        .await
        .expect("Failed to parse session response");
    let session_id = session_body["sessionId"]
        .as_str()
        .expect("Missing sessionId");

    // Terminate session
    let response = client
        .delete(&format!("{}/media/v1/session/{}", BASE_URL, session_id))
        .send()
        .await
        .expect("Failed to terminate session");

    assert_eq!(
        response.status(),
        204,
        "Expected HTTP 204 No Content for session termination"
    );

    println!("✅ Test 1.5 PASS: Session terminated successfully");
}

#[tokio::test]
#[ignore] // Requires running server
async fn test_1_6a_protocol_detection_error() {
    let client = reqwest::Client::new();

    // Key request without protocol-specific fields
    let request = KeyRequest {
        session_id: "test-session".to_string(),
        user_id: "test-user".to_string(),
        asset_id: "test-asset".to_string(),
        nanotdf_header: None,
        client_public_key: None,
        spc_data: None,
    };

    let response = client
        .post(&format!("{}/media/v1/key-request", BASE_URL))
        .json(&request)
        .send()
        .await
        .expect("Failed to send request");

    // Should return 400 Bad Request
    assert!(
        response.status().is_client_error(),
        "Expected 4xx status code"
    );

    let body: Value = response.json().await.expect("Failed to parse JSON");

    // Verify error structure
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("invalid_request"),
        "Expected error type 'invalid_request'"
    );

    let message = body.get("message").and_then(|v| v.as_str()).unwrap();
    assert!(
        message.contains("Could not detect protocol"),
        "Expected protocol detection error message"
    );

    println!("✅ Test 1.6a PASS: Protocol detection error handled correctly");
}

#[tokio::test]
#[ignore] // Requires running server
async fn test_1_6b_session_not_found_error() {
    let client = reqwest::Client::new();

    // Key request with nonexistent session
    let request = KeyRequest {
        session_id: "nonexistent-session".to_string(),
        user_id: "test-user".to_string(),
        asset_id: "test-asset".to_string(),
        nanotdf_header: None,
        client_public_key: None,
        spc_data: Some("dummy".to_string()), // Provide spc_data to pass protocol detection
    };

    let response = client
        .post(&format!("{}/media/v1/key-request", BASE_URL))
        .json(&request)
        .send()
        .await
        .expect("Failed to send request");

    // Should return 404 Not Found
    assert_eq!(
        response.status(),
        404,
        "Expected HTTP 404 for nonexistent session"
    );

    let body: Value = response.json().await.expect("Failed to parse JSON");

    // Verify error structure
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("session_not_found"),
        "Expected error type 'session_not_found'"
    );

    let message = body.get("message").and_then(|v| v.as_str()).unwrap();
    assert!(
        message.contains("not found or expired"),
        "Expected session not found error message"
    );

    println!("✅ Test 1.6b PASS: Session not found error handled correctly");
}

#[tokio::test]
#[ignore] // Requires running server
async fn test_dual_protocol_session_management() {
    let client = reqwest::Client::new();

    // Create TDF3 session
    let tdf3_request = SessionStartRequest {
        user_id: "test-user-dual".to_string(),
        asset_id: "test-asset-tdf3".to_string(),
        protocol: Some("tdf3".to_string()),
    };

    let tdf3_response = client
        .post(&format!("{}/media/v1/session/start", BASE_URL))
        .json(&tdf3_request)
        .send()
        .await
        .expect("Failed to create TDF3 session");

    assert_eq!(tdf3_response.status(), 200);

    let tdf3_body: Value = tdf3_response
        .json()
        .await
        .expect("Failed to parse TDF3 response");
    let tdf3_session_id = tdf3_body["sessionId"]
        .as_str()
        .expect("Missing TDF3 sessionId");

    // Create FairPlay session
    let fairplay_request = SessionStartRequest {
        user_id: "test-user-dual".to_string(),
        asset_id: "test-asset-fairplay".to_string(),
        protocol: Some("fairplay".to_string()),
    };

    let fairplay_response = client
        .post(&format!("{}/media/v1/session/start", BASE_URL))
        .json(&fairplay_request)
        .send()
        .await
        .expect("Failed to create FairPlay session");

    assert_eq!(fairplay_response.status(), 200);

    let fairplay_body: Value = fairplay_response
        .json()
        .await
        .expect("Failed to parse FairPlay response");
    let fairplay_session_id = fairplay_body["sessionId"]
        .as_str()
        .expect("Missing FairPlay sessionId");

    // Verify both sessions created successfully
    assert_ne!(
        tdf3_session_id, fairplay_session_id,
        "Sessions should have different IDs"
    );

    // Send heartbeats to both sessions
    let heartbeat = SessionHeartbeatRequest {
        state: "playing".to_string(),
        segment_index: 0,
    };

    let tdf3_hb = client
        .post(&format!(
            "{}/media/v1/session/{}/heartbeat",
            BASE_URL, tdf3_session_id
        ))
        .json(&heartbeat)
        .send()
        .await
        .expect("TDF3 heartbeat failed");

    assert_eq!(tdf3_hb.status(), 200);

    let fairplay_hb = client
        .post(&format!(
            "{}/media/v1/session/{}/heartbeat",
            BASE_URL, fairplay_session_id
        ))
        .json(&heartbeat)
        .send()
        .await
        .expect("FairPlay heartbeat failed");

    assert_eq!(fairplay_hb.status(), 200);

    println!("✅ Dual Protocol Test PASS: Both TDF3 and FairPlay sessions managed successfully");
}
