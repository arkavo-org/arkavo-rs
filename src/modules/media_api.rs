/// Media-specific API endpoints for TDF3-based and FairPlay DRM
///
/// Provides dedicated endpoints optimized for streaming media key delivery,
/// session management, and rental window tracking.
use crate::modules::crypto;
use crate::modules::fairplay::MediaProtocol;
use crate::modules::http_rewrap::RewrapState;
use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
#[cfg(feature = "fairplay")]
use base64::Engine;
use chrono::Utc;
use log::{error, info, warn};
use nanotdf::chain::{ChainValidationRequest, SessionValidator, ValidationError};
use nanotdf::BinaryParser;
use p256::{ecdh::EphemeralSecret, PublicKey as P256PublicKey, SecretKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
#[cfg(feature = "fairplay")]
use std::future::Future;
use std::net::SocketAddr;
#[cfg(feature = "fairplay")]
use std::pin::Pin;
use std::sync::Arc;
use uuid::Uuid;

// Constants for input validation
#[cfg(feature = "fairplay")]
const MAX_SPC_DATA_SIZE: usize = 64 * 1024; // 64KB max for SPC data
const MAX_NANOTDF_HEADER_SIZE: usize = 16 * 1024; // 16KB max for NanoTDF header

// Re-import session manager types
use crate::media_metrics::{
    KeyRequestResult, MediaEvent, MediaMetrics, RequestTimer, SessionEndReason,
};
use crate::session_manager::{PlaybackSession, SessionManager, SessionState};

/// Shared state for media API endpoints
pub struct MediaApiState {
    pub rewrap_state: Arc<RewrapState>,
    pub session_manager: Arc<SessionManager>,
    pub media_metrics: Arc<MediaMetrics>,
    #[allow(dead_code)]
    pub fairplay_handler: Option<Arc<crate::modules::fairplay::FairPlayHandler>>,
    /// Chain validator for session validation (optional for backward compatibility)
    pub chain_validator: Option<Arc<dyn SessionValidator>>,
}

// ==================== Request/Response Types ====================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaKeyRequest {
    pub session_id: String,
    pub user_id: String,
    pub asset_id: String,
    pub segment_index: Option<u32>,
    // TDF3 fields
    pub client_public_key: Option<String>, // PEM format (for TDF3)
    pub nanotdf_header: Option<String>,    // Base64-encoded (for TDF3)
    // FairPlay fields
    pub spc_data: Option<String>, // Base64-encoded (for FairPlay)
    // Chain validation fields (optional for backward compatibility)
    pub chain_session_id: Option<String>, // Chain session ID (hex-encoded)
    pub chain_header_hash: Option<String>, // SHA256 of header bytes (hex-encoded, DPoP binding)
    pub chain_signature: Option<String>,  // ECDSA signature (base64)
    pub chain_nonce: Option<u64>,         // Replay prevention nonce
    pub chain_algorithm: Option<String>,  // "ES256", "ES384", defaults to "ES256"
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaKeyResponse {
    pub session_public_key: String, // PEM format
    pub wrapped_key: String,        // Base64 (nonce + encrypted DEK)
    pub status: String,             // "success" or "denied"
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStartRequest {
    pub user_id: String,
    pub asset_id: String,
    pub protocol: Option<MediaProtocol>, // Auto-detected if not specified
    pub geo_region: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStartResponse {
    pub session_id: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionHeartbeatRequest {
    pub state: Option<String>, // "playing", "paused", "stopped"
    pub segment_index: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionHeartbeatResponse {
    pub status: String,
    pub last_heartbeat: i64,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        let status = match self.error.as_str() {
            "authentication_failed" => StatusCode::UNAUTHORIZED,
            "policy_denied" => StatusCode::FORBIDDEN,
            "session_not_found" => StatusCode::NOT_FOUND,
            "concurrency_limit" => StatusCode::TOO_MANY_REQUESTS,
            "invalid_request" => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self)).into_response()
    }
}

// ==================== Helper Functions ====================

/// Detect protocol from request payload
#[allow(dead_code)]
fn detect_protocol(payload: &MediaKeyRequest) -> Option<MediaProtocol> {
    if payload.spc_data.is_some() {
        Some(MediaProtocol::FairPlay)
    } else if payload.nanotdf_header.is_some() && payload.client_public_key.is_some() {
        Some(MediaProtocol::TDF3)
    } else {
        None
    }
}

/// Validate session exists and user_id matches
async fn validate_session(
    state: &MediaApiState,
    payload: &MediaKeyRequest,
    timer: &RequestTimer,
) -> Result<PlaybackSession, ErrorResponse> {
    // Verify session exists and update heartbeat
    let session = match state
        .session_manager
        .heartbeat(&payload.session_id, None, payload.segment_index)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            error!("Session not found: {}", e);
            log_key_request_error(
                state,
                payload,
                KeyRequestResult::InvalidRequest,
                timer.elapsed_ms(),
            )
            .await;

            return Err(ErrorResponse {
                error: "session_not_found".to_string(),
                message: format!("Session {} not found or expired", payload.session_id),
            });
        }
    };

    // Validate user_id matches session
    if session.user_id != payload.user_id {
        error!("User ID mismatch for session {}", payload.session_id);
        log_key_request_error(
            state,
            payload,
            KeyRequestResult::AuthenticationFailed,
            timer.elapsed_ms(),
        )
        .await;

        return Err(ErrorResponse {
            error: "authentication_failed".to_string(),
            message: "User ID does not match session".to_string(),
        });
    }

    Ok(session)
}

/// Log key request error event
async fn log_key_request_error(
    state: &MediaApiState,
    payload: &MediaKeyRequest,
    result: KeyRequestResult,
    latency_ms: u64,
) {
    let event = MediaEvent::KeyRequest {
        session_id: payload.session_id.clone(),
        user_id: payload.user_id.clone(),
        asset_id: payload.asset_id.clone(),
        segment_index: payload.segment_index,
        result,
        latency_ms,
        timestamp: Utc::now().timestamp(),
    };
    state.media_metrics.publish_event(event.clone()).await;
    state.media_metrics.log_event(&event);
}

/// Validate session on chain (if chain validation is configured)
async fn validate_chain_session(
    state: &MediaApiState,
    payload: &MediaKeyRequest,
) -> Result<(), ErrorResponse> {
    let validator = match state.chain_validator.as_ref() {
        Some(v) => v,
        None => return Ok(()), // Chain validation not configured
    };

    // Chain validation is required when validator is configured
    let session_id = payload.chain_session_id.as_ref().ok_or_else(|| {
        warn!("Chain validation enabled but no chain_session_id provided");
        ErrorResponse {
            error: "invalid_request".to_string(),
            message: "chain_session_id is required".to_string(),
        }
    })?;

    let signature = payload.chain_signature.as_ref().ok_or_else(|| {
        warn!("Chain validation enabled but no chain_signature provided");
        ErrorResponse {
            error: "invalid_request".to_string(),
            message: "chain_signature is required".to_string(),
        }
    })?;

    let nonce = payload.chain_nonce.ok_or_else(|| {
        warn!("Chain validation enabled but no chain_nonce provided");
        ErrorResponse {
            error: "invalid_request".to_string(),
            message: "chain_nonce is required".to_string(),
        }
    })?;

    // DPoP Header Binding: require header_hash
    let client_header_hash_hex = payload.chain_header_hash.as_ref().ok_or_else(|| {
        warn!("Chain validation enabled but no chain_header_hash provided");
        ErrorResponse {
            error: "invalid_request".to_string(),
            message: "chain_header_hash is required for DPoP binding".to_string(),
        }
    })?;

    // Decode client-provided header_hash
    let client_header_hash_bytes =
        hex::decode(client_header_hash_hex).map_err(|e| ErrorResponse {
            error: "invalid_request".to_string(),
            message: format!("Invalid chain_header_hash hex encoding: {}", e),
        })?;

    if client_header_hash_bytes.len() != 32 {
        return Err(ErrorResponse {
            error: "invalid_request".to_string(),
            message: format!(
                "chain_header_hash must be 32 bytes, got {}",
                client_header_hash_bytes.len()
            ),
        });
    }

    // Get the actual header bytes from the nanotdf_header field
    let header_bytes = payload
        .nanotdf_header
        .as_ref()
        .ok_or_else(|| ErrorResponse {
            error: "invalid_request".to_string(),
            message: "nanotdf_header is required for chain validation".to_string(),
        })?;

    let header_bytes = crypto::base64_decode(header_bytes).map_err(|e| ErrorResponse {
        error: "invalid_request".to_string(),
        message: format!("Invalid nanotdf_header base64 encoding: {}", e),
    })?;

    // Compute server-side header hash
    let server_header_hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&header_bytes).into()
    };

    // DPoP binding check: verify client's header_hash matches
    let client_header_hash: [u8; 32] = client_header_hash_bytes.try_into().unwrap();
    if client_header_hash != server_header_hash {
        warn!(
            "Header hash mismatch: client={} server={}",
            hex::encode(client_header_hash),
            hex::encode(server_header_hash)
        );
        return Err(ErrorResponse {
            error: "authentication_failed".to_string(),
            message: "chain_header_hash does not match actual header content".to_string(),
        });
    }

    // Decode signature from base64
    let signature_bytes = crypto::base64_decode(signature).map_err(|e| ErrorResponse {
        error: "invalid_request".to_string(),
        message: format!("Invalid chain_signature encoding: {}", e),
    })?;

    // Build validation request with verified header_hash
    let validation_request = ChainValidationRequest {
        session_id: session_id.clone(),
        header_hash: server_header_hash, // Use server-computed (verified) hash
        resource_id: hex::encode(server_header_hash), // Keep for logging
        signature: signature_bytes,
        algorithm: payload
            .chain_algorithm
            .clone()
            .unwrap_or_else(|| "ES256".to_string()),
        nonce,
    };

    // Validate session on chain
    match validator.validate(&validation_request).await {
        Ok(validated) => {
            info!(
                "Chain validation passed for session {}, scope {}",
                hex::encode(validated.grant.session_id),
                hex::encode(validated.grant.scope_id)
            );
            Ok(())
        }
        Err(e) => {
            warn!("Chain validation failed: {:?}", e);
            Err(match e {
                ValidationError::SessionNotFound { session_id } => ErrorResponse {
                    error: "policy_denied".to_string(),
                    message: format!("Session not found: {}", session_id),
                },
                ValidationError::SessionExpired {
                    expired_at,
                    current,
                } => ErrorResponse {
                    error: "policy_denied".to_string(),
                    message: format!(
                        "Session expired at block {} (current: {})",
                        expired_at, current
                    ),
                },
                ValidationError::SessionRevoked => ErrorResponse {
                    error: "policy_denied".to_string(),
                    message: "Session has been revoked".to_string(),
                },
                ValidationError::SignatureInvalid { reason } => ErrorResponse {
                    error: "authentication_failed".to_string(),
                    message: format!("Invalid proof-of-possession signature: {}", reason),
                },
                ValidationError::NonceReplay => ErrorResponse {
                    error: "authentication_failed".to_string(),
                    message: "Nonce already used (replay attack detected)".to_string(),
                },
                ValidationError::ScopeMismatch { resource_id } => ErrorResponse {
                    error: "policy_denied".to_string(),
                    message: format!("Resource {} not in session scope", resource_id),
                },
                ValidationError::HeaderHashMismatch { client, server } => ErrorResponse {
                    error: "authentication_failed".to_string(),
                    message: format!("Header hash mismatch: client={}, server={}", client, server),
                },
                ValidationError::Chain(chain_err) => ErrorResponse {
                    error: "internal_error".to_string(),
                    message: format!("Chain query failed: {}", chain_err),
                },
                ValidationError::Crypto(err) => ErrorResponse {
                    error: "internal_error".to_string(),
                    message: format!("Crypto error: {}", err),
                },
            })
        }
    }
}

// ==================== API Handlers ====================

/// POST /media/v1/key-request
/// Fast path for media segment key delivery (supports both TDF3 and FairPlay)
#[cfg(feature = "fairplay")]
pub fn media_key_request(
    State(state): State<Arc<MediaApiState>>,
    Json(payload): Json<MediaKeyRequest>,
) -> Pin<Box<dyn Future<Output = Result<Json<MediaKeyResponse>, ErrorResponse>> + Send>> {
    Box::pin(async move {
        let timer = RequestTimer::start();

        // Auto-detect protocol from request fields
        let protocol = detect_protocol(&payload).ok_or_else(|| ErrorResponse {
            error: "invalid_request".to_string(),
            message: "Could not detect protocol: provide either (nanotdf_header + client_public_key) for TDF3, or spc_data for FairPlay".to_string(),
        })?;

        info!(
            "Media key request [{}]: session={} asset={} segment={:?}",
            protocol, payload.session_id, payload.asset_id, payload.segment_index
        );

        // Route to protocol-specific handler
        match protocol {
            MediaProtocol::TDF3 => handle_tdf3_key_request(state, payload, timer).await,
            MediaProtocol::FairPlay => {
                handle_fairplay_key_request_router(state, payload, timer).await
            }
        }
    })
}

/// POST /media/v1/key-request (without fairplay feature)
/// Only supports TDF3 protocol
#[cfg(not(feature = "fairplay"))]
pub async fn media_key_request(
    State(state): State<Arc<MediaApiState>>,
    Json(payload): Json<MediaKeyRequest>,
) -> Result<Json<MediaKeyResponse>, ErrorResponse> {
    let timer = RequestTimer::start();

    // Only TDF3 supported
    if payload.nanotdf_header.is_none() || payload.client_public_key.is_none() {
        return Err(ErrorResponse {
            error: "invalid_request".to_string(),
            message: "TDF3 requires nanotdf_header and client_public_key".to_string(),
        });
    }

    if payload.spc_data.is_some() {
        return Err(ErrorResponse {
            error: "not_implemented".to_string(),
            message: "FairPlay support not compiled in (use --features fairplay)".to_string(),
        });
    }

    info!(
        "Media key request [tdf3]: session={} asset={} segment={:?}",
        payload.session_id, payload.asset_id, payload.segment_index
    );

    handle_tdf3_key_request(state, payload, timer).await
}

/// Router for FairPlay requests (handles feature flag)
#[cfg(feature = "fairplay")]
#[allow(dead_code)]
async fn handle_fairplay_key_request_router(
    state: Arc<MediaApiState>,
    payload: MediaKeyRequest,
    timer: RequestTimer,
) -> Result<Json<MediaKeyResponse>, ErrorResponse> {
    handle_fairplay_key_request(state, payload, timer).await
}

#[cfg(not(feature = "fairplay"))]
#[allow(dead_code)]
async fn handle_fairplay_key_request_router(
    _state: Arc<MediaApiState>,
    _payload: MediaKeyRequest,
    _timer: RequestTimer,
) -> Result<Json<MediaKeyResponse>, ErrorResponse> {
    Err(ErrorResponse {
        error: "not_implemented".to_string(),
        message: "FairPlay support not compiled in (use --features fairplay)".to_string(),
    })
}

/// Handle TDF3 key request
async fn handle_tdf3_key_request(
    state: Arc<MediaApiState>,
    payload: MediaKeyRequest,
    timer: RequestTimer,
) -> Result<Json<MediaKeyResponse>, ErrorResponse> {
    // 1. Validate session and user
    let _session = validate_session(&state, &payload, &timer).await?;

    // 2. Chain-driven session validation (if configured)
    validate_chain_session(&state, &payload).await?;

    // 3. Validate NanoTDF header size
    let nanotdf_header = payload
        .nanotdf_header
        .as_ref()
        .ok_or_else(|| ErrorResponse {
            error: "invalid_request".to_string(),
            message: "Missing nanotdf_header for TDF3".to_string(),
        })?;

    // Check header size before base64 decoding to prevent DoS
    if nanotdf_header.len() > MAX_NANOTDF_HEADER_SIZE * 4 / 3 {
        // Base64 encoding is ~4/3 the size of raw data
        return Err(ErrorResponse {
            error: "invalid_request".to_string(),
            message: format!(
                "NanoTDF header too large: {} bytes (max {} bytes encoded)",
                nanotdf_header.len(),
                MAX_NANOTDF_HEADER_SIZE * 4 / 3
            ),
        });
    }

    // 4. Parse client public key (unwrap safe: detect_protocol verified it exists)
    let client_public_key_pem =
        payload
            .client_public_key
            .as_ref()
            .ok_or_else(|| ErrorResponse {
                error: "invalid_request".to_string(),
                message: "Missing client_public_key for TDF3".to_string(),
            })?;
    let client_public_key =
        parse_pem_public_key(client_public_key_pem).map_err(|e| ErrorResponse {
            error: "invalid_request".to_string(),
            message: format!("Invalid client public key: {}", e),
        })?;

    // 4. Generate ephemeral session key pair
    let session_private_key = EphemeralSecret::random(&mut OsRng);
    let session_public_key = P256PublicKey::from(&session_private_key);
    let session_public_key_pem =
        public_key_to_pem(&session_public_key).map_err(|e| ErrorResponse {
            error: "internal_error".to_string(),
            message: format!("Failed to generate session key: {}", e),
        })?;

    // 5. Perform ECDH with client
    let session_shared_secret = session_private_key.diffie_hellman(&client_public_key);
    let session_shared_secret_bytes = session_shared_secret.raw_secret_bytes();

    // 6. Process NanoTDF header to rewrap DEK
    let wrapped_key = process_nanotdf_header(
        nanotdf_header,
        &state.rewrap_state.kas_ec_private_key,
        session_shared_secret_bytes.as_ref(),
    )
    .map_err(|e| {
        error!("Failed to process NanoTDF header: {}", e);
        ErrorResponse {
            error: "internal_error".to_string(),
            message: format!("Key processing failed: {}", e),
        }
    })?;

    let latency = timer.elapsed_ms();

    // 7. Record metrics
    state
        .media_metrics
        .record_key_request_latency(latency)
        .await;
    let event = MediaEvent::KeyRequest {
        session_id: payload.session_id.clone(),
        user_id: payload.user_id.clone(),
        asset_id: payload.asset_id.clone(),
        segment_index: payload.segment_index,
        result: KeyRequestResult::Success,
        latency_ms: latency,
        timestamp: Utc::now().timestamp(),
    };
    state.media_metrics.publish_event(event.clone()).await;
    state.media_metrics.log_event(&event);

    Ok(Json(MediaKeyResponse {
        session_public_key: session_public_key_pem,
        wrapped_key,
        status: "success".to_string(),
        metadata: Some(serde_json::json!({
            "latency_ms": latency,
            "segment_index": payload.segment_index,
        })),
    }))
}

/// Handle FairPlay key request
#[cfg(feature = "fairplay")]
async fn handle_fairplay_key_request(
    state: Arc<MediaApiState>,
    payload: MediaKeyRequest,
    timer: RequestTimer,
) -> Result<Json<MediaKeyResponse>, ErrorResponse> {
    // 1. Validate session and user
    let session = validate_session(&state, &payload, &timer).await?;

    // 2. Chain-driven session validation (if configured)
    validate_chain_session(&state, &payload).await?;

    // 3. Validate protocol matches session
    if session.protocol != MediaProtocol::FairPlay {
        error!(
            "Protocol mismatch for session {}: expected FairPlay, got {:?}",
            payload.session_id, session.protocol
        );
        return Err(ErrorResponse {
            error: "invalid_request".to_string(),
            message: "Session was created with different protocol".to_string(),
        });
    }

    // 4. Extract and validate SPC data
    let spc_data_base64 = payload.spc_data.as_ref().ok_or_else(|| ErrorResponse {
        error: "invalid_request".to_string(),
        message: "Missing spc_data for FairPlay".to_string(),
    })?;

    // Check SPC size before base64 decoding to prevent DoS
    if spc_data_base64.len() > MAX_SPC_DATA_SIZE * 4 / 3 {
        // Base64 encoding is ~4/3 the size of raw data
        return Err(ErrorResponse {
            error: "invalid_request".to_string(),
            message: format!(
                "SPC data too large: {} bytes (max {} bytes encoded)",
                spc_data_base64.len(),
                MAX_SPC_DATA_SIZE * 4 / 3
            ),
        });
    }

    let spc_data = base64::engine::general_purpose::STANDARD
        .decode(spc_data_base64)
        .map_err(|e| {
            error!("Failed to decode SPC data: {}", e);
            ErrorResponse {
                error: "invalid_request".to_string(),
                message: format!("Invalid base64 SPC data: {}", e),
            }
        })?;

    // Additional validation: Check decoded size
    if spc_data.len() > MAX_SPC_DATA_SIZE {
        return Err(ErrorResponse {
            error: "invalid_request".to_string(),
            message: format!(
                "Decoded SPC data too large: {} bytes (max {} bytes)",
                spc_data.len(),
                MAX_SPC_DATA_SIZE
            ),
        });
    }

    info!(
        "Processing FairPlay SPC for session {} (SPC size: {} bytes)",
        payload.session_id,
        spc_data.len()
    );

    // ⚠️  CRITICAL SECURITY WARNING ⚠️
    // 5. TODO: Extract content key (DEK) from policy/storage
    //
    // PLACEHOLDER IMPLEMENTATION - NOT PRODUCTION READY!
    // This uses a hardcoded zero-filled key which provides NO SECURITY.
    // All FairPlay-protected content would use the same key.
    //
    // Production implementation MUST retrieve unique DEKs from:
    // - Content metadata service (asset_id → DEK mapping)
    // - Key Management Service (KMS) or Hardware Security Module (HSM)
    // - Policy evaluation (media_policy_contract) for access control
    // - Secure key storage (Redis with encryption, Vault, etc.)
    //
    // Integration points:
    // - Add DEK lookup: `let content_key = fetch_content_key(&payload.asset_id).await?;`
    // - Add policy check: `validate_key_access(&session, &payload).await?;`
    // - Add key rotation support for long-lived content
    let content_key = vec![0x00u8; 16]; // PLACEHOLDER: Replace with actual DEK retrieval

    // Debug-mode validation: Prevent accidental production deployment
    // Remove this assertion once real DEK retrieval is implemented
    #[cfg(debug_assertions)]
    {
        log::warn!(
            "⚠️  USING PLACEHOLDER CONTENT KEY - NOT SECURE FOR PRODUCTION! Asset: {}",
            payload.asset_id
        );
    }

    // Production safety check: Fail fast if placeholder key detected in release builds
    // TODO: Remove this check once real DEK retrieval is implemented
    #[cfg(not(debug_assertions))]
    {
        if content_key == vec![0x00u8; 16] {
            error!("SECURITY ERROR: Placeholder content key detected in production build!");
            return Err(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Content key retrieval not implemented".to_string(),
            });
        }
    }

    // 6. Process SPC using FairPlay SDK
    let fairplay_handler = state
        .fairplay_handler
        .as_ref()
        .ok_or_else(|| ErrorResponse {
            error: "internal_error".to_string(),
            message: "FairPlay handler not initialized".to_string(),
        })?;

    // Convert error to String immediately to avoid !Send issues with Box<dyn Error>
    let ckc_data_result: Result<Vec<u8>, String> = match fairplay_handler
        .process_key_request(
            payload.asset_id.clone(),
            payload.asset_id.clone(), // content_id = asset_id for simplicity
            spc_data,
            content_key,
        )
        .await
    {
        Ok(data) => Ok(data),
        Err(e) => Err(e.to_string()),
    };

    let ckc_data = match ckc_data_result {
        Ok(data) => data,
        Err(error_message) => {
            error!("FairPlay SDK error: {}", error_message);
            log_key_request_error(
                &state,
                &payload,
                KeyRequestResult::PolicyDenied,
                timer.elapsed_ms(),
            )
            .await;

            return Err(ErrorResponse {
                error: "internal_error".to_string(),
                message: format!("FairPlay key processing failed: {}", error_message),
            });
        }
    };

    let latency = timer.elapsed_ms();
    info!(
        "FairPlay CKC generated for session {} (CKC size: {} bytes, latency: {}ms)",
        payload.session_id,
        ckc_data.len(),
        latency
    );

    // 7. Log successful key request
    let event = MediaEvent::KeyRequest {
        session_id: payload.session_id.clone(),
        user_id: payload.user_id.clone(),
        asset_id: payload.asset_id.clone(),
        segment_index: payload.segment_index,
        result: KeyRequestResult::Success,
        latency_ms: latency,
        timestamp: Utc::now().timestamp(),
    };
    state.media_metrics.publish_event(event.clone()).await;
    state.media_metrics.log_event(&event);

    // 8. Return CKC to client
    Ok(Json(MediaKeyResponse {
        session_public_key: String::new(), // Not used in FairPlay
        wrapped_key: base64::engine::general_purpose::STANDARD.encode(&ckc_data),
        status: "success".to_string(),
        metadata: Some(serde_json::json!({
            "latency_ms": latency,
            "segment_index": payload.segment_index,
            "protocol": "fairplay",
            "ckc_size": ckc_data.len(),
        })),
    }))
}

/// POST /media/v1/session/start
/// Initialize a new playback session
pub async fn session_start(
    State(state): State<Arc<MediaApiState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<SessionStartRequest>,
) -> Result<Json<SessionStartResponse>, ErrorResponse> {
    // Extract real client IP from connection (not from untrusted payload)
    let client_ip = addr.ip().to_string();
    // Generate cryptographically secure session ID with UUID v4
    let session_id = format!(
        "{}:{}:{}",
        payload.user_id,
        payload.asset_id,
        Uuid::new_v4()
    );

    // Default to TDF3 for backwards compatibility if protocol not specified
    let protocol = payload.protocol.unwrap_or(MediaProtocol::TDF3);

    let session = PlaybackSession {
        session_id: session_id.clone(),
        user_id: payload.user_id.clone(),
        asset_id: payload.asset_id.clone(),
        protocol,
        segment_index: None,
        state: SessionState::Starting,
        start_timestamp: Utc::now().timestamp(),
        first_play_timestamp: None,
        last_heartbeat_timestamp: Utc::now().timestamp(),
        client_ip: client_ip.clone(),
        geo_region: payload.geo_region.clone(),
        user_agent: payload.user_agent.clone(),
        c2pa_metadata: None, // C2PA metadata populated during key requests
    };

    match state.session_manager.create_session(session.clone()).await {
        Ok(_) => {
            // Publish session start event
            let event = MediaEvent::SessionStart {
                session_id: session_id.clone(),
                user_id: payload.user_id.clone(),
                asset_id: payload.asset_id.clone(),
                client_ip: client_ip.clone(),
                geo_region: payload.geo_region.clone(),
                user_agent: payload.user_agent.clone(),
                timestamp: Utc::now().timestamp(),
            };
            state.media_metrics.publish_event(event.clone()).await;
            state.media_metrics.log_event(&event);

            Ok(Json(SessionStartResponse {
                session_id,
                status: "started".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to create session: {}", e);

            // Check if concurrency limit error
            if let crate::session_manager::SessionManagerError::ConcurrencyLimitExceeded {
                current,
                max,
            } = e
            {
                let event = MediaEvent::ConcurrencyLimit {
                    user_id: payload.user_id.clone(),
                    current_streams: current,
                    max_streams: max,
                    timestamp: Utc::now().timestamp(),
                };
                state.media_metrics.publish_event(event.clone()).await;
                state.media_metrics.log_event(&event);

                return Err(ErrorResponse {
                    error: "concurrency_limit".to_string(),
                    message: format!(
                        "Maximum concurrent streams ({}) exceeded. Current: {}",
                        max, current
                    ),
                });
            }

            Err(ErrorResponse {
                error: "internal_error".to_string(),
                message: format!("Failed to create session: {}", e),
            })
        }
    }
}

/// POST /media/v1/session/{session_id}/heartbeat
/// Update session activity
pub async fn session_heartbeat(
    State(state): State<Arc<MediaApiState>>,
    Path(session_id): Path<String>,
    Json(payload): Json<SessionHeartbeatRequest>,
) -> Result<Json<SessionHeartbeatResponse>, ErrorResponse> {
    // Parse state string
    let session_state = payload.state.as_ref().and_then(|s| match s.as_str() {
        "playing" => Some(SessionState::Playing),
        "paused" => Some(SessionState::Paused),
        "stopped" => Some(SessionState::Stopped),
        _ => None,
    });

    match state
        .session_manager
        .heartbeat(&session_id, session_state, payload.segment_index)
        .await
    {
        Ok(session) => Ok(Json(SessionHeartbeatResponse {
            status: "ok".to_string(),
            last_heartbeat: session.last_heartbeat_timestamp,
        })),
        Err(e) => {
            error!("Heartbeat failed for session {}: {}", session_id, e);
            Err(ErrorResponse {
                error: "session_not_found".to_string(),
                message: format!("Session not found: {}", e),
            })
        }
    }
}

/// DELETE /media/v1/session/{session_id}
/// Terminate a playback session
pub async fn session_terminate(
    State(state): State<Arc<MediaApiState>>,
    Path(session_id): Path<String>,
) -> Result<StatusCode, ErrorResponse> {
    // Get session info before terminating
    if let Ok(Some(session)) = state.session_manager.get_session(&session_id).await {
        let duration = Utc::now().timestamp() - session.start_timestamp;

        // Publish session end event
        let event = MediaEvent::SessionEnd {
            session_id: session_id.clone(),
            user_id: session.user_id.clone(),
            asset_id: session.asset_id.clone(),
            duration_seconds: duration,
            reason: SessionEndReason::UserTerminated,
            timestamp: Utc::now().timestamp(),
        };
        state.media_metrics.publish_event(event.clone()).await;
        state.media_metrics.log_event(&event);
    }

    match state.session_manager.terminate_session(&session_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(e) => {
            error!("Failed to terminate session {}: {}", session_id, e);
            Err(ErrorResponse {
                error: "internal_error".to_string(),
                message: format!("Failed to terminate session: {}", e),
            })
        }
    }
}

// ==================== Helper Functions ====================

/// Process NanoTDF header and rewrap DEK
fn process_nanotdf_header(
    header_base64: &str,
    kas_private_key: &SecretKey,
    session_shared_secret: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    // Decode base64 header
    let header_bytes = base64_decode(header_base64)?;

    // Parse NanoTDF header
    let mut parser = BinaryParser::new(&header_bytes);
    let header = parser.parse_header()?;

    // Extract ephemeral key
    let tdf_ephemeral_key_bytes = header.get_ephemeral_key();
    if tdf_ephemeral_key_bytes.len() != 33 {
        return Err(format!(
            "Invalid ephemeral key size: {} (expected 33)",
            tdf_ephemeral_key_bytes.len()
        )
        .into());
    }

    let tdf_ephemeral_public_key = P256PublicKey::from_sec1_bytes(tdf_ephemeral_key_bytes)?;

    // Perform ECDH between KAS private key and TDF ephemeral public key
    let dek_shared_secret = crypto::custom_ecdh(kas_private_key, &tdf_ephemeral_public_key)?;

    // Detect NanoTDF version and compute salt
    let nanotdf_salt = if let Some(version) = crypto::detect_nanotdf_version(&header_bytes) {
        crypto::compute_nanotdf_salt(version)
    } else {
        crypto::compute_nanotdf_salt(crypto::NANOTDF_VERSION_V12)
    };

    // Rewrap DEK
    let (nonce, wrapped_dek) = crypto::rewrap_dek(
        &dek_shared_secret,
        session_shared_secret,
        &nanotdf_salt,
        b"", // Empty info per NanoTDF spec
    )?;

    // Combine nonce + wrapped_dek
    let mut combined = Vec::new();
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&wrapped_dek);

    Ok(base64_encode(&combined))
}

// Helper wrappers for crypto utilities with error conversion
fn parse_pem_public_key(pem: &str) -> Result<P256PublicKey, String> {
    crypto::parse_pem_public_key(pem).map_err(|e| format!("Failed to parse PEM public key: {}", e))
}

fn public_key_to_pem(public_key: &P256PublicKey) -> Result<String, String> {
    crypto::public_key_to_pem(public_key)
        .map_err(|e| format!("Failed to convert public key to PEM: {}", e))
}

fn base64_encode(data: &[u8]) -> String {
    crypto::base64_encode(data)
}

fn base64_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    crypto::base64_decode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_protocol_tdf3() {
        let request = MediaKeyRequest {
            session_id: "test-session".to_string(),
            user_id: "test-user".to_string(),
            asset_id: "test-asset".to_string(),
            segment_index: Some(0),
            client_public_key: Some(
                "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string(),
            ),
            nanotdf_header: Some("base64header".to_string()),
            spc_data: None,
            chain_session_id: None,
            chain_header_hash: None,
            chain_signature: None,
            chain_nonce: None,
            chain_algorithm: None,
        };

        assert_eq!(detect_protocol(&request), Some(MediaProtocol::TDF3));
    }

    #[test]
    fn test_detect_protocol_fairplay() {
        let request = MediaKeyRequest {
            session_id: "test-session".to_string(),
            user_id: "test-user".to_string(),
            asset_id: "test-asset".to_string(),
            segment_index: Some(0),
            client_public_key: None,
            nanotdf_header: None,
            spc_data: Some("base64spc".to_string()),
            chain_session_id: None,
            chain_header_hash: None,
            chain_signature: None,
            chain_nonce: None,
            chain_algorithm: None,
        };

        assert_eq!(detect_protocol(&request), Some(MediaProtocol::FairPlay));
    }

    #[test]
    fn test_detect_protocol_invalid_missing_all_fields() {
        let request = MediaKeyRequest {
            session_id: "test-session".to_string(),
            user_id: "test-user".to_string(),
            asset_id: "test-asset".to_string(),
            segment_index: Some(0),
            client_public_key: None,
            nanotdf_header: None,
            spc_data: None,
            chain_session_id: None,
            chain_header_hash: None,
            chain_signature: None,
            chain_nonce: None,
            chain_algorithm: None,
        };

        assert_eq!(detect_protocol(&request), None);
    }

    #[test]
    fn test_detect_protocol_invalid_incomplete_tdf3() {
        // Missing nanotdf_header
        let request = MediaKeyRequest {
            session_id: "test-session".to_string(),
            user_id: "test-user".to_string(),
            asset_id: "test-asset".to_string(),
            segment_index: Some(0),
            client_public_key: Some("pubkey".to_string()),
            nanotdf_header: None,
            spc_data: None,
            chain_session_id: None,
            chain_header_hash: None,
            chain_signature: None,
            chain_nonce: None,
            chain_algorithm: None,
        };

        assert_eq!(detect_protocol(&request), None);
    }

    #[test]
    fn test_error_response_status_codes() {
        let auth_error = ErrorResponse {
            error: "authentication_failed".to_string(),
            message: "Auth failed".to_string(),
        };
        let response = auth_error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let policy_error = ErrorResponse {
            error: "policy_denied".to_string(),
            message: "Policy denied".to_string(),
        };
        let response = policy_error.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let not_found_error = ErrorResponse {
            error: "session_not_found".to_string(),
            message: "Not found".to_string(),
        };
        let response = not_found_error.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let rate_limit_error = ErrorResponse {
            error: "concurrency_limit".to_string(),
            message: "Too many".to_string(),
        };
        let response = rate_limit_error.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        let bad_request_error = ErrorResponse {
            error: "invalid_request".to_string(),
            message: "Bad request".to_string(),
        };
        let response = bad_request_error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let unknown_error = ErrorResponse {
            error: "unknown".to_string(),
            message: "Unknown".to_string(),
        };
        let response = unknown_error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
