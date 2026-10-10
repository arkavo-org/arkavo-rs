/// Media-specific API endpoints for FairPlay DRM
///
/// Provides dedicated endpoints for streaming media key delivery,
/// session management, and rental window tracking.
use crate::modules::fairplay::MediaProtocol;
use crate::modules::http_rewrap::RewrapState;
use crate::modules::license::issuer::{IssueError, IssuedLicense, LicenseContentType};
use crate::modules::license::person_token::Person;
use crate::modules::license::tdf_policy::PolicyKeys;
use crate::modules::license::LicenseError;
use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use chrono::Utc;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

// Constants for input validation
const MAX_SPC_DATA_SIZE: usize = 64 * 1024; // 64KB max for SPC data

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
    /// Pre-loaded FairPlay certificate (.bin) bytes for client certificate fetching.
    /// Loaded once at startup; serving from memory avoids per-request disk I/O.
    pub fairplay_certificate_data: Option<Arc<Vec<u8>>>,
    /// Verifies the viewer's passkey CWT on every /media/v1 call except /certificate.
    pub person_tokens: Arc<crate::modules::license::person_token::PersonTokenVerifier>,
    /// None → FairPlay key requests fail closed with 503.
    pub license: Option<Arc<crate::modules::license::config::LicenseAuthz>>,
    /// None when the fairplay feature is off.
    pub issuer: Option<Arc<dyn crate::modules::license::issuer::LicenseIssuer>>,
}

// ==================== Request/Response Types ====================

/// Unknown JSON fields (the old `userId`, `tdfWrappedKey` and `chain*`
/// fields) are ignored, so old clients still parse.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaKeyRequest {
    pub session_id: String,
    pub asset_id: String,
    pub segment_index: Option<u32>,
    // TDF3 fields (detected only to refuse them)
    pub client_public_key: Option<String>, // PEM format (for TDF3)
    pub nanotdf_header: Option<String>,    // Base64-encoded (for TDF3)
    // FairPlay fields
    pub spc_data: Option<String>, // Base64-encoded (for FairPlay)
    /// Base64-encoded manifest.json from Standard TDF (required for FairPlay)
    pub tdf_manifest: Option<String>,
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
    /// Ignored: the session is keyed by the verified token `sub`. Still
    /// accepted so old clients parse.
    #[serde(rename = "userId", default)]
    pub _user_id: String,
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
            "forbidden" => StatusCode::FORBIDDEN,
            "service_unavailable" => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self)).into_response()
    }
}

impl From<LicenseError> for ErrorResponse {
    fn from(e: LicenseError) -> Self {
        ErrorResponse {
            error: e.error_code().to_string(),
            message: e.reason().to_string(),
        }
    }
}

// ==================== Helper Functions ====================

/// Detect protocol from request payload
fn detect_protocol(payload: &MediaKeyRequest) -> Option<MediaProtocol> {
    if payload.spc_data.is_some() {
        Some(MediaProtocol::FairPlay)
    } else if payload.nanotdf_header.is_some() && payload.client_public_key.is_some() {
        Some(MediaProtocol::TDF3)
    } else {
        None
    }
}

/// Authorize and issue a FairPlay license: TDF manifest check, platform
/// decision for the person, then a leased CKC for the policy's key.
pub async fn authorize_license(
    state: &MediaApiState,
    person: &Person,
    payload: &MediaKeyRequest,
    rid: &str,
) -> Result<IssuedLicense, LicenseError> {
    let license = state
        .license
        .as_ref()
        .ok_or(LicenseError::Unavailable("licensing not configured"))?;
    let issuer = state
        .issuer
        .as_ref()
        .ok_or(LicenseError::Unavailable("FairPlay not available"))?;
    let rsa = state
        .rewrap_state
        .kas_rsa_private_key
        .as_ref()
        .ok_or(LicenseError::Unavailable("KAS RSA key not configured"))?;
    let manifest_b64 = payload
        .tdf_manifest
        .as_deref()
        .ok_or(LicenseError::BadRequest("tdfManifest is required"))?;
    let manifest = base64::engine::general_purpose::STANDARD
        .decode(manifest_b64)
        .map_err(|_| LicenseError::BadRequest("tdfManifest is not base64"))?;
    let spc_b64 = payload
        .spc_data
        .as_deref()
        .ok_or(LicenseError::BadRequest("spcData is required"))?;
    if spc_b64.len() > MAX_SPC_DATA_SIZE * 4 / 3 {
        return Err(LicenseError::BadRequest("spcData too large"));
    }
    let spc = base64::engine::general_purpose::STANDARD
        .decode(spc_b64)
        .map_err(|_| LicenseError::BadRequest("spcData is not base64"))?;

    // Every manifest refusal reaches the client as one generic reason, so the
    // endpoint is not an oracle for which check failed. The specific reason
    // (a static string, never key material) is logged here.
    let policy =
        crate::modules::license::tdf_policy::check_manifest(&manifest, rsa, &license.kas_urls)
            .map_err(|e| {
                warn!("license {rid}: manifest refused: {}", e.reason());
                match e {
                    LicenseError::Forbidden(_) => LicenseError::Forbidden("manifest refused"),
                    other => other,
                }
            })?;
    // Same for the platform: an explicit deny and a bad-input refusal (e.g. an
    // unknown attribute) look identical to the client; 503s pass through.
    license
        .pdp
        .decide(&person.token, &policy.policy_uuid, &policy.fqns, rid)
        .await
        .map_err(|e| {
            warn!("license {rid}: platform decision refused: {}", e.reason());
            match e {
                LicenseError::Forbidden(_) => LicenseError::Forbidden("platform refused"),
                other => other,
            }
        })?;

    let key = match &policy.keys {
        PolicyKeys::Single(dek) => {
            let mut key = [0u8; 16];
            key.copy_from_slice(&dek[..16]);
            key
        }
        // A profile v2 key needs the request's component, which the request
        // does not carry yet: refused like any other manifest.
        PolicyKeys::Components(_) => {
            warn!("license {rid}: manifest refused: profile v2 needs a component");
            return Err(LicenseError::Forbidden("manifest refused"));
        }
    };
    let issued = issuer
        .issue(
            spc,
            key,
            policy.content_iv,
            &policy.policy_uuid,
            LicenseContentType::Uhd,
            license.lease_secs,
        )
        .await
        .map_err(|e| match e {
            IssueError::MalformedSpc(detail) => {
                warn!("license {rid}: FairPlay SDK refused a malformed SPC: {detail}");
                LicenseError::BadRequest("spcData is malformed")
            }
            IssueError::Sdk(detail) => {
                error!("license {rid}: FairPlay SDK failed: {detail}");
                LicenseError::Unavailable("FairPlay license service unavailable")
            }
        })?;
    if issued.spc_asset_id.as_deref() != Some(policy.policy_uuid.as_str()) {
        warn!("license {rid}: SPC asset id does not match the policy uuid");
    }
    Ok(issued)
}

async fn require_owned_session(
    state: &MediaApiState,
    session_id: &str,
    person: &Person,
) -> Result<PlaybackSession, LicenseError> {
    match state.session_manager.get_session(session_id).await {
        Ok(Some(s)) if s.user_id == person.sub => Ok(s),
        Ok(_) => Err(LicenseError::Forbidden(
            "session not found for this subject",
        )),
        Err(_) => Err(LicenseError::Unavailable("session store unavailable")),
    }
}

// ==================== API Handlers ====================

/// POST /media/v1/key-request
/// FairPlay license delivery: person token → owned session → TDF policy →
/// platform decision → leased CKC. TDF3 media keys are refused.
pub async fn media_key_request(
    State(state): State<Arc<MediaApiState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<MediaKeyRequest>,
) -> Result<Json<MediaKeyResponse>, ErrorResponse> {
    let timer = RequestTimer::start();
    let rid = Uuid::new_v4().to_string();
    let person = state
        .person_tokens
        .verify(&headers, Utc::now().timestamp())
        .await?;
    match detect_protocol(&payload) {
        Some(MediaProtocol::FairPlay) => {}
        Some(MediaProtocol::TDF3) => {
            return Err(LicenseError::Forbidden(
                "TDF3 media keys are disabled pending policy enforcement",
            )
            .into())
        }
        None => return Err(LicenseError::BadRequest("spcData is required").into()),
    }
    let session = require_owned_session(&state, &payload.session_id, &person).await?;
    if session.protocol != MediaProtocol::FairPlay {
        return Err(LicenseError::BadRequest("session protocol is not fairplay").into());
    }
    // A key request (including AVFoundation lease renewal) keeps the session
    // alive, as the old validate_session did; phase 2 adds explicit heartbeats.
    state
        .session_manager
        .heartbeat(&payload.session_id, None, payload.segment_index)
        .await
        .map_err(|e| match e {
            crate::session_manager::SessionManagerError::SessionNotFound => {
                LicenseError::Forbidden("session not found for this subject")
            }
            _ => LicenseError::Unavailable("session store unavailable"),
        })?;
    let result = authorize_license(&state, &person, &payload, &rid).await;
    let outcome = match &result {
        Ok(_) => KeyRequestResult::Success,
        Err(LicenseError::Forbidden(_)) => KeyRequestResult::PolicyDenied,
        Err(LicenseError::Unauthenticated(_)) => KeyRequestResult::AuthenticationFailed,
        Err(_) => KeyRequestResult::InvalidRequest,
    };
    if let Err(e) = &result {
        info!(
            "license {rid}: refused {} ({})",
            e.status().as_u16(),
            e.reason()
        );
    }
    let event = MediaEvent::KeyRequest {
        session_id: payload.session_id.clone(),
        user_id: person.sub.clone(),
        asset_id: payload.asset_id.clone(),
        segment_index: payload.segment_index,
        result: outcome,
        latency_ms: timer.elapsed_ms(),
        timestamp: Utc::now().timestamp(),
    };
    state.media_metrics.publish_event(event.clone()).await;
    state.media_metrics.log_event(&event);
    let issued = result?;
    Ok(Json(MediaKeyResponse {
        session_public_key: String::new(),
        wrapped_key: base64::engine::general_purpose::STANDARD.encode(&issued.ckc),
        status: "success".to_string(),
        metadata: Some(serde_json::json!({
            "protocol": "fairplay",
            "lease_seconds": state.license.as_ref().map(|l| l.lease_secs),
        })),
    }))
}

/// GET /media/v1/certificate
/// Serve the FairPlay Streaming certificate for client SPC generation
pub async fn fairplay_certificate(
    State(state): State<Arc<MediaApiState>>,
) -> Result<Response, ErrorResponse> {
    let cert_data = state.fairplay_certificate_data.as_ref().ok_or_else(|| {
        warn!("FairPlay certificate requested but not configured");
        ErrorResponse {
            error: "not_configured".to_string(),
            message: "FairPlay certificate not configured".to_string(),
        }
    })?;

    info!("FairPlay certificate served ({} bytes)", cert_data.len());

    Ok((
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "application/octet-stream"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        cert_data.as_ref().clone(),
    )
        .into_response())
}

/// POST /media/v1/session/start
/// Initialize a new playback session
pub async fn session_start(
    State(state): State<Arc<MediaApiState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<SessionStartRequest>,
) -> Result<Json<SessionStartResponse>, ErrorResponse> {
    let person = state
        .person_tokens
        .verify(&headers, Utc::now().timestamp())
        .await?;
    // Extract real client IP from connection (not from untrusted payload)
    let client_ip = addr.ip().to_string();
    // Generate cryptographically secure session ID with UUID v4
    let session_id = format!("{}:{}:{}", person.sub, payload.asset_id, Uuid::new_v4());

    // Default to TDF3 for backwards compatibility if protocol not specified
    let protocol = payload.protocol.unwrap_or(MediaProtocol::TDF3);

    let session = PlaybackSession {
        session_id: session_id.clone(),
        user_id: person.sub.clone(),
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
                user_id: person.sub.clone(),
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
                    user_id: person.sub.clone(),
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

            Err(LicenseError::Unavailable("session store unavailable").into())
        }
    }
}

/// POST /media/v1/session/{session_id}/heartbeat
/// Update session activity
pub async fn session_heartbeat(
    State(state): State<Arc<MediaApiState>>,
    Path(session_id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<SessionHeartbeatRequest>,
) -> Result<Json<SessionHeartbeatResponse>, ErrorResponse> {
    let person = state
        .person_tokens
        .verify(&headers, Utc::now().timestamp())
        .await?;
    require_owned_session(&state, &session_id, &person).await?;
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
        // The session was owned a moment ago; it can still expire in between.
        Err(crate::session_manager::SessionManagerError::SessionNotFound) => Err(ErrorResponse {
            error: "session_not_found".to_string(),
            message: "session not found".to_string(),
        }),
        Err(e) => {
            error!("Heartbeat failed for session {}: {}", session_id, e);
            Err(LicenseError::Unavailable("session store unavailable").into())
        }
    }
}

/// DELETE /media/v1/session/{session_id}
/// Terminate a playback session
pub async fn session_terminate(
    State(state): State<Arc<MediaApiState>>,
    Path(session_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<StatusCode, ErrorResponse> {
    let person = state
        .person_tokens
        .verify(&headers, Utc::now().timestamp())
        .await?;
    require_owned_session(&state, &session_id, &person).await?;
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
            Err(LicenseError::Unavailable("session store unavailable").into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_protocol_tdf3() {
        let request = MediaKeyRequest {
            session_id: "test-session".to_string(),
            asset_id: "test-asset".to_string(),
            segment_index: Some(0),
            client_public_key: Some(
                "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string(),
            ),
            nanotdf_header: Some("base64header".to_string()),
            spc_data: None,
            tdf_manifest: None,
        };

        assert_eq!(detect_protocol(&request), Some(MediaProtocol::TDF3));
    }

    #[test]
    fn test_detect_protocol_fairplay() {
        let request = MediaKeyRequest {
            session_id: "test-session".to_string(),
            asset_id: "test-asset".to_string(),
            segment_index: Some(0),
            client_public_key: None,
            nanotdf_header: None,
            spc_data: Some("base64spc".to_string()),
            tdf_manifest: None,
        };

        assert_eq!(detect_protocol(&request), Some(MediaProtocol::FairPlay));
    }

    #[test]
    fn test_detect_protocol_fairplay_with_tdf_manifest() {
        // FairPlay with Standard TDF manifest should still detect as FairPlay
        let request = MediaKeyRequest {
            session_id: "test-session".to_string(),
            asset_id: "test-asset".to_string(),
            segment_index: Some(0),
            client_public_key: None,
            nanotdf_header: None,
            spc_data: Some("base64spc".to_string()),
            tdf_manifest: Some("base64manifest".to_string()),
        };

        assert_eq!(detect_protocol(&request), Some(MediaProtocol::FairPlay));
    }

    #[test]
    fn test_detect_protocol_invalid_missing_all_fields() {
        let request = MediaKeyRequest {
            session_id: "test-session".to_string(),
            asset_id: "test-asset".to_string(),
            segment_index: Some(0),
            client_public_key: None,
            nanotdf_header: None,
            spc_data: None,
            tdf_manifest: None,
        };

        assert_eq!(detect_protocol(&request), None);
    }

    #[test]
    fn test_detect_protocol_invalid_incomplete_tdf3() {
        // Missing nanotdf_header
        let request = MediaKeyRequest {
            session_id: "test-session".to_string(),
            asset_id: "test-asset".to_string(),
            segment_index: Some(0),
            client_public_key: Some("pubkey".to_string()),
            nanotdf_header: None,
            spc_data: None,
            tdf_manifest: None,
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

        let forbidden_error = ErrorResponse {
            error: "forbidden".to_string(),
            message: "Forbidden".to_string(),
        };
        assert_eq!(
            forbidden_error.into_response().status(),
            StatusCode::FORBIDDEN
        );

        let unavailable_error = ErrorResponse {
            error: "service_unavailable".to_string(),
            message: "Unavailable".to_string(),
        };
        assert_eq!(
            unavailable_error.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        let unknown_error = ErrorResponse {
            error: "unknown".to_string(),
            message: "Unknown".to_string(),
        };
        let response = unknown_error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}

#[cfg(test)]
mod license_pipeline_tests {
    use super::*;
    use crate::modules::authzen::cose_keys::CoseKeyCache;
    use crate::modules::license::config::LicenseAuthz;
    use crate::modules::license::issuer::test_support::FakeIssuer;
    use crate::modules::license::issuer::LicenseContentType;
    use crate::modules::license::pdp::PlatformPdp;
    use crate::modules::license::person_token::{Person, PersonTokenVerifier};
    use rsa::pkcs8::DecodePrivateKey;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const UUID: &str = "3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b";

    pub(super) fn manifest() -> &'static str {
        &crate::modules::license::fixtures::fixtures().manifest_allowed
    }
    fn key_pem() -> &'static str {
        &crate::modules::license::fixtures::fixtures().key_pem
    }

    /// A wiremock platform: service token plus a fixed GetDecision answer.
    pub(super) async fn platform(decision: &str) -> MockServer {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"access_token":"svc","expires_in":3600})),
            )
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/authorization.v2.AuthorizationService/GetDecision"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"decision":{"decision":decision}})),
            )
            .mount(&s)
            .await;
        s
    }

    /// Rewrap state holding the test KAS RSA key the fixture manifest is wrapped to.
    pub(super) fn rewrap_state_with_rsa() -> Arc<RewrapState> {
        let rsa = rsa::RsaPrivateKey::from_pkcs8_pem(key_pem()).unwrap();
        Arc::new(RewrapState {
            kas_ec_private_key: p256::SecretKey::random(&mut rand_core::OsRng),
            kas_ec_public_key_pem: String::new(),
            kas_rsa_private_key: Some(rsa),
            kas_rsa_public_key_pem: None,
            oauth_public_key_pem: None,
            chain_validator: None,
        })
    }

    /// Licensing against `server`, for the fixture manifest's KAS, 3600 s lease.
    pub(super) fn license_authz(server: &MockServer) -> Arc<LicenseAuthz> {
        Arc::new(LicenseAuthz {
            pdp: PlatformPdp::new(
                &server.uri(),
                format!("{}/oauth/token", server.uri()),
                "arks-media".into(),
                "s".into(),
            )
            .unwrap(),
            kas_urls: vec![crate::modules::license::tdf_policy::normalize_kas_url(
                "https://platform.arkavo.net",
            )
            .unwrap()],
            lease_secs: 3600,
        })
    }

    fn state(server: &MockServer, issuer: Arc<FakeIssuer>) -> MediaApiState {
        let redis = redis::Client::open(
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into()),
        )
        .unwrap();
        MediaApiState {
            rewrap_state: rewrap_state_with_rsa(),
            session_manager: Arc::new(SessionManager::new(Arc::new(redis), Some(100))),
            media_metrics: Arc::new(MediaMetrics::new(None, "media.metrics".to_string(), false)),
            fairplay_certificate_data: None,
            person_tokens: Arc::new(PersonTokenVerifier::new(
                CoseKeyCache::with_static_keys(vec![]),
                "i".into(),
                "a".into(),
            )),
            license: Some(license_authz(server)),
            issuer: Some(issuer),
        }
    }

    fn payload(manifest: &str) -> MediaKeyRequest {
        serde_json::from_value(json!({
            "sessionId": "s", "userId": "ignored", "assetId": "a",
            "spcData": base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3]),
            "tdfManifest": base64::engine::general_purpose::STANDARD.encode(manifest),
        }))
        .unwrap()
    }

    fn person() -> Person {
        Person {
            sub: "550e8400-e29b-41d4-a716-446655440000".into(),
            token: "user-cwt".into(),
        }
    }

    #[tokio::test]
    async fn permit_issues_with_truncated_key_and_lease() {
        let server = platform("DECISION_PERMIT").await;
        let fake = Arc::new(FakeIssuer::new(Some(
            "3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b",
        )));
        let st = state(&server, fake.clone());
        let out = authorize_license(&st, &person(), &payload(manifest()), "rid")
            .await
            .unwrap();
        assert_eq!(out.ckc, b"fake-ckc");
        // First 16 bytes of the fixture DEK, and only after the binding passed on all 32.
        assert_eq!(
            fake.seen_key.lock().unwrap().unwrap(),
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        assert_eq!(*fake.seen_lease.lock().unwrap(), Some(3600));
        // The manifest's method.iv, decoded from base64.
        assert_eq!(
            fake.seen_iv.lock().unwrap().unwrap(),
            [
                0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
                0xfe, 0xff
            ]
        );
    }

    /// Profile v1 is issued as before: `uhd`, under the bare policy uuid.
    #[tokio::test]
    async fn v1_is_issued_as_uhd_under_the_policy_uuid() {
        let server = platform("DECISION_PERMIT").await;
        let fake = Arc::new(FakeIssuer::new(Some(UUID)));
        let st = state(&server, fake.clone());
        authorize_license(&st, &person(), &payload(manifest()), "rid")
            .await
            .unwrap();
        assert_eq!(
            *fake.seen_content_type.lock().unwrap(),
            Some(LicenseContentType::Uhd)
        );
        assert_eq!(fake.seen_asset_id.lock().unwrap().as_deref(), Some(UUID));
    }

    #[tokio::test]
    async fn deny_never_reaches_issuer() {
        let server = platform("DECISION_DENY").await;
        let fake = Arc::new(FakeIssuer::new(None));
        let st = state(&server, fake.clone());
        let err = authorize_license(&st, &person(), &payload(manifest()), "rid")
            .await
            .err()
            .unwrap();
        assert_eq!(err, LicenseError::Forbidden("platform refused"));
        assert!(fake.seen_key.lock().unwrap().is_none());
    }

    /// A platform bad-input refusal (e.g. unknown attribute FQN) and an
    /// explicit deny must look identical to the client, so the endpoint is
    /// not an oracle for which attributes exist.
    #[tokio::test]
    async fn platform_refusals_share_one_reason() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"access_token":"svc","expires_in":3600})),
            )
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/authorization.v2.AuthorizationService/GetDecision"))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(json!({"code":"invalid_argument"})),
            )
            .mount(&s)
            .await;
        let fake = Arc::new(FakeIssuer::new(None));
        let st = state(&s, fake.clone());
        let err = authorize_license(&st, &person(), &payload(manifest()), "rid")
            .await
            .err()
            .unwrap();
        assert_eq!(err, LicenseError::Forbidden("platform refused"));
        assert!(fake.seen_key.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn empty_content_iv_is_400_not_403() {
        // A broken package must not read as "no access" in the viewer.
        let server = platform("DECISION_PERMIT").await;
        let fake = Arc::new(FakeIssuer::new(None));
        let st = state(&server, fake.clone());
        let mut m: serde_json::Value = serde_json::from_str(manifest()).unwrap();
        m["encryptionInformation"]["method"]["iv"] = json!("");
        let err = authorize_license(&st, &person(), &payload(&m.to_string()), "rid")
            .await
            .err()
            .unwrap();
        assert_eq!(err, LicenseError::BadRequest("content iv must be 16 bytes"));
        assert_eq!(err.status(), axum::http::StatusCode::BAD_REQUEST);
        assert!(fake.seen_key.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn missing_manifest_is_400_and_wrapped_key_is_ignored() {
        let server = platform("DECISION_PERMIT").await;
        let st = state(&server, Arc::new(FakeIssuer::new(None)));
        let p: MediaKeyRequest = serde_json::from_value(json!({
            "sessionId":"s","userId":"u","assetId":"a","spcData":"AQID","tdfWrappedKey":"AAAA"}))
        .unwrap();
        assert!(matches!(
            authorize_license(&st, &person(), &p, "rid").await,
            Err(LicenseError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn unconfigured_licensing_is_503() {
        let server = platform("DECISION_PERMIT").await;
        let mut st = state(&server, Arc::new(FakeIssuer::new(None)));
        st.license = None;
        assert!(matches!(
            authorize_license(&st, &person(), &payload(manifest()), "rid").await,
            Err(LicenseError::Unavailable(_))
        ));
    }

    /// An SDK or credential fault is the server's (503); a malformed SPC is
    /// the client's (400). Neither is a policy refusal.
    #[tokio::test]
    async fn issuer_failures_map_to_503_and_400() {
        use crate::modules::license::issuer::IssueError;
        let server = platform("DECISION_PERMIT").await;
        for (fail, want) in [
            (
                IssueError::Sdk("status -42605".into()),
                LicenseError::Unavailable("FairPlay license service unavailable"),
            ),
            (
                IssueError::MalformedSpc("status -42581".into()),
                LicenseError::BadRequest("spcData is malformed"),
            ),
        ] {
            let st = state(&server, Arc::new(FakeIssuer::failing(fail)));
            let err = authorize_license(&st, &person(), &payload(manifest()), "rid")
                .await
                .err()
                .unwrap();
            assert_eq!(err, want);
        }
    }

    /// A tampered manifest must not tell the client which check failed.
    #[tokio::test]
    async fn tampered_manifest_gets_one_generic_refusal() {
        let server = platform("DECISION_PERMIT").await;
        let fake = Arc::new(FakeIssuer::new(None));
        let st = state(&server, fake.clone());
        let mut m: serde_json::Value = serde_json::from_str(manifest()).unwrap();
        // Swap in a different policy: the binding no longer matches.
        m["encryptionInformation"]["policy"] = json!(base64::engine::general_purpose::STANDARD
            .encode(r#"{"uuid":"x","body":{"dataAttributes":[{"attribute":"https://e/attr/a/value/b"}]}}"#));
        let tampered = m.to_string();

        // The native reason is specific...
        let native = crate::modules::license::tdf_policy::check_manifest(
            tampered.as_bytes(),
            st.rewrap_state.kas_rsa_private_key.as_ref().unwrap(),
            &st.license.as_ref().unwrap().kas_urls,
        )
        .err()
        .unwrap();
        assert_ne!(native, LicenseError::Forbidden("manifest refused"));

        // ...but the client only ever sees the generic one.
        let err = authorize_license(&st, &person(), &payload(&tampered), "rid")
            .await
            .err()
            .unwrap();
        assert_eq!(err, LicenseError::Forbidden("manifest refused"));
        assert!(fake.seen_key.lock().unwrap().is_none());
    }
}

#[cfg(test)]
mod session_auth_tests {
    use super::*;
    use crate::modules::authzen::cose_keys::CoseKeyCache;
    use crate::modules::authzen::cwt_verify::test_support::{keypair, mint_map};
    use crate::modules::license::person_token::PersonTokenVerifier;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{delete, post};
    use axum::Router;
    use ciborium::value::Value;
    use serde_json::json;
    use tower::ServiceExt;

    const ISS: &str = "https://identity.test";
    const PLATFORM: &str = "https://platform.arkavo.net";
    const KID: &[u8] = b"kid-1";

    fn token(sub: &str) -> String {
        let (sk, _) = keypair();
        let now = Utc::now().timestamp();
        mint_map(
            &sk,
            KID,
            vec![
                (Value::Integer(1.into()), Value::Text(ISS.into())),
                (Value::Integer(2.into()), Value::Text(sub.into())),
                (
                    Value::Integer(3.into()),
                    Value::Array(vec![
                        Value::Text("arkavo".into()),
                        Value::Text(PLATFORM.into()),
                    ]),
                ),
                (
                    Value::Integer(4.into()),
                    Value::Integer((now + 3600).into()),
                ),
                (Value::Integer(6.into()), Value::Integer(now.into())),
                (
                    Value::Integer(7.into()),
                    Value::Bytes(Uuid::new_v4().as_bytes().to_vec()),
                ),
            ],
        )
    }

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into())
    }

    fn app() -> Router {
        router(state_with_redis(&redis_url()))
    }

    fn app_with_redis(redis_url: &str) -> Router {
        router(state_with_redis(redis_url))
    }

    fn state_with_redis(redis_url: &str) -> MediaApiState {
        let (_, vk) = keypair();
        let redis = redis::Client::open(redis_url).unwrap();
        MediaApiState {
            rewrap_state: Arc::new(RewrapState {
                kas_ec_private_key: p256::SecretKey::random(&mut rand_core::OsRng),
                kas_ec_public_key_pem: String::new(),
                kas_rsa_private_key: None,
                kas_rsa_public_key_pem: None,
                oauth_public_key_pem: None,
                chain_validator: None,
            }),
            session_manager: Arc::new(SessionManager::new(Arc::new(redis), Some(100))),
            media_metrics: Arc::new(MediaMetrics::new(None, "media.metrics".to_string(), false)),
            fairplay_certificate_data: None,
            person_tokens: Arc::new(PersonTokenVerifier::new(
                CoseKeyCache::with_static_keys(vec![(KID.to_vec(), vk)]),
                ISS.into(),
                PLATFORM.into(),
            )),
            license: None,
            issuer: None,
        }
    }

    fn router(st: MediaApiState) -> Router {
        Router::new()
            .route("/start", post(session_start))
            .route("/key", post(media_key_request))
            .route("/s/:session_id/heartbeat", post(session_heartbeat))
            .route("/s/:session_id", delete(session_terminate))
            .with_state(Arc::new(st))
    }

    async fn send(
        app: &Router,
        method: &str,
        uri: &str,
        tok: Option<&str>,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(t) = tok {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        let mut req = b.body(Body::from(body.to_string())).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9))));
        let res = app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    fn urlencoding_path(s: &str) -> String {
        s.replace(':', "%3A")
    }

    async fn start_fairplay_session(app: &Router, sub: &str) -> String {
        let body = json!({"userId": "ignored", "assetId": "a", "protocol": "fairplay"});
        let (st, v) = send(app, "POST", "/start", Some(&token(sub)), body).await;
        assert_eq!(st, StatusCode::OK);
        v["sessionId"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn start_requires_token_and_binds_sub() {
        let app = app();
        let body = json!({"userId": "someone-else", "assetId": "a", "protocol": "fairplay"});
        assert_eq!(
            send(&app, "POST", "/start", None, body.clone()).await.0,
            StatusCode::UNAUTHORIZED
        );
        let sub = Uuid::new_v4().to_string();
        let (st, v) = send(&app, "POST", "/start", Some(&token(&sub)), body).await;
        assert_eq!(st, StatusCode::OK);
        let sid = v["sessionId"].as_str().unwrap().to_string();
        assert!(
            sid.starts_with(&sub),
            "session is keyed by the verified sub"
        );

        // Owner may heartbeat; another person may not.
        let hb = format!("/s/{}/heartbeat", urlencoding_path(&sid));
        assert_eq!(
            send(&app, "POST", &hb, Some(&token(&sub)), json!({}))
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            send(&app, "POST", &hb, None, json!({})).await.0,
            StatusCode::UNAUTHORIZED
        );
        let other = Uuid::new_v4().to_string();
        assert_eq!(
            send(&app, "POST", &hb, Some(&token(&other)), json!({}))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        let del = format!("/s/{}", urlencoding_path(&sid));
        assert_eq!(
            send(&app, "DELETE", &del, Some(&token(&other)), json!(null))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(&app, "DELETE", &del, Some(&token(&sub)), json!(null))
                .await
                .0,
            StatusCode::NO_CONTENT
        );
    }

    #[tokio::test]
    async fn key_request_requires_token() {
        let app = app();
        let body =
            json!({"sessionId": "s", "assetId": "a", "spcData": "AQID", "tdfManifest": "e30="});
        assert_eq!(
            send(&app, "POST", "/key", None, body).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn key_request_refuses_tdf3_shape() {
        let app = app();
        let body = json!({
            "sessionId": "s", "assetId": "a",
            "nanotdfHeader": "AAAA", "clientPublicKey": "pem",
        });
        let tok = token(&Uuid::new_v4().to_string());
        assert_eq!(
            send(&app, "POST", "/key", Some(&tok), body).await.0,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn key_request_for_another_subjects_session_is_403() {
        let app = app();
        let owner = Uuid::new_v4().to_string();
        let sid = start_fairplay_session(&app, &owner).await;
        let body = json!({
            "sessionId": sid, "assetId": "a", "spcData": "AQID", "tdfManifest": "e30=",
        });
        let other = token(&Uuid::new_v4().to_string());
        assert_eq!(
            send(&app, "POST", "/key", Some(&other), body).await.0,
            StatusCode::FORBIDDEN
        );
    }

    /// A store outage is a 503 with a static reason: no Redis error text.
    #[tokio::test]
    async fn session_store_outage_is_503_without_detail() {
        let app = app_with_redis("redis://127.0.0.1:1");
        let tok = token(&Uuid::new_v4().to_string());
        let body = json!({"assetId": "a", "protocol": "fairplay"});
        let (st, v) = send(&app, "POST", "/start", Some(&tok), body).await;
        assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(v["message"], "session store unavailable");
        for (m, uri) in [("POST", "/s/x/heartbeat"), ("DELETE", "/s/x")] {
            let (st, v) = send(&app, m, uri, Some(&tok), json!({})).await;
            assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "{m} {uri}");
            assert_eq!(v["message"], "session store unavailable");
        }
    }

    /// End to end through the router: a person starts a FairPlay session,
    /// then gets a CKC for the fixture manifest on a platform permit.
    #[tokio::test]
    async fn owned_fairplay_session_gets_a_license() {
        use super::license_pipeline_tests::{
            license_authz, manifest, platform, rewrap_state_with_rsa,
        };
        use crate::modules::license::issuer::test_support::FakeIssuer;
        let server = platform("DECISION_PERMIT").await;
        let mut st = state_with_redis(&redis_url());
        st.rewrap_state = rewrap_state_with_rsa();
        st.license = Some(license_authz(&server));
        st.issuer = Some(Arc::new(FakeIssuer::new(Some(
            "3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b",
        ))));
        let app = router(st);

        let sub = Uuid::new_v4().to_string();
        let sid = start_fairplay_session(&app, &sub).await;
        let b64 = base64::engine::general_purpose::STANDARD;
        let body = json!({
            "sessionId": sid, "assetId": "a",
            "spcData": b64.encode([1u8, 2, 3]),
            "tdfManifest": b64.encode(manifest()),
        });
        let (status, v) = send(&app, "POST", "/key", Some(&token(&sub)), body).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        assert_eq!(v["wrappedKey"], b64.encode(b"fake-ckc"));
        assert_eq!(v["metadata"]["protocol"], "fairplay");
        assert_eq!(v["status"], "success");
    }
}
