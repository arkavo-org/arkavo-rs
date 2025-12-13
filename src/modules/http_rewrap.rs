use crate::modules::crypto;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use log::{error, info, warn};
use nanotdf::chain::{ChainValidationRequest, SessionValidator, ValidationError};
use nanotdf::BinaryParser;
use p256::{ecdh::EphemeralSecret, PublicKey as P256PublicKey, SecretKey};
use rand_core::OsRng;
use rsa::{Oaep, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::sync::Arc;

/// Server state shared with rewrap endpoint
pub struct RewrapState {
    pub kas_ec_private_key: SecretKey,
    pub kas_ec_public_key_pem: String,
    pub kas_rsa_private_key: Option<RsaPrivateKey>,
    pub kas_rsa_public_key_pem: Option<String>,
    pub oauth_public_key_pem: Option<String>, // Optional OAuth public key for JWT validation
    pub chain_validator: Option<Arc<dyn SessionValidator>>, // Chain-driven session validator
}

/// Signed rewrap request wrapper (outer envelope)
#[derive(Debug, Deserialize)]
pub struct SignedRewrapRequest {
    pub signed_request_token: String,
}

/// JWT claims structure for the signed request
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct JWTClaims {
    #[serde(rename = "requestBody")]
    pub request_body: String, // JSON string of UnsignedRewrapRequest
    pub iat: i64,
    pub exp: i64,
}

/// Unsigned rewrap request structure (inner payload)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedRewrapRequest {
    pub client_public_key: String, // PEM format
    pub requests: Vec<RewrapRequestEntry>,
    // Chain validation fields (optional for backward compatibility)
    pub chain_session_id: Option<String>, // Chain session ID (hex-encoded)
    pub chain_header_hash: Option<String>, // SHA256 of header bytes (hex-encoded, DPoP binding)
    pub chain_signature: Option<String>,  // ECDSA signature (base64)
    pub chain_nonce: Option<u64>,         // Replay prevention nonce
    pub chain_algorithm: Option<String>,  // "ES256", "ES384", defaults to "ES256"
}

/// Individual rewrap request entry
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct RewrapRequestEntry {
    pub algorithm: String, // "ec:secp256r1"
    pub policy: Policy,
    pub key_access_objects: Vec<KeyAccessObjectWrapper>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyAccessObjectWrapper {
    pub key_access_object_id: String,
    pub key_access_object: KeyAccessObject,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct KeyAccessObject {
    pub header: String, // Base64-encoded NanoTDF header
    #[serde(rename = "type")]
    pub type_field: String,
    pub url: String,
    pub protocol: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Policy {
    pub id: String,
    pub body: String, // Base64-encoded policy
}

/// Rewrap response structure
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RewrapResponse {
    pub responses: Vec<ResponsePolicyEntry>,
    pub session_public_key: String, // PEM format
    pub schema_version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponsePolicyEntry {
    pub policy_id: String,
    pub results: Vec<KASResult>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KASResult {
    pub key_access_object_id: String,
    pub status: String,                  // "permit" or "fail"
    pub kas_wrapped_key: Option<String>, // Base64
    pub metadata: Option<serde_json::Value>,
}

/// Error response for rewrap failures
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        let status = if self.error == "authentication_failed" {
            StatusCode::UNAUTHORIZED
        } else if self.error == "policy_denied" {
            StatusCode::FORBIDDEN
        } else if self.error == "invalid_request" {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        (status, Json(self)).into_response()
    }
}

/// Query parameters for public key endpoint
/// Matches OpenTDF spec: algorithm (rsa:2048, ec:secp256r1), fmt (pkcs8, jwk), v (legacy)
#[derive(Debug, Deserialize)]
pub struct PublicKeyQuery {
    /// Algorithm: "rsa:2048", "ec:secp256r1", or legacy "ec"/"rsa"
    pub algorithm: Option<String>,
    /// Format: "pkcs8" (default) or "jwk" (RSA only)
    pub fmt: Option<String>,
    /// Legacy version flag: when "1", hides kid in response
    pub v: Option<String>,
}

/// Response structure matching OpenTDF spec
#[derive(Debug, Serialize)]
pub struct PublicKeyResponse {
    /// PEM-encoded public key (or JWK for RSA with fmt=jwk)
    pub public_key: String,
    /// Key identifier (omitted when v=1 for legacy clients)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// KAS public key endpoint handler
/// GET /kas/v2/kas_public_key?algorithm=ec:secp256r1
/// Implements OpenTDF spec: https://github.com/opentdf/spec
pub async fn kas_public_key_handler(
    State(state): State<Arc<RewrapState>>,
    Query(params): Query<PublicKeyQuery>,
) -> Result<Json<PublicKeyResponse>, ErrorResponse> {
    // Parse algorithm - support both OpenTDF format (ec:secp256r1) and legacy (ec)
    let algorithm = params.algorithm.as_deref().unwrap_or("ec:secp256r1");
    let format = params.fmt.as_deref().unwrap_or("pkcs8");
    let is_legacy = params.v.as_deref() == Some("1");

    info!(
        "KAS public key request: algorithm={}, fmt={}, legacy={}",
        algorithm, format, is_legacy
    );

    // Normalize algorithm to determine key type
    let is_rsa = algorithm.starts_with("rsa") || algorithm == "rsa";
    let is_ec = algorithm.starts_with("ec") || algorithm == "ec" || algorithm.contains("secp256");

    let (public_key, kid) = if is_rsa {
        if let Some(ref rsa_public_key_pem) = state.kas_rsa_public_key_pem {
            // TODO: Support JWK format for RSA when fmt=jwk
            if format == "jwk" {
                warn!("JWK format requested but not yet implemented, returning PKCS8");
            }
            (rsa_public_key_pem.clone(), "rsa:2048".to_string())
        } else {
            warn!("RSA key requested but not configured");
            return Err(ErrorResponse {
                error: "not_found".to_string(),
                message: "no default key for algorithm rsa:2048".to_string(),
            });
        }
    } else if is_ec {
        (
            state.kas_ec_public_key_pem.clone(),
            "ec:secp256r1".to_string(),
        )
    } else {
        warn!("Unsupported algorithm requested: {}", algorithm);
        return Err(ErrorResponse {
            error: "invalid_argument".to_string(),
            message: format!(
                "Unsupported algorithm: {}. Use 'ec:secp256r1' or 'rsa:2048'",
                algorithm
            ),
        });
    };

    // Hide kid for legacy clients (v=1)
    let kid = if is_legacy {
        warn!("hiding kid in public key response for legacy client");
        None
    } else {
        Some(kid)
    };

    Ok(Json(PublicKeyResponse { public_key, kid }))
}

/// Main rewrap endpoint handler
/// POST /kas/v2/rewrap
pub async fn rewrap_handler(
    State(state): State<Arc<RewrapState>>,
    Json(payload): Json<SignedRewrapRequest>,
) -> Result<Json<RewrapResponse>, ErrorResponse> {
    info!("Received rewrap request");

    // 1. Verify and decode JWT
    let unsigned_request = verify_and_decode_jwt(
        &payload.signed_request_token,
        state.oauth_public_key_pem.as_deref(),
    )?;

    // 2. Chain-driven session validation (if configured)
    if let Some(ref validator) = state.chain_validator {
        // Chain validation is required when validator is configured
        let session_id = unsigned_request.chain_session_id.as_ref().ok_or_else(|| {
            warn!("Chain validation enabled but no session_id provided");
            ErrorResponse {
                error: "invalid_request".to_string(),
                message: "chain_session_id is required".to_string(),
            }
        })?;

        let signature = unsigned_request.chain_signature.as_ref().ok_or_else(|| {
            warn!("Chain validation enabled but no signature provided");
            ErrorResponse {
                error: "invalid_request".to_string(),
                message: "chain_signature is required".to_string(),
            }
        })?;

        let nonce = unsigned_request.chain_nonce.ok_or_else(|| {
            warn!("Chain validation enabled but no nonce provided");
            ErrorResponse {
                error: "invalid_request".to_string(),
                message: "chain_nonce is required".to_string(),
            }
        })?;

        // DPoP Header Binding: require header_hash
        let client_header_hash_hex =
            unsigned_request.chain_header_hash.as_ref().ok_or_else(|| {
                warn!("Chain validation enabled but no header_hash provided");
                ErrorResponse {
                    error: "invalid_request".to_string(),
                    message: "chain_header_hash is required for DPoP binding".to_string(),
                }
            })?;

        // Decode client-provided header_hash
        let client_header_hash_bytes =
            hex::decode(client_header_hash_hex).map_err(|e| ErrorResponse {
                error: "invalid_request".to_string(),
                message: format!("Invalid header_hash hex encoding: {}", e),
            })?;

        if client_header_hash_bytes.len() != 32 {
            return Err(ErrorResponse {
                error: "invalid_request".to_string(),
                message: format!(
                    "header_hash must be 32 bytes, got {}",
                    client_header_hash_bytes.len()
                ),
            });
        }

        // Get the actual header bytes from the first request
        let header_bytes = unsigned_request
            .requests
            .first()
            .and_then(|r| r.key_access_objects.first())
            .map(|kao| base64::decode(&kao.key_access_object.header))
            .transpose()
            .map_err(|e| ErrorResponse {
                error: "invalid_request".to_string(),
                message: format!("Invalid header base64 encoding: {}", e),
            })?
            .ok_or_else(|| ErrorResponse {
                error: "invalid_request".to_string(),
                message: "No key access object found".to_string(),
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
                message: "header_hash does not match actual header content".to_string(),
            });
        }

        // Build validation request with verified header_hash
        let validation_request = ChainValidationRequest {
            session_id: session_id.clone(),
            header_hash: server_header_hash, // Use server-computed (verified) hash
            resource_id: hex::encode(server_header_hash), // Keep for logging
            signature: base64::decode(signature).map_err(|e| ErrorResponse {
                error: "invalid_request".to_string(),
                message: format!("Invalid signature encoding: {}", e),
            })?,
            algorithm: unsigned_request
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
            }
            Err(e) => {
                warn!("Chain validation failed: {:?}", e);
                return Err(match e {
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
                        message: format!(
                            "Header hash mismatch: client={}, server={}",
                            client, server
                        ),
                    },
                    ValidationError::Chain(chain_err) => ErrorResponse {
                        error: "internal_error".to_string(),
                        message: format!("Chain query failed: {}", chain_err),
                    },
                    ValidationError::Crypto(err) => ErrorResponse {
                        error: "internal_error".to_string(),
                        message: format!("Crypto error: {}", err),
                    },
                });
            }
        }
    }

    // 3. Parse client public key from PEM
    let client_public_key = parse_pem_public_key(&unsigned_request.client_public_key)?;

    // 4. Generate ephemeral session key pair
    let session_private_key = EphemeralSecret::random(&mut OsRng);
    let session_public_key = P256PublicKey::from(&session_private_key);
    let session_public_key_pem = public_key_to_pem(&session_public_key)?;

    // 5. Perform ECDH with client public key
    let session_shared_secret = session_private_key.diffie_hellman(&client_public_key);
    let session_shared_secret_bytes = session_shared_secret.raw_secret_bytes();

    // 6. Process each rewrap request
    let mut responses = Vec::new();

    for request_entry in unsigned_request.requests {
        let mut results = Vec::new();

        for kao_wrapper in request_entry.key_access_objects {
            match process_key_access_object(
                &kao_wrapper,
                &request_entry.algorithm,
                &state,
                session_shared_secret_bytes.as_ref(),
            ) {
                Ok(wrapped_key_base64) => {
                    results.push(KASResult {
                        key_access_object_id: kao_wrapper.key_access_object_id.clone(),
                        status: "permit".to_string(),
                        kas_wrapped_key: Some(wrapped_key_base64),
                        metadata: None,
                    });
                }
                Err(e) => {
                    error!("Failed to process key access object: {}", e);
                    results.push(KASResult {
                        key_access_object_id: kao_wrapper.key_access_object_id.clone(),
                        status: "fail".to_string(),
                        kas_wrapped_key: None,
                        metadata: Some(serde_json::json!({ "error": e.to_string() })),
                    });
                }
            }
        }

        responses.push(ResponsePolicyEntry {
            policy_id: request_entry.policy.id,
            results,
        });
    }

    Ok(Json(RewrapResponse {
        responses,
        session_public_key: session_public_key_pem,
        schema_version: "1.0.0".to_string(),
    }))
}

/// Process a single key access object
fn process_key_access_object(
    kao_wrapper: &KeyAccessObjectWrapper,
    algorithm: &str,
    state: &Arc<RewrapState>,
    session_shared_secret: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    // Determine algorithm type based on request
    // Per OpenTDF spec: empty algorithm indicates Standard TDF with RSA-OAEP
    // NanoTDF explicitly uses "ec:secp256r1" format
    // Valid values: "" (Standard TDF/RSA), "ec:secp256r1" (NanoTDF), "rsa:2048" (Standard TDF)
    let is_rsa = algorithm.is_empty() || algorithm.starts_with("rsa");
    let is_ec = algorithm.starts_with("ec");

    if is_rsa {
        // RSA unwrap path for Standard TDF
        process_rsa_unwrap(kao_wrapper, state, session_shared_secret)
    } else if is_ec {
        // EC unwrap path for NanoTDF
        process_ec_unwrap(
            kao_wrapper,
            &state.kas_ec_private_key,
            session_shared_secret,
        )
    } else {
        error!("Unsupported algorithm requested: {}", algorithm);
        Err(format!("Unsupported algorithm: {}", algorithm).into())
    }
}

/// Process EC (NanoTDF) unwrap
fn process_ec_unwrap(
    kao_wrapper: &KeyAccessObjectWrapper,
    kas_private_key: &SecretKey,
    session_shared_secret: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    // Decode base64 header
    let header_bytes = base64::decode(&kao_wrapper.key_access_object.header)?;

    // Parse NanoTDF header to extract ephemeral key
    let mut parser = BinaryParser::new(&header_bytes);
    let header = parser.parse_header()?;

    // Get TDF ephemeral public key
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

    // Detect NanoTDF version and compute appropriate salt
    let nanotdf_salt = if let Some(version) = crypto::detect_nanotdf_version(&header_bytes) {
        crypto::compute_nanotdf_salt(version)
    } else {
        crypto::compute_nanotdf_salt(crypto::NANOTDF_VERSION_V12)
    };

    // Rewrap DEK using NanoTDF-compatible HKDF (empty info)
    let (nonce, wrapped_dek) = crypto::rewrap_dek(
        &dek_shared_secret,
        session_shared_secret,
        &nanotdf_salt,
        b"", // Empty info per NanoTDF spec
    )?;

    // Combine nonce + wrapped_dek and encode as base64
    let mut combined = Vec::new();
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&wrapped_dek);

    Ok(base64::encode(&combined))
}

/// Process RSA (Standard TDF) unwrap
fn process_rsa_unwrap(
    kao_wrapper: &KeyAccessObjectWrapper,
    state: &Arc<RewrapState>,
    session_shared_secret: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    // Check if RSA key is configured
    let rsa_private_key = state
        .kas_rsa_private_key
        .as_ref()
        .ok_or("RSA key not configured")?;

    // Standard TDF KAO header contains the RSA-OAEP wrapped DEK (base64-encoded)
    let wrapped_key_bytes = base64::decode(&kao_wrapper.key_access_object.header)?;

    // Validate wrapped key size (RSA-2048 produces 256-byte ciphertext)
    if wrapped_key_bytes.len() != 256 {
        return Err(format!(
            "Invalid RSA-wrapped key size: {} bytes (expected 256 for RSA-2048)",
            wrapped_key_bytes.len()
        )
        .into());
    }

    // Unwrap DEK using RSA-OAEP with SHA-1 padding (OpenTDF compatibility)
    let padding = Oaep::new::<Sha1>();
    let dek = rsa_private_key
        .decrypt(padding, &wrapped_key_bytes)
        .map_err(|e| format!("RSA decryption failed: {}", e))?;

    // Re-wrap DEK with session shared secret using AES-256-GCM
    let (nonce, wrapped_dek) = crypto::rewrap_dek_simple(&dek, session_shared_secret)?;

    // Combine nonce + wrapped_dek and encode as base64
    let mut combined = Vec::new();
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&wrapped_dek);

    Ok(base64::encode(&combined))
}

/// Verify JWT signature and decode to UnsignedRewrapRequest
fn verify_and_decode_jwt(
    token: &str,
    oauth_public_key_pem: Option<&str>,
) -> Result<UnsignedRewrapRequest, ErrorResponse> {
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = true;

    let token_data = if let Some(pem) = oauth_public_key_pem {
        // Validate signature with provided public key
        let decoding_key = DecodingKey::from_ec_pem(pem.as_bytes()).map_err(|e| ErrorResponse {
            error: "configuration_error".to_string(),
            message: format!("Failed to load OAuth public key: {}", e),
        })?;

        decode::<JWTClaims>(token, &decoding_key, &validation).map_err(|e| ErrorResponse {
            error: "authentication_failed".to_string(),
            message: format!("JWT validation failed: {}", e),
        })?
    } else {
        // Development mode: skip signature validation
        validation.insecure_disable_signature_validation();
        decode::<JWTClaims>(token, &DecodingKey::from_secret(&[]), &validation).map_err(|e| {
            ErrorResponse {
                error: "authentication_failed".to_string(),
                message: format!("Invalid JWT: {}", e),
            }
        })?
    };

    // Parse the requestBody JSON string
    let unsigned_request: UnsignedRewrapRequest =
        serde_json::from_str(&token_data.claims.request_body).map_err(|e| ErrorResponse {
            error: "invalid_request".to_string(),
            message: format!("Failed to parse request body: {}", e),
        })?;

    Ok(unsigned_request)
}

/// Parse PEM-encoded P-256 public key
/// Parse PEM-formatted P-256 public key with ErrorResponse error conversion
fn parse_pem_public_key(pem: &str) -> Result<P256PublicKey, ErrorResponse> {
    crypto::parse_pem_public_key(pem).map_err(|e| ErrorResponse {
        error: "invalid_request".to_string(),
        message: format!("Failed to parse PEM public key: {}", e),
    })
}

/// Convert P-256 public key to PEM format with ErrorResponse error conversion
fn public_key_to_pem(public_key: &P256PublicKey) -> Result<String, ErrorResponse> {
    crypto::public_key_to_pem(public_key).map_err(|e| ErrorResponse {
        error: "internal_error".to_string(),
        message: format!("Failed to convert public key to PEM: {}", e),
    })
}

// Re-export base64 crate for this module
mod base64 {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    pub fn encode(data: &[u8]) -> String {
        STANDARD.encode(data)
    }

    pub fn decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
        STANDARD.decode(data)
    }
}
