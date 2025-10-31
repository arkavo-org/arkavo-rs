use crate::modules::crypto;
use crate::modules::dpop;
use crate::modules::terminal_link_ntdf;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use log::{error, info, warn};
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
    pub enable_dpop: bool, // Enable DPoP validation
    pub ntdf_expected_audience: String, // Expected audience for NTDF token validation
}

/// Rewrap request wrapper
#[derive(Debug, Deserialize)]
pub struct SignedRewrapRequest {
    pub signed_request_token: String, // JSON string of UnsignedRewrapRequest (no JWT wrapping)
}

/// Unwrapped rewrap request structure
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedRewrapRequest {
    pub client_public_key: String, // PEM format
    pub requests: Vec<RewrapRequestEntry>,
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
#[derive(Debug, Deserialize)]
pub struct PublicKeyQuery {
    pub algorithm: Option<String>, // "ec" or "rsa", defaults to "ec"
}

/// KAS public key endpoint handler
/// GET /kas/v2/kas_public_key?algorithm=rsa
pub async fn kas_public_key_handler(
    State(state): State<Arc<RewrapState>>,
    Query(params): Query<PublicKeyQuery>,
) -> Result<String, ErrorResponse> {
    // Determine which key to return based on algorithm parameter
    let algorithm = params.algorithm.as_deref().unwrap_or("ec");

    match algorithm {
        "rsa" => {
            if let Some(ref rsa_public_key_pem) = state.kas_rsa_public_key_pem {
                Ok(rsa_public_key_pem.clone())
            } else {
                Err(ErrorResponse {
                    error: "not_configured".to_string(),
                    message: "RSA keys not configured. Set KAS_RSA_KEY_PATH environment variable to enable RSA support.".to_string(),
                })
            }
        }
        "ec" => Ok(state.kas_ec_public_key_pem.clone()),
        _ => Err(ErrorResponse {
            error: "invalid_algorithm".to_string(),
            message: format!("Unsupported algorithm: {}. Use 'ec' or 'rsa'", algorithm),
        }),
    }
}

/// Main rewrap endpoint handler
/// POST /kas/v2/rewrap
pub async fn rewrap_handler(
    State(state): State<Arc<RewrapState>>,
    headers: HeaderMap,
    Json(payload): Json<SignedRewrapRequest>,
) -> Result<Json<RewrapResponse>, ErrorResponse> {
    info!("Received rewrap request");

    // 0a. Validate NTDF token from Authorization header
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(ErrorResponse {
            error: "authentication_failed".to_string(),
            message: "Missing Authorization header".to_string(),
        })?;

    let z85_token = auth_header
        .strip_prefix("NTDF ")
        .ok_or(ErrorResponse {
            error: "authentication_failed".to_string(),
            message: "Invalid Authorization scheme (expected 'NTDF')".to_string(),
        })?;

    // Convert KAS private key to PEM for validation
    use p256::pkcs8::EncodePrivateKey;
    let kas_private_key_pem = state
        .kas_ec_private_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| ErrorResponse {
            error: "internal_error".to_string(),
            message: format!("Failed to encode KAS private key: {}", e),
        })?;

    let validated_ntdf_claims =
        match terminal_link_ntdf::validate_ntdf_token(z85_token, kas_private_key_pem.as_bytes(), &state.ntdf_expected_audience) {
            Ok(terminal_link_ntdf::ValidationResult::Valid(claims)) => {
                info!(
                    "NTDF token valid for user: {:?}",
                    hex::encode(claims.sub_id)
                );
                claims
            }
            Ok(result) => {
                warn!("NTDF token validation failed: {:?}", result);
                return Err(ErrorResponse {
                    error: "authentication_failed".to_string(),
                    message: format!("NTDF token validation failed: {:?}", result),
                });
            }
            Err(e) => {
                error!("NTDF token validation error: {}", e);
                return Err(ErrorResponse {
                    error: "authentication_failed".to_string(),
                    message: format!("NTDF token validation error: {}", e),
                });
            }
        };

    // 0b. Validate DPoP if enabled
    if state.enable_dpop {
        if let Some(dpop_header) = headers.get("DPoP") {
            if let Ok(dpop_proof) = dpop_header.to_str() {
                // Get HTTP method and URI from request context
                let http_method = "POST"; // Rewrap is always POST
                let http_uri = "/kas/v2/rewrap"; // Standard rewrap URI

                // Use Z85-encoded NTDF token for ath validation
                let access_token = Some(z85_token);

                match dpop::validate_dpop_proof(dpop_proof, http_method, http_uri, access_token, 60) {
                    Ok(dpop::DPoPValidationResult::Valid { jti, jwk_thumbprint }) => {
                        info!("DPoP proof valid: jti={}, thumbprint={}", jti, jwk_thumbprint);

                        // Verify JTI matches NTDF token dpop_jti if present
                        if let Some(ref expected_jti) = validated_ntdf_claims.dpop_jti {
                            let jti_bytes = jti.as_bytes();
                            if jti_bytes.len() != 16 || jti_bytes != expected_jti {
                                warn!("DPoP JTI mismatch");
                                return Err(ErrorResponse {
                                    error: "authentication_failed".to_string(),
                                    message: "DPoP JTI mismatch".to_string(),
                                });
                            }
                        }
                    }
                    Ok(result) => {
                        warn!("DPoP validation failed: {:?}", result);
                        return Err(ErrorResponse {
                            error: "authentication_failed".to_string(),
                            message: format!("DPoP validation failed: {:?}", result),
                        });
                    }
                    Err(e) => {
                        error!("DPoP validation error: {}", e);
                        return Err(ErrorResponse {
                            error: "authentication_failed".to_string(),
                            message: format!("DPoP validation error: {}", e),
                        });
                    }
                }
            } else {
                warn!("Invalid DPoP header");
                return Err(ErrorResponse {
                    error: "authentication_failed".to_string(),
                    message: "Invalid DPoP header".to_string(),
                });
            }
        } else {
            warn!("Missing DPoP header");
            return Err(ErrorResponse {
                error: "authentication_failed".to_string(),
                message: "Missing DPoP header".to_string(),
            });
        }
    }

    // 1. Parse unsigned request directly (no OAuth JWT wrapping)
    let unsigned_request: UnsignedRewrapRequest = serde_json::from_str(&payload.signed_request_token)
        .map_err(|e| ErrorResponse {
            error: "invalid_request".to_string(),
            message: format!("Failed to parse rewrap request: {}", e),
        })?;

    // 2. Parse client public key from PEM
    let client_public_key = parse_pem_public_key(&unsigned_request.client_public_key)?;

    // 3. Generate ephemeral session key pair
    let session_private_key = EphemeralSecret::random(&mut OsRng);
    let session_public_key = P256PublicKey::from(&session_private_key);
    let session_public_key_pem = public_key_to_pem(&session_public_key)?;

    // 4. Perform ECDH with client public key
    let session_shared_secret = session_private_key.diffie_hellman(&client_public_key);
    let session_shared_secret_bytes = session_shared_secret.raw_secret_bytes();

    // 5. Process each rewrap request
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
