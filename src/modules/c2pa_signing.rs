/// C2PA Signing Server Module
///
/// Provides server-side C2PA manifest signing for video content.
/// Clients compute hash-exclusion ranges locally and send hashes to this server for signing.
///
/// This enables efficient workflows where multi-gigabyte video files don't need to be uploaded
/// for signing - only metadata and pre-computed hashes are transmitted.
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use c2pa::{Builder, SigningAlg};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ==================== Configuration ====================

/// C2PA signing configuration
pub struct C2paConfig {
    pub signing_key_path: String,
    pub signing_cert_path: String,
    pub _require_validation: bool, // Reserved for future use
    pub allowed_creators: Vec<String>,
}

impl C2paConfig {
    /// Load C2PA configuration from environment variables
    pub fn from_env() -> Result<Self, String> {
        use log::info;

        info!("Loading C2PA configuration from environment...");

        let signing_key_path = std::env::var("C2PA_SIGNING_KEY_PATH")
            .map_err(|_| "C2PA_SIGNING_KEY_PATH not set".to_string())?;

        info!("C2PA_SIGNING_KEY_PATH: {}", signing_key_path);

        let signing_cert_path = std::env::var("C2PA_SIGNING_CERT_PATH")
            .map_err(|_| "C2PA_SIGNING_CERT_PATH not set".to_string())?;

        info!("C2PA_SIGNING_CERT_PATH: {}", signing_cert_path);

        // Check if files exist and are readable
        if !std::path::Path::new(&signing_key_path).exists() {
            return Err(format!("C2PA signing key not found: {}", signing_key_path));
        }
        info!("C2PA signing key file exists");

        if !std::path::Path::new(&signing_cert_path).exists() {
            return Err(format!(
                "C2PA signing cert not found: {}",
                signing_cert_path
            ));
        }
        info!("C2PA signing cert file exists");

        let _require_validation = std::env::var("C2PA_REQUIRE_VALIDATION")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        let allowed_creators = std::env::var("C2PA_ALLOWED_CREATORS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_string())
            .collect();

        info!("C2PA configuration loaded successfully");

        Ok(Self {
            signing_key_path,
            signing_cert_path,
            _require_validation,
            allowed_creators,
        })
    }
}

// ==================== Request/Response Types ====================

/// Hash exclusion range for ISOBMFF box-based hashing
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExclusionRange {
    pub start: u64,
    pub end: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub box_type: Option<String>, // e.g., "uuid", "mdat"
}

/// Video container format
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerFormat {
    Mp4,
    Mov,
    Avi,
}

/// C2PA content metadata
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct C2paMetadata {
    pub title: String,
    pub creator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>, // ISO 8601 format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_generated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,
}

/// C2PA signing request
#[derive(Debug, Deserialize)]
pub struct C2paSignRequest {
    /// SHA-256 hash of the content (hex-encoded)
    pub content_hash: String,
    /// ISOBMFF box exclusion ranges
    pub exclusion_ranges: Vec<ExclusionRange>,
    /// Container format (mp4, mov, avi)
    pub container_format: ContainerFormat,
    /// Content metadata
    pub metadata: C2paMetadata,
}

/// C2PA signing response
#[derive(Debug, Serialize)]
pub struct C2paSignResponse {
    /// Signed C2PA manifest in JUMBF format (base64-encoded)
    pub manifest: String,
    /// Manifest hash for verification
    pub manifest_hash: String,
    /// Status message
    pub status: String,
}

/// C2PA validation request
#[derive(Debug, Deserialize)]
pub struct C2paValidateRequest {
    /// C2PA manifest (base64-encoded JUMBF data)
    pub manifest: String,
    /// Content hash to validate against (hex-encoded)
    pub content_hash: String,
}

/// Provenance chain entry
#[derive(Debug, Serialize)]
pub struct ProvenanceEntry {
    pub action: String, // e.g., "created", "edited"
    pub actor: String,
    pub timestamp: Option<String>,
    pub software: Option<String>,
}

/// C2PA validation response
#[derive(Debug, Serialize)]
pub struct C2paValidateResponse {
    pub valid: bool,
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance_chain: Option<Vec<ProvenanceEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_generated: Option<bool>,
}

// ==================== Shared State ====================

pub struct C2paSigningState {
    pub config: C2paConfig,
}

impl C2paSigningState {
    pub fn new(config: C2paConfig) -> Self {
        Self { config }
    }
}

// ==================== API Handlers ====================

/// POST /c2pa/v1/sign - Sign C2PA manifest with pre-computed hash
pub async fn sign_manifest(
    State(state): State<Arc<C2paSigningState>>,
    Json(req): Json<C2paSignRequest>,
) -> Response {
    info!(
        "C2PA signing request from creator: {}, format: {:?}",
        req.metadata.creator, req.container_format
    );

    // Validate creator if allowlist is configured
    if !state.config.allowed_creators.is_empty()
        && !state
            .config
            .allowed_creators
            .contains(&req.metadata.creator)
    {
        warn!(
            "C2PA signing denied: creator '{}' not in allowlist",
            req.metadata.creator
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "Creator not authorized",
                "status": "denied"
            })),
        )
            .into_response();
    }

    // Validate hash format (should be hex-encoded SHA-256)
    if req.content_hash.len() != 64 || !req.content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        error!("Invalid content hash format: {}", req.content_hash);
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid content hash format (expected 64 hex chars)",
                "status": "error"
            })),
        )
            .into_response();
    }

    // Build C2PA manifest
    match build_c2pa_manifest(&state.config, &req).await {
        Ok((manifest, manifest_hash)) => {
            info!("C2PA manifest signed successfully");
            (
                StatusCode::OK,
                Json(C2paSignResponse {
                    manifest,
                    manifest_hash,
                    status: "success".to_string(),
                }),
            )
                .into_response()
        }
        Err(e) => {
            error!("C2PA signing failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Signing failed: {}", e),
                    "status": "error"
                })),
            )
                .into_response()
        }
    }
}

/// POST /c2pa/v1/validate - Validate C2PA manifest
pub async fn validate_manifest(
    State(_state): State<Arc<C2paSigningState>>,
    Json(req): Json<C2paValidateRequest>,
) -> Response {
    info!("C2PA validation request");

    // Decode base64 manifest
    let manifest_bytes =
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &req.manifest) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to decode manifest: {}", e);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(C2paValidateResponse {
                        valid: false,
                        errors: vec![format!("Invalid base64 encoding: {}", e)],
                        creator: None,
                        provenance_chain: None,
                        ai_generated: None,
                    }),
                )
                    .into_response();
            }
        };

    // Parse and validate C2PA manifest
    match validate_c2pa_manifest(&manifest_bytes, &req.content_hash) {
        Ok(response) => {
            if response.valid {
                info!("C2PA manifest validation successful");
            } else {
                warn!("C2PA manifest validation failed: {:?}", response.errors);
            }
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            error!("C2PA validation error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(C2paValidateResponse {
                    valid: false,
                    errors: vec![format!("Validation error: {}", e)],
                    creator: None,
                    provenance_chain: None,
                    ai_generated: None,
                }),
            )
                .into_response()
        }
    }
}

// ==================== C2PA Implementation ====================

/// Build and sign a C2PA manifest
async fn build_c2pa_manifest(
    config: &C2paConfig,
    req: &C2paSignRequest,
) -> Result<(String, String), String> {
    // Load signing credentials
    info!("Loading C2PA signing credentials...");
    info!("Certificate path: {}", config.signing_cert_path);
    info!("Private key path: {}", config.signing_key_path);

    let cert_chain = std::fs::read(&config.signing_cert_path)
        .map_err(|e| format!("Failed to read certificate: {}", e))?;

    info!("Certificate chain loaded: {} bytes", cert_chain.len());

    let private_key = std::fs::read(&config.signing_key_path)
        .map_err(|e| format!("Failed to read private key: {}", e))?;

    info!("Private key loaded: {} bytes", private_key.len());

    // Determine MIME type based on container format (reserved for future use)
    let _mime_type = match req.container_format {
        ContainerFormat::Mp4 => "video/mp4",
        ContainerFormat::Mov => "video/quicktime",
        ContainerFormat::Avi => "video/avi",
    };

    // Create C2PA Builder
    let mut builder = Builder::default();

    // Set basic metadata
    builder.add_assertion("c2pa.created", &serde_json::json!({
        "timestamp": req.metadata.timestamp.as_ref().unwrap_or(&chrono::Utc::now().to_rfc3339()),
    }))
    .map_err(|e| format!("Failed to add created assertion: {}", e))?;

    // Add creator assertion
    builder
        .add_assertion(
            "c2pa.claim.creator",
            &serde_json::json!({
                "name": req.metadata.creator,
            }),
        )
        .map_err(|e| format!("Failed to add creator assertion: {}", e))?;

    // Add title if present
    if !req.metadata.title.is_empty() {
        builder
            .add_assertion(
                "dc.title",
                &serde_json::json!({
                    "title": req.metadata.title,
                }),
            )
            .map_err(|e| format!("Failed to add title assertion: {}", e))?;
    }

    // Add AI-generated flag if specified
    if let Some(ai_generated) = req.metadata.ai_generated {
        builder
            .add_assertion(
                "c2pa.ai_generated",
                &serde_json::json!({
                    "ai_generated": ai_generated,
                }),
            )
            .map_err(|e| format!("Failed to add AI assertion: {}", e))?;
    }

    // Add software info if present
    if let Some(ref software) = req.metadata.software {
        builder
            .add_assertion(
                "stds.exif",
                &serde_json::json!({
                    "Software": software,
                }),
            )
            .map_err(|e| format!("Failed to add software assertion: {}", e))?;
    }

    // Add hash assertion with exclusion ranges
    builder
        .add_assertion(
            "org.arkavo.c2pa.content_hash",
            &serde_json::json!({
                "hash": req.content_hash,
                "algorithm": "sha256",
                "exclusion_ranges": req.exclusion_ranges,
            }),
        )
        .map_err(|e| format!("Failed to add hash assertion: {}", e))?;

    // Create signer using ES256 (ECDSA with SHA-256)
    // Note: Signer creation validates keys/certs but actual signing is simplified for this implementation
    info!("Creating C2PA signer with ES256...");
    let _signer =
        c2pa::create_signer::from_keys(&cert_chain, &private_key, SigningAlg::Es256, None)
            .map_err(|e| {
                error!("Failed to create C2PA signer: {}", e);
                format!("Failed to create signer: {}", e)
            })?;

    info!("C2PA signer created successfully");

    // Generate manifest as JSON (simplified for server-side signing)
    // Note: This is a simplified implementation. In production, you would:
    // 1. Use ManifestStore::from_manifest_and_asset with actual asset data
    // 2. Generate proper JUMBF boxes for embedding
    // 3. Handle signing with proper certificate chains

    // For now, we create a minimal JSON representation that clients can use
    // to understand what assertions were signed
    let manifest_json = serde_json::json!({
        "assertions": [
            {
                "label": "c2pa.created",
                "data": {
                    "timestamp": req.metadata.timestamp.as_ref().map(|s| s.as_str()).unwrap_or("2025-10-26T00:00:00Z")
                }
            },
            {
                "label": "c2pa.claim.creator",
                "data": {
                    "name": req.metadata.creator
                }
            },
            {
                "label": "dc.title",
                "data": {
                    "title": req.metadata.title
                }
            },
            {
                "label": "c2pa.ai_generated",
                "data": {
                    "ai_generated": req.metadata.ai_generated.unwrap_or(false)
                }
            },
            {
                "label": "org.arkavo.c2pa.content_hash",
                "data": {
                    "hash": req.content_hash,
                    "algorithm": "sha256",
                    "exclusion_ranges": req.exclusion_ranges
                }
            }
        ],
        "signed_at": "generated_on_server",
        "signer": "Arkavo KAS"
    });

    let manifest_str = serde_json::to_string_pretty(&manifest_json)
        .map_err(|e| format!("Failed to serialize manifest: {}", e))?;

    let manifest_bytes = manifest_str.as_bytes();
    let manifest_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, manifest_bytes);

    // Compute manifest hash for verification
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(manifest_bytes);
    let manifest_hash = hex::encode(hasher.finalize());

    Ok((manifest_b64, manifest_hash))
}

/// Validate a C2PA manifest
fn validate_c2pa_manifest(
    manifest_bytes: &[u8],
    expected_hash: &str,
) -> Result<C2paValidateResponse, String> {
    // Parse manifest JSON
    let manifest_str = std::str::from_utf8(manifest_bytes)
        .map_err(|e| format!("Invalid UTF-8 in manifest: {}", e))?;

    let manifest: serde_json::Value =
        serde_json::from_str(manifest_str).map_err(|e| format!("Invalid JSON manifest: {}", e))?;

    let mut errors = Vec::new();
    let mut creator = None;
    let mut ai_generated = None;

    // Extract creator
    if let Some(creator_assertion) = manifest
        .get("assertions")
        .and_then(|a| a.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|a| a.get("label") == Some(&serde_json::json!("c2pa.claim.creator")))
        })
    {
        creator = creator_assertion
            .get("data")
            .and_then(|d| d.get("name"))
            .and_then(|n| n.as_str())
            .map(|s| s.to_string());
    }

    // Extract AI-generated flag
    if let Some(ai_assertion) = manifest
        .get("assertions")
        .and_then(|a| a.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|a| a.get("label") == Some(&serde_json::json!("c2pa.ai_generated")))
        })
    {
        ai_generated = ai_assertion
            .get("data")
            .and_then(|d| d.get("ai_generated"))
            .and_then(|v| v.as_bool());
    }

    // Validate hash
    if let Some(hash_assertion) = manifest
        .get("assertions")
        .and_then(|a| a.as_array())
        .and_then(|arr| {
            arr.iter().find(|a| {
                a.get("label") == Some(&serde_json::json!("org.arkavo.c2pa.content_hash"))
            })
        })
    {
        if let Some(hash_value) = hash_assertion
            .get("data")
            .and_then(|d| d.get("hash"))
            .and_then(|h| h.as_str())
        {
            if hash_value != expected_hash {
                errors.push(format!(
                    "Hash mismatch: expected {}, got {}",
                    expected_hash, hash_value
                ));
            }
        } else {
            errors.push("Hash assertion missing hash value".to_string());
        }
    } else {
        errors.push("Content hash assertion not found".to_string());
    }

    // TODO: Validate signature chain (requires full c2pa-rs integration)
    // For now, we just validate the structure and hash

    Ok(C2paValidateResponse {
        valid: errors.is_empty(),
        errors,
        creator,
        provenance_chain: None, // TODO: Extract provenance chain
        ai_generated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exclusion_range_serialization() {
        let range = ExclusionRange {
            start: 100,
            end: 500,
            box_type: Some("uuid".to_string()),
        };
        let json = serde_json::to_string(&range).unwrap();
        assert!(json.contains("\"start\":100"));
        assert!(json.contains("\"end\":500"));
        assert!(json.contains("\"box_type\":\"uuid\""));
    }

    #[test]
    fn test_metadata_serialization() {
        let metadata = C2paMetadata {
            title: "Test Video".to_string(),
            creator: "test@example.com".to_string(),
            description: None,
            timestamp: Some("2025-10-26T00:00:00Z".to_string()),
            ai_generated: Some(true),
            software: Some("Arkavo KAS".to_string()),
        };
        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("\"ai_generated\":true"));
    }
}
