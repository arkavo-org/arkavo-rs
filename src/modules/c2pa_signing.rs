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
use c2pa::assertions::{c2pa_action, Action, Actions, DigitalSourceType, SoftwareAgent};
use c2pa::{Builder, ClaimGeneratorInfo, Context, HashRange, Reader, SigningAlg};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::sync::Arc;

/// schema.org CreativeWork assertion carrying the author (C2PA 2.x, section 18.4).
const CREATIVE_WORK_LABEL: &str = "stds.schema-org.CreativeWork";

/// Hash-binding status c2pa-rs reports when the manifest is read without its asset.
const DATA_HASH_MISMATCH: &str = "assertion.dataHash.mismatch";

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

/// Build and sign a C2PA manifest using the hashed-data signing workflow.
///
/// The client computes a content hash with exclusion ranges and sends it to the server.
/// The server constructs a C2PA manifest with assertions, signs it using the configured
/// credentials, and returns the signed JUMBF manifest bytes for the client to embed.
async fn build_c2pa_manifest(
    config: &C2paConfig,
    req: &C2paSignRequest,
) -> Result<(String, String), String> {
    info!("Loading C2PA signing credentials...");

    let cert_chain = std::fs::read(&config.signing_cert_path)
        .map_err(|e| format!("Failed to read certificate: {}", e))?;

    let private_key = std::fs::read(&config.signing_key_path)
        .map_err(|e| format!("Failed to read private key: {}", e))?;
    let private_key = signing_key_pkcs8_pem(&private_key)?;

    // Use "c2pa" format for sign_embeddable to produce standalone JUMBF.
    // The client is responsible for embedding the JUMBF into the actual container
    // format (MP4, MOV, etc.) at the correct location.
    let _container_format = match req.container_format {
        ContainerFormat::Mp4 => "video/mp4",
        ContainerFormat::Mov => "video/quicktime",
        ContainerFormat::Avi => "video/avi",
    };
    let mime_type = "c2pa";

    // Create signer using ES256 (ECDSA with P-256)
    info!("Creating C2PA signer with ES256...");
    let signer = c2pa::create_signer::from_keys(
        &cert_chain,
        private_key.as_bytes(),
        SigningAlg::Es256,
        None,
    )
    .map_err(|e| format!("Failed to create signer: {}", e))?;

    // Build a C2PA manifest from spec assertions. Claim v2 requires a c2pa.actions
    // assertion whose first action is c2pa.created (arkavo-rs#98).
    let mut builder = Builder::from_context(Context::new().with_signer(signer));
    if !req.metadata.title.is_empty() {
        builder.definition.title = Some(req.metadata.title.clone());
    }

    let when = req
        .metadata
        .timestamp
        .clone()
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let source_type = if req.metadata.ai_generated == Some(true) {
        DigitalSourceType::TrainedAlgorithmicMedia
    } else {
        DigitalSourceType::DigitalCapture
    };
    let mut created = Action::new(c2pa_action::CREATED)
        .set_when(when)
        .set_source_type(source_type);
    if let Some(ref software) = req.metadata.software {
        created = created.set_software_agent(ClaimGeneratorInfo::new(software));
    }
    builder
        .add_action(created)
        .map_err(|e| format!("Failed to add created action: {}", e))?;

    let mut creative_work = serde_json::json!({
        "@context": "https://schema.org",
        "@type": "CreativeWork",
        "author": [{ "@type": "Person", "name": req.metadata.creator }],
    });
    if let Some(ref description) = req.metadata.description {
        creative_work["description"] = serde_json::json!(description);
    }
    builder
        .add_assertion_json(CREATIVE_WORK_LABEL, &creative_work)
        .map_err(|e| format!("Failed to add CreativeWork assertion: {}", e))?;

    // Store content hash as a custom assertion so it can be retrieved during validation
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

    // Build DataHash from client-provided hash and exclusion ranges.
    // "jumbf manifest" is the name c2pa gives the manifest exclusion.
    let mut data_hash = c2pa::assertions::DataHash::new("jumbf manifest", "sha256");

    let content_hash_bytes = hex::decode(&req.content_hash)
        .map_err(|e| format!("Failed to decode content hash: {}", e))?;
    data_hash.set_hash(content_hash_bytes);

    for range in &req.exclusion_ranges {
        let length = range.end.saturating_sub(range.start);
        data_hash.add_exclusion(HashRange::new(range.start, length));
    }

    // Add DataHash as the hard binding assertion (c2pa.hash.data). The hash is already
    // computed by the client, so sign_embeddable signs it as-is without an asset stream.
    builder
        .add_assertion(c2pa::assertions::DataHash::LABEL, &data_hash)
        .map_err(|e| format!("Failed to add data hash assertion: {}", e))?;

    // Sign with the hashed-data workflow: produces JUMBF bytes for client embedding
    info!("Signing C2PA manifest with data-hashed workflow...");
    let manifest_bytes = builder
        .sign_embeddable(mime_type)
        .map_err(|e| format!("C2PA signing failed: {}", e))?;

    info!(
        "C2PA manifest signed: {} bytes of JUMBF data",
        manifest_bytes.len()
    );

    let manifest_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &manifest_bytes);

    // Compute manifest hash for verification
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&manifest_bytes);
    let manifest_hash = hex::encode(hasher.finalize());

    Ok((manifest_b64, manifest_hash))
}

/// Normalise the P-256 signing key to PKCS#8 PEM. c2pa's rust_native_crypto signer only
/// reads PKCS#8, while `openssl ecparam -genkey` (docs/c2pa_video_drm.md) writes SEC1.
fn signing_key_pkcs8_pem(pem: &[u8]) -> Result<zeroize::Zeroizing<String>, String> {
    use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};

    let pem = std::str::from_utf8(pem).map_err(|_| "Private key is not PEM".to_string())?;
    let key = p256::SecretKey::from_pkcs8_pem(pem)
        .or_else(|_| p256::SecretKey::from_sec1_pem(pem))
        .map_err(|_| "Private key is not a P-256 PKCS#8 or SEC1 PEM key".to_string())?;
    key.to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("Failed to encode private key: {}", e))
}

/// Validate a C2PA manifest by parsing JUMBF data and verifying the signature chain.
///
/// Server-side validation verifies the COSE signature chain and extracts metadata.
/// Full asset-hash binding verification requires the actual asset (done client-side).
fn validate_c2pa_manifest(
    manifest_bytes: &[u8],
    expected_hash: &str,
) -> Result<C2paValidateResponse, String> {
    // Use Reader to parse JUMBF and verify signature chain.
    // We provide an empty stream since the actual asset is on the client side;
    // the Reader will still verify COSE signatures on the manifest itself.
    let empty_stream = Cursor::new(Vec::<u8>::new());
    let reader = Reader::from_context(Context::new())
        .with_manifest_data_and_stream(manifest_bytes, "video/mp4", empty_stream)
        .map_err(|e| format!("Failed to parse C2PA manifest: {}", e))?;

    let mut errors = Vec::new();
    let mut creator = None;
    let mut ai_generated = None;
    let mut provenance_chain = Vec::new();

    // Check validation status from c2pa-rs signature verification. The server never has
    // the asset, so the data-hash check runs against an empty stream and always mismatches;
    // the binding is checked against org.arkavo.c2pa.content_hash below instead.
    if let Some(statuses) = reader.validation_status() {
        for status in statuses {
            if status.code() == DATA_HASH_MISMATCH {
                continue;
            }
            errors.push(format!("C2PA validation: {}", status.code()));
        }
    }

    // Extract metadata from the active manifest
    if let Some(manifest) = reader.active_manifest() {
        if let Ok(work) = manifest.find_assertion::<serde_json::Value>(CREATIVE_WORK_LABEL) {
            creator = work
                .pointer("/author/0/name")
                .and_then(|n| n.as_str())
                .map(String::from);
        }

        if let Ok(actions) = manifest.find_assertion::<Actions>(Actions::LABEL) {
            for action in actions.actions() {
                if action.action() == c2pa_action::CREATED {
                    ai_generated = Some(matches!(
                        action.source_type(),
                        Some(DigitalSourceType::TrainedAlgorithmicMedia)
                    ));
                }
                let software = match action.software_agent() {
                    Some(SoftwareAgent::ClaimGeneratorInfo(info)) => Some(info.name.clone()),
                    Some(SoftwareAgent::String(name)) => Some(name.clone()),
                    None => None,
                };
                provenance_chain.push(ProvenanceEntry {
                    action: action.action().trim_start_matches("c2pa.").to_string(),
                    actor: creator.clone().unwrap_or_default(),
                    timestamp: action.when().map(String::from),
                    software,
                });
            }
        }

        match manifest.find_assertion::<serde_json::Value>("org.arkavo.c2pa.content_hash") {
            Ok(data) => match data.get("hash").and_then(|h| h.as_str()) {
                Some(hash_value) if hash_value != expected_hash => errors.push(format!(
                    "Hash mismatch: expected {}, got {}",
                    expected_hash, hash_value
                )),
                Some(_) => {}
                None => errors.push("Content hash assertion missing hash value".to_string()),
            },
            Err(_) => errors.push("Content hash assertion missing".to_string()),
        }
    } else {
        errors.push("No active manifest found".to_string());
    }

    let chain = if provenance_chain.is_empty() {
        None
    } else {
        Some(provenance_chain)
    };

    Ok(C2paValidateResponse {
        valid: errors.is_empty(),
        errors,
        creator,
        provenance_chain: chain,
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

    /// Generate a CA + end-entity P-256 cert chain for C2PA signing tests.
    /// C2PA rejects self-signed signing certificates and needs a digitalSignature key
    /// usage and an emailProtection EKU on the end-entity certificate.
    /// Returns (cert_chain_pem_path, end_entity_key_pem_path) in a temp directory.
    fn generate_test_certs() -> (std::path::PathBuf, std::path::PathBuf) {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType,
            ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
        };

        let dn = |cn: &str, o: &str| {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, cn);
            dn.push(DnType::OrganizationName, o);
            dn.push(DnType::CountryName, "US");
            dn
        };

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.distinguished_name = dn("Test CA", "Arkavo Test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let ee_key = KeyPair::generate().unwrap();
        let mut ee_params = CertificateParams::new(Vec::new()).unwrap();
        ee_params.distinguished_name = dn("C2PA Test Signer", "Arkavo Test");
        ee_params.is_ca = IsCa::ExplicitNoCa;
        ee_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        ee_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
        ee_params.use_authority_key_identifier_extension = true;
        let ee_cert = ee_params.signed_by(&ee_key, &ca_cert, &ca_key).unwrap();

        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let thread_id = format!("{:?}", std::thread::current().id());
        let dir = std::env::temp_dir().join(format!(
            "c2pa_test_certs_{}_{}",
            unique_id,
            thread_id.replace(|c: char| !c.is_alphanumeric(), "_")
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // Chain file: end-entity first, then CA
        let chain_path = dir.join("cert_chain.pem");
        let ee_key_path = dir.join("ee_key.pem");
        std::fs::write(&chain_path, format!("{}{}", ee_cert.pem(), ca_cert.pem())).unwrap();
        std::fs::write(&ee_key_path, ee_key.serialize_pem()).unwrap();

        (chain_path, ee_key_path)
    }

    fn make_test_config() -> C2paConfig {
        let (cert_path, key_path) = generate_test_certs();
        C2paConfig {
            signing_key_path: key_path.to_str().unwrap().to_string(),
            signing_cert_path: cert_path.to_str().unwrap().to_string(),
            _require_validation: false,
            allowed_creators: vec![],
        }
    }

    fn make_test_request(content_hash: &str) -> C2paSignRequest {
        C2paSignRequest {
            content_hash: content_hash.to_string(),
            exclusion_ranges: vec![ExclusionRange {
                start: 100,
                end: 500,
                box_type: Some("uuid".to_string()),
            }],
            container_format: ContainerFormat::Mp4,
            metadata: C2paMetadata {
                title: "Test Video".to_string(),
                creator: "test@example.com".to_string(),
                description: Some("A test video".to_string()),
                timestamp: Some("2025-10-26T12:00:00Z".to_string()),
                ai_generated: Some(false),
                software: Some("Arkavo Test Suite".to_string()),
            },
        }
    }

    /// Round-trip test: sign a manifest and validate it, checking metadata preservation.
    #[tokio::test]
    async fn test_c2pa_sign_and_validate_round_trip() {
        let config = make_test_config();
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let req = make_test_request(hash);

        // Sign
        let (manifest_b64, manifest_hash) = build_c2pa_manifest(&config, &req)
            .await
            .expect("Signing should succeed");

        // Manifest should be non-empty base64
        assert!(!manifest_b64.is_empty(), "Manifest should not be empty");
        assert!(
            !manifest_hash.is_empty(),
            "Manifest hash should not be empty"
        );

        // Decode and validate
        let manifest_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .expect("Should be valid base64");

        // Verify the manifest hash matches
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&manifest_bytes);
        let computed_hash = hex::encode(hasher.finalize());
        assert_eq!(manifest_hash, computed_hash, "Manifest hash should match");

        // Validate using c2pa-rs Reader
        let result =
            validate_c2pa_manifest(&manifest_bytes, hash).expect("Validation should not error");

        // Check metadata was preserved
        assert_eq!(
            result.creator.as_deref(),
            Some("test@example.com"),
            "Creator should be preserved"
        );
        assert_eq!(
            result.ai_generated,
            Some(false),
            "AI-generated flag should be preserved"
        );

        // Content hash should match
        assert!(
            !result.errors.iter().any(|e| e.contains("Hash mismatch")),
            "Content hash should match: {:?}",
            result.errors
        );
    }

    /// Test that validation detects a content hash mismatch.
    #[tokio::test]
    async fn test_c2pa_hash_mismatch_detected() {
        let config = make_test_config();
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let req = make_test_request(hash);

        // Sign with one hash
        let (manifest_b64, _) = build_c2pa_manifest(&config, &req)
            .await
            .expect("Signing should succeed");

        let manifest_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .unwrap();

        // Validate with a different hash
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = validate_c2pa_manifest(&manifest_bytes, wrong_hash)
            .expect("Validation should not error");

        assert!(
            result.errors.iter().any(|e| e.contains("Hash mismatch")),
            "Should detect hash mismatch, got errors: {:?}",
            result.errors
        );
    }

    /// Test that signing produces valid JUMBF (not JSON).
    #[tokio::test]
    async fn test_c2pa_produces_jumbf_not_json() {
        let config = make_test_config();
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let req = make_test_request(hash);

        let (manifest_b64, _) = build_c2pa_manifest(&config, &req)
            .await
            .expect("Signing should succeed");

        let manifest_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .unwrap();

        // JUMBF starts with a box header, not '{' (JSON) or other text
        assert!(
            manifest_bytes.len() > 8,
            "JUMBF manifest should be non-trivial size"
        );
        // Verify it's NOT plain JSON (the old fake implementation)
        let is_json = std::str::from_utf8(&manifest_bytes)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
            .is_some();
        assert!(!is_json, "Manifest should be JUMBF binary, not JSON");
    }

    /// Test signing with AI-generated flag set to true.
    #[tokio::test]
    async fn test_c2pa_ai_generated_flag() {
        let config = make_test_config();
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let mut req = make_test_request(hash);
        req.metadata.ai_generated = Some(true);

        let (manifest_b64, _) = build_c2pa_manifest(&config, &req)
            .await
            .expect("Signing should succeed");

        let manifest_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .unwrap();

        let result =
            validate_c2pa_manifest(&manifest_bytes, hash).expect("Validation should not error");

        assert_eq!(
            result.ai_generated,
            Some(true),
            "AI-generated=true should be preserved"
        );
    }

    /// The manifest carries spec assertions (arkavo-rs#98): a `c2pa.actions` assertion whose
    /// first action is `c2pa.created` with a digitalSourceType, and no custom `c2pa.*` labels.
    #[tokio::test]
    async fn test_c2pa_manifest_uses_spec_actions() {
        let config = make_test_config();
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let req = make_test_request(hash);

        let (manifest_b64, _) = build_c2pa_manifest(&config, &req)
            .await
            .expect("Signing should succeed");
        let manifest_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .unwrap();

        let reader = Reader::from_context(Context::new())
            .with_manifest_data_and_stream(
                &manifest_bytes,
                "video/mp4",
                Cursor::new(Vec::<u8>::new()),
            )
            .expect("Manifest should parse");
        let codes: Vec<&str> = reader
            .validation_status()
            .unwrap_or_default()
            .iter()
            .map(|s| s.code())
            .collect();
        assert!(
            !codes.contains(&"assertion.action.malformed"),
            "Actions must be well formed: {:?}",
            codes
        );

        let manifest = reader.active_manifest().expect("Active manifest");
        assert_eq!(manifest.title(), Some("Test Video"));

        let labels: Vec<&str> = manifest.assertions().iter().map(|a| a.label()).collect();
        for legacy in [
            "c2pa.created",
            "c2pa.claim.creator",
            "c2pa.ai_generated",
            "dc.title",
        ] {
            assert!(!labels.contains(&legacy), "Legacy label {legacy} emitted");
        }

        let actions: c2pa::assertions::Actions = manifest
            .find_assertion(c2pa::assertions::Actions::LABEL)
            .expect("c2pa.actions assertion");
        let first = &actions.actions()[0];
        assert_eq!(first.action(), c2pa::assertions::c2pa_action::CREATED);
        assert_eq!(first.when(), Some("2025-10-26T12:00:00Z"));
        assert!(matches!(
            first.source_type(),
            Some(c2pa::assertions::DigitalSourceType::DigitalCapture)
        ));
    }

    /// The signer accepts the SEC1 keys `openssl ecparam` writes as well as PKCS#8.
    #[test]
    fn test_signing_key_accepts_sec1_and_pkcs8() {
        use p256::pkcs8::{EncodePrivateKey, LineEnding};

        let key = p256::SecretKey::random(&mut rand_core::OsRng);
        let sec1 = key.to_sec1_pem(LineEnding::LF).unwrap();
        let pkcs8 = key.to_pkcs8_pem(LineEnding::LF).unwrap();
        assert!(sec1.starts_with("-----BEGIN EC PRIVATE KEY-----"));

        let from_sec1 = signing_key_pkcs8_pem(sec1.as_bytes()).unwrap();
        let from_pkcs8 = signing_key_pkcs8_pem(pkcs8.as_bytes()).unwrap();
        assert_eq!(*from_sec1, *pkcs8);
        assert_eq!(*from_pkcs8, *pkcs8);
        assert!(signing_key_pkcs8_pem(b"not a key").is_err());
    }

    /// Test that invalid base64 is rejected during validation.
    #[test]
    fn test_c2pa_validate_invalid_jumbf() {
        // Random bytes that aren't valid JUMBF
        let invalid_bytes = b"this is not valid JUMBF data at all";
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";

        let result = validate_c2pa_manifest(invalid_bytes, hash);
        assert!(result.is_err(), "Should fail to parse invalid JUMBF");
    }

    /// c2patool interop: sign a manifest, write JUMBF to disk, validate with c2patool.
    /// Skipped if c2patool is not installed.
    #[tokio::test]
    async fn test_c2patool_interop_validation() {
        // Check if c2patool is available
        let c2patool_check = std::process::Command::new("c2patool")
            .arg("--version")
            .output();
        let c2patool_available = c2patool_check.map(|o| o.status.success()).unwrap_or(false);
        if !c2patool_available {
            eprintln!("SKIPPED: c2patool not installed");
            return;
        }

        let config = make_test_config();
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let req = make_test_request(hash);

        // Sign
        let (manifest_b64, _) = build_c2pa_manifest(&config, &req)
            .await
            .expect("Signing should succeed");

        let manifest_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .unwrap();

        // Write JUMBF to a .c2pa file for c2patool
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let jumbf_path = std::env::temp_dir().join(format!("c2pa_interop_{}.c2pa", unique_id));
        std::fs::write(&jumbf_path, &manifest_bytes).unwrap();

        // Run c2patool to read the manifest (detailed JSON output)
        let output = std::process::Command::new("c2patool")
            .arg(&jumbf_path)
            .arg("--detailed")
            .output()
            .expect("Failed to run c2patool");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // c2patool should be able to parse the JUMBF and produce JSON output
        assert!(
            output.status.success(),
            "c2patool should parse our JUMBF successfully.\nstdout: {}\nstderr: {}",
            stdout,
            stderr
        );

        // Verify the output is valid JSON with manifest data
        let c2pa_output: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!(
                "c2patool output should be valid JSON: {}\noutput: {}",
                e, stdout
            )
        });

        // Should contain a manifests section or active_manifest
        assert!(
            c2pa_output.get("manifests").is_some() || c2pa_output.get("active_manifest").is_some(),
            "c2patool output should contain manifest data: {}",
            stdout
        );

        // Verify our creator assertion is present somewhere in the output
        let output_str = stdout.to_string();
        assert!(
            output_str.contains("test@example.com"),
            "c2patool output should contain our creator: {}",
            stdout
        );

        // Claim v2 actions must be well formed (arkavo-rs#98)
        assert!(
            !output_str.contains("assertion.action.malformed"),
            "c2patool reported malformed actions: {}",
            stdout
        );

        // Clean up
        let _ = std::fs::remove_file(&jumbf_path);
    }
}
