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

use super::c2pa_kms::{
    connect_with_retry, DigestSigner, KmsKey, RemoteKeySigner, CONNECT_ATTEMPTS,
    CONNECT_FIRST_RETRY,
};
use super::license::person_token::PersonTokenVerifier;
use axum::http::HeaderMap;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::sync::Arc;

/// The entitlement signing requires when `C2PA_REQUIRE_ENTITLEMENT` is set: the creator
/// membership's publish attribute, the same one publishing requires (arkavo-rs#120).
pub(crate) const SIGNING_ENTITLEMENT: &str =
    "https://patreon.arkavo.com/attr/arkavo-creator/value/publish";
/// Arkavo's assertion for the request's creator and description. It replaces
/// `stds.schema-org.CreativeWork`, which spec 2.2 deprecates (arkavo-rs#115).
const RECORDING_LABEL: &str = "org.arkavo.recording";
/// Where manifests signed before arkavo-rs#115 carry the creator, as the author
const LEGACY_CREATIVE_WORK_LABEL: &str = "stds.schema-org.CreativeWork";
/// The product that generates the claims, named in `claim_generator_info`
const PRODUCT_NAME: &str = "Arkavo Creator";
/// The C2PA specification version the claims follow: c2pa-rs 0.91 generates spec 2.2
const C2PA_SPEC_VERSION: &str = "2.2.0";

/// Default hourly cap on sign requests per token subject (C2PA_SIGN_LIMIT_PER_HOUR).
const DEFAULT_SIGN_LIMIT_PER_HOUR: usize = 120;

/// Bytes a top-level C2PA `uuid` box adds around the JUMBF: size (4) + type (4) +
/// UUID (16) + version/flags (4) + "manifest\0" (9) + Merkle offset (8).
const MANIFEST_BOX_OVERHEAD: u64 = 45;

/// Upper bound on a sign request, including the TSA round trip.
const SIGNING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Hash-binding status c2pa-rs reports when the manifest is read without its asset.
const DATA_HASH_MISMATCH: &str = "assertion.dataHash.mismatch";

// ==================== Configuration ====================

/// Where the claim-signing private key lives.
pub enum SigningKey {
    /// PEM file on disk; development and tests only (C2PA_SIGNER=file)
    File(String),
    /// Non-exportable key in a key service, e.g. AWS KMS (C2PA_SIGNER=kms)
    Remote(Arc<dyn DigestSigner>),
}

/// C2PA signing configuration
pub struct C2paConfig {
    pub signing_key: SigningKey,
    pub signing_cert_path: String,
    /// PEM bundle `/c2pa/v1/validate` trusts; empty trusts nothing
    pub trust_anchors: String,
    /// PEM bundle of timestamp-authority roots `/c2pa/v1/validate` trusts
    pub tsa_trust_anchors: String,
    /// RFC 3161 timestamp authority; unset signs without a timestamp
    pub tsa_url: Option<String>,
    pub _require_validation: bool, // Reserved for future use
    pub allowed_creators: Vec<String>,
    /// `C2PA_REQUIRE_ENTITLEMENT`: only tokens carrying [`SIGNING_ENTITLEMENT`] may sign
    pub require_entitlement: bool,
}

impl C2paConfig {
    /// Load C2PA configuration from environment variables. With C2PA_SIGNER=kms this
    /// also checks that the KMS key matches the signer certificate.
    pub async fn from_env() -> Result<Self, String> {
        use log::info;

        info!("Loading C2PA configuration from environment...");

        let signing_cert_path = std::env::var("C2PA_SIGNING_CERT_PATH")
            .map_err(|_| "C2PA_SIGNING_CERT_PATH not set".to_string())?;

        info!("C2PA_SIGNING_CERT_PATH: {}", signing_cert_path);

        if !std::path::Path::new(&signing_cert_path).exists() {
            return Err(format!(
                "C2PA signing cert not found: {}",
                signing_cert_path
            ));
        }
        info!("C2PA signing cert file exists");

        // The key backend must be chosen explicitly: a key file is for development and
        // tests; production keeps the key in KMS (arkavo-rs#104).
        let signing_key = match std::env::var("C2PA_SIGNER").as_deref() {
            Ok("kms") => {
                let key_id = std::env::var("C2PA_KMS_KEY_ID")
                    .map_err(|_| "C2PA_SIGNER=kms needs C2PA_KMS_KEY_ID".to_string())?;
                let chain = std::fs::read(&signing_cert_path)
                    .map_err(|e| format!("Failed to read C2PA signing cert: {}", e))?;
                let signer_cert = pem::parse_many(&chain)
                    .ok()
                    .and_then(|blocks| blocks.into_iter().find(|b| b.tag() == "CERTIFICATE"))
                    .ok_or("C2PA signing cert chain has no certificate")?;
                let key = connect_with_retry(CONNECT_ATTEMPTS, CONNECT_FIRST_RETRY, || {
                    KmsKey::connect(key_id.clone(), signer_cert.contents())
                })
                .await?;
                info!("C2PA claim signing uses AWS KMS");
                SigningKey::Remote(Arc::new(key))
            }
            Ok("file") => {
                let path = std::env::var("C2PA_SIGNING_KEY_PATH")
                    .map_err(|_| "C2PA_SIGNER=file needs C2PA_SIGNING_KEY_PATH".to_string())?;
                if !std::path::Path::new(&path).exists() {
                    return Err(format!("C2PA signing key not found: {}", path));
                }
                warn!("C2PA claim signing uses a key file: development only");
                SigningKey::File(path)
            }
            Ok(other) => return Err(format!("C2PA_SIGNER must be kms or file, not {}", other)),
            Err(_) => {
                return Err(
                    "C2PA_SIGNER not set (kms for production, file for development)".to_string(),
                )
            }
        };

        // Trust our own CA by default: the certificates after the end-entity in the
        // signing chain. C2PA_TRUST_ANCHORS_PATH replaces them, e.g. to keep a retired
        // CA during a rotation.
        let trust_anchors = match std::env::var("C2PA_TRUST_ANCHORS_PATH") {
            Ok(path) => std::fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read C2PA trust anchors {}: {}", path, e))?,
            Err(_) => {
                let chain = std::fs::read_to_string(&signing_cert_path)
                    .map_err(|e| format!("Failed to read C2PA signing cert: {}", e))?;
                ca_certs_from_chain(&chain)
            }
        };
        let trust_anchors = usable_trust_anchors(trust_anchors, AnchorKind::Manifest);

        // A timestamp keeps manifests valid after the signer certificate expires.
        // When set, a TSA failure fails the sign request (arkavo-rs#102).
        let tsa_url = std::env::var("C2PA_TSA_URL")
            .ok()
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty());
        match &tsa_url {
            Some(url) if !(url.starts_with("http://") || url.starts_with("https://")) => {
                return Err(format!("C2PA_TSA_URL must be an http(s) URL: {}", url));
            }
            Some(url) => info!("C2PA timestamp authority: {}", url),
            None => warn!(
                "C2PA_TSA_URL not set: manifests carry no timestamp and expire with the signer certificate"
            ),
        }

        // Only a trusted timestamp sets the signing time, so /c2pa/v1/validate needs the
        // TSA's roots (e.g. the C2PA TSA trust list). Kept apart from the manifest
        // anchors so a TSA root never vouches for a signing certificate.
        let tsa_trust_anchors = match std::env::var("C2PA_TSA_TRUST_ANCHORS_PATH") {
            Ok(path) => usable_trust_anchors(
                std::fs::read_to_string(&path).map_err(|e| {
                    format!("Failed to read C2PA TSA trust anchors {}: {}", path, e)
                })?,
                AnchorKind::Tsa,
            ),
            Err(_) => {
                if tsa_url.is_some() {
                    warn!("C2PA_TSA_TRUST_ANCHORS_PATH not set: /c2pa/v1/validate will report every timestamp untrusted");
                }
                String::new()
            }
        };

        let _require_validation = std::env::var("C2PA_REQUIRE_VALIDATION")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        // A typo must not silently leave signing open to non-members
        let require_entitlement = parse_flag(
            "C2PA_REQUIRE_ENTITLEMENT",
            std::env::var("C2PA_REQUIRE_ENTITLEMENT").ok().as_deref(),
        )?;

        let allowed_creators = std::env::var("C2PA_ALLOWED_CREATORS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_string())
            .collect();

        info!("C2PA configuration loaded successfully");

        Ok(Self {
            signing_key,
            signing_cert_path,
            trust_anchors,
            tsa_trust_anchors,
            tsa_url,
            _require_validation,
            allowed_creators,
            require_entitlement,
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
    /// Ignored on input: the signer sets it to the verified token subject.
    #[serde(default)]
    pub creator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>, // ISO 8601 format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_generated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,
    /// Whether the actions describe the asset's whole history; false when absent
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all_actions_included: Option<bool>,
}

/// C2PA signing request
#[derive(Debug, Clone, Deserialize)]
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
    /// Where the client found the manifest box. When given, it must be the exclusion the
    /// manifest was signed with: a box that grew or moved leaves the hash of the other
    /// bytes unchanged while the media offsets point elsewhere.
    #[serde(default)]
    pub exclusion_ranges: Option<Vec<ExclusionRange>>,
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
    /// Trusted signing time from the RFC 3161 timestamp, if the manifest has one
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
}

// ==================== Shared State ====================

pub struct C2paSigningState {
    pub config: C2paConfig,
    /// identity.arkavo.net passkey tokens; only people may sign (arkavo-rs#109)
    pub person_tokens: Arc<PersonTokenVerifier>,
    /// Recent sign requests per token subject, for the hourly limit
    sign_requests: std::sync::Mutex<std::collections::HashMap<String, Vec<std::time::Instant>>>,
    sign_limit_per_hour: usize,
}

impl C2paSigningState {
    pub fn new(config: C2paConfig, person_tokens: Arc<PersonTokenVerifier>) -> Self {
        let sign_limit_per_hour = std::env::var("C2PA_SIGN_LIMIT_PER_HOUR")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&n: &usize| n > 0)
            .unwrap_or(DEFAULT_SIGN_LIMIT_PER_HOUR);
        Self {
            config,
            person_tokens,
            sign_requests: Default::default(),
            sign_limit_per_hour,
        }
    }

    /// Count a sign request for `sub`; Err(seconds to wait) when over the hourly limit.
    fn admit(&self, sub: &str) -> Result<(), u64> {
        const HOUR: std::time::Duration = std::time::Duration::from_secs(3600);
        let now = std::time::Instant::now();
        let mut requests = self
            .sign_requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        requests.retain(|_, times| {
            times.retain(|t| now.duration_since(*t) < HOUR);
            !times.is_empty()
        });
        let times = requests.entry(sub.to_string()).or_default();
        if times.len() >= self.sign_limit_per_hour {
            let wait = HOUR.saturating_sub(now.duration_since(times[0]));
            return Err(wait.as_secs().max(1));
        }
        times.push(now);
        Ok(())
    }
}

// ==================== API Handlers ====================

/// JSON error response for the sign endpoint.
fn sign_error(status: StatusCode, error: &str, extra: serde_json::Value) -> Response {
    let mut body = serde_json::json!({ "error": error, "status": "error" });
    if let (Some(body), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
        body.extend(extra.clone());
    }
    (status, Json(body)).into_response()
}

/// POST /c2pa/v1/sign - Sign C2PA manifest with pre-computed hash
///
/// Only a signed-in person may sign, and the manifest names them as the author
/// (arkavo-rs#109). The request must exclude exactly one range, the C2PA
/// `uuid` box the manifest is embedded in, so no media bytes can be left unhashed.
pub async fn sign_manifest(
    State(state): State<Arc<C2paSigningState>>,
    headers: HeaderMap,
    Json(mut req): Json<C2paSignRequest>,
) -> Response {
    let person = match state
        .person_tokens
        .verify(&headers, chrono::Utc::now().timestamp())
        .await
    {
        Ok(person) => person,
        Err(e) => {
            warn!("C2PA signing refused: {}", e.reason());
            return sign_error(e.status(), e.reason(), serde_json::json!({}));
        }
    };

    // The author is the verified subject, never the self-asserted metadata.creator.
    if !state.config.allowed_creators.is_empty()
        && !state.config.allowed_creators.contains(&person.sub)
    {
        warn!("C2PA signing denied: subject not in C2PA_ALLOWED_CREATORS");
        return sign_error(
            StatusCode::FORBIDDEN,
            "Creator not authorized",
            serde_json::json!({}),
        );
    }
    // Signing is for creator members: the same entitlement publishing needs (arkavo-rs#120).
    // Checked before anything counts against the subject's quota.
    if state.config.require_entitlement
        && !person.entitlements.iter().any(|e| e == SIGNING_ENTITLEMENT)
    {
        warn!("C2PA signing denied: token lacks the signing entitlement");
        return sign_error(
            StatusCode::FORBIDDEN,
            "signing entitlement required",
            serde_json::json!({ "required_entitlement": SIGNING_ENTITLEMENT }),
        );
    }
    req.metadata.creator = person.sub.clone();

    let exclusion = match req.exclusion_ranges.as_slice() {
        [range] if range.box_type.as_deref() == Some("uuid") && range.end > range.start => {
            range.clone()
        }
        _ => {
            return sign_error(
                StatusCode::BAD_REQUEST,
                "exclusion_ranges must be exactly one range with box_type \"uuid\" covering the C2PA manifest box",
                serde_json::json!({}),
            )
        }
    };

    // Validate hash format (should be hex-encoded SHA-256) before it counts against
    // the subject's quota.
    if req.content_hash.len() != 64 || !req.content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        error!("Invalid content hash format: {}", req.content_hash);
        return sign_error(
            StatusCode::BAD_REQUEST,
            "Invalid content hash format (expected 64 hex chars)",
            serde_json::json!({}),
        );
    }

    if let Err(retry_after) = state.admit(&person.sub) {
        warn!("C2PA signing rate limited for {}", person.sub);
        let mut response = sign_error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many signing requests",
            serde_json::json!({}),
        );
        if let Ok(value) = axum::http::HeaderValue::from_str(&retry_after.to_string()) {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, value);
        }
        return response;
    }
    info!(
        "C2PA sign request: sub={} content_hash={} exclusion={}..{} format={:?}",
        person.sub, req.content_hash, exclusion.start, exclusion.end, req.container_format
    );

    // Measure the manifest box first, without a KMS signature or a timestamp: a
    // length mismatch is answered without spending a (metered) timestamp, so a
    // file costs one timestamp, not two (arkavo-rs#119).
    let sizing_state = state.clone();
    let sizing_req = req.clone();
    let sized = tokio::task::spawn_blocking(move || {
        build_c2pa_manifest(&sizing_state.config, &sizing_req, SignPass::Size)
            .and_then(|(manifest, _)| manifest_box_len(&manifest))
    })
    .await
    .unwrap_or_else(|e| Err(format!("Sizing task failed: {}", e)));
    match sized {
        Ok(box_len) if exclusion.end - exclusion.start != box_len => {
            info!(
                "C2PA manifest not signed: exclusion length {} != manifest box {}",
                exclusion.end - exclusion.start,
                box_len
            );
            return sign_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "exclusion range length must equal the C2PA manifest box length",
                serde_json::json!({ "required_exclusion_length": box_len }),
            );
        }
        Ok(_) => {}
        Err(e) => return signing_failed_response(&e),
    }

    // Signing is blocking: with a TSA it waits on an HTTP round trip, and c2pa's HTTP
    // client has no timeout of its own, so bound the request here.
    let signing_state = state.clone();
    let signing = tokio::task::spawn_blocking(move || {
        build_c2pa_manifest(&signing_state.config, &req, SignPass::Sign)
    });
    let signed = match tokio::time::timeout(SIGNING_TIMEOUT, signing).await {
        Ok(joined) => joined.unwrap_or_else(|e| Err(format!("Signing task failed: {}", e))),
        Err(_) => {
            error!("C2PA signing timed out after {:?}", SIGNING_TIMEOUT);
            return (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({
                    "error": "Signing timed out waiting for the timestamp authority",
                    "status": "error"
                })),
            )
                .into_response();
        }
    };
    // Only the manifest box itself may be unhashed: the excluded range must be exactly
    // as long as the box that will carry this manifest. The sizing pass matched; check
    // the signed manifest too, and discard it if it ever differs.
    let signed = signed.and_then(|(manifest, manifest_hash)| {
        let box_len = manifest_box_len(&manifest)?;
        Ok((manifest, manifest_hash, box_len))
    });
    match signed {
        Ok((_, _, box_len)) if exclusion.end - exclusion.start != box_len => {
            info!(
                "C2PA manifest discarded: exclusion length {} != manifest box {}",
                exclusion.end - exclusion.start,
                box_len
            );
            sign_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "exclusion range length must equal the C2PA manifest box length",
                serde_json::json!({ "required_exclusion_length": box_len }),
            )
        }
        Ok((manifest, manifest_hash, _)) => {
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
        Err(e) => signing_failed_response(&e),
    }
}

/// Logs why signing failed and returns a generic 500. The cause can carry KMS
/// detail (AWS account id, IAM role and session, key ARN) that callers must not see.
fn signing_failed_response(detail: &str) -> Response {
    error!("C2PA signing failed: {}", detail);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "error": "Signing failed",
            "status": "error"
        })),
    )
        .into_response()
}

/// POST /c2pa/v1/validate - Validate C2PA manifest
pub async fn validate_manifest(
    State(state): State<Arc<C2paSigningState>>,
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
                        signed_at: None,
                    }),
                )
                    .into_response();
            }
        };

    // Parse and validate C2PA manifest
    match validate_c2pa_manifest(
        &manifest_bytes,
        &req.content_hash,
        &state.config.trust_anchors,
        &state.config.tsa_trust_anchors,
        req.exclusion_ranges.as_deref(),
    ) {
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
                    signed_at: None,
                }),
            )
                .into_response()
        }
    }
}

// ==================== C2PA Implementation ====================

/// Which pass of a sign request builds the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignPass {
    /// Measure the manifest: no KMS signature, no timestamp (arkavo-rs#119).
    Size,
    /// Sign it for real.
    Sign,
}

/// Stands in for the real signer while the manifest is measured. It reports the
/// same certificates and reserved signature size, and c2pa pads every signature to
/// exactly that reserve, so the manifest comes out the same length as the signed
/// one. It signs with zeros and asks for no timestamp.
struct SizingSigner(c2pa::BoxedSigner);

impl c2pa::Signer for SizingSigner {
    fn sign(&self, _data: &[u8]) -> c2pa::Result<Vec<u8>> {
        // An ES256 signature is r || s, 64 bytes
        Ok(vec![0; 64])
    }

    fn alg(&self) -> SigningAlg {
        self.0.alg()
    }

    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        self.0.certs()
    }

    fn reserve_size(&self) -> usize {
        self.0.reserve_size()
    }

    fn time_authority_url(&self) -> Option<String> {
        None
    }

    fn send_timestamp_request(&self, _message: &[u8]) -> Option<c2pa::Result<Vec<u8>>> {
        None
    }
}

/// The length of the box that carries `manifest` (base64 JUMBF): the JUMBF plus
/// the box header.
fn manifest_box_len(manifest: &str) -> Result<u64, String> {
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, manifest)
        .map(|bytes| MANIFEST_BOX_OVERHEAD + bytes.len() as u64)
        .map_err(|e| format!("Signed manifest is not base64: {}", e))
}

/// Build and sign a C2PA manifest using the hashed-data signing workflow.
///
/// The client computes a content hash with exclusion ranges and sends it to the server.
/// The server constructs a C2PA manifest with assertions, signs it using the configured
/// credentials, and returns the signed JUMBF manifest bytes for the client to embed.
fn build_c2pa_manifest(
    config: &C2paConfig,
    req: &C2paSignRequest,
    pass: SignPass,
) -> Result<(String, String), String> {
    info!("Loading C2PA signing credentials...");

    let cert_chain = std::fs::read(&config.signing_cert_path)
        .map_err(|e| format!("Failed to read certificate: {}", e))?;

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
    let signer: c2pa::BoxedSigner = match &config.signing_key {
        SigningKey::File(path) => {
            let private_key =
                std::fs::read(path).map_err(|e| format!("Failed to read private key: {}", e))?;
            let private_key = signing_key_pkcs8_pem(&private_key)?;
            c2pa::create_signer::from_keys(
                &cert_chain,
                private_key.as_bytes(),
                SigningAlg::Es256,
                config.tsa_url.clone(),
            )
            .map_err(|e| format!("Failed to create signer: {}", e))?
        }
        SigningKey::Remote(key) => Box::new(RemoteKeySigner::new(
            key.clone(),
            &cert_chain,
            config.tsa_url.clone(),
        )?),
    };

    // A default time with whole seconds, so its length (and the manifest's) doesn't
    // depend on the clock's fractional digits between the sizing pass, the signing
    // pass and the client's retry.
    let when =
        req.metadata.timestamp.clone().unwrap_or_else(|| {
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        });
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
    let created =
        serde_json::to_value(created).map_err(|e| format!("Failed to encode action: {}", e))?;

    let mut recording = serde_json::json!({ "creator": req.metadata.creator });
    if let Some(ref description) = req.metadata.description {
        recording["description"] = serde_json::json!(description);
    }

    // Build a C2PA manifest from spec assertions. Claim v2 requires a c2pa.actions
    // assertion whose first action is c2pa.created (arkavo-rs#98). The actions and the
    // recording are created assertions, attributed to the signer, as the conformance
    // rubrics require of the inception action; allActionsIncluded is only true when the
    // client says the actions are the asset's whole history (arkavo-rs#115).
    let mut definition = serde_json::json!({
        // The claim schema requires a non-empty instanceID, and the server never has
        // the asset to take one from, so mint one per signed version (arkavo-rs#114).
        "instance_id": format!("xmp:iid:{}", uuid::Uuid::new_v4()),
        "assertions": [
            {
                "label": Actions::LABEL_VERSIONED,
                "created": true,
                "data": {
                    "actions": [created],
                    "allActionsIncluded": req.metadata.all_actions_included.unwrap_or(false),
                },
            },
            { "label": RECORDING_LABEL, "created": true, "data": recording },
        ],
    });
    if !req.metadata.title.is_empty() {
        definition["title"] = serde_json::json!(req.metadata.title);
    }
    let mut context = Context::new();
    let signer: c2pa::BoxedSigner = match pass {
        SignPass::Sign => signer,
        SignPass::Size => {
            // The stand-in signature doesn't verify, and isn't meant to.
            context.settings_mut().verify.verify_after_sign = false;
            Box::new(SizingSigner(signer))
        }
    };
    let mut builder = Builder::from_context(context.with_signer(signer))
        .with_definition(definition.to_string())
        .map_err(|e| format!("Failed to build manifest definition: {}", e))?;
    builder.definition.claim_generator_info =
        vec![claim_generator_info(req.metadata.software.as_deref())];

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

/// The claim generator is the product, Arkavo Creator, with its version when the request's
/// software is `Arkavo Creator <version>`. It carries the spec version the claim follows
/// (required for spec 2.4+) and the signing service that built it.
fn claim_generator_info(software: Option<&str>) -> ClaimGeneratorInfo {
    let mut info = ClaimGeneratorInfo::new(PRODUCT_NAME);
    info.version = software
        .and_then(|software| software.strip_prefix(PRODUCT_NAME))
        .and_then(|rest| rest.strip_prefix(' '))
        .map(|version| version.trim().to_string())
        .filter(|version| !version.is_empty());
    info.set_spec_version(C2PA_SPEC_VERSION);
    info.insert(
        "org.arkavo.signer",
        format!("arks/{}", env!("CARGO_PKG_VERSION")),
    );
    info
}

/// Parses a boolean setting: absent is `false`; an explicit value must be one of
/// true/false/1/0/yes/no (any case, surrounding space ignored)
fn parse_flag(name: &str, value: Option<&str>) -> Result<bool, String> {
    let Some(value) = value else {
        return Ok(false);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(format!("{} must be true or false, got {:?}", name, value)),
    }
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

/// The certificates after the first (end-entity) one in a PEM chain, as a PEM bundle.
fn ca_certs_from_chain(chain_pem: &str) -> String {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    match chain_pem.match_indices(BEGIN).nth(1) {
        Some((start, _)) => chain_pem[start..].to_string(),
        None => String::new(),
    }
}

/// Which trust list an anchor bundle feeds.
#[derive(Clone, Copy)]
enum AnchorKind {
    /// Roots for manifest signing certificates (our own CA)
    Manifest,
    /// Roots for RFC 3161 timestamp-authority certificates
    Tsa,
}

impl AnchorKind {
    fn name(self) -> &'static str {
        match self {
            AnchorKind::Manifest => "trust anchors",
            AnchorKind::Tsa => "TSA trust anchors",
        }
    }

    fn untrusted(self) -> &'static str {
        match self {
            AnchorKind::Manifest => "/c2pa/v1/validate will report every manifest untrusted",
            AnchorKind::Tsa => "/c2pa/v1/validate will report every timestamp untrusted",
        }
    }
}

/// Check the anchor bundle once at startup. c2pa silently skips certificates it can't
/// parse, so malformed blocks are dropped here with a warning; a bundle with no usable
/// certificate becomes empty (trust nothing) instead of failing quietly per request.
fn usable_trust_anchors(pem: String, kind: AnchorKind) -> String {
    let untrusted = kind.untrusted();

    let blocks = match pem::parse_many(&pem) {
        Ok(blocks) => blocks,
        Err(e) => {
            warn!("C2PA {} are not PEM ({}): {}", kind.name(), e, untrusted);
            return String::new();
        }
    };
    let certs: Vec<pem::Pem> = blocks
        .into_iter()
        .filter(|block| block.tag() == "CERTIFICATE")
        .filter(
            |block| match x509_parser::parse_x509_certificate(block.contents()) {
                Ok(_) => true,
                Err(e) => {
                    warn!("Skipping malformed C2PA {}: {}", kind.name(), e);
                    false
                }
            },
        )
        .collect();
    if certs.is_empty() {
        warn!("No C2PA {}: {}", kind.name(), untrusted);
        return String::new();
    }

    let pem = pem::encode_many_config(
        &certs,
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    );
    let checked = match kind {
        AnchorKind::Manifest => validation_context(&pem, ""),
        AnchorKind::Tsa => validation_context("", &pem),
    };
    if let Err(e) = checked {
        warn!("{}: {}", e, untrusted);
        return String::new();
    }
    pem
}

/// Reader context that trusts only `trust_anchors` for manifest signing credentials and
/// only `tsa_trust_anchors` for timestamps.
fn validation_context(trust_anchors: &str, tsa_trust_anchors: &str) -> Result<Context, String> {
    let anchors: Vec<serde_json::Value> = [(trust_anchors, "manifest"), (tsa_trust_anchors, "tsa")]
        .into_iter()
        .filter(|(pem, _)| !pem.is_empty())
        .map(|(pem, kind)| serde_json::json!({ "trust_anchors": pem, "trust_kind": kind }))
        .collect();
    if anchors.is_empty() {
        return Ok(Context::new());
    }
    let settings = serde_json::json!({ "trust": { "anchors": anchors } });
    Context::new()
        .with_settings(settings.to_string().as_str())
        .map_err(|e| format!("Invalid C2PA trust anchors: {}", e))
}

/// Validate a C2PA manifest by parsing JUMBF data and verifying the signature chain.
///
/// Server-side validation verifies the COSE signature chain and extracts metadata.
/// Full asset-hash binding verification requires the actual asset (done client-side).
fn validate_c2pa_manifest(
    manifest_bytes: &[u8],
    expected_hash: &str,
    trust_anchors: &str,
    tsa_trust_anchors: &str,
    exclusion_ranges: Option<&[ExclusionRange]>,
) -> Result<C2paValidateResponse, String> {
    // Use Reader to parse JUMBF and verify signature chain.
    // We provide an empty stream since the actual asset is on the client side;
    // the Reader will still verify COSE signatures on the manifest itself.
    let empty_stream = Cursor::new(Vec::<u8>::new());
    let reader = Reader::from_context(validation_context(trust_anchors, tsa_trust_anchors)?)
        .with_manifest_data_and_stream(manifest_bytes, "video/mp4", empty_stream)
        .map_err(|e| format!("Failed to parse C2PA manifest: {}", e))?;

    let mut errors = Vec::new();
    let mut creator = None;
    let mut ai_generated = None;
    let mut signed_at = None;
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
        signed_at = manifest.signature_info().and_then(|info| info.time.clone());

        if let Ok(recording) = manifest.find_assertion::<serde_json::Value>(RECORDING_LABEL) {
            creator = recording
                .get("creator")
                .and_then(|n| n.as_str())
                .map(String::from);
        } else if let Ok(work) =
            manifest.find_assertion::<serde_json::Value>(LEGACY_CREATIVE_WORK_LABEL)
        {
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

        // The exclusion the manifest was signed with, from arks' own content-hash
        // assertion: it holds the same ranges as c2pa.hash.data, which the Reader's
        // manifest view leaves out.
        if let Some(observed) = exclusion_ranges {
            let mut observed: Vec<(u64, u64)> = observed.iter().map(|r| (r.start, r.end)).collect();
            observed.sort_unstable();
            // arks always signs exactly one range, so a missing, malformed or empty one
            // means the signed exclusion is unknown, and nothing matches it
            let signed: Option<Vec<(u64, u64)>> = manifest
                .find_assertion::<serde_json::Value>("org.arkavo.c2pa.content_hash")
                .ok()
                .and_then(|data| data.get("exclusion_ranges").cloned())
                .and_then(|ranges| serde_json::from_value::<Vec<ExclusionRange>>(ranges).ok())
                .filter(|ranges| !ranges.is_empty())
                .map(|ranges| {
                    let mut signed: Vec<(u64, u64)> =
                        ranges.iter().map(|r| (r.start, r.end)).collect();
                    signed.sort_unstable();
                    signed
                });
            match signed {
                Some(signed) if signed == observed => {}
                Some(signed) => errors.push(format!(
                    "Exclusion mismatch: the manifest box is at {:?}, signed at {:?}",
                    observed, signed
                )),
                None => errors.push(
                    "Exclusion mismatch: the manifest does not say where it was signed".to_string(),
                ),
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
        signed_at,
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

    /// C2PA_REQUIRE_ENTITLEMENT gates signing, so a value that isn't clearly true or false
    /// must stop startup rather than silently leave the gate open (arkavo-rs#120).
    #[test]
    fn test_flag_parsing_fails_closed() {
        assert_eq!(parse_flag("F", None), Ok(false));
        for on in ["true", "TRUE", " True ", "1", "yes"] {
            assert_eq!(parse_flag("F", Some(on)), Ok(true), "{:?}", on);
        }
        for off in ["false", "FALSE", "0", "no", " false"] {
            assert_eq!(parse_flag("F", Some(off)), Ok(false), "{:?}", off);
        }
        for bad in ["", "on", "enabled", "tru"] {
            let err = parse_flag("C2PA_REQUIRE_ENTITLEMENT", Some(bad)).unwrap_err();
            assert!(err.contains("C2PA_REQUIRE_ENTITLEMENT"), "{}", err);
        }
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
            all_actions_included: None,
        };
        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("\"ai_generated\":true"));
    }

    /// Generate a CA + end-entity P-256 cert chain for C2PA signing tests.
    /// C2PA rejects self-signed signing certificates and needs a digitalSignature key
    /// usage and an emailProtection EKU on the end-entity certificate.
    /// Returns (cert_chain_pem_path, end_entity_key_pem_path) in a temp directory.
    fn generate_test_certs() -> (std::path::PathBuf, std::path::PathBuf) {
        generate_test_certs_until(None)
    }

    /// As `generate_test_certs`, with the end-entity certificate expiring at `ee_not_after`.
    fn generate_test_certs_until(
        ee_not_after: Option<time::OffsetDateTime>,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
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
        if let Some(not_after) = ee_not_after {
            ee_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
            ee_params.not_after = not_after;
        }
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

    pub(super) fn make_test_config() -> C2paConfig {
        config_from_certs(generate_test_certs())
    }

    fn config_from_certs(
        (cert_path, key_path): (std::path::PathBuf, std::path::PathBuf),
    ) -> C2paConfig {
        let chain = std::fs::read_to_string(&cert_path).unwrap();
        C2paConfig {
            signing_key: SigningKey::File(key_path.to_str().unwrap().to_string()),
            signing_cert_path: cert_path.to_str().unwrap().to_string(),
            trust_anchors: usable_trust_anchors(ca_certs_from_chain(&chain), AnchorKind::Manifest),
            tsa_trust_anchors: String::new(),
            tsa_url: None,
            _require_validation: false,
            allowed_creators: vec![],
            require_entitlement: false,
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
                all_actions_included: None,
            },
        }
    }

    /// The signed manifest as crJSON, the form the C2PA conformance rubrics evaluate
    fn signed_crjson(req: &C2paSignRequest) -> serde_json::Value {
        let (manifest_b64, _) = build_c2pa_manifest(&make_test_config(), req, SignPass::Sign)
            .expect("Signing should succeed");
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .unwrap();
        Reader::from_context(Context::new())
            .with_manifest_data_and_stream(&bytes, "video/mp4", Cursor::new(Vec::<u8>::new()))
            .unwrap()
            .to_crjson_value()
            .unwrap()
    }

    const RUBRIC_HASH: &str = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";

    /// Rubrics `inception_action_position` and `mandatory_all_actions_included` (arkavo-rs#115):
    /// the actions are attributed to the signer, and say whether they are the whole history.
    #[test]
    fn test_c2pa_actions_are_created_and_say_whether_complete() {
        let crjson = signed_crjson(&make_test_request(RUBRIC_HASH));
        let manifest = &crjson["manifests"][0];
        let created: Vec<&str> = manifest["claim.v2"]["created_assertions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|a| a["url"].as_str())
            .collect();
        assert!(
            created.iter().any(|url| url.ends_with("c2pa.actions.v2")),
            "actions must be a created assertion: {:?}",
            created
        );
        let actions = &manifest["assertions"]["c2pa.actions.v2"];
        assert_eq!(actions["actions"][0]["action"], "c2pa.created");
        assert_eq!(actions["allActionsIncluded"], false);

        let mut complete = make_test_request(RUBRIC_HASH);
        complete.metadata.all_actions_included = Some(true);
        let crjson = signed_crjson(&complete);
        assert_eq!(
            crjson["manifests"][0]["assertions"]["c2pa.actions.v2"]["allActionsIncluded"],
            true
        );
    }

    /// Rubric `no_deprecated_assertions` (arkavo-rs#115): no `stds.*` assertions. The creator
    /// and description move to a namespaced assertion.
    #[test]
    fn test_c2pa_manifest_has_no_deprecated_assertions() {
        let crjson = signed_crjson(&make_test_request(RUBRIC_HASH));
        let assertions = crjson["manifests"][0]["assertions"].as_object().unwrap();
        let labels: Vec<&String> = assertions.keys().collect();
        assert!(
            labels.iter().all(|label| !label.starts_with("stds.")),
            "{:?}",
            labels
        );
        assert_eq!(assertions[RECORDING_LABEL]["creator"], "test@example.com");
        assert_eq!(assertions[RECORDING_LABEL]["description"], "A test video");
    }

    /// Manifests signed before arkavo-rs#115 carry the creator in the deprecated
    /// `stds.schema-org.CreativeWork` author; /c2pa/v1/validate still reports it.
    #[test]
    fn test_c2pa_validate_reads_the_creator_of_older_manifests() {
        let config = make_test_config();
        let SigningKey::File(ref key_path) = config.signing_key else {
            unreachable!("test config signs with a key file")
        };
        let cert_chain = std::fs::read(&config.signing_cert_path).unwrap();
        let key = signing_key_pkcs8_pem(&std::fs::read(key_path).unwrap()).unwrap();
        let signer =
            c2pa::create_signer::from_keys(&cert_chain, key.as_bytes(), SigningAlg::Es256, None)
                .unwrap();

        // The pre-#115 manifest: a gathered actions assertion and a CreativeWork author
        let mut builder = Builder::from_context(Context::new().with_signer(signer));
        builder.definition.instance_id = "xmp:iid:older".to_string();
        builder
            .add_action(
                Action::new(c2pa_action::CREATED)
                    .set_source_type(DigitalSourceType::DigitalCapture),
            )
            .unwrap();
        builder
            .add_assertion_json(
                "stds.schema-org.CreativeWork",
                &serde_json::json!({
                    "@context": "https://schema.org",
                    "@type": "CreativeWork",
                    "author": [{ "@type": "Person", "name": "arkavo:older-subject" }],
                }),
            )
            .unwrap();
        builder
            .add_assertion(
                "org.arkavo.c2pa.content_hash",
                &serde_json::json!({ "hash": RUBRIC_HASH, "algorithm": "sha256" }),
            )
            .unwrap();
        let mut data_hash = c2pa::assertions::DataHash::new("jumbf manifest", "sha256");
        data_hash.set_hash(hex::decode(RUBRIC_HASH).unwrap());
        data_hash.add_exclusion(HashRange::new(100, 400));
        builder
            .add_assertion(c2pa::assertions::DataHash::LABEL, &data_hash)
            .unwrap();
        let bytes = builder.sign_embeddable("c2pa").unwrap();

        let result =
            validate_c2pa_manifest(&bytes, RUBRIC_HASH, &config.trust_anchors, "", None).unwrap();
        assert!(result.valid, "{:?}", result.errors);
        assert_eq!(result.creator.as_deref(), Some("arkavo:older-subject"));

        // Its content-hash assertion has no exclusion_ranges, so the signed exclusion is
        // unknown: no client-supplied range, not even an empty one, can match it.
        let range = ExclusionRange {
            start: 100,
            end: 500,
            box_type: Some("uuid".into()),
        };
        for observed in [vec![], vec![range]] {
            let result = validate_c2pa_manifest(
                &bytes,
                RUBRIC_HASH,
                &config.trust_anchors,
                "",
                Some(&observed),
            )
            .unwrap();
            assert!(!result.valid, "{} range(s)", observed.len());
            assert!(
                result
                    .errors
                    .iter()
                    .any(|e| e.starts_with("Exclusion mismatch")),
                "{:?}",
                result.errors
            );
        }
    }

    /// The box a client found must be the exclusion the manifest was signed with: a box
    /// that grew or moved leaves the hash of the other bytes unchanged while the media
    /// offsets point elsewhere.
    #[test]
    fn test_c2pa_validate_checks_the_signed_exclusion() {
        let config = make_test_config();
        let (manifest_b64, _) =
            build_c2pa_manifest(&config, &make_test_request(RUBRIC_HASH), SignPass::Sign)
                .expect("Signing should succeed");
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .unwrap();
        let validate = |ranges: Option<Vec<ExclusionRange>>| {
            validate_c2pa_manifest(
                &bytes,
                RUBRIC_HASH,
                &config.trust_anchors,
                "",
                ranges.as_deref(),
            )
            .unwrap()
        };
        let range = |start, end| ExclusionRange {
            start,
            end,
            box_type: Some("uuid".into()),
        };

        // make_test_request signs the exclusion 100..500
        let matching = validate(Some(vec![range(100, 500)]));
        assert!(matching.valid, "{:?}", matching.errors);
        assert!(
            validate(None).valid,
            "clients that send no range are checked as before"
        );
        for observed in [vec![range(100, 516)], vec![range(116, 516)], vec![]] {
            let result = validate(Some(observed.clone()));
            assert!(
                !result.valid,
                "{:?}",
                observed
                    .iter()
                    .map(|r| (r.start, r.end))
                    .collect::<Vec<_>>()
            );
            assert!(
                result
                    .errors
                    .iter()
                    .any(|e| e.starts_with("Exclusion mismatch")),
                "{:?}",
                result.errors
            );
        }
    }

    /// The claim generator is the product, with the spec version the claim follows
    /// (rubric `mandatory_spec_version`, arkavo-rs#115).
    #[test]
    fn test_c2pa_claim_generator_names_the_product_and_spec_version() {
        let generator = |software: &str| {
            let mut req = make_test_request(RUBRIC_HASH);
            req.metadata.software = Some(software.to_string());
            let info =
                signed_crjson(&req)["manifests"][0]["claim.v2"]["claim_generator_info"].clone();
            if info.is_array() {
                info[0].clone()
            } else {
                info
            }
        };

        let info = generator("Arkavo Creator 1.4.2");
        assert_eq!(info["name"], "Arkavo Creator");
        assert_eq!(info["version"], "1.4.2");
        assert_eq!(info["specVersion"], C2PA_SPEC_VERSION);
        assert!(info["org.arkavo.signer"]
            .as_str()
            .unwrap()
            .starts_with("arks/"));

        let info = generator("ArkavoKit c2pa-sign");
        assert_eq!(info["name"], "Arkavo Creator");
        assert!(info.get("version").is_none(), "{}", info);
    }

    /// Round-trip test: sign a manifest and validate it, checking metadata preservation.
    #[tokio::test]
    async fn test_c2pa_sign_and_validate_round_trip() {
        let config = make_test_config();
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let req = make_test_request(hash);

        // Sign
        let (manifest_b64, manifest_hash) =
            build_c2pa_manifest(&config, &req, SignPass::Sign).expect("Signing should succeed");

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
        let result = validate_c2pa_manifest(&manifest_bytes, hash, &config.trust_anchors, "", None)
            .expect("Validation should not error");

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
        let (manifest_b64, _) =
            build_c2pa_manifest(&config, &req, SignPass::Sign).expect("Signing should succeed");

        let manifest_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .unwrap();

        // Validate with a different hash
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let result =
            validate_c2pa_manifest(&manifest_bytes, wrong_hash, &config.trust_anchors, "", None)
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

        let (manifest_b64, _) =
            build_c2pa_manifest(&config, &req, SignPass::Sign).expect("Signing should succeed");

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

        let (manifest_b64, _) =
            build_c2pa_manifest(&config, &req, SignPass::Sign).expect("Signing should succeed");

        let manifest_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .unwrap();

        let result = validate_c2pa_manifest(&manifest_bytes, hash, &config.trust_anchors, "", None)
            .expect("Validation should not error");

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

        let (manifest_b64, _) =
            build_c2pa_manifest(&config, &req, SignPass::Sign).expect("Signing should succeed");
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

    /// A manifest signed with our own chain validates with no errors once its CA is a
    /// trust anchor (arkavo-rs#100).
    #[tokio::test]
    async fn test_c2pa_validate_trusts_own_ca() {
        let config = make_test_config();
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let (manifest_b64, _) =
            build_c2pa_manifest(&config, &make_test_request(hash), SignPass::Sign)
                .expect("Signing should succeed");
        let manifest_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .unwrap();

        let result = validate_c2pa_manifest(&manifest_bytes, hash, &config.trust_anchors, "", None)
            .expect("Validation should not error");
        assert!(
            result.valid,
            "Own CA should be trusted: {:?}",
            result.errors
        );
        assert!(result.errors.is_empty());
    }

    /// A manifest from a CA we don't anchor stays untrusted, and so does every manifest
    /// when no anchors are configured.
    #[tokio::test]
    async fn test_c2pa_validate_rejects_foreign_ca() {
        let ours = make_test_config();
        let theirs = make_test_config();
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let (manifest_b64, _) =
            build_c2pa_manifest(&theirs, &make_test_request(hash), SignPass::Sign)
                .expect("Signing should succeed");
        let manifest_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .unwrap();

        for anchors in [ours.trust_anchors.as_str(), ""] {
            let result = validate_c2pa_manifest(&manifest_bytes, hash, anchors, "", None)
                .expect("Validation should not error");
            assert!(!result.valid);
            assert!(
                result
                    .errors
                    .iter()
                    .any(|e| e.contains("signingCredential.untrusted")),
                "Expected untrusted, got {:?}",
                result.errors
            );
        }
    }

    /// Whitespace, certificate-free or malformed bundles become "trust nothing" at startup;
    /// a good bundle is kept (trimmed) and still validates our manifests.
    #[test]
    fn test_usable_trust_anchors() {
        assert_eq!(
            usable_trust_anchors(" \n\t\n".to_string(), AnchorKind::Manifest),
            ""
        );
        assert_eq!(
            usable_trust_anchors("not a certificate\n".to_string(), AnchorKind::Manifest),
            ""
        );
        assert_eq!(
            usable_trust_anchors(
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_string(),
                AnchorKind::Manifest
            ),
            ""
        );

        let config = make_test_config();
        assert!(!config.trust_anchors.is_empty());
        let padded = format!("\n{}\n\n", config.trust_anchors);
        assert_eq!(
            usable_trust_anchors(padded, AnchorKind::Manifest),
            config.trust_anchors
        );

        // A malformed block is dropped; the good certificate survives.
        let mixed = format!(
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n{}",
            config.trust_anchors
        );
        assert_eq!(
            usable_trust_anchors(mixed, AnchorKind::Manifest),
            config.trust_anchors
        );
    }

    /// With a TSA configured, a TSA that can't be reached fails the sign request rather
    /// than returning a manifest without a timestamp (arkavo-rs#102).
    #[test]
    fn test_c2pa_tsa_failure_fails_signing() {
        let mut config = make_test_config();
        config.tsa_url = Some("http://127.0.0.1:9/".to_string());
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let result = build_c2pa_manifest(&config, &make_test_request(hash), SignPass::Sign);
        assert!(
            result.is_err(),
            "Signing must fail when the TSA is unreachable"
        );
    }

    /// The sizing pass measures the manifest the signing pass produces, without a
    /// signature or a timestamp (arkavo-rs#119). With a TSA configured it reserves the
    /// timestamp's room without contacting the TSA, so even an unreachable one sizes.
    #[test]
    fn test_c2pa_sizing_pass_matches_the_signed_length() {
        let config = make_test_config();
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let len = |config: &C2paConfig, req: &C2paSignRequest, pass| {
            let (b64, _) = build_c2pa_manifest(config, req, pass).expect("build should succeed");
            manifest_box_len(&b64).unwrap()
        };
        let mut req = make_test_request(hash);
        assert_eq!(
            len(&config, &req, SignPass::Size),
            len(&config, &req, SignPass::Sign)
        );
        // The default `when` has a fixed length, so passes a moment apart still agree.
        req.metadata.timestamp = None;
        assert_eq!(
            len(&config, &req, SignPass::Size),
            len(&config, &req, SignPass::Sign)
        );

        let mut with_tsa = make_test_config();
        with_tsa.tsa_url = Some("http://127.0.0.1:9/".to_string());
        assert!(len(&with_tsa, &req, SignPass::Size) > len(&config, &req, SignPass::Size));
    }

    /// With a live TSA, the sizing pass's length equals the timestamped manifest's.
    /// Runs only with C2PA_TSA_TEST_URL set; it spends one timestamp.
    #[test]
    fn test_c2pa_sizing_pass_matches_a_timestamped_length() {
        let Ok(tsa_url) = std::env::var("C2PA_TSA_TEST_URL") else {
            eprintln!("SKIPPED: C2PA_TSA_TEST_URL not set");
            return;
        };
        let mut config = make_test_config();
        config.tsa_url = Some(tsa_url);
        let req =
            make_test_request("a1b2c3d4e5f67890123456789012345678901234567890123456789012345678");
        let (sized, _) = build_c2pa_manifest(&config, &req, SignPass::Size).unwrap();
        let (signed, _) = build_c2pa_manifest(&config, &req, SignPass::Sign).unwrap();
        assert_eq!(
            manifest_box_len(&sized).unwrap(),
            manifest_box_len(&signed).unwrap()
        );
    }

    /// Untimestamped manifests report no signing time.
    #[test]
    fn test_c2pa_signed_at_absent_without_tsa() {
        let config = make_test_config();
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let (manifest_b64, _) =
            build_c2pa_manifest(&config, &make_test_request(hash), SignPass::Sign)
                .expect("Signing should succeed");
        let manifest_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .unwrap();
        let result = validate_c2pa_manifest(&manifest_bytes, hash, &config.trust_anchors, "", None)
            .expect("Validation should not error");
        assert_eq!(result.signed_at, None);
    }

    /// A trusted timestamp keeps a manifest valid after its signer certificate expires;
    /// without one the manifest expires with the certificate. Needs a live TSA, so it runs
    /// only with C2PA_TSA_TEST_URL and C2PA_TSA_TEST_ANCHORS (PEM roots of that TSA) set.
    #[test]
    fn test_c2pa_timestamp_outlives_signer_certificate() {
        let (Ok(tsa_url), Ok(tsa_anchors_path)) = (
            std::env::var("C2PA_TSA_TEST_URL"),
            std::env::var("C2PA_TSA_TEST_ANCHORS"),
        ) else {
            eprintln!("SKIPPED: C2PA_TSA_TEST_URL / C2PA_TSA_TEST_ANCHORS not set");
            return;
        };
        let tsa_anchors = usable_trust_anchors(
            std::fs::read_to_string(tsa_anchors_path).unwrap(),
            AnchorKind::Tsa,
        );
        assert!(
            !tsa_anchors.is_empty(),
            "TSA anchors must hold a certificate"
        );

        let expiry = time::OffsetDateTime::now_utc() + time::Duration::seconds(4);
        let mut config = config_from_certs(generate_test_certs_until(Some(expiry)));
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let sign = |config: &C2paConfig| {
            let (b64, _) = build_c2pa_manifest(config, &make_test_request(hash), SignPass::Sign)
                .expect("Signing should succeed");
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64).unwrap()
        };
        let untimestamped = sign(&config);
        config.tsa_url = Some(tsa_url);
        let timestamped = sign(&config);

        while time::OffsetDateTime::now_utc() <= expiry + time::Duration::seconds(1) {
            std::thread::sleep(std::time::Duration::from_millis(250));
        }

        let check = |bytes: &[u8], tsa: &str| {
            validate_c2pa_manifest(bytes, hash, &config.trust_anchors, tsa, None)
                .expect("Validation should not error")
        };
        let expired = check(&untimestamped, &tsa_anchors);
        assert!(
            !expired.valid,
            "Untimestamped manifest must expire: {:?}",
            expired.errors
        );

        let with_tsa_root = check(&timestamped, &tsa_anchors);
        assert!(
            with_tsa_root.valid,
            "Trusted timestamp must keep it valid: {:?}",
            with_tsa_root.errors
        );
        assert!(with_tsa_root.signed_at.is_some());

        let without_tsa_root = check(&timestamped, "");
        assert!(
            !without_tsa_root.valid,
            "An untrusted timestamp must not extend validity"
        );
    }

    /// A key held by a key service signs manifests that validate like file-key ones:
    /// the DER signature it returns is converted for COSE (arkavo-rs#104).
    #[test]
    fn test_c2pa_remote_key_round_trip() {
        let (cert_path, key_path) = generate_test_certs();
        let pem = std::fs::read_to_string(&key_path).unwrap();
        let key = p256::ecdsa::SigningKey::from(
            <p256::SecretKey as p256::pkcs8::DecodePrivateKey>::from_pkcs8_pem(&pem).unwrap(),
        );
        let mut config = config_from_certs((cert_path, key_path.clone()));
        config.signing_key =
            SigningKey::Remote(Arc::new(super::super::c2pa_kms::tests::LocalKey(key)));
        std::fs::remove_file(&key_path).unwrap();

        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let (manifest_b64, _) =
            build_c2pa_manifest(&config, &make_test_request(hash), SignPass::Sign)
                .expect("Signing should succeed");
        let manifest_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .unwrap();
        let result = validate_c2pa_manifest(&manifest_bytes, hash, &config.trust_anchors, "", None)
            .expect("Validation should not error");
        assert!(
            result.valid,
            "Remote-key manifest should validate: {:?}",
            result.errors
        );
    }

    /// Signing errors can carry KMS detail (account id, IAM role, key ARN); the
    /// response body must not.
    #[tokio::test]
    async fn test_signing_failure_response_hides_the_cause() {
        let detail = "KMS Sign failed: AccessDeniedException: User: \
                      arn:aws:sts::123456789012:assumed-role/arks/i-0abc is not authorized \
                      to perform: kms:Sign on resource: arn:aws:kms:us-east-1:123456789012:key/k";
        let response = signing_failed_response(detail);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "Signing failed");
        assert_eq!(json["status"], "error");
        assert!(!String::from_utf8_lossy(&body).contains("123456789012"));
    }

    /// Only the certificates after the end-entity become anchors.
    #[test]
    fn test_ca_certs_from_chain() {
        let config = make_test_config();
        let chain = std::fs::read_to_string(&config.signing_cert_path).unwrap();
        let anchors = ca_certs_from_chain(&chain);
        assert_eq!(anchors.matches("-----BEGIN CERTIFICATE-----").count(), 1);
        assert!(chain.ends_with(&anchors));
        assert_eq!(ca_certs_from_chain(&anchors), "");
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

    /// Every signed manifest carries its own non-empty `xmp:iid:` instanceID (arkavo-rs#114).
    #[test]
    fn test_c2pa_instance_id_is_unique_and_non_empty() {
        let config = make_test_config();
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let instance_id = || {
            let (manifest_b64, _) =
                build_c2pa_manifest(&config, &make_test_request(hash), SignPass::Sign)
                    .expect("Signing should succeed");
            let bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                    .unwrap();
            let result =
                validate_c2pa_manifest(&bytes, hash, &config.trust_anchors, "", None).unwrap();
            assert!(result.valid, "{:?}", result.errors);
            let reader = Reader::from_context(Context::new())
                .with_manifest_data_and_stream(&bytes, "video/mp4", Cursor::new(Vec::<u8>::new()))
                .unwrap();
            reader.active_manifest().unwrap().instance_id().to_string()
        };
        let (first, second) = (instance_id(), instance_id());
        assert!(
            first.starts_with("xmp:iid:") && first.len() > "xmp:iid:".len(),
            "{}",
            first
        );
        assert_ne!(first, second);
    }

    /// Test that invalid base64 is rejected during validation.
    #[test]
    fn test_c2pa_validate_invalid_jumbf() {
        // Random bytes that aren't valid JUMBF
        let invalid_bytes = b"this is not valid JUMBF data at all";
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";

        let result = validate_c2pa_manifest(invalid_bytes, hash, "", "", None);
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
        let (manifest_b64, _) =
            build_c2pa_manifest(&config, &req, SignPass::Sign).expect("Signing should succeed");

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

/// `/c2pa/v1/sign` is not a signing oracle (arkavo-rs#109).
#[cfg(test)]
mod sign_endpoint_tests {
    use super::*;
    use crate::modules::authzen::cose_keys::CoseKeyCache;
    use crate::modules::authzen::cwt_verify::test_support::{keypair, mint_map};
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::post;
    use axum::Router;
    use ciborium::value::Value;
    use tower::ServiceExt;

    const ISS: &str = "https://identity.test";
    const PLATFORM: &str = "https://platform.arkavo.net";
    const KID: &[u8] = b"kid-1";
    const SUB: &str = "arkavo:9b1d3c5e-0000-4000-8000-000000000001";
    const HASH: &str = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";

    fn token(sub: &str) -> String {
        token_with_entitlements(sub, &[])
    }

    /// A passkey token whose `arkavo_entitlements` lists `entitlements` (omitted when empty)
    fn token_with_entitlements(sub: &str, entitlements: &[&str]) -> String {
        let (sk, _) = keypair();
        let now = chrono::Utc::now().timestamp();
        let mut claims = vec![
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
                Value::Bytes(uuid::Uuid::new_v4().as_bytes().to_vec()),
            ),
        ];
        if !entitlements.is_empty() {
            claims.push((
                Value::Text("arkavo_entitlements".into()),
                Value::Array(
                    entitlements
                        .iter()
                        .map(|e| Value::Text((*e).into()))
                        .collect(),
                ),
            ));
        }
        mint_map(&sk, KID, claims)
    }

    fn state(limit: usize) -> Arc<C2paSigningState> {
        state_with(limit, false)
    }

    fn state_with(limit: usize, require_entitlement: bool) -> Arc<C2paSigningState> {
        let mut config = tests::make_test_config();
        config.require_entitlement = require_entitlement;
        state_from(limit, config)
    }

    fn state_from(limit: usize, config: C2paConfig) -> Arc<C2paSigningState> {
        let (_, vk) = keypair();
        let verifier = PersonTokenVerifier::new(
            CoseKeyCache::with_static_keys(vec![(KID.to_vec(), vk)]),
            ISS.into(),
            PLATFORM.into(),
        );
        let mut state = C2paSigningState::new(config, Arc::new(verifier));
        state.sign_limit_per_hour = limit;
        Arc::new(state)
    }

    fn body(ranges: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "content_hash": HASH,
            "exclusion_ranges": ranges,
            "container_format": "mov",
            "metadata": {
                "title": "Test", "creator": "anyone",
                "timestamp": "2026-10-25T00:00:00Z"
            }
        })
    }

    async fn sign(
        state: &Arc<C2paSigningState>,
        bearer: Option<&str>,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value, Option<String>) {
        let app = Router::new()
            .route("/c2pa/v1/sign", post(sign_manifest))
            .with_state(state.clone());
        let mut request = Request::post("/c2pa/v1/sign").header("content-type", "application/json");
        if let Some(token) = bearer {
            request = request.header("authorization", format!("Bearer {}", token));
        }
        let response = app
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let retry_after = response
            .headers()
            .get("retry-after")
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or_default(),
            retry_after,
        )
    }

    fn uuid_range(start: u64, len: u64) -> serde_json::Value {
        serde_json::json!([{ "start": start, "end": start + len, "box_type": "uuid" }])
    }

    #[tokio::test]
    async fn test_sign_requires_a_person_token() {
        let state = state(10);
        let (status, _, _) = sign(&state, None, body(uuid_range(1000, 4045))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _, _) = sign(&state, Some("not-a-cwt"), body(uuid_range(1000, 4045))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_sign_refuses_other_exclusion_shapes() {
        let state = state(10);
        let t = token(SUB);
        for ranges in [
            serde_json::json!([]),
            serde_json::json!([{ "start": 0, "end": 10, "box_type": "uuid" },
                               { "start": 20, "end": 30, "box_type": "uuid" }]),
            serde_json::json!([{ "start": 0, "end": 4045 }]),
            serde_json::json!([{ "start": 0, "end": 4045, "box_type": "mdat" }]),
            serde_json::json!([{ "start": 100, "end": 100, "box_type": "uuid" }]),
        ] {
            let (status, _, _) = sign(&state, Some(&t), body(ranges.clone())).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{}", ranges);
        }
    }

    /// The advisory's reproduction: excluding the whole file is refused, and nothing is
    /// returned that could be embedded.
    #[tokio::test]
    async fn test_sign_refuses_whole_file_exclusion() {
        let state = state(10);
        let (status, json, _) = sign(
            &state,
            Some(&token(SUB)),
            body(uuid_range(0, 7_375 + 45 + 14_000)),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(json.get("manifest").is_none());
        assert!(json["required_exclusion_length"].as_u64().unwrap() > 45);
    }

    /// A client learns the box length from the 422 and signs on the next pass; the
    /// manifest names the token subject, not metadata.creator.
    #[tokio::test]
    async fn test_sign_binds_creator_and_box_length() {
        let state = state(10);
        let t = token(SUB);
        let (status, json, _) = sign(&state, Some(&t), body(uuid_range(7_375, 1))).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let mut len = json["required_exclusion_length"].as_u64().unwrap();
        let mut signed = None;
        for _ in 0..4 {
            let (status, json, _) = sign(&state, Some(&t), body(uuid_range(7_375, len))).await;
            if status == StatusCode::OK {
                signed = Some(json);
                break;
            }
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            len = json["required_exclusion_length"].as_u64().unwrap();
        }
        let signed = signed.expect("length should converge");
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            signed["manifest"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(bytes.len() as u64 + MANIFEST_BOX_OVERHEAD, len);
        let result =
            validate_c2pa_manifest(&bytes, HASH, &state.config.trust_anchors, "", None).unwrap();
        assert!(result.valid, "{:?}", result.errors);
        assert_eq!(result.creator.as_deref(), Some(SUB));
    }

    /// A length mismatch is answered without asking the TSA for a timestamp, so a file
    /// costs one timestamp however many rounds the length takes to settle
    /// (arkavo-rs#119). With an unreachable TSA every mismatch still gets its 422; only
    /// the request at the settled length asks the TSA, and fails.
    #[tokio::test]
    async fn test_sign_length_mismatch_spends_no_timestamp() {
        let mut config = tests::make_test_config();
        config.tsa_url = Some("http://127.0.0.1:9/".to_string());
        let state = state_from(10, config);
        let t = token(SUB);
        let mut len = 1;
        for _ in 0..5 {
            let (status, json, _) = sign(&state, Some(&t), body(uuid_range(7_375, len))).await;
            if status == StatusCode::INTERNAL_SERVER_ERROR {
                return;
            }
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{json}");
            len = json["required_exclusion_length"].as_u64().unwrap();
        }
        panic!("the length should settle and only then reach the TSA");
    }

    #[tokio::test]
    async fn test_sign_bad_hash_uses_no_quota() {
        let state = state(1);
        let mut bad = body(uuid_range(0, 1));
        bad["content_hash"] = serde_json::json!("not-hex");
        let (status, _, _) = sign(&state, Some(&token(SUB)), bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _, _) = sign(&state, Some(&token(SUB)), body(uuid_range(0, 1))).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "quota must be intact"
        );
    }

    /// With C2PA_REQUIRE_ENTITLEMENT, only a creator member may sign: the token must carry
    /// the publish entitlement (arkavo-rs#120). A refusal costs no quota.
    #[tokio::test]
    async fn test_sign_requires_the_publish_entitlement_when_configured() {
        let state = state_with(1, true);
        let view = "https://patreon.arkavo.com/attr/arkavo-creator/value/view";
        for bearer in [token(SUB), token_with_entitlements(SUB, &[view])] {
            let (status, json, _) = sign(&state, Some(&bearer), body(uuid_range(0, 1))).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(json["error"], "signing entitlement required");
            assert_eq!(json["required_entitlement"], SIGNING_ENTITLEMENT);
        }
        let member = token_with_entitlements(SUB, &[view, SIGNING_ENTITLEMENT]);
        let (status, _, _) = sign(&state, Some(&member), body(uuid_range(0, 1))).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a member signs as before, with the quota intact"
        );
    }

    #[tokio::test]
    async fn test_sign_ignores_entitlements_unless_configured() {
        let state = state(10);
        let (status, _, _) = sign(&state, Some(&token(SUB)), body(uuid_range(0, 1))).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_sign_is_rate_limited_per_subject() {
        let state = state(1);
        let (first, _, _) = sign(&state, Some(&token(SUB)), body(uuid_range(0, 1))).await;
        assert_eq!(first, StatusCode::UNPROCESSABLE_ENTITY);
        let (second, _, retry_after) =
            sign(&state, Some(&token(SUB)), body(uuid_range(0, 1))).await;
        assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
        assert!(retry_after.unwrap().parse::<u64>().unwrap() > 0);
        let other = "arkavo:9b1d3c5e-0000-4000-8000-000000000002";
        let (third, _, _) = sign(&state, Some(&token(other)), body(uuid_range(0, 1))).await;
        assert_eq!(third, StatusCode::UNPROCESSABLE_ENTITY);
    }
}
