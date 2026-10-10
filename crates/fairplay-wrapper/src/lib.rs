//! Safe Rust wrapper for Apple FairPlay Streaming Server SDK
//!
//! This crate provides a safe, idiomatic Rust API over the fpssdk FFI bindings
//! from Apple's FairPlay Streaming Server SDK 26.
//!
//! # Usage
//!
//! ```no_run
//! use fairplay_wrapper::{ContentType, FairPlayKeyServer, SpcRequest};
//! use std::path::PathBuf;
//!
//! let credentials_path = PathBuf::from("./credentials");
//! let key_server = FairPlayKeyServer::new(credentials_path).unwrap();
//!
//! let request = SpcRequest {
//!     content_id: "movie-12345".to_string(),
//!     spc_data: vec![/* SPC bytes */],
//!     asset_id: "asset-001".to_string(),
//!     content_key: vec![/* 16-byte DEK */],
//!     content_iv: vec![/* 16-byte content IV */],
//!     content_type: ContentType::Uhd,
//!     lease_duration_secs: Some(3600),
//! };
//!
//! let response = key_server.process_spc(request).unwrap();
//! // response.ckc_data contains the encrypted CKC to send to client
//! ```

use base64::Engine;
use std::ffi::{CStr, CString};
use std::path::PathBuf;
use std::sync::Once;

static INIT: Once = Once::new();

/// FairPlay Key Server instance
///
/// Manages FairPlay Streaming content key operations using Apple's SDK.
pub struct FairPlayKeyServer {
    #[allow(dead_code)] // Stored for debugging/logging purposes
    credentials_path: PathBuf,
    sdk_version: String,
}

impl FairPlayKeyServer {
    /// Initialize FairPlay Key Server with credentials directory
    ///
    /// The credentials directory must contain:
    /// - `certificates.json` or `test_certificates.json`
    /// - FPS certificate files (*.bin)
    /// - Private key files (*.pem)
    /// - Provisioning data files (*.bin)
    ///
    /// # Arguments
    /// * `credentials_path` - Path to credentials directory
    ///
    /// # Example
    /// ```no_run
    /// use fairplay_wrapper::FairPlayKeyServer;
    /// use std::path::PathBuf;
    ///
    /// let path = PathBuf::from("./vendor/FairPlay_SDK/credentials");
    /// let server = FairPlayKeyServer::new(path).unwrap();
    /// ```
    pub fn new(credentials_path: PathBuf) -> Result<Self, FairPlayError> {
        // Set environment variable for fpssdk to find certificates
        std::env::set_var("FAIRPLAY_CREDENTIALS_PATH", &credentials_path);
        // The SDK itself only reads FPS_CERT_PATH (the certificates JSON file)
        // and otherwise falls back to a path relative to the working directory.
        if std::env::var_os("FPS_CERT_PATH").is_none() {
            let certs = ["certificates.json", "test_certificates.json"]
                .iter()
                .map(|name| credentials_path.join(name))
                .find(|p| p.exists());
            if let Some(certs) = certs {
                std::env::set_var("FPS_CERT_PATH", certs);
            }
        }
        match std::env::var("FPS_CERT_PATH") {
            Ok(p) => log::info!("FairPlay certificates: {p}"),
            Err(_) => {
                log::warn!("FairPlay certificates: no certificates JSON found; SDK default path")
            }
        }

        // Initialize SDK (one-time operation)
        INIT.call_once(|| {
            log::info!("Initializing FairPlay SDK from: {:?}", credentials_path);
        });

        let sdk_version = Self::get_sdk_version()?;
        log::info!("FairPlay SDK version: {}", sdk_version);

        Ok(Self {
            credentials_path,
            sdk_version,
        })
    }

    /// Process SPC (Server Playback Context) and return CKC (Content Key Context)
    ///
    /// This is the main key exchange operation. The client sends an SPC,
    /// and the server responds with a CKC containing the encrypted content key.
    ///
    /// # Arguments
    /// * `request` - SPC request containing content ID, SPC data, and content key
    ///
    /// # Returns
    /// CKC response containing encrypted key data for the client
    ///
    /// # Example
    /// ```no_run
    /// # use fairplay_wrapper::{ContentType, FairPlayKeyServer, SpcRequest};
    /// # let server = FairPlayKeyServer::new("./creds".into()).unwrap();
    /// let request = SpcRequest {
    ///     content_id: "asset-123".to_string(),
    ///     spc_data: vec![0x01, 0x02, 0x03],  // Client SPC
    ///     asset_id: "asset-123".to_string(),
    ///     content_key: vec![0xAA; 16],  // 16-byte DEK
    ///     content_iv: vec![0xBB; 16],   // 16-byte content IV
    ///     content_type: ContentType::Uhd,
    ///     lease_duration_secs: Some(3600),
    /// };
    /// let response = server.process_spc(request).unwrap();
    /// ```
    pub fn process_spc(&self, request: SpcRequest) -> Result<CkcResponse, FairPlayError> {
        log::debug!(
            "Processing SPC for content_id={} asset_id={}",
            request.content_id,
            request.asset_id
        );
        // Baseline for the SDK 27 upgrade: which SPC versions devices send.
        match spc_version(&request.spc_data) {
            Some(v) => log::info!("FairPlay SPC version {v:#010x}"),
            None => log::info!("FairPlay SPC shorter than its version field"),
        }

        // Never hand the SDK key material it would have to repair: its decode
        // warnings and its panic handler print the request to stderr (#83).
        let json_request = build_request_json(&request)?;
        let json_str = serde_json::to_string(&json_request)?;

        // Call fpssdk FFI
        let parsed = unsafe {
            let input = CString::new(json_str.as_str())?;
            let mut output: *mut i8 = std::ptr::null_mut();
            let mut output_size: usize = 0;

            let status = fpssdk::fpsProcessOperations(
                input.as_ptr(),
                json_str.len(),
                &mut output,
                &mut output_size,
            );

            if status as i32 != 0 {
                // noErr = 0
                log::error!("fpssdk error status: {}", status as i32);
                return Err(FairPlayError::SdkError(status as i32));
            }

            let response_str = CStr::from_ptr(output).to_string_lossy();
            let response = serde_json::from_str::<serde_json::Value>(&response_str);

            // Always free SDK-allocated memory, whether or not parsing succeeded
            fpssdk::fpsDisposeResponse(output, output_size);

            parse_response(&response?)
        };
        let response = parsed?;

        log::debug!(
            "Successfully generated CKC ({} bytes)",
            response.ckc_data.len()
        );

        Ok(response)
    }

    /// Get SDK version string
    pub fn version(&self) -> &str {
        &self.sdk_version
    }

    /// Get SDK version from fpssdk (internal)
    fn get_sdk_version() -> Result<String, FairPlayError> {
        unsafe {
            let mut version_ptr: *mut i8 = std::ptr::null_mut();

            let status = fpssdk::fpsGetVersion(&mut version_ptr);
            if status as i32 != 0 {
                // noErr = 0
                return Err(FairPlayError::SdkError(status as i32));
            }

            let version = CStr::from_ptr(version_ptr).to_string_lossy().to_string();
            fpssdk::fpsDisposeVersion(version_ptr);

            Ok(version)
        }
    }
}

/// AES-128 key and IV length the SDK expects in `asset-info`.
const KEY_IV_LEN: usize = 16;

/// The SDK `content-type` a CKC is issued as (arkavo-ios ADR-0055 §7). Both
/// are issued with HDCP Type 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// Video: security level Main; with SPC v3 keys the SDK seals the key
    /// for the device's secure video path.
    Uhd,
    /// Audio: security level audio; the key is usable by the audio decoder.
    Audio,
}

impl ContentType {
    pub fn as_str(self) -> &'static str {
        match self {
            ContentType::Uhd => "uhd",
            ContentType::Audio => "audio",
        }
    }
}

/// Build the SDK JSON request for one CKC. Never requests `offline-hls`.
///
/// The SDK reads the key, IV and lease only from `asset-info[0]`, as hex
/// strings; anything at the item level is ignored and the CKC would carry a
/// zero key and IV.
pub fn build_request_json(request: &SpcRequest) -> Result<serde_json::Value, FairPlayError> {
    if request.content_key.len() != KEY_IV_LEN || request.content_iv.len() != KEY_IV_LEN {
        return Err(FairPlayError::InvalidKeyMaterial);
    }
    // SDK 26 issues a streaming licence unless an `offline-hls` object is present, so omitting it requests a streaming, non-persistable licence.
    let mut asset_info = serde_json::json!({
        "content-key": hex::encode(&request.content_key),
        "content-iv": hex::encode(&request.content_iv),
        // The SDK refuses a CKC without a content type. UHD: the device must
        // support security level Main, and the SDK refuses UHD unless HDCP
        // Type 1 is required. Audio is issued with HDCP Type 1 too (ADR-0055).
        "content-type": request.content_type.as_str(),
        "hdcp-type": 1,
        // HLS FairPlay (SAMPLE-AES) segments.
        "encryption-scheme": "cbcs",
    });
    // Without `lease-duration` the SDK issues a licence with no lease.
    if let Some(secs) = request.lease_duration_secs {
        asset_info["lease-duration"] = serde_json::json!(secs);
    }
    let item = serde_json::json!({
        "id": 1,
        "spc": base64::engine::general_purpose::STANDARD.encode(&request.spc_data),
        "asset-id": request.asset_id,
        "asset-info": [asset_info],
    });
    Ok(serde_json::json!({ "fairplay-streaming-request": { "create-ckc": [item] } }))
}

/// SPC version, the first 4 bytes of the SPC container (not secret).
pub fn spc_version(spc: &[u8]) -> Option<u32> {
    spc.get(..4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Extract the CKC and echoed asset id from the SDK JSON response.
pub fn parse_response(response: &serde_json::Value) -> Result<CkcResponse, FairPlayError> {
    let item = response
        .get("fairplay-streaming-response")
        .and_then(|r| r.get("create-ckc"))
        .and_then(|c| c.get(0))
        .ok_or(FairPlayError::InvalidResponse)?;
    // A per-item failure comes back as a non-zero `status` and no `ckc`.
    if let Some(status) = item.get("status").and_then(|s| s.as_i64()) {
        if status != 0 {
            return Err(FairPlayError::SdkError(status as i32));
        }
    }
    let ckc_base64 = item
        .get("ckc")
        .and_then(|c| c.as_str())
        .ok_or(FairPlayError::InvalidResponse)?;
    let ckc_data = base64::engine::general_purpose::STANDARD.decode(ckc_base64)?;
    let asset_id = item
        .get("asset-id")
        .and_then(|a| a.as_str())
        .map(str::to_string);
    Ok(CkcResponse { ckc_data, asset_id })
}

/// SPC (Server Playback Context) request
///
/// Sent by the client to initiate key exchange.
#[derive(Debug, Clone)]
pub struct SpcRequest {
    /// Content identifier (e.g., "asset-12345")
    pub content_id: String,
    /// Raw SPC data from client
    pub spc_data: Vec<u8>,
    /// Asset identifier for tracking
    pub asset_id: String,
    /// Content key to encrypt in the CKC; exactly 16 bytes (AES-128)
    pub content_key: Vec<u8>,
    /// Content IV for the recording; exactly 16 bytes
    pub content_iv: Vec<u8>,
    /// The SDK content type: `Uhd` for video, `Audio` for audio.
    pub content_type: ContentType,
    /// CKC lease in seconds; None sends no lease. Streaming licence type only; `offline-hls` is never requested.
    pub lease_duration_secs: Option<u32>,
}

/// CKC (Content Key Context) response
///
/// Returned to the client, contains encrypted content key.
#[derive(Debug, Clone)]
pub struct CkcResponse {
    /// Raw CKC data to send to client
    pub ckc_data: Vec<u8>,
    /// Asset ID the device put in the SPC, as echoed by the SDK.
    pub asset_id: Option<String>,
}

/// FairPlay error types
#[derive(Debug, thiserror::Error)]
pub enum FairPlayError {
    /// SDK returned an error status
    #[error("FairPlay SDK error: status code {0}")]
    SdkError(i32),

    /// SDK response was missing expected fields
    #[error("Invalid response from FairPlay SDK")]
    InvalidResponse,

    /// Content key or IV is not 16 bytes; refused before the SDK is called.
    /// The text is fixed and never carries the bytes.
    #[error("content key or IV is not 16 bytes")]
    InvalidKeyMaterial,

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64 encoding/decoding error
    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// String conversion error
    #[error("String conversion error: {0}")]
    NulError(#[from] std::ffi::NulError),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl FairPlayError {
    /// True when the SDK refused the client's SPC itself (bad version,
    /// unparseable or missing/duplicated TLLVs): a client fault. Every other
    /// failure (parameters we supplied, credentials, integrity, internal) is
    /// treated as a server-side fault.
    pub fn is_malformed_spc(&self) -> bool {
        matches!(
            self,
            FairPlayError::SdkError(
                SPC_VERSION_ERR | PARSER_ERR | MISSING_REQUIRED_TAG_ERR | VERSION_ERR | DUP_TAG_ERR
            )
        )
    }
}

// FPSStatus values from the SDK (vendor/fpssdk/src/extension/validate.rs).
const SPC_VERSION_ERR: i32 = -42580;
const PARSER_ERR: i32 = -42581;
const MISSING_REQUIRED_TAG_ERR: i32 = -42583;
const VERSION_ERR: i32 = -42590;
const DUP_TAG_ERR: i32 = -42591;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        // This test requires credentials to be set up
        if let Ok(server) = FairPlayKeyServer::new(PathBuf::from("./credentials")) {
            let version = server.version();
            assert!(!version.is_empty());
            assert!(version.starts_with("26")); // SDK 26
        }
    }
}

#[cfg(test)]
mod request_json_tests {
    use super::*;

    fn req(lease: Option<u32>) -> SpcRequest {
        SpcRequest {
            content_id: "c".into(),
            spc_data: vec![1, 2],
            asset_id: "a".into(),
            content_key: (0u8..16).collect(),
            content_iv: (0xf0u8..=0xff).collect(),
            content_type: ContentType::Uhd,
            lease_duration_secs: lease,
        }
    }

    #[test]
    fn key_iv_and_lease_go_in_asset_info() {
        let v = build_request_json(&req(Some(3600))).unwrap();
        let item = &v["fairplay-streaming-request"]["create-ckc"][0];
        let infos = item["asset-info"].as_array().unwrap();
        assert_eq!(infos.len(), 1);
        let info = &infos[0];
        assert_eq!(info["content-key"], "000102030405060708090a0b0c0d0e0f");
        assert_eq!(info["content-iv"], "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        assert_eq!(info["lease-duration"], 3600);
        assert_eq!(info["content-type"], "uhd");
        assert_eq!(info["hdcp-type"], 1);
        assert_eq!(info["encryption-scheme"], "cbcs");
        // The SDK ignores item-level key material; none may be left there.
        for k in ["ck", "content-key", "content-iv", "lease-duration"] {
            assert!(item.get(k).is_none(), "{k} at item level");
        }
        assert!(item.get("offline-hls").is_none());
        assert!(info.get("offline-hls").is_none());
        assert_eq!(item["asset-id"], "a");
    }

    /// ADR-0055: audio keys are issued as `audio`, still with HDCP Type 1.
    #[test]
    fn audio_is_issued_as_audio_with_hdcp_type_1() {
        let mut r = req(Some(60));
        r.content_type = ContentType::Audio;
        let v = build_request_json(&r).unwrap();
        let info = &v["fairplay-streaming-request"]["create-ckc"][0]["asset-info"][0];
        assert_eq!(info["content-type"], "audio");
        assert_eq!(info["hdcp-type"], 1);
        assert_eq!(info["encryption-scheme"], "cbcs");
    }

    #[test]
    fn content_types_name_the_sdk_values() {
        assert_eq!(ContentType::Uhd.as_str(), "uhd");
        assert_eq!(ContentType::Audio.as_str(), "audio");
    }

    #[test]
    fn no_lease_omits_lease_duration() {
        let v = build_request_json(&req(None)).unwrap();
        let info = &v["fairplay-streaming-request"]["create-ckc"][0]["asset-info"][0];
        assert!(info.get("lease-duration").is_none());
    }

    #[test]
    fn wrong_length_key_or_iv_is_refused_without_echo() {
        for (key, iv) in [
            (15, 16),
            (17, 16),
            (32, 16),
            (0, 16),
            (16, 12),
            (16, 0),
            (16, 32),
        ] {
            let mut r = req(Some(60));
            r.content_key = vec![0xab; key];
            r.content_iv = vec![0xcd; iv];
            let e = build_request_json(&r).unwrap_err();
            assert!(matches!(e, FairPlayError::InvalidKeyMaterial), "{key}/{iv}");
            let text = e.to_string();
            assert!(!text.contains("ab") && !text.contains("cd"), "{text}");
            assert!(!e.is_malformed_spc());
        }
    }

    #[test]
    fn spc_version_reads_first_four_bytes() {
        assert_eq!(spc_version(&[0, 0, 0, 2, 9, 9]), Some(2));
        assert_eq!(spc_version(&[0, 0, 1]), None);
    }

    #[test]
    fn response_asset_id_is_returned() {
        let ckc = base64::engine::general_purpose::STANDARD.encode([9u8; 4]);
        let v = serde_json::json!({"fairplay-streaming-response":{"create-ckc":[{"id":1,"ckc":ckc,"asset-id":"uuid-1"}]}});
        let r = parse_response(&v).unwrap();
        assert_eq!(r.ckc_data, vec![9u8; 4]);
        assert_eq!(r.asset_id.as_deref(), Some("uuid-1"));
    }

    #[test]
    fn item_status_is_surfaced_as_sdk_error() {
        let v = serde_json::json!({"fairplay-streaming-response":{"create-ckc":[{"id":1,"status":-42581}]}});
        assert!(matches!(
            parse_response(&v),
            Err(FairPlayError::SdkError(-42581))
        ));
    }

    #[test]
    fn only_spc_shape_statuses_are_malformed_spc() {
        for code in [-42580, -42581, -42583, -42590, -42591] {
            assert!(FairPlayError::SdkError(code).is_malformed_spc(), "{code}");
        }
        // Server side (params, credentials, internal) or ambiguous (integrity).
        for code in [-42585, -42586, -42589, -42601, -42604, -42605, -42612, -1] {
            assert!(!FairPlayError::SdkError(code).is_malformed_spc(), "{code}");
        }
        assert!(!FairPlayError::InvalidResponse.is_malformed_spc());
    }
}
