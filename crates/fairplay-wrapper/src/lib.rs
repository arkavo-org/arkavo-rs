//! Safe Rust wrapper for Apple FairPlay Streaming Server SDK
//!
//! This crate provides a safe, idiomatic Rust API over the fpssdk FFI bindings
//! from Apple's FairPlay Streaming Server SDK 26.
//!
//! # Usage
//!
//! ```no_run
//! use fairplay_wrapper::{FairPlayKeyServer, SpcRequest};
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
    /// # use fairplay_wrapper::{FairPlayKeyServer, SpcRequest};
    /// # let server = FairPlayKeyServer::new("./creds".into()).unwrap();
    /// let request = SpcRequest {
    ///     content_id: "asset-123".to_string(),
    ///     spc_data: vec![0x01, 0x02, 0x03],  // Client SPC
    ///     asset_id: "asset-123".to_string(),
    ///     content_key: vec![0xAA; 16],  // 16-byte DEK
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

        let json_request = build_request_json(&request);
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

/// Build the SDK JSON request for one CKC. Never requests `offline-hls`.
pub fn build_request_json(request: &SpcRequest) -> serde_json::Value {
    // SDK 26 issues a streaming licence unless an `offline-hls` object is present, so omitting it requests a streaming, non-persistable licence.
    let mut item = serde_json::json!({
        "id": 1,
        "content-id": request.content_id,
        "spc": base64::engine::general_purpose::STANDARD.encode(&request.spc_data),
        "asset-id": request.asset_id,
        "ck": base64::engine::general_purpose::STANDARD.encode(&request.content_key),
    });
    if let Some(secs) = request.lease_duration_secs {
        item["lease-duration"] = serde_json::json!(secs);
    }
    serde_json::json!({ "fairplay-streaming-request": { "create-ckc": [item] } })
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
    /// Content key (DEK) to encrypt in CKC (typically 16 bytes for AES-128)
    pub content_key: Vec<u8>,
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
            content_key: vec![0; 16],
            lease_duration_secs: lease,
        }
    }

    #[test]
    fn lease_is_sent_and_never_offline() {
        let v = build_request_json(&req(Some(3600)));
        let item = &v["fairplay-streaming-request"]["create-ckc"][0];
        assert_eq!(item["lease-duration"], 3600);
        assert!(item.get("offline-hls").is_none());
        let v = build_request_json(&req(None));
        assert!(v["fairplay-streaming-request"]["create-ckc"][0]
            .get("lease-duration")
            .is_none());
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
