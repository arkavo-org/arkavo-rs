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
//! };
//!
//! let response = key_server.process_spc(request).unwrap();
//! // response.ckc_data contains the encrypted CKC to send to client
//! ```

use std::ffi::{CStr, CString};
use std::path::PathBuf;
use std::sync::Once;

static INIT: Once = Once::new();

/// FairPlay Key Server instance
///
/// Manages FairPlay Streaming content key operations using Apple's SDK.
pub struct FairPlayKeyServer {
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
    /// };
    /// let response = server.process_spc(request).unwrap();
    /// ```
    pub fn process_spc(&self, request: SpcRequest) -> Result<CkcResponse, FairPlayError> {
        log::debug!(
            "Processing SPC for content_id={} asset_id={}",
            request.content_id,
            request.asset_id
        );

        // Build JSON request per FairPlay SDK specification
        let json_request = serde_json::json!({
            "fairplay-streaming-request": {
                "create-ckc": [{
                    "id": 1,
                    "content-id": request.content_id,
                    "spc": base64::encode(&request.spc_data),
                    "asset-id": request.asset_id,
                    "ck": base64::encode(&request.content_key),
                }]
            }
        });

        let json_str = serde_json::to_string(&json_request)?;
        log::trace!("FairPlay request JSON: {}", json_str);

        // Call fpssdk FFI
        let ckc_data = unsafe {
            let input = CString::new(json_str.as_str())?;
            let mut output: *mut i8 = std::ptr::null_mut();
            let mut output_size: usize = 0;

            let status = fpssdk::fpsProcessOperations(
                input.as_ptr(),
                json_str.len(),
                &mut output,
                &mut output_size,
            );

            if status != fpssdk::validate::FPSStatus::noErr {
                log::error!("fpssdk error status: {:?}", status);
                return Err(FairPlayError::SdkError(status as i32));
            }

            let response_str = CStr::from_ptr(output).to_string_lossy();
            log::trace!("FairPlay response JSON: {}", response_str);

            let response: serde_json::Value = serde_json::from_str(&response_str)?;

            // Cleanup SDK-allocated memory
            fpssdk::fpsDisposeResponse(output, output_size);

            // Extract CKC from response
            let ckc_base64 = response
                .get("fairplay-streaming-response")
                .and_then(|r| r.get("create-ckc"))
                .and_then(|c| c.get(0))
                .and_then(|item| item.get("ckc"))
                .and_then(|ckc| ckc.as_str())
                .ok_or(FairPlayError::InvalidResponse)?;

            base64::decode(ckc_base64)?
        };

        log::debug!("Successfully generated CKC ({} bytes)", ckc_data.len());

        Ok(CkcResponse { ckc_data })
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
            if status != fpssdk::validate::FPSStatus::noErr {
                return Err(FairPlayError::SdkError(status as i32));
            }

            let version = CStr::from_ptr(version_ptr).to_string_lossy().to_string();
            fpssdk::fpsDisposeVersion(version_ptr);

            Ok(version)
        }
    }
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
}

/// CKC (Content Key Context) response
///
/// Returned to the client, contains encrypted content key.
#[derive(Debug, Clone)]
pub struct CkcResponse {
    /// Raw CKC data to send to client
    pub ckc_data: Vec<u8>,
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
