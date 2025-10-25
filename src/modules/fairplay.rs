//! FairPlay Streaming protocol handler
//!
//! Integrates Apple's FairPlay Streaming SDK with the arkavo media DRM system.
//! Provides key delivery for Apple devices (iOS, tvOS, macOS, Safari) while
//! maintaining unified session management and policy enforcement with TDF3.

#[cfg(feature = "fairplay")]
use fairplay_wrapper::{FairPlayKeyServer, SpcRequest};
use std::path::PathBuf;
use std::sync::Arc;

/// FairPlay protocol handler
///
/// Wraps the FairPlay SDK and integrates with arkavo's session management.
pub struct FairPlayHandler {
    #[cfg(feature = "fairplay")]
    key_server: Arc<FairPlayKeyServer>,
    #[allow(dead_code)]
    enabled: bool,
}

impl FairPlayHandler {
    /// Create new FairPlay handler
    ///
    /// # Arguments
    /// * `credentials_path` - Path to FairPlay credentials directory
    ///
    /// # Returns
    /// Handler instance, or error if credentials invalid
    #[cfg(feature = "fairplay")]
    #[allow(dead_code)]
    pub fn new(credentials_path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let key_server = FairPlayKeyServer::new(credentials_path)?;
        log::info!("FairPlay handler initialized (SDK v{})", key_server.version());

        Ok(Self {
            key_server: Arc::new(key_server),
            enabled: true,
        })
    }

    /// Create disabled handler when feature not compiled
    #[cfg(not(feature = "fairplay"))]
    #[allow(dead_code)]
    pub fn new(_credentials_path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        log::warn!("FairPlay feature not enabled at compile time");
        Ok(Self { enabled: false })
    }

    /// Check if FairPlay is enabled
    #[allow(dead_code)]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Process FairPlay key request
    ///
    /// Takes an SPC from the client and returns a CKC with encrypted content key.
    ///
    /// # Arguments
    /// * `content_id` - Content identifier
    /// * `asset_id` - Asset identifier for tracking/policy
    /// * `spc_data` - Raw SPC bytes from client
    /// * `content_key` - DEK to encrypt in CKC (typically 16 bytes)
    ///
    /// # Returns
    /// CKC bytes to send to client
    #[cfg(feature = "fairplay")]
    #[allow(dead_code)]
    pub async fn process_key_request(
        &self,
        content_id: String,
        asset_id: String,
        spc_data: Vec<u8>,
        content_key: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        log::debug!(
            "Processing FairPlay key request: content_id={} asset_id={} spc_len={} key_len={}",
            content_id,
            asset_id,
            spc_data.len(),
            content_key.len()
        );

        // Validate content key length (should be 16 bytes for AES-128)
        if content_key.len() != 16 {
            log::warn!(
                "Content key length {} != 16, FairPlay expects AES-128",
                content_key.len()
            );
        }

        let request = SpcRequest {
            content_id,
            spc_data,
            asset_id,
            content_key,
        };

        // Process SPC using SDK (blocking operation, run in blocking task)
        let key_server = self.key_server.clone();
        let response = tokio::task::spawn_blocking(move || key_server.process_spc(request)).await??;

        log::debug!("FairPlay CKC generated ({} bytes)", response.ckc_data.len());

        Ok(response.ckc_data)
    }

    /// Process key request when feature not compiled
    #[cfg(not(feature = "fairplay"))]
    #[allow(dead_code)]
    pub async fn process_key_request(
        &self,
        _content_id: String,
        _asset_id: String,
        _spc_data: Vec<u8>,
        _content_key: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Err("FairPlay support not compiled in (use --features fairplay)".into())
    }

    /// Get SDK version (if available)
    #[cfg(feature = "fairplay")]
    #[allow(dead_code)]
    pub fn version(&self) -> Option<&str> {
        Some(self.key_server.version())
    }

    #[cfg(not(feature = "fairplay"))]
    #[allow(dead_code)]
    pub fn version(&self) -> Option<&str> {
        None
    }
}

// Re-export MediaProtocol from lib
pub use nanotdf::modules::MediaProtocol;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_creation_without_feature() {
        #[cfg(not(feature = "fairplay"))]
        {
            let handler = FairPlayHandler::new(PathBuf::from("./test")).unwrap();
            assert!(!handler.is_enabled());
        }
    }

    #[test]
    fn test_protocol_serialization() {
        let json = serde_json::to_string(&MediaProtocol::FairPlay).unwrap();
        assert_eq!(json, "\"fairplay\"");

        let json = serde_json::to_string(&MediaProtocol::TDF3).unwrap();
        assert_eq!(json, "\"tdf3\"");
    }
}
