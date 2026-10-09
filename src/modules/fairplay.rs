//! FairPlay Streaming protocol handler
//!
//! Integrates Apple's FairPlay Streaming SDK with the arkavo media DRM system.
//! Provides key delivery for Apple devices (iOS, tvOS, macOS, Safari) while
//! maintaining unified session management and policy enforcement with TDF3.

#[cfg(feature = "fairplay")]
use fairplay_wrapper::{FairPlayKeyServer, SpcRequest};
use std::path::PathBuf;
#[cfg(feature = "fairplay")]
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
        log::info!(
            "FairPlay handler initialized (SDK v{})",
            key_server.version()
        );

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
    /// Takes an SPC from the client and returns a leased CKC with the encrypted
    /// content key. `asset_id` is the TDF policy uuid, sent to the SDK as both
    /// `content-id` and `asset-id`.
    #[cfg(feature = "fairplay")]
    pub async fn process_key_request(
        &self,
        spc_data: Vec<u8>,
        content_key: Vec<u8>,
        asset_id: String,
        lease_secs: u32,
    ) -> Result<
        crate::modules::license::issuer::IssuedLicense,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        log::debug!(
            "Processing FairPlay key request: asset_id={} spc_len={} lease_secs={}",
            asset_id,
            spc_data.len(),
            lease_secs
        );

        let request = SpcRequest {
            content_id: asset_id.clone(),
            spc_data,
            asset_id,
            content_key,
            lease_duration_secs: Some(lease_secs),
        };

        // Process SPC using SDK (blocking operation, run in blocking task)
        let key_server = self.key_server.clone();
        let response =
            tokio::task::spawn_blocking(move || key_server.process_spc(request)).await??;

        log::debug!("FairPlay CKC generated ({} bytes)", response.ckc_data.len());

        Ok(crate::modules::license::issuer::IssuedLicense {
            ckc: response.ckc_data,
            spc_asset_id: response.asset_id,
        })
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
