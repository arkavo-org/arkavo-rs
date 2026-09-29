//! The one step that needs the Apple SDK, behind a trait so the whole
//! authorization pipeline is tested without the `fairplay` feature.

pub struct IssuedLicense {
    pub ckc: Vec<u8>,
    /// The asset id inside the SPC (client-chosen); logged, never trusted.
    pub spc_asset_id: Option<String>,
}

/// Why no CKC was issued. The detail is for logs only (an SDK status or
/// error text, never SPC or CKC bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
// Only the `fairplay` issuer (and the test fake) construct these.
#[cfg_attr(not(feature = "fairplay"), allow(dead_code))]
pub enum IssueError {
    /// The SDK, its credentials or the issuing task failed: a server fault.
    Sdk(String),
    /// The SDK refused the client's SPC as malformed: a client fault.
    MalformedSpc(String),
}

#[async_trait::async_trait]
pub trait LicenseIssuer: Send + Sync {
    async fn issue(
        &self,
        spc: Vec<u8>,
        content_key: [u8; 16],
        asset_id: &str,
        lease_secs: u32,
    ) -> Result<IssuedLicense, IssueError>;
}

#[cfg(feature = "fairplay")]
#[async_trait::async_trait]
impl LicenseIssuer for crate::modules::fairplay::FairPlayHandler {
    async fn issue(
        &self,
        spc: Vec<u8>,
        content_key: [u8; 16],
        asset_id: &str,
        lease_secs: u32,
    ) -> Result<IssuedLicense, IssueError> {
        self.process_key_request(spc, content_key.to_vec(), asset_id.to_string(), lease_secs)
            .await
            .map_err(|e| {
                let malformed = e
                    .downcast_ref::<fairplay_wrapper::FairPlayError>()
                    .is_some_and(fairplay_wrapper::FairPlayError::is_malformed_spc);
                if malformed {
                    IssueError::MalformedSpc(e.to_string())
                } else {
                    IssueError::Sdk(e.to_string())
                }
            })
    }
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use std::sync::Mutex;

    /// Records the key it was asked to issue and returns a fixed CKC, or the
    /// failure it was built with.
    pub struct FakeIssuer {
        pub seen_key: Mutex<Option<[u8; 16]>>,
        pub seen_lease: Mutex<Option<u32>>,
        pub spc_asset_id: Option<String>,
        pub failure: Option<IssueError>,
    }

    impl FakeIssuer {
        pub fn new(spc_asset_id: Option<&str>) -> Self {
            Self {
                seen_key: Mutex::new(None),
                seen_lease: Mutex::new(None),
                spc_asset_id: spc_asset_id.map(str::to_string),
                failure: None,
            }
        }

        pub fn failing(failure: IssueError) -> Self {
            Self {
                failure: Some(failure),
                ..Self::new(None)
            }
        }
    }

    #[async_trait::async_trait]
    impl LicenseIssuer for FakeIssuer {
        async fn issue(
            &self,
            _spc: Vec<u8>,
            content_key: [u8; 16],
            _asset_id: &str,
            lease_secs: u32,
        ) -> Result<IssuedLicense, IssueError> {
            *self.seen_key.lock().unwrap() = Some(content_key);
            *self.seen_lease.lock().unwrap() = Some(lease_secs);
            if let Some(f) = &self.failure {
                return Err(f.clone());
            }
            Ok(IssuedLicense {
                ckc: b"fake-ckc".to_vec(),
                spc_asset_id: self.spc_asset_id.clone(),
            })
        }
    }
}
