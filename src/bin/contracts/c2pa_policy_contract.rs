#![allow(unexpected_cfgs)]
#![allow(dead_code)] // Ink contract generated functions

/// C2PA Policy Contract
///
/// Implements C2PA provenance validation and policy enforcement for content authenticity.
/// This contract validates C2PA manifests, verifies creator allowlists, and enforces
/// AI-generated content policies.

#[ink::contract]
pub mod c2pa_policy {

    /// C2PA validation result
    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ValidationResult {
        Valid,
        Invalid,
        Missing,
    }

    /// Content authenticity level
    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum AuthenticityLevel {
        Verified,   // Full C2PA validation passed
        Unverified, // No C2PA manifest
        Suspicious, // Manifest present but validation failed
    }

    /// AI content disclosure requirement
    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum AiDisclosurePolicy {
        Required,   // AI-generated flag must be present if content is AI-generated
        Prohibited, // AI-generated content not allowed
        Optional,   // No AI disclosure requirements
    }

    /// C2PA manifest metadata extracted from assertions
    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct C2paManifest {
        pub validation_result: ValidationResult,
        pub creator: Option<[u8; 64]>, // Creator identifier (truncated/hashed)
        pub ai_generated: Option<bool>,
        pub edit_count: u32,        // Number of edits in provenance chain
        pub timestamp: Option<i64>, // Creation timestamp
        pub content_hash: [u8; 32], // SHA-256 hash from manifest
    }

    /// Content policy requirements
    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct ContentPolicy {
        pub require_c2pa: bool,              // C2PA manifest required
        pub allowed_creators: Vec<[u8; 64]>, // Whitelist of trusted creators (empty = all allowed)
        pub ai_disclosure_policy: AiDisclosurePolicy,
        pub max_edit_count: Option<u32>, // Maximum allowed edits (None = unlimited)
        pub require_timestamp: bool,     // Creation timestamp required
    }

    /// Access decision
    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct AccessDecision {
        pub granted: bool,
        pub reason: AccessDenialReason,
        pub authenticity_level: AuthenticityLevel,
    }

    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum AccessDenialReason {
        Granted,
        C2paRequired,
        C2paValidationFailed,
        CreatorNotAllowed,
        AiContentProhibited,
        AiDisclosureMissing,
        TooManyEdits,
        TimestampMissing,
        InvalidManifest,
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        C2paRequired,
        C2paValidationFailed,
        CreatorNotAllowed,
        AiContentProhibited,
        AiDisclosureMissing,
        TooManyEdits,
        TimestampMissing,
        InvalidManifest,
    }

    #[ink(storage)]
    #[derive(Default)]
    pub struct C2paPolicy {
        // Contract storage (empty - stateless validation)
    }

    impl C2paPolicy {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {}
        }

        /// Main policy validation entrypoint
        #[ink(message)]
        pub fn validate_access(
            &self,
            manifest: Option<C2paManifest>,
            policy: ContentPolicy,
        ) -> AccessDecision {
            // Check if C2PA is required
            if policy.require_c2pa && manifest.is_none() {
                return AccessDecision {
                    granted: false,
                    reason: AccessDenialReason::C2paRequired,
                    authenticity_level: AuthenticityLevel::Unverified,
                };
            }

            // If no manifest and not required, allow access
            if manifest.is_none() {
                return AccessDecision {
                    granted: true,
                    reason: AccessDenialReason::Granted,
                    authenticity_level: AuthenticityLevel::Unverified,
                };
            }

            let manifest = manifest.unwrap();

            // Validate C2PA signature
            match self.validate_c2pa_signature(&manifest) {
                Ok(_) => {}
                Err(reason) => {
                    return AccessDecision {
                        granted: false,
                        reason,
                        authenticity_level: AuthenticityLevel::Suspicious,
                    };
                }
            }

            // Validate creator
            if let Err(reason) = self.validate_creator(&manifest, &policy) {
                return AccessDecision {
                    granted: false,
                    reason,
                    authenticity_level: AuthenticityLevel::Verified,
                };
            }

            // Validate AI disclosure
            if let Err(reason) = self.validate_ai_disclosure(&manifest, &policy) {
                return AccessDecision {
                    granted: false,
                    reason,
                    authenticity_level: AuthenticityLevel::Verified,
                };
            }

            // Validate edit count
            if let Err(reason) = self.validate_edit_count(&manifest, &policy) {
                return AccessDecision {
                    granted: false,
                    reason,
                    authenticity_level: AuthenticityLevel::Verified,
                };
            }

            // Validate timestamp
            if let Err(reason) = self.validate_timestamp(&manifest, &policy) {
                return AccessDecision {
                    granted: false,
                    reason,
                    authenticity_level: AuthenticityLevel::Verified,
                };
            }

            // All validations passed
            AccessDecision {
                granted: true,
                reason: AccessDenialReason::Granted,
                authenticity_level: AuthenticityLevel::Verified,
            }
        }

        /// Validate C2PA signature and manifest integrity
        fn validate_c2pa_signature(
            &self,
            manifest: &C2paManifest,
        ) -> Result<(), AccessDenialReason> {
            match manifest.validation_result {
                ValidationResult::Valid => Ok(()),
                ValidationResult::Invalid => Err(AccessDenialReason::C2paValidationFailed),
                ValidationResult::Missing => Err(AccessDenialReason::InvalidManifest),
            }
        }

        /// Validate creator against allowlist
        fn validate_creator(
            &self,
            manifest: &C2paManifest,
            policy: &ContentPolicy,
        ) -> Result<(), AccessDenialReason> {
            // If no allowlist, allow all creators
            if policy.allowed_creators.is_empty() {
                return Ok(());
            }

            // Check if creator is in allowlist
            if let Some(ref creator) = manifest.creator {
                if policy.allowed_creators.contains(creator) {
                    Ok(())
                } else {
                    Err(AccessDenialReason::CreatorNotAllowed)
                }
            } else {
                // Creator missing but allowlist configured
                Err(AccessDenialReason::CreatorNotAllowed)
            }
        }

        /// Validate AI content disclosure
        fn validate_ai_disclosure(
            &self,
            manifest: &C2paManifest,
            policy: &ContentPolicy,
        ) -> Result<(), AccessDenialReason> {
            match policy.ai_disclosure_policy {
                AiDisclosurePolicy::Optional => Ok(()),
                AiDisclosurePolicy::Required => {
                    // Require AI disclosure to be present (true or false)
                    if manifest.ai_generated.is_some() {
                        Ok(())
                    } else {
                        // Missing disclosure
                        Err(AccessDenialReason::AiDisclosureMissing)
                    }
                }
                AiDisclosurePolicy::Prohibited => {
                    // AI-generated content not allowed
                    if let Some(true) = manifest.ai_generated {
                        Err(AccessDenialReason::AiContentProhibited)
                    } else {
                        Ok(())
                    }
                }
            }
        }

        /// Validate edit count against policy limits
        fn validate_edit_count(
            &self,
            manifest: &C2paManifest,
            policy: &ContentPolicy,
        ) -> Result<(), AccessDenialReason> {
            if let Some(max_edits) = policy.max_edit_count {
                if manifest.edit_count > max_edits {
                    Err(AccessDenialReason::TooManyEdits)
                } else {
                    Ok(())
                }
            } else {
                Ok(())
            }
        }

        /// Validate timestamp presence
        fn validate_timestamp(
            &self,
            manifest: &C2paManifest,
            policy: &ContentPolicy,
        ) -> Result<(), AccessDenialReason> {
            if policy.require_timestamp && manifest.timestamp.is_none() {
                Err(AccessDenialReason::TimestampMissing)
            } else {
                Ok(())
            }
        }

        /// Helper: Check if content is verified authentic
        #[ink(message)]
        pub fn is_authentic(&self, manifest: Option<C2paManifest>) -> bool {
            if let Some(ref m) = manifest {
                m.validation_result == ValidationResult::Valid
            } else {
                false
            }
        }

        /// Helper: Get authenticity level
        #[ink(message)]
        pub fn get_authenticity_level(&self, manifest: Option<C2paManifest>) -> AuthenticityLevel {
            match manifest {
                Some(m) => match m.validation_result {
                    ValidationResult::Valid => AuthenticityLevel::Verified,
                    ValidationResult::Invalid => AuthenticityLevel::Suspicious,
                    ValidationResult::Missing => AuthenticityLevel::Unverified,
                },
                None => AuthenticityLevel::Unverified,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn test_no_manifest_no_requirement() {
            let contract = C2paPolicy::new();
            let policy = ContentPolicy {
                require_c2pa: false,
                allowed_creators: Vec::new(),
                ai_disclosure_policy: AiDisclosurePolicy::Optional,
                max_edit_count: None,
                require_timestamp: false,
            };

            let decision = contract.validate_access(None, policy);
            assert!(decision.granted);
            assert_eq!(decision.reason, AccessDenialReason::Granted);
            assert_eq!(decision.authenticity_level, AuthenticityLevel::Unverified);
        }

        #[ink::test]
        fn test_no_manifest_required() {
            let contract = C2paPolicy::new();
            let policy = ContentPolicy {
                require_c2pa: true,
                allowed_creators: Vec::new(),
                ai_disclosure_policy: AiDisclosurePolicy::Optional,
                max_edit_count: None,
                require_timestamp: false,
            };

            let decision = contract.validate_access(None, policy);
            assert!(!decision.granted);
            assert_eq!(decision.reason, AccessDenialReason::C2paRequired);
        }

        #[ink::test]
        fn test_valid_manifest() {
            let contract = C2paPolicy::new();
            let manifest = C2paManifest {
                validation_result: ValidationResult::Valid,
                creator: Some([1u8; 64]),
                ai_generated: Some(false),
                edit_count: 0,
                timestamp: Some(1234567890),
                content_hash: [0u8; 32],
            };
            let policy = ContentPolicy {
                require_c2pa: true,
                allowed_creators: Vec::new(),
                ai_disclosure_policy: AiDisclosurePolicy::Optional,
                max_edit_count: None,
                require_timestamp: false,
            };

            let decision = contract.validate_access(Some(manifest), policy);
            assert!(decision.granted);
            assert_eq!(decision.authenticity_level, AuthenticityLevel::Verified);
        }

        #[ink::test]
        fn test_creator_not_in_allowlist() {
            let contract = C2paPolicy::new();
            let manifest = C2paManifest {
                validation_result: ValidationResult::Valid,
                creator: Some([1u8; 64]),
                ai_generated: Some(false),
                edit_count: 0,
                timestamp: Some(1234567890),
                content_hash: [0u8; 32],
            };
            let policy = ContentPolicy {
                require_c2pa: true,
                allowed_creators: vec![[2u8; 64]], // Different creator
                ai_disclosure_policy: AiDisclosurePolicy::Optional,
                max_edit_count: None,
                require_timestamp: false,
            };

            let decision = contract.validate_access(Some(manifest), policy);
            assert!(!decision.granted);
            assert_eq!(decision.reason, AccessDenialReason::CreatorNotAllowed);
        }

        #[ink::test]
        fn test_ai_content_prohibited() {
            let contract = C2paPolicy::new();
            let manifest = C2paManifest {
                validation_result: ValidationResult::Valid,
                creator: Some([1u8; 64]),
                ai_generated: Some(true),
                edit_count: 0,
                timestamp: Some(1234567890),
                content_hash: [0u8; 32],
            };
            let policy = ContentPolicy {
                require_c2pa: true,
                allowed_creators: Vec::new(),
                ai_disclosure_policy: AiDisclosurePolicy::Prohibited,
                max_edit_count: None,
                require_timestamp: false,
            };

            let decision = contract.validate_access(Some(manifest), policy);
            assert!(!decision.granted);
            assert_eq!(decision.reason, AccessDenialReason::AiContentProhibited);
        }

        #[ink::test]
        fn test_too_many_edits() {
            let contract = C2paPolicy::new();
            let manifest = C2paManifest {
                validation_result: ValidationResult::Valid,
                creator: Some([1u8; 64]),
                ai_generated: Some(false),
                edit_count: 10,
                timestamp: Some(1234567890),
                content_hash: [0u8; 32],
            };
            let policy = ContentPolicy {
                require_c2pa: true,
                allowed_creators: Vec::new(),
                ai_disclosure_policy: AiDisclosurePolicy::Optional,
                max_edit_count: Some(5),
                require_timestamp: false,
            };

            let decision = contract.validate_access(Some(manifest), policy);
            assert!(!decision.granted);
            assert_eq!(decision.reason, AccessDenialReason::TooManyEdits);
        }
    }
}
