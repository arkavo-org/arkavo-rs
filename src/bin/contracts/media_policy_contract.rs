#![allow(unexpected_cfgs)]
#![allow(dead_code)] // Ink contract generated functions

/// Media DRM Policy Contract
///
/// Implements streaming-specific business rules for TDF3-protected media content.
/// Inspired by FairPlay Streaming SDK's policy enforcement model.

#[ink::contract]
pub mod media_policy {

    /// Content security levels based on resolution/quality
    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    #[allow(clippy::upper_case_acronyms)]
    pub enum ContentSecurityLevel {
        Audio, // Audio-only content
        SD,    // Standard Definition (< 720p)
        HD,    // High Definition (720p-1080p)
        UHD,   // Ultra High Definition (4K+)
    }

    /// HDCP (High-bandwidth Digital Content Protection) requirements
    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum HDCPRequirement {
        NotRequired, // No HDCP needed
        Type0,       // HDCP 1.x or 2.0
        Type1,       // HDCP 2.2+ (required for UHD)
    }

    /// License/rental type
    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum LicenseType {
        Streaming,    // Online streaming only
        Rental,       // Time-limited download
        Purchase,     // Permanent download
        Subscription, // Active subscription required
    }

    /// Subscription status
    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum SubscriptionStatus {
        Active,
        Expired,
        Suspended,
        Cancelled,
    }

    /// User entitlement information
    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct UserEntitlement {
        pub user_id: [u8; 32],
        pub subscription_status: SubscriptionStatus,
        pub subscription_tier: u8, // 0=free, 1=basic, 2=premium, etc.
        pub max_concurrent_streams: u32,
        pub geo_region: [u8; 2],           // ISO 3166-1 alpha-2 country code
        pub allowed_regions: Vec<[u8; 2]>, // Allowed country codes
    }

    /// Rental window constraints
    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct RentalWindow {
        pub purchase_timestamp: i64, // Unix timestamp
        pub first_play_timestamp: Option<i64>,
        pub rental_duration_seconds: i64, // Total time from purchase
        pub playback_duration_seconds: i64, // Time from first play
    }

    /// Content metadata
    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct ContentMetadata {
        pub asset_id: [u8; 32],
        pub security_level: ContentSecurityLevel,
        pub hdcp_requirement: HDCPRequirement,
        pub license_type: LicenseType,
        pub rental_window: Option<RentalWindow>,
    }

    /// Device security capabilities
    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct DeviceCapabilities {
        pub supports_hdcp_type_0: bool,
        pub supports_hdcp_type_1: bool,
        pub security_level: u8, // 0=none, 1=baseline, 2=main
        pub is_virtual_machine: bool,
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        SubscriptionInactive,
        SubscriptionTierInsufficient,
        ConcurrencyLimitExceeded,
        GeoRestrictionViolation,
        RentalWindowExpired,
        RentalNotStarted,
        HDCPNotSupported,
        SecurityLevelInsufficient,
        VirtualMachineNotAllowed,
        DeviceNotAuthorized,
    }

    #[ink(storage)]
    #[derive(Default)]
    pub struct MediaPolicy {
        // Contract storage (empty - stateless validation)
    }

    impl MediaPolicy {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {}
        }

        /// Main policy validation entrypoint
        #[ink(message)]
        pub fn validate_access(
            &self,
            entitlement: UserEntitlement,
            content: ContentMetadata,
            device: DeviceCapabilities,
            current_active_streams: u32,
            client_geo_region: [u8; 2],
            current_timestamp: i64,
        ) -> Result<(), Error> {
            // 1. Subscription validation
            self.validate_subscription(&entitlement, &content)?;

            // 2. Concurrency limits
            self.validate_concurrency(&entitlement, current_active_streams)?;

            // 3. Geo-restrictions
            self.validate_geo_access(&entitlement, client_geo_region)?;

            // 4. Rental windows
            if let Some(ref rental) = content.rental_window {
                self.validate_rental_window(rental, current_timestamp)?;
            }

            // 5. Device security level
            self.validate_device_security(&content, &device)?;

            // 6. HDCP requirements
            self.validate_hdcp(&content, &device)?;

            Ok(())
        }

        fn validate_subscription(
            &self,
            entitlement: &UserEntitlement,
            content: &ContentMetadata,
        ) -> Result<(), Error> {
            if content.license_type == LicenseType::Subscription {
                if entitlement.subscription_status != SubscriptionStatus::Active {
                    return Err(Error::SubscriptionInactive);
                }
                // Premium content requires higher tier
                if matches!(content.security_level, ContentSecurityLevel::UHD)
                    && entitlement.subscription_tier < 2
                {
                    return Err(Error::SubscriptionTierInsufficient);
                }
            }
            Ok(())
        }

        fn validate_concurrency(
            &self,
            entitlement: &UserEntitlement,
            current_active_streams: u32,
        ) -> Result<(), Error> {
            if current_active_streams >= entitlement.max_concurrent_streams {
                return Err(Error::ConcurrencyLimitExceeded);
            }
            Ok(())
        }

        fn validate_geo_access(
            &self,
            entitlement: &UserEntitlement,
            client_geo_region: [u8; 2],
        ) -> Result<(), Error> {
            if !entitlement.allowed_regions.is_empty()
                && !entitlement.allowed_regions.contains(&client_geo_region)
            {
                return Err(Error::GeoRestrictionViolation);
            }
            Ok(())
        }

        fn validate_rental_window(
            &self,
            rental: &RentalWindow,
            current_timestamp: i64,
        ) -> Result<(), Error> {
            // Check if rental period from purchase has expired
            let elapsed_since_purchase = current_timestamp - rental.purchase_timestamp;
            if elapsed_since_purchase > rental.rental_duration_seconds {
                return Err(Error::RentalWindowExpired);
            }

            // If playback has started, check playback window
            if let Some(first_play) = rental.first_play_timestamp {
                let elapsed_since_first_play = current_timestamp - first_play;
                if elapsed_since_first_play > rental.playback_duration_seconds {
                    return Err(Error::RentalWindowExpired);
                }
            }

            Ok(())
        }

        fn validate_device_security(
            &self,
            content: &ContentMetadata,
            device: &DeviceCapabilities,
        ) -> Result<(), Error> {
            // Block virtual machines for premium content
            if device.is_virtual_machine
                && matches!(
                    content.security_level,
                    ContentSecurityLevel::HD | ContentSecurityLevel::UHD
                )
            {
                return Err(Error::VirtualMachineNotAllowed);
            }

            // Check security level requirements
            let required_level = match content.security_level {
                ContentSecurityLevel::Audio => 0,
                ContentSecurityLevel::SD => 1,
                ContentSecurityLevel::HD => 1,
                ContentSecurityLevel::UHD => 2,
            };

            if device.security_level < required_level {
                return Err(Error::SecurityLevelInsufficient);
            }

            Ok(())
        }

        fn validate_hdcp(
            &self,
            content: &ContentMetadata,
            device: &DeviceCapabilities,
        ) -> Result<(), Error> {
            match content.hdcp_requirement {
                HDCPRequirement::NotRequired => Ok(()),
                HDCPRequirement::Type0 => {
                    if !device.supports_hdcp_type_0 {
                        Err(Error::HDCPNotSupported)
                    } else {
                        Ok(())
                    }
                }
                HDCPRequirement::Type1 => {
                    if !device.supports_hdcp_type_1 {
                        Err(Error::HDCPNotSupported)
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn test_subscription_required() {
            let contract = MediaPolicy::new();

            let mut entitlement = UserEntitlement {
                user_id: [1u8; 32],
                subscription_status: SubscriptionStatus::Expired,
                subscription_tier: 1,
                max_concurrent_streams: 2,
                geo_region: [b'U', b'S'],
                allowed_regions: vec![],
            };

            let content = ContentMetadata {
                asset_id: [2u8; 32],
                security_level: ContentSecurityLevel::HD,
                hdcp_requirement: HDCPRequirement::Type0,
                license_type: LicenseType::Subscription,
                rental_window: None,
            };

            let device = DeviceCapabilities {
                supports_hdcp_type_0: true,
                supports_hdcp_type_1: false,
                security_level: 1,
                is_virtual_machine: false,
            };

            // Should fail with expired subscription
            assert_eq!(
                contract.validate_access(
                    entitlement.clone(),
                    content.clone(),
                    device.clone(),
                    0,
                    [b'U', b'S'],
                    0
                ),
                Err(Error::SubscriptionInactive)
            );

            // Should pass with active subscription
            entitlement.subscription_status = SubscriptionStatus::Active;
            assert!(contract
                .validate_access(entitlement, content, device, 0, [b'U', b'S'], 0)
                .is_ok());
        }

        #[ink::test]
        fn test_concurrency_limit() {
            let contract = MediaPolicy::new();

            let entitlement = UserEntitlement {
                user_id: [1u8; 32],
                subscription_status: SubscriptionStatus::Active,
                subscription_tier: 1,
                max_concurrent_streams: 2,
                geo_region: [b'U', b'S'],
                allowed_regions: vec![],
            };

            let content = ContentMetadata {
                asset_id: [2u8; 32],
                security_level: ContentSecurityLevel::SD,
                hdcp_requirement: HDCPRequirement::NotRequired,
                license_type: LicenseType::Streaming,
                rental_window: None,
            };

            let device = DeviceCapabilities {
                supports_hdcp_type_0: true,
                supports_hdcp_type_1: false,
                security_level: 1,
                is_virtual_machine: false,
            };

            // Should fail when at limit
            assert_eq!(
                contract.validate_access(
                    entitlement.clone(),
                    content.clone(),
                    device.clone(),
                    2,
                    [b'U', b'S'],
                    0
                ),
                Err(Error::ConcurrencyLimitExceeded)
            );

            // Should pass when under limit
            assert!(contract
                .validate_access(entitlement, content, device, 1, [b'U', b'S'], 0)
                .is_ok());
        }

        #[ink::test]
        fn test_rental_window() {
            let contract = MediaPolicy::new();

            let entitlement = UserEntitlement {
                user_id: [1u8; 32],
                subscription_status: SubscriptionStatus::Active,
                subscription_tier: 1,
                max_concurrent_streams: 2,
                geo_region: [b'U', b'S'],
                allowed_regions: vec![],
            };

            let rental = RentalWindow {
                purchase_timestamp: 1000,
                first_play_timestamp: Some(1100),
                rental_duration_seconds: 86400 * 7, // 7 days from purchase
                playback_duration_seconds: 172800,  // 48 hours from first play
            };

            let content = ContentMetadata {
                asset_id: [2u8; 32],
                security_level: ContentSecurityLevel::HD,
                hdcp_requirement: HDCPRequirement::Type0,
                license_type: LicenseType::Rental,
                rental_window: Some(rental),
            };

            let device = DeviceCapabilities {
                supports_hdcp_type_0: true,
                supports_hdcp_type_1: false,
                security_level: 1,
                is_virtual_machine: false,
            };

            // Should pass within playback window
            assert!(contract
                .validate_access(
                    entitlement.clone(),
                    content.clone(),
                    device.clone(),
                    0,
                    [b'U', b'S'],
                    1100 + 10000
                )
                .is_ok());

            // Should fail after playback window expires (48h after first play)
            assert_eq!(
                contract.validate_access(
                    entitlement,
                    content,
                    device,
                    0,
                    [b'U', b'S'],
                    1100 + 172801
                ),
                Err(Error::RentalWindowExpired)
            );
        }

        #[ink::test]
        fn test_hdcp_requirements() {
            let contract = MediaPolicy::new();

            let entitlement = UserEntitlement {
                user_id: [1u8; 32],
                subscription_status: SubscriptionStatus::Active,
                subscription_tier: 2,
                max_concurrent_streams: 2,
                geo_region: [b'U', b'S'],
                allowed_regions: vec![],
            };

            let content = ContentMetadata {
                asset_id: [2u8; 32],
                security_level: ContentSecurityLevel::UHD,
                hdcp_requirement: HDCPRequirement::Type1,
                license_type: LicenseType::Streaming,
                rental_window: None,
            };

            let mut device = DeviceCapabilities {
                supports_hdcp_type_0: true,
                supports_hdcp_type_1: false,
                security_level: 2,
                is_virtual_machine: false,
            };

            // Should fail without HDCP Type 1
            assert_eq!(
                contract.validate_access(
                    entitlement.clone(),
                    content.clone(),
                    device.clone(),
                    0,
                    [b'U', b'S'],
                    0
                ),
                Err(Error::HDCPNotSupported)
            );

            // Should pass with HDCP Type 1
            device.supports_hdcp_type_1 = true;
            assert!(contract
                .validate_access(entitlement, content, device, 0, [b'U', b'S'], 0)
                .is_ok());
        }
    }
}
