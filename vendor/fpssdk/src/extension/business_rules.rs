//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants::{self, FPSHDCPRequirement, FPSLicenseType};
use crate::base::structures::base_fps_structures::AssetInfo;
use crate::base::structures::base_server_structures::FPSServerCtx;
use crate::extension::extension_constants::ContentType;
use crate::extension::extension_constants::FPSSecurityLevel;
use crate::extension::structures::extension_structures::SDKExtension;
use crate::validate::{FPSStatus, Result};
use crate::{fpsLogError, returnErrorStatus};

impl SDKExtension {
    /// Verifies that license is allowed to be created based on business rules
    pub fn checkBusinessRules(
        isCheckIn: bool,
        assetInfo: &AssetInfo,
        serverCtx: &mut FPSServerCtx,
    ) -> Result<()> {
        //
        // NOTE: These are just suggested default rules. Please feel free to edit as desired.
        //
        let ckcAssetInfoExtension = &mut serverCtx.ckcContainer.ckcData.ckcAssetInfo.extension;

        // Verify Kext Deny List version if client reported one
        if serverCtx.spcContainer.spcData.clientKextDenyListVersion > 0
            && serverCtx.spcContainer.spcData.clientKextDenyListVersion
                < base_constants::MIN_KDL_VERSION
        {
            fpsLogError!(
                FPSStatus::clientSecurityLevelErr,
                "KDL version supported by the client ({:?}) does not meet minimum required ({:?})",
                serverCtx.spcContainer.spcData.clientKextDenyListVersion,
                base_constants::MIN_KDL_VERSION
            );
            returnErrorStatus!(FPSStatus::clientSecurityLevelErr);
        }

        // Lease cannot be used together with Offline HLS
        if (assetInfo.leaseDuration != base_constants::NO_LEASE_DURATION)
            && (assetInfo.leaseDuration != 0)
            && assetInfo.licenseType == FPSLicenseType::offlineHLS as u32
        {
            fpsLogError!(
                FPSStatus::paramErr,
                "lease is not supported for offline HLS"
            );
            returnErrorStatus!(FPSStatus::paramErr);
        }

        // Verify that if check-in is requested then SPC has syncFlags
        if isCheckIn && (serverCtx.spcContainer.spcData.offlineSyncData.syncFlags == 0) {
            fpsLogError!(
                FPSStatus::paramErr,
                "check-in requested but SPC is missing SyncTLLV"
            );
            returnErrorStatus!(FPSStatus::paramErr);
        }

        // Device security level checks based on content type
        match assetInfo.extension.contentType {
            ContentType::uhd => {
                // UHD content requires security level Main
                ckcAssetInfoExtension.requiredSecurityLevel = FPSSecurityLevel::main;

                if let Some(supportedSecurityLevel) =
                    serverCtx.spcContainer.spcData.supportedSecurityLevel
                {
                    if supportedSecurityLevel < FPSSecurityLevel::main as u64 {
                        fpsLogError!(
                            FPSStatus::clientSecurityLevelErr,
                            "UHD content requires security level Main. Client supports 0x{:X}",
                            supportedSecurityLevel,
                        );
                        returnErrorStatus!(FPSStatus::clientSecurityLevelErr);
                    }
                } else if serverCtx
                    .spcContainer
                    .spcData
                    .clientFeatures
                    .supportsSecurityLevelBaseline
                    && !serverCtx
                        .spcContainer
                        .spcData
                        .clientFeatures
                        .supportsSecurityLevelMain
                {
                    // Note: older devices do not send any supported security fields, so only fail here if
                    // supportsSecurityLevelBaseline is set but supportsSecurityLevelMain is not
                    fpsLogError!(
                        FPSStatus::clientSecurityLevelErr,
                        "UHD content requires security level Main. Client supports Baseline"
                    );
                    returnErrorStatus!(FPSStatus::clientSecurityLevelErr);
                }

                // UHD content requires HDCP type 1
                if assetInfo.hdcpReq != FPSHDCPRequirement::hdcpType1 as u64 {
                    fpsLogError!(FPSStatus::paramErr, "UHD content requires HDCP type 1");
                    returnErrorStatus!(FPSStatus::paramErr);
                }
            }

            ContentType::hd => {
                // HD content requires security level Baseline or higher
                ckcAssetInfoExtension.requiredSecurityLevel = FPSSecurityLevel::baseline;

                if let Some(supportedSecurityLevel) =
                    serverCtx.spcContainer.spcData.supportedSecurityLevel
                {
                    if supportedSecurityLevel < FPSSecurityLevel::baseline as u64 {
                        fpsLogError!(
                            FPSStatus::clientSecurityLevelErr,
                            "HD content requires security level Baseline. Client supports 0x{:X}",
                            supportedSecurityLevel,
                        );
                        returnErrorStatus!(FPSStatus::clientSecurityLevelErr);
                    }
                }

                // HD content requires HDCP
                if assetInfo.hdcpReq == FPSHDCPRequirement::hdcpNotRequired as u64 {
                    fpsLogError!(FPSStatus::paramErr, "HD content requires HDCP");
                    returnErrorStatus!(FPSStatus::paramErr);
                }
            }

            ContentType::sd => {
                // SD content requires security level Baseline or higher
                ckcAssetInfoExtension.requiredSecurityLevel = FPSSecurityLevel::baseline;

                if let Some(supportedSecurityLevel) =
                    serverCtx.spcContainer.spcData.supportedSecurityLevel
                {
                    if supportedSecurityLevel < FPSSecurityLevel::baseline as u64 {
                        fpsLogError!(
                            FPSStatus::clientSecurityLevelErr,
                            "SD content requires security level Baseline. Client supports 0x{:X}",
                            supportedSecurityLevel,
                        );
                        returnErrorStatus!(FPSStatus::clientSecurityLevelErr);
                    }
                }
            }

            ContentType::audio => {
                // No special requirements for audio content type
                ckcAssetInfoExtension.requiredSecurityLevel = FPSSecurityLevel::audio;
            }

            ContentType::unknown => {
                //Content type must be set to determine a security level
                fpsLogError!(FPSStatus::paramErr, "No content type provided");
                returnErrorStatus!(FPSStatus::paramErr);
            }
        }

        // Verify that if HDCP Type 1 is required then client supports it
        if assetInfo.hdcpReq == FPSHDCPRequirement::hdcpType1 as u64
            && !serverCtx
                .spcContainer
                .spcData
                .clientFeatures
                .supportsHDCPTypeOne
        {
            fpsLogError!(
                FPSStatus::clientSecurityLevelErr,
                "HDCP type 1 enforcement requested but not supported by client"
            );
            returnErrorStatus!(FPSStatus::clientSecurityLevelErr);
        }

        //To stop a license from being created for a virtual machine, uncomment this if statement
        /*if serverCtx.spcContainer.spcData.vmDeviceInfo.is_some() {
            fpsLogError!(FPSStatus::clientSecurityLevelErr, "Content cannot be played on a Virtual Machine");
            returnErrorStatus!(FPSStatus::clientSecurityLevelErr);
        }*/

        Ok(())
    }
}
