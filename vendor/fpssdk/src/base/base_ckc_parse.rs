//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

#![allow(unused_assignments)]
use crate::base::base_constants::FPSKeyDurationType;
use crate::base::base_constants::FPSLicenseType;
use crate::base::base_constants::SPCVersion;
use crate::base::base_constants::KD_SYNC_SPC_FLAG_TITLEID_VALID;
use crate::base::base_constants::{FPS_MAX_TITLE_ID_LENGTH, NO_LEASE_DURATION};
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_fps_structures::{FPSOperation, FPSOperationType, FPSResult};
use crate::base::structures::base_server_structures::FPSServerCtx;
use crate::base::Utils::FPSServerUtils::readBigEndianU32;
use crate::validate::{FPSStatus, Result};
use crate::Extension;
use crate::returnErrorStatus;


impl Base {
    /// Fills in `fpsResult` with values that will be returned in the license response
    pub fn createResults(fpsOperation: &mut FPSOperation, fpsResult: &mut FPSResult) -> Result<()> {
        // Set the result id
        fpsResult.id = fpsOperation.id;

        // Generate CKC and other result fields
        Base::genCKCWithCKAndIV(fpsOperation, fpsResult)?;

        Ok(())
    }

    /// Generates CKC and other result fields
    pub fn genCKCWithCKAndIV(
        fpsOperation: &mut FPSOperation,
        fpsResult: &mut FPSResult,
    ) -> Result<()> {
        let localVersion = readBigEndianU32(&fpsOperation.spc, 0)?;

        match localVersion {
            x if (x == (SPCVersion::v1 as u32) || x == (SPCVersion::v2 as u32) || x == (SPCVersion::v3 as u32)) => {
                let mut serverCtx: FPSServerCtx = Default::default();

                // Parse SPC
                Base::parseSPC(fpsOperation, &mut serverCtx)?;

                // Lookup asset information from database (if not provided in input JSON)
                Extension::queryDatabaseCustom(fpsOperation, &serverCtx)?;

                // Extension-specific checks of the request (including checking that the request meets business rules)
                Extension::validateRequestCustom(fpsOperation, &mut serverCtx)?;

                // Populate `serverCtx.ckcContainer` and `fpsResult` structures
                Base::populateServerCtxResult(&mut serverCtx, fpsOperation, fpsResult)?;

                // Create the encrypted content key payload.
                // This also gets the client HU from the request.
                Extension::createContentKeyPayloadCustom(fpsOperation, &mut serverCtx, fpsResult)?;

                if fpsOperation.operationType == FPSOperationType::createCKC && serverCtx.ckcContainer.returnCKC {
                    // Generate the CKC
                    Base::generateCKC(&mut serverCtx)?;

                    fpsResult.ckc = serverCtx.ckcContainer.ckc.to_owned();
                }

                // Finalize `fpsResult` structure
                Extension::finalizeResultsCustom(&serverCtx, fpsResult)?;
            }

            _ => {
                returnErrorStatus!(FPSStatus::spcVersionErr);
            }
        }

        Ok(())
    }

    /// Populates `serverCtx.ckcContainer` and `fpsResult` structure with fields that will be returned to the caller
    pub fn populateServerCtxResult(
        serverCtx: &mut FPSServerCtx,
        operation: &FPSOperation,
        result: &mut FPSResult,
    ) -> Result<()> {
        // Copy some SPC information to the results structure

        let assetInfo = &operation.assetInfo;

        // Offline HLS or Online HLS rental
        if assetInfo.licenseType == FPSLicenseType::offlineHLS as u32 {
            if assetInfo.streamId.is_some() {
                serverCtx.ckcContainer.ckcData.ckcAssetInfo.streamId = assetInfo.streamId.to_owned();
            }

            if assetInfo.titleId.is_some() {
                serverCtx.ckcContainer.ckcData.ckcAssetInfo.titleId = assetInfo.titleId.to_owned();
            }

            serverCtx.ckcContainer.ckcData.ckcAssetInfo.keyDuration.rentalDuration = assetInfo.rentalDuration;
            serverCtx.ckcContainer.ckcData.ckcAssetInfo.keyDuration.playbackDuration = assetInfo.playbackDuration;
            if (assetInfo.rentalDuration != 0) || (assetInfo.playbackDuration != 0) {
                serverCtx.ckcContainer.ckcData.ckcAssetInfo.keyDuration.keyType = FPSKeyDurationType::persistenceAndDuration as u32;
            } else {
                serverCtx.ckcContainer.ckcData.ckcAssetInfo.keyDuration.keyType = FPSKeyDurationType::persistence as u32;
            }
        }

        // Is lease requested?
        if assetInfo.leaseDuration != NO_LEASE_DURATION {
            serverCtx.ckcContainer.ckcData.ckcAssetInfo.keyDuration.leaseDuration = assetInfo.leaseDuration;
            serverCtx.ckcContainer.ckcData.ckcAssetInfo.keyDuration.rentalDuration = assetInfo.rentalDuration;
            serverCtx.ckcContainer.ckcData.ckcAssetInfo.keyDuration.playbackDuration = assetInfo.playbackDuration;
            serverCtx.ckcContainer.ckcData.ckcAssetInfo.keyDuration.keyType = FPSKeyDurationType::lease as u32;
        }

        // Required HDCP type for the content
        serverCtx.ckcContainer.ckcData.ckcAssetInfo.hdcpRequirement = assetInfo.hdcpReq;

        // Copy fields from SPC
        result.resultAssetInfo.assetId = serverCtx.spcContainer.spcData.spcAssetInfo.id.clone();
        result.resultAssetInfo.playInfo = serverCtx.spcContainer.spcData.spcAssetInfo.playInfo;
        result.streamingIndicator = serverCtx.spcContainer.spcData.streamingIndicator;
        result.transactionId = serverCtx.spcContainer.spcData.transactionId;
        result.capabilities = serverCtx.spcContainer.spcData.clientCapabilities.clone();
        result.supportedSecurityLevel = serverCtx.spcContainer.spcData.supportedSecurityLevel;
        result.clientKextDenyListVersion = serverCtx.spcContainer.spcData.clientKextDenyListVersion;
        result.deviceIdentity = serverCtx.spcContainer.spcData.deviceIdentity.clone();
        result.deviceInfo = serverCtx.spcContainer.spcData.deviceInfo.clone();
        result.isCheckIn = operation.isCheckIn;

        // Report if the request came from a virtual machine
        if serverCtx.spcContainer.spcData.vmDeviceInfo.is_some() {
            result.vmDeviceInfo = serverCtx.spcContainer.spcData.vmDeviceInfo.clone();
        }
        else {
            result.vmDeviceInfo = None;
        }

        Extension::populateResultsCustom(serverCtx, operation, result)?;

        result.offlineSyncData = serverCtx.spcContainer.spcData.offlineSyncData.clone();

        if operation.isCheckIn {
            // Report title ID if present
            if (serverCtx.spcContainer.spcData.offlineSyncData.syncFlags & KD_SYNC_SPC_FLAG_TITLEID_VALID) != 0 {
                serverCtx.ckcContainer.ckcData.ckcAssetInfo.titleId = Some(serverCtx.spcContainer.spcData.offlineSyncData.syncTitleId.clone());
                result.offlineSyncData.syncTitleId = serverCtx.spcContainer.spcData.offlineSyncData.syncTitleId[..FPS_MAX_TITLE_ID_LENGTH].to_vec();
            }
        }

        Ok(())
    }
}
