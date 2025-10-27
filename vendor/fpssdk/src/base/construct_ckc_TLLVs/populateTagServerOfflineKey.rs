//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants::{
    FPSTLLVTagValue, FPS_MAX_STREAM_ID_LENGTH, FPS_MAX_TITLE_ID_LENGTH,
};
use crate::base::base_constants::{
    FPS_TLLV_OFFLINEKEY_TLLV_VERSION, FPS_TLLV_OFFLINEKEY_TLLV_VERSION_2,
};
use crate::base::structures::base_server_structures::FPSServerCtx;
use crate::base::Utils::FPSServerUtils::VectorHelperUtils;
use crate::fpsLogError;
use crate::returnErrorStatus;
use crate::validate::{FPSStatus, Result};
use crate::Base;
use crate::Extension;

impl Base {
    pub fn populateTagServerOfflineKey(serverCtx: &mut FPSServerCtx) -> Result<()> {
        let mut offlineKeyTLLVVersion: u32 = FPS_TLLV_OFFLINEKEY_TLLV_VERSION;
        let mut offlineKeyTLLV: Vec<u8> = Default::default();

        // Check if we need to send down Stream ID (aka Content ID) and Title ID
        if (serverCtx
            .ckcContainer
            .ckcData
            .ckcAssetInfo
            .streamId
            .is_some())
            || (serverCtx
                .ckcContainer
                .ckcData
                .ckcAssetInfo
                .titleId
                .is_some())
        {
            // Verify that the client device actually supports Offline TLLV V2
            if !serverCtx
                .spcContainer
                .spcData
                .clientFeatures
                .supportsOfflineKeyTLLVV2
            {
                fpsLogError!(
                    FPSStatus::paramErr,
                    "stream ID and title ID provided on the input but client doesn't support OfflineTLLV V2"
                );
                returnErrorStatus!(FPSStatus::paramErr);
            }

            // If the client supports, then change TLLV version to V2
            offlineKeyTLLVVersion = FPS_TLLV_OFFLINEKEY_TLLV_VERSION_2;
        }

        // 4B Version
        offlineKeyTLLV.appendBigEndianU32(offlineKeyTLLVVersion);

        // 4B Reserved
        offlineKeyTLLV.appendBigEndianU32(0);

        // 16B Content ID (Stream ID in V2)
        if let Some(streamId) = serverCtx
            .ckcContainer
            .ckcData
            .ckcAssetInfo
            .streamId
            .as_mut()
        {
            streamId.resize(FPS_MAX_STREAM_ID_LENGTH, 0);
            offlineKeyTLLV.extend(streamId.iter());
        } else {
            // Content ID is a custom field
            Extension::offlineKeyTagPopulateContentIDCustom(serverCtx, &mut offlineKeyTLLV)?;
        }

        // 4B Storage Duration
        offlineKeyTLLV.appendBigEndianU32(
            serverCtx
                .ckcContainer
                .ckcData
                .ckcAssetInfo
                .keyDuration
                .rentalDuration,
        );

        // 4B Playback Duration
        offlineKeyTLLV.appendBigEndianU32(
            serverCtx
                .ckcContainer
                .ckcData
                .ckcAssetInfo
                .keyDuration
                .playbackDuration,
        );

        // Additional fields for Version 2
        if offlineKeyTLLVVersion == FPS_TLLV_OFFLINEKEY_TLLV_VERSION_2 {
            // 16B Title ID
            serverCtx
                .ckcContainer
                .ckcData
                .ckcAssetInfo
                .titleId
                .as_mut()
                .unwrap()
                .resize(FPS_MAX_TITLE_ID_LENGTH, 0);
            offlineKeyTLLV.extend(
                serverCtx
                    .ckcContainer
                    .ckcData
                    .ckcAssetInfo
                    .titleId
                    .as_ref()
                    .unwrap(),
            );
        }

        Base::serializeTLLV(
            FPSTLLVTagValue::offlineKeyTag as u64,
            &offlineKeyTLLV,
            &mut serverCtx.ckcContainer,
        )?;

        Ok(())
    }
}
