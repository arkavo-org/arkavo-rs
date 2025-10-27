//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants::FPSTLLVTagValue;
use crate::base::base_constants::FPS_KEY_DURATION_RESERVED_FIELD_VALUE;
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::FPSServerCtx;
use crate::base::Utils::FPSServerUtils::VectorHelperUtils;
use crate::validate::Result;

impl Base {
    pub fn populateTagServerKeyDuration(serverCtx: &mut FPSServerCtx) -> Result<()> {
        let mut keyDuration: Vec<u8> = Default::default();

        // 4B Lease Duration
        keyDuration.appendBigEndianU32(
            serverCtx
                .ckcContainer
                .ckcData
                .ckcAssetInfo
                .keyDuration
                .leaseDuration,
        );

        // 4B Rental Duration
        keyDuration.appendBigEndianU32(
            serverCtx
                .ckcContainer
                .ckcData
                .ckcAssetInfo
                .keyDuration
                .rentalDuration,
        );

        // 4B Key Type
        keyDuration.appendBigEndianU32(
            serverCtx
                .ckcContainer
                .ckcData
                .ckcAssetInfo
                .keyDuration
                .keyType,
        );

        // 4B Reserved
        keyDuration.appendBigEndianU32(FPS_KEY_DURATION_RESERVED_FIELD_VALUE);

        Base::serializeTLLV(
            FPSTLLVTagValue::keyDurationTag as u64,
            &keyDuration,
            &mut serverCtx.ckcContainer,
        )
    }
}
