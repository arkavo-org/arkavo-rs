//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants::FPSTLLVTagValue;
use crate::base::base_constants::FPS_TLLV_SECURITY_LEVEL_TLLV_VERSION;
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::FPSServerCtx;
use crate::base::Utils::FPSServerUtils::VectorHelperUtils;
use crate::validate::Result;
use crate::SDKExtension;

impl SDKExtension {
    pub fn populateTagSecurityLevel(serverCtx: &mut FPSServerCtx) -> Result<()> {
        let mut securityLevel: Vec<u8> = Default::default();

        // 4B Version
        securityLevel.appendBigEndianU32(FPS_TLLV_SECURITY_LEVEL_TLLV_VERSION);

        // 4B Reserved
        securityLevel.appendBigEndianU32(0);

        // 8B Required Security Level
        securityLevel.appendBigEndianU64(
            serverCtx
                .ckcContainer
                .ckcData
                .ckcAssetInfo
                .extension
                .requiredSecurityLevel as u64,
        );

        Base::serializeTLLV(
            FPSTLLVTagValue::securityLevelTag as u64,
            &securityLevel,
            &mut serverCtx.ckcContainer,
        )
    }
}
