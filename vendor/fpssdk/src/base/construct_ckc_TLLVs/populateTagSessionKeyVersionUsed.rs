//
// Copyright © 2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants::FPSTLLVTagValue;
use crate::base::base_constants::FPS_TLLV_SESSION_KEY_USED_TLLV_VERSION;
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::FPSServerCtx;
use crate::base::Utils::FPSServerUtils::VectorHelperUtils;
use crate::validate::Result;

impl Base {
    pub fn populateTagSessionKeyVersionUsed(serverCtx: &mut FPSServerCtx) -> Result<()> {
        let mut sessionKeyVersion: Vec<u8> = Default::default();

        // 4B Version field
        sessionKeyVersion.appendBigEndianU32(FPS_TLLV_SESSION_KEY_USED_TLLV_VERSION);

        // 4B Reserved field set to 0
        sessionKeyVersion.appendBigEndianU32(0);

        // 8B Key Type: which session key was used: generic or video
        sessionKeyVersion.appendBigEndianU64(serverCtx.ckcContainer.ckcData.ckcAssetInfo.sessionKeyUsed);

        Base::serializeTLLV(
            FPSTLLVTagValue::sessionKeyVersionUsedTag as u64,
            &sessionKeyVersion,
            &mut serverCtx.ckcContainer,
        )
    }
}