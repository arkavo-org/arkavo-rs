//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants::FPSTLLVTagValue;
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::FPSServerCtx;
use crate::base::Utils::FPSServerUtils::VectorHelperUtils;
use crate::validate::Result;

impl Base {
    pub fn populateTagServerHDCPInformation(serverCtx: &mut FPSServerCtx) -> Result<()> {
        let mut hdcpReq: Vec<u8> = Default::default();

        // 8B HDCP Requirement
        hdcpReq.appendBigEndianU64(serverCtx.ckcContainer.ckcData.ckcAssetInfo.hdcpRequirement);

        // 8B Random Values
        hdcpReq.appendRandomBytes(8);

        Base::serializeTLLV(
            FPSTLLVTagValue::hdcpInformationTag as u64,
            &hdcpReq,
            &mut serverCtx.ckcContainer,
        )
    }
}
