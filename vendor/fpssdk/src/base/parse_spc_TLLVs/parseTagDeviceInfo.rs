//
// Copyright © 2023-2024 Apple Inc. All rights reserved.
//

use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::{FPSServerSPCContainer, FPSServerTLLV};
use crate::base::Utils::FPSServerUtils::{readBigEndianU32, readBigEndianU64};
use crate::validate::Result;

impl Base {
    pub fn parseTagDeviceInfo(tllv: &FPSServerTLLV, spcContainer: &mut FPSServerSPCContainer) -> Result<()> {
        // 8B Device Type (value is one of FPSAppleDeviceType)
        spcContainer.spcData.deviceInfo.deviceType = readBigEndianU64(&tllv.value, 0)?;

        // 4B OS Version (concatenation of 00 || major || minor || extra)
        spcContainer.spcData.deviceInfo.osVersion = readBigEndianU32(&tllv.value, 8)?;

        // 4B TLLV Version
        let _version = readBigEndianU32(&tllv.value, 12)?;

        spcContainer.spcData.deviceInfo.isDeviceInfoSet = true;

        Ok(())
    }
}
