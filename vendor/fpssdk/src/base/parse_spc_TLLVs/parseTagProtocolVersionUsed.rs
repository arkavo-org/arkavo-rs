//
// Copyright © 2023-2024 Apple Inc. All rights reserved.
//

use std::mem::size_of;

use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::{FPSServerSPCContainer, FPSServerTLLV};
use crate::base::Utils::FPSServerUtils::readBigEndianU32;
use crate::requireAction;
use crate::validate::{FPSStatus, Result};

impl Base {
    pub fn parseTagProtocolVersionUsed(tllv: &FPSServerTLLV, spcContainer: &mut FPSServerSPCContainer) -> Result<()> {
        // Check that size matches expected size exactly
        requireAction!(tllv.value.len() == size_of::<u32>(), return Err(FPSStatus::parserErr));

        // 4B Version Used
        spcContainer.spcData.versionUsed = readBigEndianU32(&tllv.value, 0)?;

        Ok(())
    }
}
