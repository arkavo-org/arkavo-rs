//
// Copyright © 2023-2024 Apple Inc. All rights reserved.
//

use crate::base::base_constants::AES128_KEY_SZ;
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::{FPSServerSPCContainer, FPSServerTLLV};
use crate::base::Utils::FPSServerUtils::readBytes;
use crate::requireAction;
use crate::validate::{FPSStatus, Result};

impl Base {
    pub fn parseTagAntiReplay(tllv: &FPSServerTLLV, spcContainer: &mut FPSServerSPCContainer) -> Result<()> {
        // Check that size matches expected size exactly
        requireAction!(tllv.value.len() == AES128_KEY_SZ, return Err(FPSStatus::parserErr));

        spcContainer.spcData.antiReplay = readBytes(&tllv.value, 0, AES128_KEY_SZ)?;

        Ok(())
    }
}
