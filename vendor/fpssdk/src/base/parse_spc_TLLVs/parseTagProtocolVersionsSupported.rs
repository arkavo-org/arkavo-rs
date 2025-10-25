//
// Copyright © 2023-2024 Apple Inc. All rights reserved.
//

use std::mem::size_of;

use crate::base::base_constants::FPS_MAX_NUM_CRYPTO_VERSIONS;
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::{FPSServerSPCContainer, FPSServerTLLV};
use crate::base::Utils::FPSServerUtils::readBigEndianU32;
use crate::requireAction;
use crate::validate::{FPSStatus, Result};

impl Base {
    pub fn parseTagProtocolVersionsSupported(
        tllv: &FPSServerTLLV,
        spcContainer: &mut FPSServerSPCContainer,
    ) -> Result<()> {
        // Size must be a multiple of the version information
        requireAction!(
            tllv.value.len() % size_of::<u32>() == 0,
            return Err(FPSStatus::parserErr)
        );

        let mut offset: usize = 0;

        // Loop through the supported version tag and store them
        while offset < tllv.value.len() {
            // 4B Supported Version
            let version = readBigEndianU32(&tllv.value, offset)?;
            offset += size_of::<u32>();

            // Save into versionsSupported list
            spcContainer.spcData.versionsSupported.push(version);

            requireAction!(
                spcContainer.spcData.versionsSupported.len() < FPS_MAX_NUM_CRYPTO_VERSIONS,
                return Err(FPSStatus::paramErr)
            );
        }

        Ok(())
    }
}
