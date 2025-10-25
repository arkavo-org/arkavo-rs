//
// Copyright © 2023-2024 Apple Inc. All rights reserved.
//

use crate::base::base_constants::FPS_MAX_KEY_FORMATS;
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::{FPSServerSPCContainer, FPSServerTLLV};
use crate::base::Utils::FPSServerUtils::{readBigEndianU32, readBigEndianU64};
use crate::validate::{FPSStatus, Result};
use crate::{fpsLogError, returnErrorStatus};
use std::mem::size_of;

impl Base {
    pub fn parseTagSupportedKeyFormat(tllv: &FPSServerTLLV, spcContainer: &mut FPSServerSPCContainer) -> Result<()> {
        // 4B Version
        let tllvVersion = readBigEndianU32(&tllv.value, 0)?;

        // Ignore the TLLV when version is not set to 1
        if tllvVersion == 1 {
            // 4B Reserved
            let _reserved = readBigEndianU32(&tllv.value, 4)?;

            // 4B Number of Key Formats
            let numberOfKeyFormats = readBigEndianU32(&tllv.value, 8)?;

            if numberOfKeyFormats > FPS_MAX_KEY_FORMATS as u32 {
                fpsLogError!(
                    FPSStatus::paramErr,
                    "{} exceeds maximum number of supported key formats {}",
                    numberOfKeyFormats,
                    FPS_MAX_KEY_FORMATS
                );
                returnErrorStatus!(FPSStatus::paramErr);
            }

            let mut offset: usize = 12;

            // Key Formats (variable size)
            spcContainer.spcData.numberOfSupportedKeyFormats = numberOfKeyFormats;
            for i in 0..numberOfKeyFormats as usize {
                spcContainer.spcData.supportedKeyFormats[i] = readBigEndianU64(&tllv.value, offset)?;
                offset += size_of::<u64>();

                // log::debug!("Client Supported Key Format {}: 0x{:016x}", i, spcContainer.spcData.supportedKeyFormats[i]);
            }
        }

        Ok(())
    }
}
