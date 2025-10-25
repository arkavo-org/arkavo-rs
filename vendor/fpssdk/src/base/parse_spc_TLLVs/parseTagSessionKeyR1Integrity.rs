//
// Copyright © 2023-2024 Apple Inc. All rights reserved.
//

use crate::base::base_constants::FPS_V1_SKR1_INTEGRITY_SZ;
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::{FPSServerSPCContainer, FPSServerTLLV};
use crate::base::Utils::FPSServerUtils::readBytes;
use crate::requireAction;
use crate::validate::{FPSStatus, Result};

impl Base {
    pub fn parseTagSessionKeyR1Integrity(tllv: &FPSServerTLLV, spcContainer: &mut FPSServerSPCContainer) -> Result<()> {
        // Check that size matches expected size exactly
        requireAction!(
            tllv.value.len() == FPS_V1_SKR1_INTEGRITY_SZ,
            return Err(FPSStatus::parserErr)
        );

        // Entire TLLV value is the SK R1 Integrity value
        spcContainer.spcData.skR1IntegrityTag = readBytes(&tllv.value, 0, FPS_V1_SKR1_INTEGRITY_SZ)?;

        Ok(())
    }
}
