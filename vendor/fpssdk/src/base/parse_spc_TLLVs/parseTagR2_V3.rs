//
// Copyright © 2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants::FPS_V1_R2_V3_MAX_SZ;
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::{FPSServerSPCContainer, FPSServerTLLV};
use crate::requireAction;
use crate::validate::{FPSStatus, Result};

impl Base {
    pub fn parseTagR2_V3(
        tllv: &FPSServerTLLV,
        spcContainer: &mut FPSServerSPCContainer,
    ) -> Result<()> {
        requireAction!(
            tllv.value.len() <= FPS_V1_R2_V3_MAX_SZ,
            return Err(FPSStatus::parserErr)
        );

        spcContainer.spcData.r2_v3 = tllv.value.clone();
        log::debug!("R2 V3: 0x{}", hex::encode(tllv.value.clone()));

        Ok(())
    }
}
