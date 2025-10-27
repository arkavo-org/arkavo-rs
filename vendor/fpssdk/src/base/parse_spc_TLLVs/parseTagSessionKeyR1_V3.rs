//
// Copyright © 2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants::FPS_V1_SKR1_V3_MAX_SZ;
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::{FPSServerSPCContainer, FPSServerTLLV};
use crate::requireAction;
use crate::validate::{FPSStatus, Result};

impl Base {
    pub fn parseTagSessionKeyR1_V3(
        tllv: &FPSServerTLLV,
        spcContainer: &mut FPSServerSPCContainer,
    ) -> Result<()> {
        requireAction!(
            tllv.value.len() <= FPS_V1_SKR1_V3_MAX_SZ,
            return Err(FPSStatus::parserErr)
        );

        spcContainer.spcData.sk_r1_v3 = tllv.value.clone();
        log::debug!("SKR1 V3: 0x{}", hex::encode(tllv.value.clone()));

        Ok(())
    }
}
