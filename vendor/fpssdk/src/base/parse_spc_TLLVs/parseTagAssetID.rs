//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants::{FPS_V1_ASSET_ID_MAX_SZ, FPS_V1_ASSET_ID_MIN_SZ};
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::{FPSServerSPCContainer, FPSServerTLLV};
use crate::requireAction;
use crate::validate::{FPSStatus, Result};

impl Base {
    pub fn parseTagAssetID(
        tllv: &FPSServerTLLV,
        spcContainer: &mut FPSServerSPCContainer,
    ) -> Result<()> {
        // Check that Asset ID size is within bounds
        requireAction!(
            (tllv.value.len() >= FPS_V1_ASSET_ID_MIN_SZ),
            return Err(FPSStatus::parserErr)
        );
        requireAction!(
            (tllv.value.len() <= FPS_V1_ASSET_ID_MAX_SZ),
            return Err(FPSStatus::parserErr)
        );

        // Entire TLLV value is the Asset ID
        // Convert to a string, stopping if it encounters any invalid characters.
        spcContainer.spcData.spcAssetInfo.id = match String::from_utf8(tllv.value.to_owned()) {
            Ok(r) => r,
            Err(e) => String::from_utf8(e.as_bytes()[0..e.utf8_error().valid_up_to()].to_vec())
                .unwrap_or_default(),
        };

        log::debug!("Asset ID: {}", spcContainer.spcData.spcAssetInfo.id);

        Ok(())
    }
}
