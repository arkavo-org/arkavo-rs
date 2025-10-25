//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants::FPS_CAPABILITIES_FLAGS_LENGTH;
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::FPSServerTLLV;
use crate::requireAction;
use crate::validate::{FPSStatus, Result};

impl Base {
    pub fn parseTagClientCapabilities(tllv: &FPSServerTLLV, clientCapabilities: &mut Vec<u8>) -> Result<()> {
        // Check that size matches expected size exactly
        requireAction!(
            tllv.value.len() == FPS_CAPABILITIES_FLAGS_LENGTH,
            return Err(FPSStatus::paramErr)
        );

        // Entire TLLV value is the client capabilities flags
        *clientCapabilities = tllv.value.clone();
        log::debug!("Client Capabilities: 0x{}", hex::encode(tllv.value.clone()));

        Ok(())
    }
}
