//
// Copyright © 2023-2024 Apple Inc. All rights reserved.
//

use std::mem::size_of;

use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::{FPSServerSPCContainer, FPSServerTLLV};
use crate::base::Utils::FPSServerUtils::readBigEndianU64;
use crate::requireAction;
use crate::validate::{FPSStatus, Result};

impl Base {
    pub fn parseTagTransactionID(
        tllv: &FPSServerTLLV,
        spcContainer: &mut FPSServerSPCContainer,
    ) -> Result<()> {
        // Check that size matches expected size exactly
        requireAction!(
            tllv.value.len() == size_of::<u64>(),
            return Err(FPSStatus::parserErr)
        );

        // 8B Transaction ID
        spcContainer.spcData.transactionId = readBigEndianU64(&tllv.value, 0)?;

        log::debug!("Transaction ID: 0x{:x}", spcContainer.spcData.transactionId);

        Ok(())
    }
}
