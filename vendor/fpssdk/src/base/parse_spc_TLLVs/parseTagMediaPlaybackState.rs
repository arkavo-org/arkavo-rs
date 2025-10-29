//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use std::mem::size_of;

use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::{FPSServerSPCContainer, FPSServerTLLV};
use crate::base::Utils::FPSServerUtils::{readBigEndianU32, readBigEndianU64};
use crate::requireAction;
use crate::validate::{FPSStatus, Result};

impl Base {
    pub fn parseTagMediaPlaybackState(tllv: &FPSServerTLLV, spcContainer: &mut FPSServerSPCContainer) -> Result<()> {
        // Check that size matches expected size exactly
        requireAction!(
            tllv.value.len() == size_of::<u32>() * 2 + size_of::<u64>(),
            return Err(FPSStatus::paramErr)
        );

        // 4B Date
        spcContainer.spcData.spcAssetInfo.playInfo.date = readBigEndianU32(&tllv.value, 0)?;

        // 4B Playback State
        spcContainer.spcData.spcAssetInfo.playInfo.playbackState = readBigEndianU32(&tllv.value, 4)?;

        // 8B Playback ID
        spcContainer.spcData.spcAssetInfo.playInfo.playbackId = readBigEndianU64(&tllv.value, 8)?;

        Ok(())
    }
}
