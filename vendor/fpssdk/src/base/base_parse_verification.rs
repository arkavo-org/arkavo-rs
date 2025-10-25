//
// base_parse_verification.rs : Defines verification functions required by the Base class.
//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants;
use crate::base::structures::base_fps_structures::AssetInfo;
use crate::base::structures::base_fps_structures::Base;
use crate::fpsLogError;
use crate::returnErrorStatus;
use crate::validate::{FPSStatus, Result};
use crate::Extension;

impl Base {
    /// Verify validity of the Offline HLS input
    pub fn verifyOfflineHLS(assetInfo: &mut AssetInfo) -> Result<()> {
        // contentID and titleID should be set (or not set) at the same time
        if assetInfo.streamId.is_some() != assetInfo.titleId.is_some() {
            fpsLogError!(
                FPSStatus::paramErr,
                "both {} and {} should be set (or both not set) in offline HLS object",
                base_constants::STREAM_ID_STR,
                base_constants::TITLE_ID_STR
            );
            returnErrorStatus!(FPSStatus::paramErr);
        }

        Extension::verifyOfflineHLSCustom(assetInfo)
    }
}
