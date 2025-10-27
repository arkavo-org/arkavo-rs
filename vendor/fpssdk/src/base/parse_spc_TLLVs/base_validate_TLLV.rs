//
// Copyright © 2023-2024 Apple Inc. All rights reserved.
//

use crate::base::base_constants::FPSTLLVTagValue;
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::FPSServerSPCContainer;
use crate::returnErrorStatus;
use crate::validate::{FPSStatus, Result};
use crate::Extension;

impl Base {
    /// Makes sure all required TLLVs have been parsed from the SPC.
    pub fn validateTLLVs(spcContainer: &mut FPSServerSPCContainer) -> Result<()> {
        // Enforce the minimum set of required TLLVs in V1
        let requiredTags: Vec<u64> = vec![
            FPSTLLVTagValue::sessionKeyR1Tag as u64,
            FPSTLLVTagValue::antiReplayTag as u64,
            FPSTLLVTagValue::r2Tag as u64,
            FPSTLLVTagValue::assetIDTag as u64,
            FPSTLLVTagValue::transactionIDTag as u64,
            FPSTLLVTagValue::protocolVersionUsedTag as u64,
            FPSTLLVTagValue::protocolVersionsSupportedTag as u64,
            FPSTLLVTagValue::returnRequestTag as u64,
            FPSTLLVTagValue::sessionKeyR1IntegrityTag as u64,
        ];
        for tag in requiredTags {
            if !spcContainer
                .spcData
                .spcDataParser
                .parsedTagValues
                .contains(&tag)
            {
                returnErrorStatus!(FPSStatus::missingRequiredTagErr);
            }
        }

        // Custom handling (if needed)
        Extension::validateTLLVsCustom(spcContainer)
    }
}
